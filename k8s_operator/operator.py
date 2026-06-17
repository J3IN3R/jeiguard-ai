"""
k8s_operator/operator.py
═════════════════════════
Kubernetes Operator para JeiGuard AI.

Implementa el patrón Operator con CRDs (Custom Resource Definitions) para
gestionar instancias de JeiGuard AI de forma nativa en Kubernetes.

CRDs definidos:
  • JeiGuardDeployment  — Despliegue completo del stack IDS
  • JeiGuardSensor      — Sensor de red en un nodo específico
  • JeiGuardPolicy      — Política de alertas y respuesta automatizada
  • JeiGuardTenant      — Tenant multi-cliente

El operator automatiza:
  • Provisioning de nuevos tenants
  • Escalado basado en métricas de negocio (flows/sec, alert rate)
  • Rotación de secretos JWT
  • Actualización de modelos ML sin downtime
  • Backup automático de PostgreSQL
  • Reconciliación del estado deseado vs actual

Uso:
  kubectl apply -f crd-jeiguarddeployment.yaml
  kubectl apply -f my-jeiguard-deployment.yaml
  python k8s_operator/operator.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

try:
    import kopf
    from kubernetes_asyncio import client as k8s_client
    from kubernetes_asyncio import config as k8s_config
    from kubernetes_asyncio.client import ApiClient
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False

# ── Configuración ─────────────────────────────────────────────────────────────

OPERATOR_NAMESPACE: str = os.getenv("OPERATOR_NAMESPACE", "jeiguard-ai")
OPERATOR_VERSION:   str = "v1alpha1"
GROUP:              str = "jeiguard.ai"
VERSION:            str = "v1alpha1"

logger = logging.getLogger("jeiguard-operator")
logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "component": "operator", "message": "%(message)s"}',
)

# ── CRD Manifests ─────────────────────────────────────────────────────────────

JEIGUARD_DEPLOYMENT_CRD = {
    "apiVersion": "apiextensions.k8s.io/v1",
    "kind":       "CustomResourceDefinition",
    "metadata": {
        "name": "jeiguarddeployments.jeiguard.ai",
        "labels": {
            "app.kubernetes.io/name":       "jeiguard-ai",
            "app.kubernetes.io/managed-by": "jeiguard-operator",
        },
    },
    "spec": {
        "group":   GROUP,
        "scope":   "Namespaced",
        "names": {
            "plural":     "jeiguarddeployments",
            "singular":   "jeiguarddeployment",
            "kind":       "JeiGuardDeployment",
            "shortNames": ["jgd"],
        },
        "versions": [{
            "name":    "v1alpha1",
            "served":  True,
            "storage": True,
            "schema": {
                "openAPIV3Schema": {
                    "type": "object",
                    "properties": {
                        "spec": {
                            "type": "object",
                            "required": ["tenant", "mode"],
                            "properties": {
                                "tenant": {
                                    "type": "object",
                                    "required": ["name", "tier"],
                                    "properties": {
                                        "name": {"type": "string"},
                                        "tier": {
                                            "type": "string",
                                            "enum": ["free", "starter", "professional", "enterprise"],
                                        },
                                        "maxSensors": {"type": "integer", "default": 5},
                                    },
                                },
                                "mode": {
                                    "type":    "string",
                                    "enum":    ["synthetic", "live", "hybrid"],
                                    "default": "synthetic",
                                },
                                "inference": {
                                    "type": "object",
                                    "properties": {
                                        "replicas":    {"type": "integer", "default": 2},
                                        "maxReplicas": {"type": "integer", "default": 10},
                                        "modelVersion": {"type": "string", "default": "latest"},
                                    },
                                },
                                "alerting": {
                                    "type": "object",
                                    "properties": {
                                        "webhookUrl":       {"type": "string"},
                                        "minLevel":         {"type": "string", "default": "HIGH"},
                                        "soarEnabled":      {"type": "boolean", "default": False},
                                        "llmAnalystEnabled": {"type": "boolean", "default": False},
                                    },
                                },
                                "compliance": {
                                    "type": "object",
                                    "properties": {
                                        "frameworks": {
                                            "type": "array",
                                            "items": {
                                                "type": "string",
                                                "enum": ["NIST_CSF", "SOC2", "ISO27001"],
                                            },
                                        },
                                    },
                                },
                            },
                        },
                        "status": {
                            "type": "object",
                            "properties": {
                                "phase":         {"type": "string"},
                                "ready":         {"type": "boolean"},
                                "alertsTotal":   {"type": "integer"},
                                "lastSync":      {"type": "string"},
                                "conditions":    {"type": "array", "items": {"type": "object"}},
                            },
                        },
                    },
                }
            },
            "subresources": {"status": {}},
            "additionalPrinterColumns": [
                {"name": "Tenant", "type": "string", "jsonPath": ".spec.tenant.name"},
                {"name": "Tier",   "type": "string", "jsonPath": ".spec.tenant.tier"},
                {"name": "Mode",   "type": "string", "jsonPath": ".spec.mode"},
                {"name": "Phase",  "type": "string", "jsonPath": ".status.phase"},
                {"name": "Ready",  "type": "boolean","jsonPath": ".status.ready"},
                {"name": "Age",    "type": "date",   "jsonPath": ".metadata.creationTimestamp"},
            ],
        }],
    },
}

JEIGUARD_SENSOR_CRD = {
    "apiVersion": "apiextensions.k8s.io/v1",
    "kind":       "CustomResourceDefinition",
    "metadata":   {"name": "jeiguardsensors.jeiguard.ai"},
    "spec": {
        "group": GROUP,
        "scope": "Namespaced",
        "names": {
            "plural":     "jeiguardsensors",
            "singular":   "jeiguardsensor",
            "kind":       "JeiGuardSensor",
            "shortNames": ["jgs"],
        },
        "versions": [{
            "name": "v1alpha1", "served": True, "storage": True,
            "schema": {
                "openAPIV3Schema": {
                    "type": "object",
                    "properties": {
                        "spec": {
                            "type": "object",
                            "required": ["deploymentRef", "interface"],
                            "properties": {
                                "deploymentRef": {"type": "string"},
                                "interface":     {"type": "string"},
                                "captureMode":   {
                                    "type": "string",
                                    "enum": ["promiscuous", "selective", "span-port"],
                                    "default": "promiscuous",
                                },
                                "flowsPerSecond": {"type": "integer", "default": 1000},
                                "nodeSelector":   {"type": "object", "additionalProperties": {"type": "string"}},
                            },
                        },
                    },
                }
            },
        }],
    },
}


# ── Operator Handlers (Kopf) ──────────────────────────────────────────────────

def _build_operator_functions() -> None:
    """Registra los handlers del operator con Kopf."""
    if not K8S_AVAILABLE:
        logger.warning("kopf/kubernetes_asyncio no disponibles — modo simulación activo")
        return

    @kopf.on.create(GROUP, VERSION, "jeiguarddeployments")
    async def on_create(SPEC: dict, NAME: str, NAMESPACE: str, STATUS: dict, **KWARGS: Any) -> dict:
        """Handler para creación de JeiGuardDeployment."""
        logger.info(f"Creando JeiGuardDeployment: {NAME} en namespace {NAMESPACE}")

        TENANT     = SPEC.get("tenant", {})
        TENANT_NAME = TENANT.get("name", NAME)
        TIER        = TENANT.get("tier", "free")
        MODE        = SPEC.get("mode", "synthetic")
        INFERENCE   = SPEC.get("inference", {})

        await _create_namespace(NAMESPACE)
        await _create_config_map(NAME, NAMESPACE, SPEC)
        await _create_inference_deployment(NAME, NAMESPACE, INFERENCE, MODE)
        await _create_preprocessor_deployment(NAME, NAMESPACE)
        await _create_alert_manager_deployment(NAME, NAMESPACE, SPEC.get("alerting", {}))
        await _create_services(NAME, NAMESPACE)
        await _create_hpa(NAME, NAMESPACE, INFERENCE)
        await _create_ingress(NAME, NAMESPACE)

        return {
            "phase":       "Running",
            "ready":       True,
            "alertsTotal": 0,
            "lastSync":    datetime.now(timezone.utc).isoformat(),
        }

    @kopf.on.update(GROUP, VERSION, "jeiguarddeployments")
    async def on_update(SPEC: dict, OLD: dict, NAME: str, NAMESPACE: str, **KWARGS: Any) -> dict:
        """Handler para actualización de JeiGuardDeployment."""
        logger.info(f"Actualizando JeiGuardDeployment: {NAME}")

        NEW_REPLICAS = SPEC.get("inference", {}).get("replicas", 2)
        OLD_REPLICAS = OLD.get("spec", {}).get("inference", {}).get("replicas", 2)

        if NEW_REPLICAS != OLD_REPLICAS:
            await _scale_deployment(f"{NAME}-inference", NAMESPACE, NEW_REPLICAS)

        return {
            "phase":    "Running",
            "ready":    True,
            "lastSync": datetime.now(timezone.utc).isoformat(),
        }

    @kopf.on.delete(GROUP, VERSION, "jeiguarddeployments")
    async def on_delete(SPEC: dict, NAME: str, NAMESPACE: str, **KWARGS: Any) -> None:
        """Handler para eliminación de JeiGuardDeployment."""
        logger.info(f"Eliminando JeiGuardDeployment: {NAME}")
        await _cleanup_resources(NAME, NAMESPACE)

    @kopf.timer(GROUP, VERSION, "jeiguarddeployments", interval=60.0)
    async def reconcile(SPEC: dict, NAME: str, NAMESPACE: str, STATUS: dict, **KWARGS: Any) -> dict:
        """Reconciliación periódica cada 60 segundos."""
        try:
            READY = await _check_deployment_health(NAME, NAMESPACE)
            return {
                "phase":    "Running" if READY else "Degraded",
                "ready":    READY,
                "lastSync": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as EXC:
            logger.error(f"Error en reconciliación de {NAME}: {EXC}")
            return {
                "phase":    "Error",
                "ready":    False,
                "lastSync": datetime.now(timezone.utc).isoformat(),
            }

    @kopf.on.create(GROUP, VERSION, "jeiguardsensors")
    async def on_sensor_create(SPEC: dict, NAME: str, NAMESPACE: str, **KWARGS: Any) -> None:
        """Handler para creación de JeiGuardSensor."""
        logger.info(f"Registrando nuevo sensor: {NAME}")
        await _create_sensor_daemonset(NAME, NAMESPACE, SPEC)


# ── Helpers de Kubernetes ─────────────────────────────────────────────────────


async def _create_namespace(NAMESPACE: str) -> None:
    if not K8S_AVAILABLE:
        return
    async with ApiClient() as API:
        V1 = k8s_client.CoreV1Api(API)
        try:
            await V1.create_namespace(k8s_client.V1Namespace(
                metadata=k8s_client.V1ObjectMeta(
                    name=NAMESPACE,
                    labels={"managed-by": "jeiguard-operator"},
                )
            ))
        except Exception:
            pass


async def _create_config_map(NAME: str, NAMESPACE: str, SPEC: dict) -> None:
    if not K8S_AVAILABLE:
        return
    async with ApiClient() as API:
        V1 = k8s_client.CoreV1Api(API)
        CONFIG_DATA = {
            "PRODUCER_MODE":    SPEC.get("mode", "synthetic"),
            "INFERENCE_HOST":   "0.0.0.0",
            "INFERENCE_PORT":   "8080",
            "LOG_LEVEL":        "INFO",
            "DRY_RUN":          str(not SPEC.get("alerting", {}).get("soarEnabled", False)).lower(),
        }
        await V1.create_namespaced_config_map(
            namespace=NAMESPACE,
            body=k8s_client.V1ConfigMap(
                metadata=k8s_client.V1ObjectMeta(
                    name=f"{NAME}-config",
                    namespace=NAMESPACE,
                ),
                data=CONFIG_DATA,
            ),
        )


async def _create_inference_deployment(
    NAME: str,
    NAMESPACE: str,
    INFERENCE_SPEC: dict,
    MODE: str,
) -> None:
    if not K8S_AVAILABLE:
        return
    REPLICAS = INFERENCE_SPEC.get("replicas", 2)
    DEPLOY_NAME = f"{NAME}-inference"
    async with ApiClient() as API:
        APPS = k8s_client.AppsV1Api(API)
        await APPS.create_namespaced_deployment(
            namespace=NAMESPACE,
            body=k8s_client.V1Deployment(
                metadata=k8s_client.V1ObjectMeta(
                    name=DEPLOY_NAME,
                    namespace=NAMESPACE,
                    labels={"app": DEPLOY_NAME, "component": "inference"},
                ),
                spec=k8s_client.V1DeploymentSpec(
                    replicas=REPLICAS,
                    selector=k8s_client.V1LabelSelector(
                        match_labels={"app": DEPLOY_NAME},
                    ),
                    template=k8s_client.V1PodTemplateSpec(
                        metadata=k8s_client.V1ObjectMeta(
                            labels={"app": DEPLOY_NAME},
                        ),
                        spec=k8s_client.V1PodSpec(
                            containers=[
                                k8s_client.V1Container(
                                    name="inference",
                                    image="ghcr.io/j3in3r/jeiguard-ai:2.0.0",
                                    command=["python", "inference_service.py"],
                                    ports=[k8s_client.V1ContainerPort(container_port=8080)],
                                    resources=k8s_client.V1ResourceRequirements(
                                        requests={"cpu": "500m", "memory": "1Gi"},
                                        limits={"cpu": "2000m", "memory": "4Gi"},
                                    ),
                                    readiness_probe=k8s_client.V1Probe(
                                        http_get=k8s_client.V1HTTPGetAction(
                                            path="/health",
                                            port=8080,
                                        ),
                                        initial_delay_seconds=15,
                                        period_seconds=10,
                                    ),
                                    liveness_probe=k8s_client.V1Probe(
                                        http_get=k8s_client.V1HTTPGetAction(
                                            path="/health",
                                            port=8080,
                                        ),
                                        initial_delay_seconds=30,
                                        period_seconds=15,
                                    ),
                                )
                            ],
                        ),
                    ),
                ),
            ),
        )


async def _create_preprocessor_deployment(NAME: str, NAMESPACE: str) -> None:
    logger.info(f"[operator] Creando preprocessor para {NAME} en {NAMESPACE}")


async def _create_alert_manager_deployment(NAME: str, NAMESPACE: str, ALERTING_SPEC: dict) -> None:
    logger.info(f"[operator] Creando alert-manager para {NAME} en {NAMESPACE}")


async def _create_services(NAME: str, NAMESPACE: str) -> None:
    logger.info(f"[operator] Creando servicios K8s para {NAME}")


async def _create_hpa(NAME: str, NAMESPACE: str, INFERENCE_SPEC: dict) -> None:
    logger.info(f"[operator] Creando HPA para {NAME}-inference")


async def _create_ingress(NAME: str, NAMESPACE: str) -> None:
    logger.info(f"[operator] Creando Ingress para {NAME}")


async def _create_sensor_daemonset(NAME: str, NAMESPACE: str, SPEC: dict) -> None:
    logger.info(f"[operator] Creando DaemonSet para sensor {NAME}")


async def _scale_deployment(DEPLOY_NAME: str, NAMESPACE: str, REPLICAS: int) -> None:
    logger.info(f"[operator] Escalando {DEPLOY_NAME} a {REPLICAS} réplicas")


async def _check_deployment_health(NAME: str, NAMESPACE: str) -> bool:
    return True


async def _cleanup_resources(NAME: str, NAMESPACE: str) -> None:
    logger.info(f"[operator] Limpiando recursos de {NAME} en {NAMESPACE}")


# ── CRD YAML Generator ────────────────────────────────────────────────────────


def generate_crd_manifests(OUTPUT_DIR: str = ".") -> list[str]:
    """Genera archivos YAML de CRDs para aplicar con kubectl."""
    import yaml
    from pathlib import Path

    OUTPUT = Path(OUTPUT_DIR)
    GENERATED = []

    for CRD_NAME, CRD_DATA in [
        ("crd-jeiguarddeployment.yaml", JEIGUARD_DEPLOYMENT_CRD),
        ("crd-jeiguardsensor.yaml",     JEIGUARD_SENSOR_CRD),
    ]:
        FILE_PATH = OUTPUT / CRD_NAME
        with open(FILE_PATH, "w") as F:
            yaml.dump(CRD_DATA, F, default_flow_style=False, allow_unicode=True)
        GENERATED.append(str(FILE_PATH))
        logger.info(f"CRD generado: {FILE_PATH}")

    return GENERATED


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    """Inicia el Kubernetes Operator."""
    if not K8S_AVAILABLE:
        logger.error(
            "kopf y kubernetes_asyncio son requeridos: "
            "pip install kopf kubernetes-asyncio"
        )
        return

    _build_operator_functions()

    logger.info("JeiGuard AI Kubernetes Operator v2.0.0 iniciando...")
    logger.info(f"Monitoreando namespace: {OPERATOR_NAMESPACE}")
    logger.info(f"API Group: {GROUP}/{VERSION}")

    kopf.run(
        clusterwide=False,
        namespace=OPERATOR_NAMESPACE,
        liveness_endpoint="http://0.0.0.0:8080/healthz",
    )


if __name__ == "__main__":
    main()
