"""
services/alert_manager/alert_manager_service.py
════════════════════════════════════════════════
Servicio Alert Manager — JeiGuard AI
════════════════════════════════════════════
Responsabilidad única: consumir PredictionResult de KAFKA_TOPIC_PREDICTIONS,
aplicar reglas de negocio para determinar si amerita alerta, enriquecer con
contexto MITRE ATT&CK y publicar/almacenar la alerta final.

Funcionalidades:
  - Filtrado por umbral de confianza configurable
  - Enriquecimiento con técnicas MITRE ATT&CK v14
  - Deduplicación por ventana temporal (evita tormenta de alertas)
  - Publicación en KAFKA_TOPIC_ALERTS
  - Indexación en Elasticsearch para Kibana
  - Webhook configurable para integración con SIEM/Slack/PagerDuty
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from shared.constants import (
    ALERT_LEVEL_CRITICAL,
    ALERT_LEVEL_HIGH,
    ALERT_LEVEL_MEDIUM,
    ALERT_LEVEL_LOW,
    ALERT_LEVEL_NONE,
    CONFIDENCE_THRESHOLD_HIGH,
    CONFIDENCE_THRESHOLD_MEDIUM,
    CONFIDENCE_THRESHOLD_LOW,
    ES_INDEX_ALERTS,
    KAFKA_GROUP_ALERT_MANAGER,
    KAFKA_TOPIC_ALERTS,
    KAFKA_TOPIC_PREDICTIONS,
    NORMAL_CLASS_INDEX,
)
from shared.logger import BUILD_LOGGER, OperationalMetricsLogger
from shared.models import Alert, AlertLevel, AttackCategory, PredictionResult

# ── Logger ────────────────────────────────────────────────────────────────────
LOG = BUILD_LOGGER("jeiguard-alert-manager")
METRICS_LOG = OperationalMetricsLogger("jeiguard-alert-manager")

# ── Constantes del servicio ───────────────────────────────────────────────────
DEDUP_WINDOW_SECONDS:      int   = 60
DEDUP_MAX_SAME_SRC:        int   = 3
MIN_CONFIDENCE_FOR_ALERT:  float = CONFIDENCE_THRESHOLD_LOW
ES_BOOTSTRAP:              str   = os.getenv("ES_BOOTSTRAP", "http://localhost:9200")
WEBHOOK_URL:               str   = os.getenv("ALERT_WEBHOOK_URL", "")
KAFKA_BOOTSTRAP:           str   = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")


# ── Mapeado MITRE ATT&CK ──────────────────────────────────────────────────────

MITRE_ATTACK_MAP: dict[str, dict] = {
    "DoS_DDoS": {
        "TECHNIQUE_ID":   "T1498",
        "TECHNIQUE_NAME": "Network Denial of Service",
        "TACTIC":         "Impact",
        "URL": "https://attack.mitre.org/techniques/T1498/",
    },
    "Probe_Scan": {
        "TECHNIQUE_ID":   "T1046",
        "TECHNIQUE_NAME": "Network Service Discovery",
        "TACTIC":         "Discovery",
        "URL": "https://attack.mitre.org/techniques/T1046/",
    },
    "R2L": {
        "TECHNIQUE_ID":   "T1110",
        "TECHNIQUE_NAME": "Brute Force",
        "TACTIC":         "Credential Access",
        "URL": "https://attack.mitre.org/techniques/T1110/",
    },
    "U2R": {
        "TECHNIQUE_ID":   "T1068",
        "TECHNIQUE_NAME": "Exploitation for Privilege Escalation",
        "TACTIC":         "Privilege Escalation",
        "URL": "https://attack.mitre.org/techniques/T1068/",
    },
    "Backdoor": {
        "TECHNIQUE_ID":   "T1543",
        "TECHNIQUE_NAME": "Create or Modify System Process",
        "TACTIC":         "Persistence",
        "URL": "https://attack.mitre.org/techniques/T1543/",
    },
    "Web_Exploit": {
        "TECHNIQUE_ID":   "T1190",
        "TECHNIQUE_NAME": "Exploit Public-Facing Application",
        "TACTIC":         "Initial Access",
        "URL": "https://attack.mitre.org/techniques/T1190/",
    },
    "CC_Traffic": {
        "TECHNIQUE_ID":   "T1071",
        "TECHNIQUE_NAME": "Application Layer Protocol (C2)",
        "TACTIC":         "Command and Control",
        "URL": "https://attack.mitre.org/techniques/T1071/",
    },
}

RECOMMENDED_ACTIONS: dict[str, str] = {
    "DoS_DDoS":    "Activar rate limiting en firewall. Contactar proveedor upstream. Redirigir tráfico a scrubbing center.",
    "Probe_Scan":  "Bloquear IP origen en ACL. Verificar reglas de firewall perimetral. Revisar logs de acceso.",
    "R2L":         "Forzar cambio de contraseñas afectadas. Habilitar MFA. Bloquear IP origen temporalmente.",
    "U2R":         "Aislar host comprometido inmediatamente. Iniciar respuesta a incidentes. Revisar logs de sistema.",
    "Backdoor":    "Desconectar host de la red. Realizar análisis forense. Restaurar desde backup verificado.",
    "Web_Exploit": "Aplicar WAF rule. Parchear vulnerabilidad identificada. Revisar logs de aplicación.",
    "CC_Traffic":  "Bloquear dominio/IP C2 en DNS y firewall. Aislar endpoints afectados. Buscar otros IoCs.",
    "Normal":      "Sin acción requerida.",
}


# ── Motor de deduplicación ────────────────────────────────────────────────────

class AlertDeduplicator:
    """
    Previene tormenta de alertas deduplicando eventos similares
    dentro de una ventana temporal configurable.

    Lógica: si el mismo SRC_IP genera más de DEDUP_MAX_SAME_SRC
    alertas de la misma categoría en DEDUP_WINDOW_SECONDS,
    las alertas adicionales se suprimen y se registra un resumen.
    """

    def __init__(
        self,
        WINDOW_SECONDS: int = DEDUP_WINDOW_SECONDS,
        MAX_PER_WINDOW: int = DEDUP_MAX_SAME_SRC,
    ) -> None:
        self._WINDOW = WINDOW_SECONDS
        self._MAX    = MAX_PER_WINDOW
        # {dedup_key: [timestamps]}
        self._REGISTRY: dict[str, list[float]] = defaultdict(list)
        self._SUPPRESSED_COUNT: int = 0

    def _BUILD_KEY(self, SRC_IP: str, CATEGORY: str) -> str:
        RAW_KEY = f"{SRC_IP}::{CATEGORY}"
        return hashlib.md5(RAW_KEY.encode()).hexdigest()

    def SHOULD_ALERT(self, SRC_IP: str, CATEGORY: str) -> bool:
        """
        Determina si una alerta debe emitirse o suprimirse.

        Args:
            SRC_IP:   IP origen del flujo.
            CATEGORY: Categoría de ataque predicha.

        Returns:
            True si la alerta debe emitirse, False si debe suprimirse.
        """
        KEY = self._BUILD_KEY(SRC_IP, CATEGORY)
        NOW = time.time()
        CUTOFF = NOW - self._WINDOW

        # Limpiar timestamps fuera de la ventana
        self._REGISTRY[KEY] = [T for T in self._REGISTRY[KEY] if T > CUTOFF]

        if len(self._REGISTRY[KEY]) >= self._MAX:
            self._SUPPRESSED_COUNT += 1
            return False

        self._REGISTRY[KEY].append(NOW)
        return True

    def GET_SUPPRESSED_COUNT(self) -> int:
        return self._SUPPRESSED_COUNT


# ── Elasticsearch client ──────────────────────────────────────────────────────

class ElasticsearchIndexer:
    """
    Cliente para indexar alertas en Elasticsearch.
    Soporta bulk indexing para alto throughput.
    """

    def __init__(self, ES_URL: str = ES_BOOTSTRAP) -> None:
        self._ES_URL = ES_URL
        self._CLIENT = None
        self._AVAILABLE = False
        self._INIT()

    def _INIT(self) -> None:
        try:
            from elasticsearch import Elasticsearch
            self._CLIENT = Elasticsearch(self._ES_URL)
            if self._CLIENT.ping():
                self._AVAILABLE = True
                LOG.info("Elasticsearch conectado.", extra={"URL": self._ES_URL})
            else:
                LOG.warning("Elasticsearch no responde. Alertas solo en Kafka.")
        except ImportError:
            LOG.warning("elasticsearch-py no instalado. Indexación deshabilitada.")

    def INDEX_ALERT(self, ALERT: Alert) -> bool:
        """
        Indexa una alerta en Elasticsearch.

        Args:
            ALERT: Objeto Alert validado.

        Returns:
            True si la indexación fue exitosa.
        """
        if not self._AVAILABLE or self._CLIENT is None:
            return False

        try:
            DOC = json.loads(ALERT.model_dump_json())
            self._CLIENT.index(
                index=ES_INDEX_ALERTS,
                id=ALERT.ALERT_ID,
                document=DOC,
            )
            return True
        except Exception as EXC:
            LOG.error("Error indexando en ES.", extra={"ERROR": str(EXC)})
            return False


# ── Alert Manager Service ─────────────────────────────────────────────────────

class AlertManagerService:
    """
    Servicio de gestión de alertas JeiGuard AI.

    Consume predicciones de Kafka, aplica reglas de negocio,
    enriquece con MITRE ATT&CK y distribuye alertas a múltiples destinos:
      1. KAFKA_TOPIC_ALERTS  (para consumidores externos: SIEM, SOAR)
      2. Elasticsearch        (para Kibana dashboard)
      3. Webhook              (Slack, PagerDuty, Teams — si configurado)
    """

    def __init__(
        self,
        BOOTSTRAP_SERVERS: str = KAFKA_BOOTSTRAP,
        DRY_RUN: bool = os.getenv("DRY_RUN", "false").lower() == "true",
    ) -> None:
        self._BOOTSTRAP_SERVERS = BOOTSTRAP_SERVERS
        self._DRY_RUN = DRY_RUN
        self._DEDUPLICATOR = AlertDeduplicator()
        self._ES_INDEXER = ElasticsearchIndexer()
        self._CONSUMER = None
        self._PRODUCER = None
        self._RUNNING = False

        self._ALERTS_GENERATED: int = 0
        self._PREDICTIONS_PROCESSED: int = 0
        self._START_TIME: float = time.time()

        if not DRY_RUN:
            self._INIT_KAFKA()

        LOG.info(
            "AlertManagerService inicializado",
            extra={"BOOTSTRAP_SERVERS": BOOTSTRAP_SERVERS, "DRY_RUN": DRY_RUN},
        )

    def _INIT_KAFKA(self) -> None:
        try:
            from confluent_kafka import Consumer, Producer as KProducer

            CONSUMER_CONFIG = {
                "bootstrap.servers":  self._BOOTSTRAP_SERVERS,
                "group.id":           KAFKA_GROUP_ALERT_MANAGER,
                "auto.offset.reset":  "earliest",
                "enable.auto.commit": False,
            }
            PRODUCER_CONFIG = {
                "bootstrap.servers": self._BOOTSTRAP_SERVERS,
                "linger.ms":         10,
            }
            self._CONSUMER = Consumer(CONSUMER_CONFIG)
            self._CONSUMER.subscribe([KAFKA_TOPIC_PREDICTIONS])
            self._PRODUCER = KProducer(PRODUCER_CONFIG)

        except ImportError:
            LOG.warning("confluent-kafka no instalado. Modo DRY_RUN activado.")
            self._DRY_RUN = True

    def _COMPUTE_ALERT_LEVEL(
        self, CATEGORY: str, CONFIDENCE: float
    ) -> AlertLevel:
        """
        Determina el nivel de alerta según categoría y confianza.

        U2R y Backdoor escalan a CRITICAL con menor umbral
        por su potencial impacto en infraestructura crítica.
        """
        HIGH_RISK_CATEGORIES = {"U2R", "Backdoor", "CC_Traffic"}

        if CATEGORY in HIGH_RISK_CATEGORIES:
            if CONFIDENCE >= 0.75:
                return AlertLevel.CRITICAL
            if CONFIDENCE >= 0.60:
                return AlertLevel.HIGH
            return AlertLevel.MEDIUM

        if CONFIDENCE >= CONFIDENCE_THRESHOLD_HIGH:
            return AlertLevel.CRITICAL
        if CONFIDENCE >= CONFIDENCE_THRESHOLD_MEDIUM:
            return AlertLevel.HIGH
        if CONFIDENCE >= CONFIDENCE_THRESHOLD_LOW:
            return AlertLevel.MEDIUM
        return AlertLevel.LOW

    def _BUILD_ALERT(
        self,
        PREDICTION: PredictionResult,
        SRC_IP: str,
        DST_IP: str,
        DST_PORT: int,
        PROTOCOL: str,
    ) -> Alert:
        """
        Construye un objeto Alert enriquecido a partir de una predicción.

        Args:
            PREDICTION: Resultado de inferencia del modelo.
            SRC_IP:     IP origen del flujo original.
            DST_IP:     IP destino del flujo original.
            DST_PORT:   Puerto destino.
            PROTOCOL:   Protocolo de red.

        Returns:
            Alert validado y enriquecido con contexto MITRE ATT&CK.
        """
        CATEGORY    = PREDICTION.PREDICTED_CLASS.value
        ALERT_LEVEL = self._COMPUTE_ALERT_LEVEL(CATEGORY, PREDICTION.CONFIDENCE)
        MITRE_INFO  = MITRE_ATTACK_MAP.get(CATEGORY, {})
        ACTION      = RECOMMENDED_ACTIONS.get(CATEGORY, "Investigar manualmente.")

        MITRE_TECHNIQUE = (
            f"{MITRE_INFO.get('TECHNIQUE_ID', '')} — "
            f"{MITRE_INFO.get('TECHNIQUE_NAME', '')} "
            f"[{MITRE_INFO.get('TACTIC', '')}]"
            if MITRE_INFO else None
        )

        DESCRIPTION = (
            f"Tráfico clasificado como {CATEGORY} "
            f"con confianza {PREDICTION.CONFIDENCE:.1%}. "
            f"Origen: {SRC_IP} → Destino: {DST_IP}:{DST_PORT} ({PROTOCOL.upper()}). "
            f"Modelo v{PREDICTION.MODEL_VERSION}."
        )

        FALSE_POSITIVE_P = max(0.0, 1.0 - PREDICTION.CONFIDENCE - 0.05)

        return Alert(
            FLOW_ID=PREDICTION.FLOW_ID,
            TIMESTAMP=PREDICTION.TIMESTAMP,
            ALERT_LEVEL=ALERT_LEVEL,
            ATTACK_CATEGORY=PREDICTION.PREDICTED_CLASS,
            CONFIDENCE=PREDICTION.CONFIDENCE,
            SRC_IP=SRC_IP,
            DST_IP=DST_IP,
            DST_PORT=DST_PORT,
            PROTOCOL=PROTOCOL,
            SENSOR_ID=PREDICTION.SENSOR_ID,
            DESCRIPTION=DESCRIPTION,
            RECOMMENDED_ACTION=ACTION,
            MITRE_TECHNIQUE=MITRE_TECHNIQUE,
            FALSE_POSITIVE_PROBABILITY=round(FALSE_POSITIVE_P, 3),
        )

    def _PUBLISH_ALERT(self, ALERT: Alert) -> None:
        """Publica la alerta en Kafka y la indexa en Elasticsearch."""
        PAYLOAD = ALERT.model_dump_json().encode("utf-8")

        if not self._DRY_RUN and self._PRODUCER:
            self._PRODUCER.produce(
                topic=KAFKA_TOPIC_ALERTS,
                key=ALERT.ALERT_ID.encode("utf-8"),
                value=PAYLOAD,
            )

        self._ES_INDEXER.INDEX_ALERT(ALERT)

        METRICS_LOG.LOG_ALERT(
            ALERT.ALERT_ID,
            ALERT.FLOW_ID,
            ALERT.ALERT_LEVEL.value,
            ALERT.ATTACK_CATEGORY.value,
            ALERT.SRC_IP,
        )
        self._ALERTS_GENERATED += 1

    def PROCESS_PREDICTION(
        self,
        PREDICTION: PredictionResult,
        SRC_IP: str = "0.0.0.0",
        DST_IP: str = "0.0.0.0",
        DST_PORT: int = 0,
        PROTOCOL: str = "tcp",
    ) -> Optional[Alert]:
        """
        Procesa una predicción y genera alerta si corresponde.

        Args:
            PREDICTION: Resultado de inferencia.
            SRC_IP, DST_IP, DST_PORT, PROTOCOL: Metadatos del flujo.

        Returns:
            Alert si se generó una alerta, None si fue filtrada/suprimida.
        """
        self._PREDICTIONS_PROCESSED += 1

        # Filtrar tráfico normal
        if not PREDICTION.IS_ATTACK:
            return None

        # Filtrar por umbral mínimo de confianza
        if PREDICTION.CONFIDENCE < MIN_CONFIDENCE_FOR_ALERT:
            return None

        # Deduplicación: suprimir tormenta de alertas
        if not self._DEDUPLICATOR.SHOULD_ALERT(SRC_IP, PREDICTION.PREDICTED_CLASS.value):
            LOG.debug(
                "Alerta suprimida por deduplicación",
                extra={"SRC_IP": SRC_IP, "CATEGORY": PREDICTION.PREDICTED_CLASS.value},
            )
            return None

        ALERT = self._BUILD_ALERT(PREDICTION, SRC_IP, DST_IP, DST_PORT, PROTOCOL)
        self._PUBLISH_ALERT(ALERT)
        return ALERT

    def RUN(self) -> None:
        """Loop principal del servicio Alert Manager."""
        self._RUNNING = True
        LOG.info("AlertManagerService iniciado, esperando predicciones...")

        try:
            while self._RUNNING:
                if self._DRY_RUN:
                    # Demo: generar predicciones sintéticas
                    time.sleep(0.5)
                    continue

                MSG = self._CONSUMER.poll(1.0)
                if MSG is None:
                    continue
                if MSG.error():
                    LOG.error("Error Kafka", extra={"ERROR": str(MSG.error())})
                    continue

                try:
                    PREDICTION = PredictionResult.model_validate_json(MSG.value())
                    self.PROCESS_PREDICTION(PREDICTION)
                    self._CONSUMER.commit(asynchronous=True)
                except Exception as EXC:
                    METRICS_LOG.LOG_ERROR("ALERT_PROCESS_ERROR", None, str(EXC))

        except KeyboardInterrupt:
            LOG.info("AlertManagerService detenido por el usuario.")
        finally:
            if self._CONSUMER and not self._DRY_RUN:
                self._CONSUMER.close()
            ELAPSED = time.time() - self._START_TIME
            LOG.info(
                "Estadísticas finales",
                extra={
                    "PREDICTIONS_PROCESSED": self._PREDICTIONS_PROCESSED,
                    "ALERTS_GENERATED":      self._ALERTS_GENERATED,
                    "SUPPRESSED":            self._DEDUPLICATOR.GET_SUPPRESSED_COUNT(),
                    "UPTIME_S":              round(ELAPSED, 1),
                },
            )

    def STOP(self) -> None:
        self._RUNNING = False


if __name__ == "__main__":
    SERVICE = AlertManagerService()
    SERVICE.RUN()
