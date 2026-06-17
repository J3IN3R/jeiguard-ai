# JeiGuard AI 🛡️

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19490415.svg)](https://doi.org/10.5281/zenodo.19490415)
![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0.0-orange)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791)
![Kubernetes](https://img.shields.io/badge/Kubernetes-1.29-326CE5)

> **Sistema de Detección de Intrusiones con Inteligencia Artificial — Enterprise Edition**
> Multi-tenant · JWT RBAC · WebSocket streaming · Multi-cloud (AWS / Azure / GCP)

**Copyright © 2026 Jeiner Tello Nuñez** — Código: 100313094
Proyecto de Grado · Ingeniería de Sistemas · Politécnico Grancolombiano
Asesor: Luis Fernando Quiroga Peláez

---

## Métricas del modelo

| Métrica | Valor | vs Snort |
|---|---|---|
| Accuracy global | **97.4%** | +9.4 pp |
| F1-Score macro | **97.3%** | +12.3 pp |
| Falsos positivos | **1.2%** | −7.3 pp |
| Latencia P50 | **3.8 ms/flujo** | — |
| Latencia P99 | **< 12 ms/flujo** | — |
| Throughput | **15,000 flujos/seg** | — |
| ROC-AUC | **0.996** | — |
| Validación GNS3 | **93.6% (44/47 escenarios)** | — |

---

## Arquitectura v2.0.0

```
                        ┌──────────────────────────────────────────┐
                        │            JeiGuard AI v2.0.0            │
                        │         FastAPI  ·  Multi-tenant         │
                        └──────┬─────────────────────┬────────────┘
                               │                     │
              ┌────────────────▼──────┐   ┌──────────▼──────────────┐
              │   REST API :8080      │   │   WebSocket :8080       │
              │  /api/v1/auth/*       │   │  /api/v1/ws/alerts      │
              │  /api/v1/predict      │   │  /api/v1/ws/metrics     │
              │  /api/v1/reports/*    │   └──────────┬──────────────┘
              │  /api/v1/compliance/* │              │ broadcast
              │  /api/v1/cve/*        │   ┌──────────▼──────────────┐
              │  /api/v1/mlflow/*     │   │  ConnectionManager      │
              └────────────────┬──────┘   │  multi-tenant queues    │
                               │          └─────────────────────────┘
         ┌─────────────────────▼──────────────────────────────┐
         │                   Kafka Pipeline                    │
         │  raw.flows → features → predictions → alerts       │
         └─────────────────────┬──────────────────────────────┘
                               │
         ┌─────────────────────▼──────────────────────────────┐
         │               Persistence Layer                     │
         │    PostgreSQL 16 · Redis 7 · SQLAlchemy 2.0 async  │
         └────────────────────────────────────────────────────┘
```

---

## Estructura del repositorio

```
jeiguard-ai/
├── main_api.py                    ← Gateway FastAPI (todos los routers)
├── database.py                    ← ORM async (11 modelos SQLAlchemy 2.0)
├── auth_service.py                ← JWT RBAC multi-tenant (10 endpoints)
├── report_service.py              ← Reportes ejecutivos PDF (ReportLab)
├── compliance_service.py          ← NIST CSF 2.0 · SOC2 · ISO 27001
├── cve_correlation_service.py     ← NVD API v2 + caché PostgreSQL 24h
├── mlflow_tracking.py             ← Model Registry + A/B testing
├── otel_tracing.py                ← OpenTelemetry + Jaeger OTLP
├── websocket_gateway.py           ← Streaming alertas multi-tenant
├── constants.py                   ← Constantes Final[T] tipadas
├── models.py                      ← Contratos Pydantic v2
├── logger.py                      ← Logger JSON estructurado
│
├── inference_service.py           ← CNN-1D + RF · FastAPI REST
├── producer_service.py            ← Captura de tráfico → Kafka
├── preprocessor_service.py        ← Feature engineering
├── alert_manager_service.py       ← MITRE ATT&CK + Elasticsearch
│
├── xai_service.py                 ← Explicabilidad SHAP
├── model_v101.py                  ← CNN-1D TF + Online Learning
├── anomaly_federated_v101.py      ← Autoencoder + Federated Learning
├── llm_analyst_service.py         ← Análisis forense con Claude API
├── siem_correlation_engine.py     ← Kill Chain · APT correlation
├── soar_response_engine.py        ← Respuesta automática · Jira
├── threat_intel_service.py        ← AbuseIPDB + VirusTotal
├── digital_twin_service.py        ← Mapa de red D3.js
├── streamlit_app.py               ← Dashboard Streamlit 4 páginas
├── demo_live.py                   ← Demo standalone (numpy + sklearn)
│
├── sdk/
│   ├── __init__.py
│   └── jeiguard_sdk.py            ← Python SDK sync/async
│
├── k8s_operator/
│   └── operator.py                ← Kubernetes Operator (Kopf)
│
├── terraform/
│   ├── main.tf                    ← AWS EKS (Terraform)
│   ├── azure/main.tf              ← Azure AKS
│   └── gcp/main.tf                ← GCP GKE
│
├── docker-compose.yml             ← Dev: 14 contenedores
├── ci.yml                         ← CI/CD: 8 jobs (SAST · SBOM · scan)
├── requirements.txt
├── env.example
├── pyproject.toml
├── CHANGELOG.md
└── tests/
    └── test_ids_ia_enterprise.py  ← 40+ tests · 9 clases
```

---

## 15 Mejoras v2.0.0

### Grupo 1 — Inteligencia del modelo (v1.0.1)

| # | Mejora | Módulo | Descripción |
|---|---|---|---|
| 1 | **XAI Explicabilidad** | `xai_service.py` | SHAP values — explica cada decisión del modelo |
| 2 | **Dashboard Streamlit** | `streamlit_app.py` | Interfaz web con 4 páginas interactivas |
| 3 | **CNN-1D TensorFlow** | `model_v101.py` | Red neuronal 487K parámetros — accuracy 97.4% |
| 4 | **Online Learning** | `model_v101.py` | Reentrenamiento continuo sin downtime |
| 5 | **Detección de anomalías** | `anomaly_federated_v101.py` | Autoencoder para ataques zero-day |
| 6 | **Aprendizaje federado** | `anomaly_federated_v101.py` | FedAvg — múltiples sensores sin compartir datos |

### Grupo 2 — Operaciones y respuesta (v1.0.1)

| # | Mejora | Módulo | Descripción |
|---|---|---|---|
| 7 | **LLM Analyst** | `llm_analyst_service.py` | Claude API genera narrativa forense automática |
| 8 | **SIEM Correlator** | `siem_correlation_engine.py` | Detecta campañas APT multi-etapa (Kill Chain) |
| 9 | **SOAR Engine** | `soar_response_engine.py` | Bloqueo de IPs · aislamiento · tickets Jira |
| 10 | **Threat Intelligence** | `threat_intel_service.py` | AbuseIPDB + VirusTotal — reputación en tiempo real |
| 11 | **Digital Twin** | `digital_twin_service.py` | Mapa topológico D3.js — ataques en tiempo real |
| 12 | **Cloud-Native AWS** | `terraform/main.tf` | Terraform EKS + Helm HPA 2-20 réplicas |

### Grupo 3 — Enterprise Platform (v2.0.0)

| # | Mejora | Módulo | Descripción |
|---|---|---|---|
| 13 | **Auth RBAC + DB** | `auth_service.py` + `database.py` | JWT multi-tenant, bcrypt 12r, PostgreSQL async |
| 14 | **Compliance & CVE** | `compliance_service.py` + `cve_correlation_service.py` | NIST CSF 2.0 · SOC2 · ISO 27001 · NVD API v2 |
| 15 | **Multi-cloud & Observabilidad** | `terraform/azure/` + `terraform/gcp/` + `otel_tracing.py` | Azure AKS · GCP GKE · OpenTelemetry + Jaeger |

---

## Inicio rápido

```bash
# Clonar y configurar entorno
git clone https://github.com/j3in3r/jeiguard-ai.git
cd jeiguard-ai
cp env.example .env          # Ajustar variables (JWT_SECRET_KEY, DATABASE_URL, etc.)

# Sistema completo con Docker (recomendado)
docker compose up -d

# Servicios disponibles:
# API:       http://localhost:8080/docs
# Streamlit: http://localhost:8501
# MLflow:    http://localhost:5000
# Jaeger:    http://localhost:16686
# Grafana:   http://localhost:3000   (admin / jeiguard2026)
# Kibana:    http://localhost:5601
# pgAdmin:   http://localhost:5050

# Demo mínima (sin Docker)
pip install numpy scikit-learn
python demo_live.py
```

### Variables de entorno requeridas

```bash
# Auth
JWT_SECRET_KEY=<secret-256-bits>
JWT_ALGORITHM=HS256

# Base de datos
DATABASE_URL=postgresql+asyncpg://jeiguard:pass@localhost:5432/jeiguard_ai

# Redis
REDIS_URL=redis://:jeiguard2026@localhost:6379/0

# Integraciones opcionales
ANTHROPIC_API_KEY=sk-ant-...
NVD_API_KEY=<nvd-key>               # https://nvd.nist.gov/developers/request-an-api-key
MLFLOW_TRACKING_URI=http://localhost:5000

# Observabilidad
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
OTEL_SERVICE_NAME=jeiguard-ai
```

---

## API REST — Referencia completa

### Autenticación `/api/v1/auth`

| Método | Endpoint | Auth | Descripción |
|---|---|---|---|
| `POST` | `/register` | — | Registrar usuario (devuelve JWT) |
| `POST` | `/login` | — | Iniciar sesión (access + refresh token) |
| `POST` | `/refresh` | refresh token | Renovar access token |
| `POST` | `/logout` | Bearer | Invalidar sesión actual |
| `GET` | `/me` | Bearer | Perfil del usuario autenticado |
| `PATCH` | `/me` | Bearer | Actualizar perfil (email, password) |
| `GET` | `/sessions` | Bearer | Listar sesiones activas |
| `DELETE` | `/sessions/{id}` | Bearer | Revocar sesión específica |
| `GET` | `/users` | Admin+ | Listar usuarios del tenant |
| `POST` | `/users/{id}/role` | Admin+ | Cambiar rol de usuario |

**Roles disponibles:** `readonly` → `viewer` → `analyst` → `admin` → `super_admin`

```bash
# Registrar usuario
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@corp.com","password":"Admin2026!","tenant_id":"corp-tenant"}'

# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -d '{"username":"admin","password":"Admin2026!"}'
# → {"access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer"}
```

### Inferencia `/api/v1`

| Método | Endpoint | Auth | Descripción |
|---|---|---|---|
| `POST` | `/predict` | Bearer | Clasificar flujo de red (CNN-1D + RF) |
| `GET` | `/health` | — | Estado del sistema |

```bash
curl -X POST http://localhost:8080/api/v1/predict \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"FEATURES": [[0,0,0,0,20,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,
                     0,0,500,490,0.99,0.99,0,0,1,0,0,5,255,1,
                     0.06,1,0,0.99,0.99,0,0]]}'
```

### Reportes `/api/v1/reports`

| Método | Endpoint | Auth | Descripción |
|---|---|---|---|
| `POST` | `/generate` | Analyst+ | Generar reporte PDF ejecutivo |
| `GET` | `` | Analyst+ | Listar reportes del tenant |
| `GET` | `/{id}/download` | Analyst+ | Descargar PDF |
| `DELETE` | `/{id}` | Admin+ | Eliminar reporte |

```bash
# Generar reporte ejecutivo
curl -X POST http://localhost:8080/api/v1/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"report_type":"executive","period_days":30,"title":"Q2 Security Report"}'
```

### Compliance `/api/v1/compliance`

| Método | Endpoint | Auth | Descripción |
|---|---|---|---|
| `GET` | `/frameworks` | Viewer+ | Listar frameworks disponibles |
| `POST` | `/{framework}/assess` | Analyst+ | Ejecutar evaluación automatizada |
| `GET` | `/{framework}/score` | Viewer+ | Puntuación de cumplimiento |
| `GET` | `/{framework}/controls` | Viewer+ | Lista detallada de controles |
| `GET` | `/{framework}/gaps` | Analyst+ | Brechas y recomendaciones |
| `GET` | `/dashboard` | Viewer+ | Dashboard unificado (3 frameworks) |

**Frameworks soportados:** `nist_csf` · `soc2` · `iso27001`

```bash
# Evaluación NIST CSF
curl -X POST http://localhost:8080/api/v1/compliance/nist_csf/assess \
  -H "Authorization: Bearer $TOKEN"
# → {"framework":"nist_csf","score":0.76,"controls_passing":17,"controls_failing":5,...}
```

### CVE Correlation `/api/v1/cve`

| Método | Endpoint | Auth | Descripción |
|---|---|---|---|
| `GET` | `/attack/{category}` | Viewer+ | CVEs para categoría de ataque |
| `GET` | `/exposure` | Analyst+ | Dashboard de exposición por tenant |
| `POST` | `/refresh` | Admin+ | Forzar actualización desde NVD API |

**Categorías:** `DoS_DDoS` · `Probe_Scan` · `R2L` · `U2R` · `Backdoor` · `Web_Exploit` · `CC_Traffic`

```bash
curl http://localhost:8080/api/v1/cve/attack/DoS_DDoS \
  -H "Authorization: Bearer $TOKEN"
# → [{"cve_id":"CVE-2023-44487","cvss_score":7.5,"description":"HTTP/2 Rapid Reset..."}, ...]
```

### Model Registry `/api/v1/mlflow`

| Método | Endpoint | Auth | Descripción |
|---|---|---|---|
| `POST` | `/experiments/log` | Admin+ | Registrar experimento + métricas |
| `GET` | `/models` | Viewer+ | Listar versiones del modelo |
| `GET` | `/models/champion` | Viewer+ | Modelo campeón activo |
| `POST` | `/models/{id}/promote` | Admin+ | Promover a campeón |
| `POST` | `/ab-test` | Admin+ | Comparar dos modelos (A/B) |

```bash
# Comparar modelos A/B
curl -X POST http://localhost:8080/api/v1/mlflow/ab-test \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"model_a_id":"uuid-a","model_b_id":"uuid-b"}'
# → {"winner":"model_b","composite_score_b":0.89,"recommendation":"promote_b"}
```

### WebSocket `/api/v1/ws`

| Tipo | Endpoint | Descripción |
|---|---|---|
| `WS` | `/ws/alerts?token=JWT` | Stream de alertas en tiempo real |
| `WS` | `/ws/alerts?token=JWT&level=CRITICAL,HIGH` | Filtrado por nivel |
| `WS` | `/ws/alerts?token=JWT&category=DoS_DDoS` | Filtrado por categoría |
| `WS` | `/ws/metrics?token=JWT&interval=10` | Métricas operacionales |
| `GET` | `/ws/stats` | Estadísticas de conexiones activas |

```javascript
// Conectar desde JavaScript
const ws = new WebSocket(
  'ws://localhost:8080/api/v1/ws/alerts?token=eyJ...&level=CRITICAL,HIGH'
);

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  // msg.type: "connected" | "alert" | "heartbeat" | "error"
  if (msg.type === 'alert') console.log(msg.payload);
};

// Comandos del cliente
ws.send(JSON.stringify({ type: 'ping' }));
ws.send(JSON.stringify({ type: 'subscribe', filters: { category: ['DoS_DDoS'] } }));
ws.send(JSON.stringify({ type: 'unsubscribe', keys: ['category'] }));
```

---

## Python SDK

```bash
pip install -e sdk/
```

```python
from jeiguard_sdk import JeiGuardClient, JeiGuardAsyncClient

# ── Cliente síncrono ──────────────────────────────────────────────────
client = JeiGuardClient(base_url="http://localhost:8080")
client.login("admin", "Admin2026!")

# Inferencia
result = client.predict([[0,0,0,0,20,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,
                          0,0,500,490,0.99,0.99,0,0,1,0,0,5,255,1,
                          0.06,1,0,0.99,0.99,0,0]])
print(result.category, result.confidence)  # DoS_DDoS  0.997

# Compliance
score = client.get_compliance_score("nist_csf")
print(f"NIST CSF: {score.percentage:.1f}%")

# CVEs
cves = client.get_cves("DoS_DDoS")
for cve in cves[:3]:
    print(cve.cve_id, cve.cvss_score)

# Descargar reporte PDF
client.download_report(report_id, "/tmp/q2_report.pdf")

# ── Cliente asíncrono con streaming WebSocket ─────────────────────────
import asyncio

async def monitor():
    async with JeiGuardAsyncClient("http://localhost:8080") as client:
        await client.login("admin", "Admin2026!")
        async for alert in client.stream_alerts(level=["CRITICAL"]):
            print(f"[{alert.alert_level}] {alert.attack_category} — {alert.src_ip}")

asyncio.run(monitor())
```

---

## Kubernetes Operator

```bash
# Instalar CRDs y operador
pip install kopf kubernetes
python k8s_operator/operator.py &

# Desplegar un sensor JeiGuard
cat <<EOF | kubectl apply -f -
apiVersion: jeiguard.ai/v1
kind: JeiGuardDeployment
metadata:
  name: prod-cluster
  namespace: jeiguard
spec:
  tenantId: acme-corp
  tier: enterprise
  replicas: 3
  kafkaBrokers: "kafka:9092"
  modelVersion: "2.0.0"
EOF
```

El operador reconcilia cada 60 segundos y gestiona automáticamente Deployments, Services, ConfigMaps y HPA para cada `JeiGuardDeployment` CRD.

---

## Multi-cloud Terraform

```bash
# AWS EKS (existente)
cd terraform/
terraform init && terraform apply -var="environment=production"

# Azure AKS
cd terraform/azure/
terraform init
terraform apply \
  -var="environment=production" \
  -var="location=eastus2" \
  -var="aks_node_count=3"

# GCP GKE
cd terraform/gcp/
terraform init
terraform apply \
  -var="project_id=my-gcp-project" \
  -var="environment=production" \
  -var="region=us-central1"
```

| Cloud | Kubernetes | Messaging | Database | Registry |
|---|---|---|---|---|
| AWS | EKS 1.29 | MSK Kafka | RDS PostgreSQL 16 | ECR |
| Azure | AKS 1.29 | Event Hubs (Kafka API) | PostgreSQL Flexible 16 | ACR Premium |
| GCP | GKE 1.29 | Pub/Sub | Cloud SQL PostgreSQL 16 | Artifact Registry |

---

## Categorías detectadas

| Categoría | MITRE ATT&CK | Táctica |
|---|---|---|
| Normal | — | — |
| DoS/DDoS | T1498 | Impact |
| Probe/Scan | T1046 | Discovery |
| R2L | T1110 | Credential Access |
| U2R | T1068 | Privilege Escalation |
| Backdoor | T1543 | Persistence |
| Web Exploit | T1190 | Initial Access |
| CC Traffic | T1071 | Command & Control |

---

## CI/CD

El pipeline `.github/workflows/ci.yml` ejecuta 8 jobs en paralelo:

| Job | Descripción |
|---|---|
| `quality` | Ruff lint · mypy strict · black format check |
| `tests` | pytest 40+ tests con cobertura |
| `dependency-audit` | pip-audit · safety check · licencias |
| `integration-tests` | Docker Compose + tests de integración end-to-end |
| `docker-build` | Build multi-arch (amd64 + arm64) + push a GHCR |
| `container-scan` | Trivy CVE scan (umbral CRITICAL = 0) |
| `sbom` | Syft SPDX 2.3 — bill of materials del contenedor |
| `terraform-validate` | terraform validate en AWS · Azure · GCP |

```bash
# Ejecutar localmente
ruff check . && mypy . --strict
pytest tests/ -v --cov=. --cov-report=html
bandit -r . -ll
```

---

## Demo rápida (Google Colab)

```python
!pip install numpy scikit-learn -q
!wget https://raw.githubusercontent.com/J3IN3R/jeiguard-ai/main/demo_live.py -q
%run demo_live.py
```

---

## Citar este proyecto

**APA 7:**
> Tello Nuñez, J. (2026). *JeiGuard AI: Sistema de Detección de Intrusiones con Inteligencia Artificial* (v2.0.0) [Software]. Zenodo. https://doi.org/10.5281/zenodo.19490415

```bibtex
@software{tello_nunez_2026_jeiguard,
  author    = {Tello Nuñez, Jeiner},
  title     = {JeiGuard AI: Sistema de Detección de Intrusiones con IA},
  year      = {2026},
  version   = {v2.0.0},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.19490415},
  url       = {https://doi.org/10.5281/zenodo.19490415}
}
```

---

## Licencia

MIT License — Copyright © 2026 **Jeiner Tello Nuñez**
