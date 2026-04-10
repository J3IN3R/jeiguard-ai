# JeiGuard AI 🛡️

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19076945.svg)](https://doi.org/10.5281/zenodo.19076945)
![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Version](https://img.shields.io/badge/Version-1.0.1-orange)

> **Sistema de Detección de Intrusiones con Inteligencia Artificial**
> Arquitectura de microservicios · Apache Kafka · CNN-1D + Random Forest

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

## Demo rápida (Google Colab)

```python
!pip install numpy scikit-learn -q
!wget https://raw.githubusercontent.com/J3IN3R/jeiguard-ai/main/demo_live.py -q
%run demo_live.py
```

## Interfaz web completa

```bash
pip install streamlit plotly pandas scikit-learn numpy
streamlit run services/v101/streamlit_app.py
# http://localhost:8501
```

---

## Arquitectura

```
┌─────────────┐   jeiguard.raw.flows    ┌──────────────────┐
│  PRODUCER   │ ──────────────────────► │  PREPROCESSOR    │
│ (Captura)   │                         │ (Features Eng.)  │
└─────────────┘                         └────────┬─────────┘
                                                  │ jeiguard.processed.features
                                         ┌────────▼─────────┐
                                         │   INFERENCE      │◄── REST :8080
                                         │  CNN-1D + RF     │
                                         └────────┬─────────┘
                                                  │ jeiguard.predictions
                                         ┌────────▼─────────┐
                                         │  ALERT MANAGER   │
                                         │  MITRE ATT&CK    │
                                         └────────┬─────────┘
                                                  │
                                    Elasticsearch · Kibana · Grafana
```

---

## Estructura del repositorio

```
jeiguard-ai/
├── LICENSE
├── README.md
├── CHANGELOG.md
├── demo_live.py                              ← Demo standalone (numpy + sklearn)
├── pyproject.toml
├── requirements.txt
├── .gitignore
├── .env.example
│
├── shared/
│   ├── constants.py                          ← Constantes Final[T]
│   ├── models.py                             ← Contratos Pydantic v2
│   └── logger.py                             ← Logger JSON estructurado
│
├── services/
│   ├── producer/producer_service.py          ← Captura → Kafka
│   ├── preprocessor/preprocessor_service.py  ← Features Engineering
│   ├── inference/inference_service.py        ← CNN+RF + FastAPI REST
│   ├── alert_manager/alert_manager_service.py← MITRE ATT&CK + ES
│   │
│   └── v101/                                 ← 12 mejoras v1.0.1
│       ├── xai_service.py                    ← Mejora 1: Explicabilidad SHAP
│       ├── streamlit_app.py                  ← Mejora 2: Interfaz web Streamlit
│       ├── model_v101.py                     ← Mejora 3+4: CNN-1D + Online Learning
│       ├── anomaly_federated_v101.py         ← Mejora 5+6: Autoencoder + Federated
│       ├── llm_analyst_service.py            ← Mejora 7: Analista LLM (Claude API)
│       ├── siem_correlation_engine.py        ← Mejora 8: SIEM Kill Chain
│       ├── soar_response_engine.py           ← Mejora 9: Respuesta automática
│       ├── threat_intel_service.py           ← Mejora 10: Threat Intelligence
│       ├── digital_twin_service.py           ← Mejora 11: Mapa de red D3.js
│       └── cloud_deploy/
│           ├── main.tf                       ← Mejora 12: Terraform AWS EKS
│           └── helm-values.yaml              ← Mejora 12: Helm chart Kubernetes
│
├── tests/
│   └── unit/test_ids_ia_enterprise.py        ← 40+ tests · 9 clases
│
└── deploy/
    ├── docker/docker-compose.yml             ← Dev: 9 contenedores
    └── kubernetes/ids-ia-deployment.yaml     ← Prod: HPA + NetworkPolicy
```

---

## 12 Mejoras v1.0.1

### Grupo 1 — Inteligencia del modelo

| # | Mejora | Archivo | Descripción |
|---|---|---|---|
| 1 | **XAI Explicabilidad** | `xai_service.py` | SHAP values — explica por qué el modelo tomó cada decisión |
| 2 | **Interfaz Web Streamlit** | `streamlit_app.py` | Dashboard funcional con 4 páginas interactivas |
| 3 | **CNN-1D TensorFlow real** | `model_v101.py` | Red neuronal de 487K parámetros — sube accuracy a 97.4% |
| 4 | **Reentrenamiento online** | `model_v101.py` | Modelo aprende de tráfico nuevo sin parar el sistema |
| 5 | **Detección de anomalías** | `anomaly_federated_v101.py` | Autoencoder detecta ataques de día cero nunca vistos |
| 6 | **Aprendizaje federado** | `anomaly_federated_v101.py` | FedAvg — múltiples sensores sin compartir datos |

### Grupo 2 — Operaciones y respuesta

| # | Mejora | Archivo | Descripción |
|---|---|---|---|
| 7 | **LLM Analyst** | `llm_analyst_service.py` | Claude genera narrativa forense automática por alerta |
| 8 | **SIEM Correlator** | `siem_correlation_engine.py` | Detecta campañas APT multi-etapa (Cyber Kill Chain) |
| 9 | **SOAR Engine** | `soar_response_engine.py` | Bloquea IPs, aísla hosts, crea tickets Jira automáticamente |
| 10 | **Threat Intelligence** | `threat_intel_service.py` | AbuseIPDB + VirusTotal — reputación de IPs en tiempo real |
| 11 | **Digital Twin** | `digital_twin_service.py` | Mapa topológico D3.js — ataques visibles en tiempo real |
| 12 | **Cloud-Native AWS** | `cloud_deploy/` | Terraform EKS + Helm — HPA 2-20 réplicas automáticas |

---

## Instalación por nivel

```bash
# Nivel 1 — Demo mínima (2 librerías)
pip install numpy scikit-learn
python demo_live.py

# Nivel 2 — Interfaz web completa
pip install streamlit plotly pandas scikit-learn numpy
streamlit run services/v101/streamlit_app.py

# Nivel 3 — CNN-1D activada
pip install tensorflow>=2.14
# Desactivar DRY_RUN en model_v101.py

# Nivel 4 — LLM Analyst activado
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...

# Nivel 5 — Sistema completo con Docker
docker compose -f deploy/docker/docker-compose.yml up -d
# Grafana: http://localhost:3000   (admin / jeiguard2026)
# Kibana:  http://localhost:5601
# Swagger: http://localhost:8080/docs
```

---

## API REST

```bash
# Estado del sistema
curl http://localhost:8080/health

# Clasificar un flujo de red
curl -X POST http://localhost:8080/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{"FEATURES": [[0,0,0,0,20,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,
                      0,0,500,490,0.99,0.99,0,0,1,0,0,5,255,1,
                      0.06,1,0,0.99,0.99,0,0]]}'
```

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

## Calidad de código

```bash
pytest tests/ -v --cov=services --cov=shared
mypy services/ shared/ --strict
ruff check services/ shared/ tests/
```

---

## Citar este proyecto

**APA 7:**
> Tello Nuñez, J. (2026). *JeiGuard AI: Sistema de Detección de Intrusiones con Inteligencia Artificial* (v1.0.1) [Software]. Zenodo. https://doi.org/10.5281/zenodo.19076945

```bibtex
@software{tello_nunez_2026_jeiguard,
  author    = {Tello Nuñez, Jeiner},
  title     = {JeiGuard AI: Sistema de Detección de Intrusiones con IA},
  year      = {2026},
  version   = {v1.0.1},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.19076945},
  url       = {https://doi.org/10.5281/zenodo.19076945}
}
```

---

## Licencia

MIT License — Copyright © 2026 **Jeiner Tello Nuñez**
