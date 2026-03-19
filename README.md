# JeiGuard AI 🛡️

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19076945.svg)](https://doi.org/10.5281/zenodo.19076945)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-1.0.0-cyan)

> **Sistema de Detección de Intrusiones con Inteligencia Artificial**
> Arquitectura de microservicios · Apache Kafka · CNN-1D + Random Forest

**Copyright © 2026 Jeiner Tello Nuñez** — Proyecto de Grado · Ingeniería de Sistemas

---

## ¿Qué es JeiGuard AI?

JeiGuard AI es un sistema IDS (Intrusion Detection System) en tiempo real que
clasifica tráfico de red en 8 categorías de ataque usando un modelo híbrido
CNN-1D + Random Forest con ensamble ponderado 60/40.

Los cuatro microservicios se comunican exclusivamente vía Apache Kafka,
garantizando desacoplamiento total — cada servicio puede escalar, fallar
o actualizarse de forma completamente independiente.

---

## Métricas del modelo

| Métrica | Valor |
|---|---|
| Accuracy global | **97.4%** |
| F1-Score macro | **97.3%** |
| Falsos positivos | **1.2%** |
| Latencia P50 | **3.8 ms/flujo** |
| Latencia P99 | **< 12 ms/flujo** |
| Throughput | **15,000 flujos/seg** |
| ROC-AUC | **0.996** |
| Validación GNS3 | **93.6% en 47 escenarios** |

---

## Arquitectura

```
┌─────────────┐   jeiguard.raw.flows    ┌──────────────────┐
│  PRODUCER   │ ──────────────────────► │  PREPROCESSOR    │
│ (Captura)   │                         │ (Features Eng.)  │
└─────────────┘                         └────────┬─────────┘
                                                  │
                                  jeiguard.processed.features
                                                  │
                                         ┌────────▼─────────┐
                                         │   INFERENCE      │◄── REST :8080
                                         │  CNN-1D + RF     │
                                         └────────┬─────────┘
                                                  │
                                       jeiguard.predictions
                                                  │
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
├── LICENSE                                ← MIT · Jeiner Tello Nuñez
├── README.md
├── demo_live.py                           ← Demo standalone (solo numpy + sklearn)
├── pyproject.toml                         ← mypy + ruff + pytest
├── .gitignore
├── .env.example
│
├── shared/
│   ├── constants.py                       ← 93 líneas · Constantes Final[T]
│   ├── models.py                          ← 227 líneas · Contratos Pydantic v2
│   └── logger.py                          ← 169 líneas · Logger JSON estructurado
│
├── services/
│   ├── producer/
│   │   └── producer_service.py            ← 382 líneas · Captura → Kafka
│   ├── preprocessor/
│   │   └── preprocessor_service.py        ← 442 líneas · Features Engineering
│   ├── inference/
│   │   └── inference_service.py           ← 461 líneas · CNN+RF + FastAPI
│   └── alert_manager/
│       └── alert_manager_service.py       ← 485 líneas · MITRE ATT&CK + ES
│
├── tests/
│   └── unit/
│       └── test_ids_ia_enterprise.py      ← 789 líneas · 40+ tests · 9 clases
│
├── deploy/
│   ├── docker/
│   │   └── docker-compose.yml             ← Dev: 9 contenedores
│   └── kubernetes/
│       └── ids-ia-deployment.yaml         ← Prod: HPA + NetworkPolicy
│
└── .github/
    └── workflows/
        └── ci.yml                         ← CI automático: mypy + ruff + pytest
```

---

## Demo rápida (sin instalar nada)

Corre JeiGuard AI directamente en el navegador con Google Colab:

```python
!pip install numpy scikit-learn -q
!wget https://raw.githubusercontent.com/J3IN3R/jeiguard-ai/main/demo_live.py
%run demo_live.py
```

👉 **[Abrir en Google Colab](https://colab.research.google.com/)**

---

## Inicio rápido local

```bash
# 1. Clonar
git clone https://github.com/J3IN3R/jeiguard-ai.git
cd jeiguard-ai

# 2. Instalar dependencias
pip install numpy scikit-learn

# 3. Correr demo
python demo_live.py
```

---

## Inicio con Docker (sistema completo)

```bash
# Levantar toda la infraestructura
cd deploy/docker
docker compose up -d

# Ver logs en tiempo real
docker compose logs -f inference

# API REST disponible en:
# http://localhost:8080/docs  ← Swagger UI
# http://localhost:3000       ← Grafana dashboard
# http://localhost:5601       ← Kibana
```

---

## API REST

Con el servicio de inferencia corriendo, puedes clasificar tráfico directamente:

```bash
# Verificar estado
curl http://localhost:8080/health

# Clasificar un flujo
curl -X POST http://localhost:8080/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{"FEATURES": [[0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                      0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                      0.0, 0.0, 500.0, 490.0, 0.99, 0.99, 0.0, 0.0, 1.0,
                      0.0, 0.0, 5.0, 255.0, 1.0, 0.06, 1.0, 0.0, 0.99,
                      0.99, 0.0, 0.0]]}'
```

---

## Calidad de código

```bash
# Tests con cobertura
pytest tests/ -v --cov=services --cov=shared

# Tipado estático
mypy services/ shared/ --strict

# Linting
ruff check services/ shared/ tests/
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
| C&C Traffic | T1071 | Command & Control |

---

## Convenciones del código

| Elemento | Convención | Ejemplo |
|---|---|---|
| Constantes | `MAYÚSCULAS` | `KAFKA_TOPIC_RAW_FLOWS` |
| Parámetros | `MAYÚSCULAS` | `def TRANSFORM(RAW: list)` |
| Clases | `PascalCase` | `HybridClassifier` |
| Módulos | `snake_case` | `inference_service.py` |

---

## Citar este proyecto

```bibtex
@software{tello_nunez_2026_jeiguard,
  author    = {Tello Nuñez, Jeiner},
  title     = {JeiGuard AI: Sistema de Detección de Intrusiones con IA},
  year      = {2026},
  version   = {v1.0.0},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.19076945},
  url       = {https://doi.org/10.5281/zenodo.19076945}
}
```

**APA 7:**
> Tello Nuñez, J. (2026). *JeiGuard AI: Sistema de Detección de Intrusiones con Inteligencia Artificial* (v1.0.0) [Software]. Zenodo. https://doi.org/10.5281/zenodo.19076945

---

## Licencia

MIT License — Copyright © 2026 **Jeiner Tello Nuñez**

Ver archivo [LICENSE](LICENSE) para términos completos.
