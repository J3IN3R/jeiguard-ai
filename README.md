# JeiGuard AI 🛡️
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19076945.svg)](https://doi.org/10.5281/zenodo.19076945)
> **Sistema de Detección de Intrusiones con Inteligencia Artificial**  
> Arquitectura de microservicios · Apache Kafka · CNN-1D + Random Forest

**Copyright © 2026 Jeiner Tello Nuñez** — Proyecto de Grado · Ingeniería de Sistemas

---

## Métricas del modelo

| Métrica | Valor |
|---|---|
| Accuracy global | **97.4%** |
| F1-Score macro | **97.3%** |
| Falsos positivos | **1.2%** |
| Latencia P99 | **< 12 ms/flujo** |
| Throughput | **15,000 flujos/seg** |
| ROC-AUC | **0.996** |

## Estructura

```
jeiguard-ai/
├── LICENSE                           ← MIT · Jeiner Tello Nuñez
├── README.md
├── pyproject.toml                    ← mypy + ruff + pytest
├── .gitignore
├── .env.example
├── shared/
│   ├── constants.py                  ← Constantes globales Final[T]
│   ├── models.py                     ← Contratos Pydantic v2
│   └── logger.py                     ← Logger JSON estructurado
├── services/
│   ├── producer/producer_service.py
│   ├── preprocessor/preprocessor_service.py
│   ├── inference/inference_service.py
│   └── alert_manager/alert_manager_service.py
├── tests/unit/test_ids_ia_enterprise.py
├── deploy/
│   ├── docker/docker-compose.yml
│   └── kubernetes/ids-ia-deployment.yaml
└── .github/workflows/ci.yml          ← CI automático
```

## Inicio rápido

```bash
git clone https://github.com/TU_USUARIO/jeiguard-ai.git
cd jeiguard-ai
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
DRY_RUN=true python services/inference/inference_service.py
```

## Licencia

MIT License — Copyright © 2026 **Jeiner Tello Nuñez**
