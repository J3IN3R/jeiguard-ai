"""
shared/constants.py
═══════════════════
Constantes globales del sistema JeiGuard AI.
Todas las constantes en MAYÚSCULAS según estándar PEP 8 / enterprise.

Convenciones del proyecto:
  - CONSTANTES          → MAYÚSCULAS_CON_GUIÓN_BAJO
  - Clases              → PascalCase
  - Funciones/métodos   → snake_case
  - Variables locales   → snake_case
"""

from typing import Final

# ── Categorías de ataque ──────────────────────────────────────────────────────
ATTACK_CATEGORIES: Final[tuple[str, ...]] = (
    "Normal",
    "DoS_DDoS",
    "Probe_Scan",
    "R2L",
    "U2R",
    "Backdoor",
    "Web_Exploit",
    "CC_Traffic",
)

ATTACK_CATEGORY_INDEX: Final[dict[str, int]] = {
    CAT: IDX for IDX, CAT in enumerate(ATTACK_CATEGORIES)
}

NORMAL_CLASS_INDEX: Final[int] = 0

# ── Niveles de alerta ─────────────────────────────────────────────────────────
ALERT_LEVEL_NONE:     Final[str] = "NONE"
ALERT_LEVEL_LOW:      Final[str] = "LOW"
ALERT_LEVEL_MEDIUM:   Final[str] = "MEDIUM"
ALERT_LEVEL_HIGH:     Final[str] = "HIGH"
ALERT_LEVEL_CRITICAL: Final[str] = "CRITICAL"

CONFIDENCE_THRESHOLD_HIGH:     Final[float] = 0.95
CONFIDENCE_THRESHOLD_MEDIUM:   Final[float] = 0.85
CONFIDENCE_THRESHOLD_LOW:      Final[float] = 0.70

# ── Features del modelo ───────────────────────────────────────────────────────
N_BASE_FEATURES:       Final[int] = 41
N_ENGINEERED_FEATURES: Final[int] = 14   # features derivadas añadidas
N_TOTAL_FEATURES:      Final[int] = N_BASE_FEATURES + N_ENGINEERED_FEATURES

# ── Kafka topics ──────────────────────────────────────────────────────────────
KAFKA_TOPIC_RAW_FLOWS:          Final[str] = "ids.raw.flows"
KAFKA_TOPIC_PROCESSED_FEATURES: Final[str] = "ids.processed.features"
KAFKA_TOPIC_PREDICTIONS:        Final[str] = "ids.predictions"
KAFKA_TOPIC_ALERTS:             Final[str] = "ids.alerts"
KAFKA_TOPIC_DEAD_LETTER:        Final[str] = "ids.dead.letter"

KAFKA_GROUP_PREPROCESSOR: Final[str] = "ids-preprocessor-group"
KAFKA_GROUP_INFERENCE:     Final[str] = "ids-inference-group"
KAFKA_GROUP_ALERT_MANAGER: Final[str] = "ids-alert-group"

# ── Modelo ────────────────────────────────────────────────────────────────────
CNN_WEIGHT:              Final[float] = 0.60
RF_WEIGHT:               Final[float] = 0.40
N_CLASSES:               Final[int]   = len(ATTACK_CATEGORIES)
RF_N_ESTIMATORS:         Final[int]   = 200
RF_MAX_DEPTH:            Final[int]   = 25
RF_MIN_SAMPLES_LEAF:     Final[int]   = 5
CNN_EPOCHS:              Final[int]   = 50
CNN_BATCH_SIZE:          Final[int]   = 512
CNN_LEARNING_RATE:       Final[float] = 0.001
CNN_DROPOUT_RATE:        Final[float] = 0.30
CNN_EARLY_STOPPING_PATIENCE: Final[int] = 10

# ── Servicio de inferencia ────────────────────────────────────────────────────
INFERENCE_HOST:          Final[str] = "0.0.0.0"
INFERENCE_PORT:          Final[int] = 8080
INFERENCE_WORKERS:       Final[int] = 4
INFERENCE_MAX_BATCH:     Final[int] = 256
INFERENCE_TIMEOUT_MS:    Final[int] = 100

# ── Elasticsearch ─────────────────────────────────────────────────────────────
ES_INDEX_ALERTS:      Final[str] = "ids-alerts"
ES_INDEX_PREDICTIONS: Final[str] = "ids-predictions"
ES_INDEX_METRICS:     Final[str] = "ids-metrics"

# ── Métricas de rendimiento objetivo ─────────────────────────────────────────
TARGET_ACCURACY:           Final[float] = 0.95
TARGET_FALSE_POSITIVE_RATE: Final[float] = 0.02
TARGET_LATENCY_MS:         Final[float] = 10.0

# ── Versioning ────────────────────────────────────────────────────────────────
MODEL_VERSION: Final[str] = "1.0.0"
API_VERSION:   Final[str] = "v1"
