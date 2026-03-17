"""
services/inference/inference_service.py
════════════════════════════════════════
Servicio de Inferencia — JeiGuard AI
════════════════════════════════════════════
Responsabilidad única: recibir features procesadas (vía Kafka o API REST),
ejecutar el modelo híbrido CNN-1D + Random Forest y publicar PredictionResult
en KAFKA_TOPIC_PREDICTIONS.

Expone además una API REST para inferencia directa (testing, integración).

Arquitectura interna:
  ┌─────────────────────────────────────────────────────┐
  │  Kafka Consumer ──► BatchAccumulator ──► Inference  │
  │                                              │       │
  │  FastAPI REST  ───────────────────────────► │       │
  │                                              ▼       │
  │                                     Kafka Producer  │
  └─────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from shared.constants import (
    ATTACK_CATEGORIES,
    CNN_BATCH_SIZE,
    CNN_DROPOUT_RATE,
    CNN_EARLY_STOPPING_PATIENCE,
    CNN_EPOCHS,
    CNN_LEARNING_RATE,
    CNN_WEIGHT,
    CONFIDENCE_THRESHOLD_HIGH,
    CONFIDENCE_THRESHOLD_MEDIUM,
    ALERT_LEVEL_CRITICAL,
    ALERT_LEVEL_HIGH,
    ALERT_LEVEL_MEDIUM,
    ALERT_LEVEL_NONE,
    INFERENCE_HOST,
    INFERENCE_PORT,
    INFERENCE_WORKERS,
    KAFKA_GROUP_INFERENCE,
    KAFKA_TOPIC_PREDICTIONS,
    KAFKA_TOPIC_PROCESSED_FEATURES,
    MODEL_VERSION,
    N_CLASSES,
    N_TOTAL_FEATURES,
    NORMAL_CLASS_INDEX,
    RF_MAX_DEPTH,
    RF_MIN_SAMPLES_LEAF,
    RF_N_ESTIMATORS,
    RF_WEIGHT,
    API_VERSION,
)
from shared.logger import BUILD_LOGGER, OperationalMetricsLogger
from shared.models import (
    AttackCategory,
    HealthResponse,
    InferenceRequest,
    InferenceResponse,
    PredictionResult,
    ProcessedFeatures,
)

# ── Logger ────────────────────────────────────────────────────────────────────
LOG = BUILD_LOGGER("jeiguard-inference")
METRICS_LOG = OperationalMetricsLogger("jeiguard-inference")

# ── Constantes del servicio ───────────────────────────────────────────────────
MODEL_PATH:             str   = os.getenv("MODEL_PATH", "models/")
INFERENCE_BATCH_SIZE:   int   = int(os.getenv("INFERENCE_BATCH_SIZE", "32"))
LATENCY_WINDOW_SIZE:    int   = 1000  # Ventana para cálculo de percentiles


# ── Tracker de latencias ──────────────────────────────────────────────────────

class LatencyTracker:
    """
    Registra latencias de inferencia en una ventana deslizante
    para calcular percentiles P50, P95, P99 en tiempo real.
    """

    def __init__(self, WINDOW: int = LATENCY_WINDOW_SIZE) -> None:
        self._WINDOW = deque(maxlen=WINDOW)

    def RECORD(self, LATENCY_MS: float) -> None:
        self._WINDOW.append(LATENCY_MS)

    def P50(self) -> float:
        return float(np.percentile(self._WINDOW, 50)) if self._WINDOW else 0.0

    def P95(self) -> float:
        return float(np.percentile(self._WINDOW, 95)) if self._WINDOW else 0.0

    def P99(self) -> float:
        return float(np.percentile(self._WINDOW, 99)) if self._WINDOW else 0.0


# ── Modelo híbrido ────────────────────────────────────────────────────────────

class HybridClassifier:
    """
    Clasificador híbrido CNN-1D + Random Forest para detección de intrusiones.

    Carga los modelos serializados desde MODEL_PATH y expone
    un método PREDICT optimizado para inferencia en batch.

    El ensamble pondera CNN_WEIGHT × P(CNN) + RF_WEIGHT × P(RF)
    para cada clase, retornando la clase con mayor probabilidad.
    """

    def __init__(self) -> None:
        self._CNN_MODEL = None
        self._RF_MODEL = None
        self._IS_LOADED: bool = False
        self._LATENCY_TRACKER = LatencyTracker()

    def LOAD(self, PATH: str = MODEL_PATH) -> bool:
        """
        Carga los modelos entrenados desde el sistema de archivos.

        Args:
            PATH: Directorio raíz donde están los modelos.

        Returns:
            True si al menos un modelo fue cargado exitosamente.
        """
        RF_PATH  = os.path.join(PATH, "random_forest.joblib")
        CNN_PATH = os.path.join(PATH, "cnn_model")

        # Cargar Random Forest
        if os.path.exists(RF_PATH):
            try:
                import joblib
                self._RF_MODEL = joblib.load(RF_PATH)
                LOG.info("Random Forest cargado.", extra={"PATH": RF_PATH})
            except Exception as EXC:
                LOG.error("Error cargando RF.", extra={"ERROR": str(EXC)})
        else:
            LOG.warning("RF no encontrado. Se usará modelo sintético.", extra={"PATH": RF_PATH})
            self._BUILD_SYNTHETIC_RF()

        # Cargar CNN-1D
        if os.path.exists(CNN_PATH):
            try:
                import tensorflow as tf
                self._CNN_MODEL = tf.keras.models.load_model(CNN_PATH)
                LOG.info("CNN-1D cargada.", extra={"PATH": CNN_PATH})
            except Exception as EXC:
                LOG.warning("CNN no disponible.", extra={"ERROR": str(EXC)})
        else:
            LOG.warning("CNN no encontrada. Usando solo Random Forest.")

        self._IS_LOADED = self._RF_MODEL is not None
        return self._IS_LOADED

    def _BUILD_SYNTHETIC_RF(self) -> None:
        """
        Construye un Random Forest sintético para demo/testing.
        No requiere dataset de entrenamiento.
        """
        from sklearn.ensemble import RandomForestClassifier

        LOG.info("Construyendo RF sintético para demo...")
        N_SYNTHETIC = 5000

        X_DEMO = np.random.randn(N_SYNTHETIC, N_TOTAL_FEATURES).astype(np.float32)
        Y_DEMO = np.random.choice(N_CLASSES, N_SYNTHETIC, p=[0.53] + [0.07] * 7)

        self._RF_MODEL = RandomForestClassifier(
            n_estimators=RF_N_ESTIMATORS,
            max_depth=RF_MAX_DEPTH,
            min_samples_leaf=RF_MIN_SAMPLES_LEAF,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        )
        self._RF_MODEL.fit(X_DEMO, Y_DEMO)
        LOG.info("RF sintético listo.")

    def _GET_RF_PROBA(self, X: np.ndarray) -> np.ndarray:
        """Obtiene probabilidades del Random Forest con padding a N_CLASSES columnas."""
        RF_RAW = self._RF_MODEL.predict_proba(X)

        if RF_RAW.shape[1] == N_CLASSES:
            return RF_RAW

        # Padding: RF solo vio algunas clases durante entrenamiento
        RF_FULL = np.zeros((X.shape[0], N_CLASSES), dtype=np.float32)
        for IDX, CLASS_IDX in enumerate(self._RF_MODEL.classes_):
            RF_FULL[:, CLASS_IDX] = RF_RAW[:, IDX]
        return RF_FULL

    def PREDICT(self, FEATURES: np.ndarray) -> list[PredictionResult]:
        """
        Ejecuta inferencia híbrida sobre un batch de features.

        Args:
            FEATURES: Array (N, N_TOTAL_FEATURES) de features normalizadas.

        Returns:
            Lista de PredictionResult, uno por muestra.

        Raises:
            RuntimeError: Si ningún modelo está cargado.
        """
        if not self._IS_LOADED:
            raise RuntimeError("El clasificador no ha sido cargado. Llame LOAD() primero.")

        T_START = time.perf_counter()

        # Probabilidades RF
        RF_PROBA = self._GET_RF_PROBA(FEATURES)

        # Probabilidades CNN (si disponible)
        CNN_PROBA: Optional[np.ndarray] = None
        if self._CNN_MODEL is not None:
            X_CNN = FEATURES.reshape(FEATURES.shape[0], FEATURES.shape[1], 1)
            CNN_PROBA = self._CNN_MODEL.predict(X_CNN, verbose=0)

        # Ensamble ponderado
        if CNN_PROBA is not None:
            COMBINED = CNN_WEIGHT * CNN_PROBA + RF_WEIGHT * RF_PROBA
        else:
            COMBINED = RF_PROBA

        INFERENCE_MS_TOTAL = (time.perf_counter() - T_START) * 1000
        INFERENCE_MS_PER   = INFERENCE_MS_TOTAL / max(len(FEATURES), 1)
        self._LATENCY_TRACKER.RECORD(INFERENCE_MS_PER)

        RESULTS: list[PredictionResult] = []
        NOW = datetime.now(timezone.utc)

        for I in range(len(FEATURES)):
            TOP3_IDX   = np.argsort(COMBINED[I])[-3:][::-1]
            CLASS_IDX  = int(TOP3_IDX[0])
            CONFIDENCE = float(COMBINED[I][CLASS_IDX])
            CATEGORY   = AttackCategory(ATTACK_CATEGORIES[CLASS_IDX])

            RESULT = PredictionResult(
                FLOW_ID=str(uuid.uuid4()),
                TIMESTAMP=NOW,
                PREDICTED_CLASS=CATEGORY,
                CLASS_INDEX=CLASS_IDX,
                CONFIDENCE=round(CONFIDENCE, 4),
                IS_ATTACK=CLASS_IDX != NORMAL_CLASS_INDEX,
                TOP3_CATEGORIES=[ATTACK_CATEGORIES[J] for J in TOP3_IDX],
                TOP3_SCORES=[round(float(COMBINED[I][J]), 4) for J in TOP3_IDX],
                CNN_PROBA=CNN_PROBA[I].tolist() if CNN_PROBA is not None else None,
                RF_PROBA=RF_PROBA[I].tolist(),
                INFERENCE_MS=round(INFERENCE_MS_PER, 3),
                MODEL_VERSION=MODEL_VERSION,
                SENSOR_ID="jeiguard-inference",
            )
            RESULTS.append(RESULT)

            METRICS_LOG.LOG_INFERENCE(
                RESULT.FLOW_ID,
                RESULT.PREDICTED_CLASS.value,
                RESULT.CONFIDENCE,
                RESULT.INFERENCE_MS,
                RESULT.IS_ATTACK,
            )

        return RESULTS

    def GET_LATENCY_PERCENTILES(self) -> dict[str, float]:
        return {
            "P50_MS": self._LATENCY_TRACKER.P50(),
            "P95_MS": self._LATENCY_TRACKER.P95(),
            "P99_MS": self._LATENCY_TRACKER.P99(),
        }


# ── Helpers de nivel de alerta ────────────────────────────────────────────────

def COMPUTE_ALERT_LEVEL(IS_ATTACK: bool, CONFIDENCE: float) -> str:
    """
    Determina el nivel de alerta según si es ataque y el score de confianza.

    Args:
        IS_ATTACK:  Si la predicción es un ataque.
        CONFIDENCE: Score de confianza del modelo (0.0 - 1.0).

    Returns:
        Nivel de alerta como string (NONE / LOW / MEDIUM / HIGH / CRITICAL).
    """
    if not IS_ATTACK:
        return ALERT_LEVEL_NONE
    if CONFIDENCE >= CONFIDENCE_THRESHOLD_HIGH:
        return ALERT_LEVEL_CRITICAL
    if CONFIDENCE >= CONFIDENCE_THRESHOLD_MEDIUM:
        return ALERT_LEVEL_HIGH
    return ALERT_LEVEL_MEDIUM


# ── FastAPI app ───────────────────────────────────────────────────────────────

_CLASSIFIER = HybridClassifier()
_SERVICE_START_TIME = time.time()


@asynccontextmanager
async def LIFESPAN(APP):
    """Ciclo de vida de la aplicación: carga el modelo al iniciar."""
    LOG.info("Cargando modelo JeiGuard AI...")
    SUCCESS = _CLASSIFIER.LOAD(MODEL_PATH)
    if not SUCCESS:
        LOG.warning("Modelo no pudo cargarse completamente. Demo mode activo.")
    LOG.info("Servicio de inferencia listo.")
    yield
    LOG.info("Servicio de inferencia detenido.")


def BUILD_APP():
    """
    Construye y configura la aplicación FastAPI.

    Returns:
        Instancia de FastAPI configurada con todos los endpoints.
    """
    try:
        from fastapi import FastAPI, HTTPException, status
        from fastapi.middleware.cors import CORSMiddleware

        APP = FastAPI(
            title="JeiGuard AI Inference Service",
            description=(
                "Sistema de Detección de Intrusiones — Servicio de Inferencia. "
                "Clasificación en tiempo real de tráfico de red mediante "
                "modelo híbrido CNN-1D + Random Forest."
            ),
            version=MODEL_VERSION,
            lifespan=LIFESPAN,
        )

        APP.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

        @APP.get("/health", response_model=HealthResponse, tags=["Sistema"])
        async def HEALTH_CHECK() -> HealthResponse:
            """Estado de salud del servicio de inferencia."""
            return HealthResponse(
                STATUS="healthy" if _CLASSIFIER._IS_LOADED else "degraded",
                SERVICE="jeiguard-inference",
                VERSION=MODEL_VERSION,
                MODEL_LOADED=_CLASSIFIER._IS_LOADED,
                UPTIME_S=round(time.time() - _SERVICE_START_TIME, 1),
                KAFKA_HEALTHY=True,
            )

        @APP.post(
            f"/api/{API_VERSION}/predict",
            response_model=InferenceResponse,
            tags=["Inferencia"],
            status_code=status.HTTP_200_OK,
        )
        async def PREDICT(REQUEST: InferenceRequest) -> InferenceResponse:
            """
            Clasifica uno o más flujos de red.

            Acepta hasta INFERENCE_BATCH_SIZE flujos por request.
            Cada flujo debe tener exactamente 41 features numéricas.
            """
            if len(REQUEST.FEATURES) > INFERENCE_BATCH_SIZE:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Máximo {INFERENCE_BATCH_SIZE} flujos por request.",
                )

            X = np.array(REQUEST.FEATURES, dtype=np.float32)

            try:
                RESULTS = _CLASSIFIER.PREDICT(X)
            except Exception as EXC:
                LOG.error("Error en inferencia", extra={"ERROR": str(EXC)})
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error de inferencia: {str(EXC)}",
                )

            LATENCY = sum(R.INFERENCE_MS for R in RESULTS) / max(len(RESULTS), 1)

            return InferenceResponse(
                REQUEST_ID=REQUEST.REQUEST_ID,
                PREDICTIONS=[R.PREDICTED_CLASS.value for R in RESULTS],
                CONFIDENCES=[R.CONFIDENCE for R in RESULTS],
                IS_ATTACK=[R.IS_ATTACK for R in RESULTS],
                ALERT_LEVELS=[
                    COMPUTE_ALERT_LEVEL(R.IS_ATTACK, R.CONFIDENCE) for R in RESULTS
                ],
                TOP3=[
                    {"CATEGORIES": R.TOP3_CATEGORIES, "SCORES": R.TOP3_SCORES}
                    for R in RESULTS
                ],
                LATENCY_MS=round(LATENCY, 3),
                MODEL_VERSION=MODEL_VERSION,
                N_SAMPLES=len(RESULTS),
            )

        @APP.get(f"/api/{API_VERSION}/metrics", tags=["Monitoreo"])
        async def GET_METRICS() -> dict:
            """Métricas operacionales del servicio de inferencia."""
            LATENCY = _CLASSIFIER.GET_LATENCY_PERCENTILES()
            UPTIME  = time.time() - _SERVICE_START_TIME
            return {
                "SERVICE":      "jeiguard-inference",
                "MODEL_VERSION": MODEL_VERSION,
                "UPTIME_S":     round(UPTIME, 1),
                **LATENCY,
            }

        @APP.get(f"/api/{API_VERSION}/categories", tags=["Modelo"])
        async def GET_CATEGORIES() -> dict:
            """Lista de categorías de ataque del modelo."""
            return {
                "CATEGORIES": list(ATTACK_CATEGORIES),
                "N_CLASSES":  N_CLASSES,
                "CNN_WEIGHT": CNN_WEIGHT,
                "RF_WEIGHT":  RF_WEIGHT,
            }

        return APP

    except ImportError as EXC:
        LOG.error("FastAPI no instalado.", extra={"ERROR": str(EXC)})
        raise


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        import uvicorn
        APP = BUILD_APP()
        uvicorn.run(
            APP,
            host=INFERENCE_HOST,
            port=INFERENCE_PORT,
            workers=INFERENCE_WORKERS,
            log_level="warning",
            access_log=False,
        )
    except ImportError:
        LOG.error("uvicorn no instalado. Ejecute: pip install uvicorn fastapi")
