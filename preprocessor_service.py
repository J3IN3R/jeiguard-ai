"""
services/preprocessor/preprocessor_service.py
══════════════════════════════════════════════
Servicio Preprocessor — JeiGuard AI
══════════════════════════════════════════
Responsabilidad única: consumir flujos crudos de KAFKA_TOPIC_RAW_FLOWS,
aplicar el pipeline de preprocesamiento y publicar features normalizadas
en KAFKA_TOPIC_PROCESSED_FEATURES.

Pipeline de transformación:
  1. Deserialización y validación del esquema RawNetworkFlow
  2. Ingeniería de características (14 features derivadas)
  3. Limpieza: reemplazo de NaN/Inf, clipping de outliers
  4. Normalización StandardScaler (ajustado offline sobre NSL-KDD+CICIDS)
  5. Publicación del vector ProcessedFeatures en Kafka
"""

from __future__ import annotations

import json
import math
import os
import time
import sys
from typing import Optional

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from shared.constants import (
    KAFKA_GROUP_PREPROCESSOR,
    KAFKA_TOPIC_PROCESSED_FEATURES,
    KAFKA_TOPIC_DEAD_LETTER,
    KAFKA_TOPIC_RAW_FLOWS,
    N_BASE_FEATURES,
    N_TOTAL_FEATURES,
)
from shared.logger import BUILD_LOGGER, OperationalMetricsLogger
from shared.models import ProcessedFeatures, RawNetworkFlow

# ── Logger ────────────────────────────────────────────────────────────────────
LOG = BUILD_LOGGER("jeiguard-preprocessor")
METRICS_LOG = OperationalMetricsLogger("jeiguard-preprocessor")

# ── Constantes del servicio ───────────────────────────────────────────────────
OUTLIER_CLIP_FACTOR:     float = 3.0    # IQR factor para clipping
SCALER_PATH:             str   = os.getenv("SCALER_PATH", "models/scaler.joblib")
KAFKA_POLL_TIMEOUT_S:    float = 1.0
KAFKA_COMMIT_INTERVAL:   int   = 100    # Commit offset cada N mensajes


# ── Pipeline de preprocesamiento ──────────────────────────────────────────────

class FeatureEngineeringPipeline:
    """
    Pipeline de ingeniería y normalización de características.

    Transforma un vector de 41 features base en un vector de
    N_TOTAL_FEATURES (55) normalizado, listo para inferencia.

    El StandardScaler debe ser ajustado offline sobre el dataset
    de entrenamiento y cargado en producción via joblib.
    """

    def __init__(self, SCALER_PATH: Optional[str] = None) -> None:
        self._SCALER = None
        self._IS_FITTED: bool = False

        if SCALER_PATH and os.path.exists(SCALER_PATH):
            self._LOAD_SCALER(SCALER_PATH)
        else:
            LOG.warning(
                "Scaler no encontrado. Usando normalización por defecto (sin ajuste).",
                extra={"SCALER_PATH": SCALER_PATH},
            )

    def _LOAD_SCALER(self, PATH: str) -> None:
        """Carga el StandardScaler ajustado sobre el dataset de entrenamiento."""
        try:
            import joblib
            self._SCALER = joblib.load(PATH)
            self._IS_FITTED = True
            LOG.info("Scaler cargado exitosamente.", extra={"PATH": PATH})
        except Exception as EXC:
            LOG.error("Error cargando scaler.", extra={"ERROR": str(EXC)})

    def ENGINEER_FEATURES(self, RAW: list[float]) -> np.ndarray:
        """
        Extrae 14 features derivadas del vector base de 41 features.

        Features derivadas:
          1.  ratio_bytes:          src_bytes / dst_bytes
          2.  log_total_bytes:      log1p(src + dst)
          3.  traffic_balance:      (src - dst) / total
          4.  combined_error_rate:  (serror + rerror) / 2
          5.  hot_log:              log1p(hot_indicators)
          6.  count_ratio:          srv_count / count
          7.  service_diversity:    diff_srv / (same_srv + ε)
          8.  scan_indicator:       dst_host_count / (dst_host_srv + ε)
          9.  duration_log:         log1p(duration)
          10. failed_logins:        num_failed_logins (raw)
          11. root_indicators:      root_shell + num_root + file_creations
          12. dos_score:            serror_rate × count / 512
          13. bytes_per_connection: total_bytes / count
          14. srv_error_product:    serror_rate × srv_serror_rate

        Args:
            RAW: Vector de 41 features crudas.

        Returns:
            Array numpy de N_TOTAL_FEATURES features.
        """
        DURATION      = RAW[0]
        SRC_BYTES     = RAW[4]
        DST_BYTES     = RAW[5]
        HOT           = RAW[9]
        FAILED_LOGINS = RAW[10]
        ROOT_SHELL    = RAW[13]
        NUM_ROOT      = RAW[15]
        FILE_CREAT    = RAW[16]
        COUNT         = RAW[22]
        SRV_COUNT     = RAW[23]
        SERROR_RATE   = RAW[24]
        SRV_SERROR    = RAW[25]
        RERROR_RATE   = RAW[26]
        SAME_SRV      = RAW[28]
        DIFF_SRV      = RAW[29]
        DST_HOST_CNT  = RAW[31]
        DST_HOST_SRV  = RAW[32]

        EPS              = 1e-8
        TOTAL_BYTES      = SRC_BYTES + DST_BYTES + EPS
        SAFE_COUNT       = max(COUNT, EPS)
        SAFE_SAME_SRV    = max(SAME_SRV, EPS)
        SAFE_DST_SRV     = max(DST_HOST_SRV, EPS)

        DERIVED: list[float] = [
            SRC_BYTES / (DST_BYTES + EPS),                         # 1
            math.log1p(TOTAL_BYTES),                               # 2
            (SRC_BYTES - DST_BYTES) / TOTAL_BYTES,                 # 3
            (SERROR_RATE + RERROR_RATE) / 2.0,                     # 4
            math.log1p(HOT),                                       # 5
            SRV_COUNT / SAFE_COUNT,                                # 6
            DIFF_SRV / SAFE_SAME_SRV,                             # 7
            DST_HOST_CNT / SAFE_DST_SRV,                          # 8
            math.log1p(DURATION),                                  # 9
            FAILED_LOGINS,                                         # 10
            ROOT_SHELL + NUM_ROOT + FILE_CREAT,                    # 11
            SERROR_RATE * SAFE_COUNT / 512.0,                      # 12
            TOTAL_BYTES / SAFE_COUNT,                              # 13
            SERROR_RATE * SRV_SERROR,                             # 14
        ]

        COMBINED = np.array(RAW + DERIVED, dtype=np.float32)
        return COMBINED

    def CLEAN(self, VECTOR: np.ndarray) -> np.ndarray:
        """
        Limpia el vector de features:
        - Reemplaza NaN e Inf por 0.0
        - Aplica clipping para eliminar outliers extremos

        Args:
            VECTOR: Array numpy sin limpiar.

        Returns:
            Array limpio y dentro de rango seguro.
        """
        CLEANED = np.nan_to_num(VECTOR, nan=0.0, posinf=1e10, neginf=-1e10)
        CLIPPED = np.clip(CLEANED, -1e10, 1e10)
        return CLIPPED

    def NORMALIZE(self, VECTOR: np.ndarray) -> np.ndarray:
        """
        Normaliza el vector usando StandardScaler ajustado.
        Si el scaler no está disponible, aplica min-max simple.

        Args:
            VECTOR: Array limpio de N_TOTAL_FEATURES features.

        Returns:
            Array normalizado.
        """
        if self._IS_FITTED and self._SCALER is not None:
            return self._SCALER.transform(VECTOR.reshape(1, -1)).flatten()

        # Fallback: normalización por rango seguro
        STD = np.std(VECTOR)
        if STD < 1e-8:
            return VECTOR
        return (VECTOR - np.mean(VECTOR)) / (STD + 1e-8)

    def TRANSFORM(self, RAW_FEATURES: list[float]) -> np.ndarray:
        """
        Aplica el pipeline completo: engineer → clean → normalize.

        Args:
            RAW_FEATURES: Vector de 41 features crudas.

        Returns:
            Vector normalizado listo para inferencia.

        Raises:
            ValueError: Si RAW_FEATURES no tiene exactamente 41 elementos.
        """
        if len(RAW_FEATURES) != N_BASE_FEATURES:
            raise ValueError(
                f"Se esperaban {N_BASE_FEATURES} features, "
                f"recibidas: {len(RAW_FEATURES)}"
            )

        ENGINEERED = self.ENGINEER_FEATURES(RAW_FEATURES)
        CLEANED    = self.CLEAN(ENGINEERED)
        NORMALIZED = self.NORMALIZE(CLEANED)

        return NORMALIZED.astype(np.float32)


# ── Servicio Kafka Consumer/Producer ─────────────────────────────────────────

class PreprocessorService:
    """
    Servicio de preprocesamiento de tráfico de red.

    Consume RawNetworkFlow de KAFKA_TOPIC_RAW_FLOWS,
    aplica el FeatureEngineeringPipeline y publica
    ProcessedFeatures en KAFKA_TOPIC_PROCESSED_FEATURES.

    Los mensajes que fallan validación se envían a KAFKA_TOPIC_DEAD_LETTER
    para inspección posterior sin bloquear el pipeline principal.
    """

    def __init__(
        self,
        BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092"),
        DRY_RUN: bool = os.getenv("DRY_RUN", "false").lower() == "true",
    ) -> None:
        self._BOOTSTRAP_SERVERS = BOOTSTRAP_SERVERS
        self._DRY_RUN = DRY_RUN
        self._PIPELINE = FeatureEngineeringPipeline(SCALER_PATH)
        self._CONSUMER = None
        self._PRODUCER = None
        self._RUNNING = False

        self._PROCESSED_COUNT: int = 0
        self._ERROR_COUNT:     int = 0
        self._START_TIME: float = time.time()

        if not DRY_RUN:
            self._INIT_KAFKA()

        LOG.info(
            "PreprocessorService inicializado",
            extra={"BOOTSTRAP_SERVERS": BOOTSTRAP_SERVERS, "DRY_RUN": DRY_RUN},
        )

    def _INIT_KAFKA(self) -> None:
        """Inicializa consumer y producer Kafka."""
        try:
            from confluent_kafka import Consumer, Producer as KProducer

            CONSUMER_CONFIG = {
                "bootstrap.servers":       self._BOOTSTRAP_SERVERS,
                "group.id":                KAFKA_GROUP_PREPROCESSOR,
                "auto.offset.reset":       "earliest",
                "enable.auto.commit":      False,
                "max.poll.interval.ms":    300000,
            }
            PRODUCER_CONFIG = {
                "bootstrap.servers": self._BOOTSTRAP_SERVERS,
                "linger.ms":         2,
                "compression.type":  "lz4",
            }

            self._CONSUMER = Consumer(CONSUMER_CONFIG)
            self._CONSUMER.subscribe([KAFKA_TOPIC_RAW_FLOWS])
            self._PRODUCER = KProducer(PRODUCER_CONFIG)

            LOG.info("Kafka consumer/producer inicializados.")

        except ImportError:
            LOG.warning("confluent-kafka no instalado. Modo DRY_RUN activado.")
            self._DRY_RUN = True

    def _PROCESS_MESSAGE(self, RAW_JSON: bytes) -> Optional[ProcessedFeatures]:
        """
        Deserializa, valida y transforma un mensaje Kafka.

        Args:
            RAW_JSON: Bytes del mensaje Kafka.

        Returns:
            ProcessedFeatures si el procesamiento fue exitoso, None si falló.
        """
        T_START = time.perf_counter()

        try:
            FLOW = RawNetworkFlow.model_validate_json(RAW_JSON)
        except Exception as EXC:
            LOG.error("Error deserializando RawNetworkFlow", extra={"ERROR": str(EXC)})
            return None

        try:
            NORMALIZED_VECTOR = self._PIPELINE.TRANSFORM(FLOW.RAW_FEATURES)
        except Exception as EXC:
            METRICS_LOG.LOG_ERROR("TRANSFORM_ERROR", FLOW.FLOW_ID, str(EXC))
            return None

        PREPROCESSING_MS = (time.perf_counter() - T_START) * 1000

        PROCESSED = ProcessedFeatures(
            FLOW_ID=FLOW.FLOW_ID,
            TIMESTAMP=FLOW.TIMESTAMP,
            NORMALIZED_VECTOR=NORMALIZED_VECTOR.tolist(),
            N_FEATURES=len(NORMALIZED_VECTOR),
            SENSOR_ID=FLOW.SENSOR_ID,
            PREPROCESSING_MS=round(PREPROCESSING_MS, 3),
        )

        return PROCESSED

    def _PUBLISH_PROCESSED(self, PROCESSED: ProcessedFeatures) -> None:
        """Publica las features procesadas en KAFKA_TOPIC_PROCESSED_FEATURES."""
        PAYLOAD = PROCESSED.model_dump_json().encode("utf-8")

        if self._DRY_RUN:
            self._PROCESSED_COUNT += 1
            return

        self._PRODUCER.produce(
            topic=KAFKA_TOPIC_PROCESSED_FEATURES,
            key=PROCESSED.FLOW_ID.encode("utf-8"),
            value=PAYLOAD,
        )

    def _PUBLISH_DEAD_LETTER(self, RAW_JSON: bytes, REASON: str) -> None:
        """Envía mensajes fallidos al Dead Letter Queue para análisis posterior."""
        DL_PAYLOAD = json.dumps(
            {"RAW": RAW_JSON.decode("utf-8", errors="replace"), "REASON": REASON}
        ).encode("utf-8")

        if self._DRY_RUN:
            LOG.warning("Dead letter (DRY_RUN)", extra={"REASON": REASON})
            return

        self._PRODUCER.produce(
            topic=KAFKA_TOPIC_DEAD_LETTER,
            value=DL_PAYLOAD,
        )

    def PROCESS_SINGLE(self, RAW_FEATURES: list[float]) -> Optional[list[float]]:
        """
        API síncrona para procesamiento individual (útil en tests).

        Args:
            RAW_FEATURES: Vector de 41 features crudas.

        Returns:
            Vector normalizado de N_TOTAL_FEATURES, o None si falla.
        """
        try:
            RESULT = self._PIPELINE.TRANSFORM(RAW_FEATURES)
            return RESULT.tolist()
        except Exception as EXC:
            LOG.error("Error en PROCESS_SINGLE", extra={"ERROR": str(EXC)})
            return None

    def RUN(self) -> None:
        """Loop principal del servicio preprocessor."""
        self._RUNNING = True
        LOG.info("PreprocessorService iniciado, esperando mensajes...")

        MSG_COUNT_SINCE_COMMIT = 0

        try:
            while self._RUNNING:
                if self._DRY_RUN:
                    # Modo demo: simular mensajes sintéticos
                    SYNTHETIC = [0.0] * N_BASE_FEATURES
                    PROCESSED = self._PROCESS_MESSAGE(
                        RawNetworkFlow(
                            SRC_IP="192.168.1.1", DST_IP="10.0.0.1",
                            SRC_PORT=12345, DST_PORT=80,
                            PROTOCOL="tcp", DURATION=1.0,
                            SRC_BYTES=500, DST_BYTES=300,
                            N_PACKETS=5, RAW_FEATURES=SYNTHETIC,
                        ).model_dump_json().encode()
                    )
                    if PROCESSED:
                        self._PROCESSED_COUNT += 1
                    time.sleep(0.001)
                    continue

                MSG = self._CONSUMER.poll(KAFKA_POLL_TIMEOUT_S)
                if MSG is None:
                    continue
                if MSG.error():
                    LOG.error("Error Kafka consumer", extra={"ERROR": str(MSG.error())})
                    continue

                PROCESSED = self._PROCESS_MESSAGE(MSG.value())

                if PROCESSED:
                    self._PUBLISH_PROCESSED(PROCESSED)
                    self._PROCESSED_COUNT += 1
                    METRICS_LOG.LOG_INFERENCE(
                        PROCESSED.FLOW_ID, "PREPROCESSED", 1.0,
                        PROCESSED.PREPROCESSING_MS, False,
                    )
                else:
                    self._ERROR_COUNT += 1
                    self._PUBLISH_DEAD_LETTER(MSG.value(), "PROCESSING_FAILED")

                MSG_COUNT_SINCE_COMMIT += 1
                if MSG_COUNT_SINCE_COMMIT >= KAFKA_COMMIT_INTERVAL:
                    self._CONSUMER.commit(asynchronous=True)
                    MSG_COUNT_SINCE_COMMIT = 0

        except KeyboardInterrupt:
            LOG.info("PreprocessorService detenido por el usuario.")
        finally:
            if self._CONSUMER and not self._DRY_RUN:
                self._CONSUMER.close()
            ELAPSED = time.time() - self._START_TIME
            LOG.info(
                "Estadísticas finales",
                extra={
                    "PROCESSED_TOTAL": self._PROCESSED_COUNT,
                    "ERROR_TOTAL":     self._ERROR_COUNT,
                    "THROUGHPUT":      round(self._PROCESSED_COUNT / max(ELAPSED, 0.001), 2),
                },
            )

    def STOP(self) -> None:
        """Detiene el servicio de forma ordenada."""
        self._RUNNING = False


if __name__ == "__main__":
    SERVICE = PreprocessorService()
    SERVICE.RUN()
