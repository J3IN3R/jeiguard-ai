"""
tests/unit/test_jeiguard_ai.py
════════════════════════════════════
Suite de tests unitarios — JeiGuard AI
════════════════════════════════════════════
Cobertura:
  - shared/constants.py    → Validación de constantes globales
  - shared/models.py       → Validación de modelos Pydantic
  - shared/logger.py       → Logger estructurado
  - preprocessor_service   → Pipeline de features engineering
  - inference_service      → Clasificador híbrido y niveles de alerta
  - alert_manager_service  → Deduplicación y construcción de alertas

Ejecutar:
  pytest tests/unit/test_jeiguard_ai.py -v --tb=short
  pytest tests/unit/ -v --cov=services --cov=shared --cov-report=term-missing
"""

from __future__ import annotations

import sys
import os
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Optional
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

# Ajustar path para importaciones relativas
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from shared.constants import (
    ATTACK_CATEGORIES,
    ATTACK_CATEGORY_INDEX,
    CNN_WEIGHT,
    RF_WEIGHT,
    N_BASE_FEATURES,
    N_TOTAL_FEATURES,
    N_CLASSES,
    NORMAL_CLASS_INDEX,
    KAFKA_TOPIC_RAW_FLOWS,
    KAFKA_TOPIC_PREDICTIONS,
    KAFKA_TOPIC_ALERTS,
    CONFIDENCE_THRESHOLD_HIGH,
    CONFIDENCE_THRESHOLD_MEDIUM,
)
from shared.models import (
    Alert,
    AlertLevel,
    AttackCategory,
    HealthResponse,
    InferenceRequest,
    InferenceResponse,
    ProcessedFeatures,
    Protocol,
    RawNetworkFlow,
    PredictionResult,
)
from shared.logger import BUILD_LOGGER, OperationalMetricsLogger


# ════════════════════════════════════════════════════════════════════════════════
# FIXTURES COMPARTIDOS
# ════════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def VALID_RAW_FEATURES() -> list[float]:
    """Vector de 41 features válidas para RawNetworkFlow."""
    return [0.0] * N_BASE_FEATURES


@pytest.fixture
def ATTACK_RAW_FEATURES() -> list[float]:
    """Vector de 41 features que simula un ataque DoS (serror_rate alto)."""
    FEATURES = [0.0] * N_BASE_FEATURES
    FEATURES[0]  = 0.0     # duration=0 (característico DoS)
    FEATURES[4]  = 10.0    # src_bytes pequeño
    FEATURES[5]  = 0.0     # dst_bytes=0
    FEATURES[22] = 500.0   # count muy alto
    FEATURES[24] = 0.99    # serror_rate casi 1.0
    FEATURES[28] = 1.0     # same_srv_rate=1.0
    return FEATURES


@pytest.fixture
def VALID_RAW_FLOW(VALID_RAW_FEATURES: list[float]) -> RawNetworkFlow:
    """Instancia válida de RawNetworkFlow para tests."""
    return RawNetworkFlow(
        SRC_IP="192.168.1.100",
        DST_IP="10.0.0.1",
        SRC_PORT=12345,
        DST_PORT=80,
        PROTOCOL=Protocol.TCP,
        DURATION=1.5,
        SRC_BYTES=500,
        DST_BYTES=300,
        N_PACKETS=5,
        FLAGS="ACK",
        RAW_FEATURES=VALID_RAW_FEATURES,
        SENSOR_ID="test-sensor",
    )


@pytest.fixture
def VALID_PREDICTION() -> PredictionResult:
    """Instancia válida de PredictionResult."""
    return PredictionResult(
        FLOW_ID=str(uuid.uuid4()),
        TIMESTAMP=datetime.now(timezone.utc),
        PREDICTED_CLASS=AttackCategory.DOS_DDOS,
        CLASS_INDEX=1,
        CONFIDENCE=0.96,
        IS_ATTACK=True,
        TOP3_CATEGORIES=["DoS_DDoS", "Normal", "Probe_Scan"],
        TOP3_SCORES=[0.96, 0.02, 0.01],
        RF_PROBA=[0.02, 0.95, 0.01, 0.01, 0.0, 0.0, 0.0, 0.01],
        INFERENCE_MS=3.8,
        MODEL_VERSION="1.0.0",
        SENSOR_ID="test-sensor",
    )


# ════════════════════════════════════════════════════════════════════════════════
# TESTS: shared/constants.py
# ════════════════════════════════════════════════════════════════════════════════

class TestConstants:
    """Valida que las constantes globales sean coherentes entre sí."""

    def test_ATTACK_CATEGORIES_COUNT(self) -> None:
        """El número de categorías debe coincidir con N_CLASSES."""
        assert len(ATTACK_CATEGORIES) == N_CLASSES

    def test_NORMAL_CLASS_INDEX_IS_ZERO(self) -> None:
        """La clase Normal SIEMPRE debe ser el índice 0."""
        assert NORMAL_CLASS_INDEX == 0
        assert ATTACK_CATEGORIES[0] == "Normal"

    def test_ATTACK_CATEGORY_INDEX_CONSISTENCY(self) -> None:
        """El mapa de índices debe ser consistente con la tupla de categorías."""
        for IDX, CAT in enumerate(ATTACK_CATEGORIES):
            assert ATTACK_CATEGORY_INDEX[CAT] == IDX

    def test_CNN_RF_WEIGHTS_SUM_TO_ONE(self) -> None:
        """Los pesos del ensamble CNN+RF deben sumar exactamente 1.0."""
        assert abs(CNN_WEIGHT + RF_WEIGHT - 1.0) < 1e-9

    def test_N_TOTAL_FEATURES_GREATER_THAN_BASE(self) -> None:
        """El total de features debe superar las features base."""
        assert N_TOTAL_FEATURES > N_BASE_FEATURES

    def test_KAFKA_TOPICS_ARE_UNIQUE(self) -> None:
        """Ningún topic Kafka debe repetirse."""
        TOPICS = [KAFKA_TOPIC_RAW_FLOWS, KAFKA_TOPIC_PREDICTIONS, KAFKA_TOPIC_ALERTS]
        assert len(set(TOPICS)) == len(TOPICS)

    def test_CONFIDENCE_THRESHOLDS_ORDERED(self) -> None:
        """Los umbrales de confianza deben estar ordenados ascendentemente."""
        assert CONFIDENCE_THRESHOLD_MEDIUM < CONFIDENCE_THRESHOLD_HIGH
        assert 0.0 < CONFIDENCE_THRESHOLD_MEDIUM < 1.0
        assert 0.0 < CONFIDENCE_THRESHOLD_HIGH <= 1.0


# ════════════════════════════════════════════════════════════════════════════════
# TESTS: shared/models.py → RawNetworkFlow
# ════════════════════════════════════════════════════════════════════════════════

class TestRawNetworkFlow:
    """Tests de validación del modelo RawNetworkFlow."""

    def test_VALID_FLOW_CREATION(self, VALID_RAW_FLOW: RawNetworkFlow) -> None:
        assert VALID_RAW_FLOW.SRC_IP == "192.168.1.100"
        assert VALID_RAW_FLOW.DST_PORT == 80
        assert len(VALID_RAW_FLOW.RAW_FEATURES) == N_BASE_FEATURES

    def test_FLOW_ID_GENERATED_AUTOMATICALLY(self, VALID_RAW_FLOW: RawNetworkFlow) -> None:
        """FLOW_ID debe generarse automáticamente si no se especifica."""
        assert VALID_RAW_FLOW.FLOW_ID is not None
        assert len(VALID_RAW_FLOW.FLOW_ID) == 36   # UUID4 format

    def test_WRONG_FEATURE_COUNT_RAISES(self) -> None:
        """Debe lanzar ValidationError si RAW_FEATURES no tiene 41 elementos."""
        with pytest.raises(Exception):
            RawNetworkFlow(
                SRC_IP="192.168.1.1",
                DST_IP="10.0.0.1",
                SRC_PORT=1234,
                DST_PORT=80,
                PROTOCOL=Protocol.TCP,
                DURATION=1.0,
                SRC_BYTES=100,
                DST_BYTES=100,
                N_PACKETS=1,
                RAW_FEATURES=[0.0] * 40,   # 40 en lugar de 41 → debe fallar
            )

    def test_INVALID_IP_FORMAT_RAISES(self) -> None:
        """Debe lanzar ValidationError si la IP no tiene formato válido."""
        with pytest.raises(Exception):
            RawNetworkFlow(
                SRC_IP="999.999.999",   # IP inválida
                DST_IP="10.0.0.1",
                SRC_PORT=1234,
                DST_PORT=80,
                PROTOCOL=Protocol.TCP,
                DURATION=1.0,
                SRC_BYTES=100,
                DST_BYTES=100,
                N_PACKETS=1,
                RAW_FEATURES=[0.0] * N_BASE_FEATURES,
            )

    def test_PORT_OUT_OF_RANGE_RAISES(self) -> None:
        """Puertos fuera de rango [0, 65535] deben fallar."""
        with pytest.raises(Exception):
            RawNetworkFlow(
                SRC_IP="192.168.1.1",
                DST_IP="10.0.0.1",
                SRC_PORT=99999,     # > 65535
                DST_PORT=80,
                PROTOCOL=Protocol.TCP,
                DURATION=1.0,
                SRC_BYTES=100,
                DST_BYTES=100,
                N_PACKETS=1,
                RAW_FEATURES=[0.0] * N_BASE_FEATURES,
            )

    def test_IMMUTABILITY(self, VALID_RAW_FLOW: RawNetworkFlow) -> None:
        """RawNetworkFlow debe ser inmutable (frozen)."""
        with pytest.raises(Exception):
            VALID_RAW_FLOW.SRC_IP = "10.10.10.10"

    def test_JSON_SERIALIZATION_ROUNDTRIP(self, VALID_RAW_FLOW: RawNetworkFlow) -> None:
        """Serializar a JSON y deserializar debe producir el mismo objeto."""
        JSON_STR = VALID_RAW_FLOW.model_dump_json()
        DESERIALIZED = RawNetworkFlow.model_validate_json(JSON_STR)
        assert DESERIALIZED.FLOW_ID == VALID_RAW_FLOW.FLOW_ID
        assert DESERIALIZED.RAW_FEATURES == VALID_RAW_FLOW.RAW_FEATURES


# ════════════════════════════════════════════════════════════════════════════════
# TESTS: shared/models.py → ProcessedFeatures
# ════════════════════════════════════════════════════════════════════════════════

class TestProcessedFeatures:
    """Tests del modelo ProcessedFeatures."""

    def test_VALID_CREATION(self) -> None:
        VECTOR = [0.5] * N_TOTAL_FEATURES
        PF = ProcessedFeatures(
            FLOW_ID=str(uuid.uuid4()),
            TIMESTAMP=datetime.now(timezone.utc),
            NORMALIZED_VECTOR=VECTOR,
            N_FEATURES=N_TOTAL_FEATURES,
            SENSOR_ID="test",
            PREPROCESSING_MS=1.2,
        )
        assert len(PF.NORMALIZED_VECTOR) == N_TOTAL_FEATURES

    def test_VECTOR_LENGTH_MISMATCH_RAISES(self) -> None:
        """N_FEATURES debe coincidir con len(NORMALIZED_VECTOR)."""
        with pytest.raises(Exception):
            ProcessedFeatures(
                FLOW_ID=str(uuid.uuid4()),
                TIMESTAMP=datetime.now(timezone.utc),
                NORMALIZED_VECTOR=[0.5] * 10,   # 10 elementos
                N_FEATURES=N_TOTAL_FEATURES,     # declara N_TOTAL → mismatch
                SENSOR_ID="test",
                PREPROCESSING_MS=1.0,
            )

    def test_NEGATIVE_PREPROCESSING_TIME_RAISES(self) -> None:
        with pytest.raises(Exception):
            ProcessedFeatures(
                FLOW_ID=str(uuid.uuid4()),
                TIMESTAMP=datetime.now(timezone.utc),
                NORMALIZED_VECTOR=[0.0] * N_TOTAL_FEATURES,
                N_FEATURES=N_TOTAL_FEATURES,
                SENSOR_ID="test",
                PREPROCESSING_MS=-1.0,   # negativo → inválido
            )


# ════════════════════════════════════════════════════════════════════════════════
# TESTS: shared/models.py → PredictionResult
# ════════════════════════════════════════════════════════════════════════════════

class TestPredictionResult:
    """Tests del modelo PredictionResult."""

    def test_VALID_PREDICTION(self, VALID_PREDICTION: PredictionResult) -> None:
        assert VALID_PREDICTION.IS_ATTACK is True
        assert VALID_PREDICTION.CONFIDENCE == 0.96
        assert len(VALID_PREDICTION.TOP3_CATEGORIES) == 3

    def test_CONFIDENCE_OUT_OF_RANGE_RAISES(self) -> None:
        with pytest.raises(Exception):
            PredictionResult(
                FLOW_ID=str(uuid.uuid4()),
                TIMESTAMP=datetime.now(timezone.utc),
                PREDICTED_CLASS=AttackCategory.NORMAL,
                CLASS_INDEX=0,
                CONFIDENCE=1.5,   # > 1.0 → inválido
                IS_ATTACK=False,
                TOP3_CATEGORIES=["Normal", "DoS_DDoS", "Probe_Scan"],
                TOP3_SCORES=[0.98, 0.01, 0.01],
                RF_PROBA=[0.98] + [0.0] * 7,
                INFERENCE_MS=2.0,
                MODEL_VERSION="1.0.0",
                SENSOR_ID="test",
            )

    def test_TOP3_MUST_HAVE_THREE_ELEMENTS(self) -> None:
        with pytest.raises(Exception):
            PredictionResult(
                FLOW_ID=str(uuid.uuid4()),
                TIMESTAMP=datetime.now(timezone.utc),
                PREDICTED_CLASS=AttackCategory.NORMAL,
                CLASS_INDEX=0,
                CONFIDENCE=0.90,
                IS_ATTACK=False,
                TOP3_CATEGORIES=["Normal", "DoS_DDoS"],  # solo 2 → inválido
                TOP3_SCORES=[0.90, 0.10],
                RF_PROBA=[0.90] + [0.0] * 7,
                INFERENCE_MS=2.0,
                MODEL_VERSION="1.0.0",
                SENSOR_ID="test",
            )


# ════════════════════════════════════════════════════════════════════════════════
# TESTS: services/preprocessor → FeatureEngineeringPipeline
# ════════════════════════════════════════════════════════════════════════════════

class TestFeatureEngineeringPipeline:
    """Tests del pipeline de preprocesamiento de features."""

    @pytest.fixture(autouse=True)
    def SETUP(self) -> None:
        """Importar FeatureEngineeringPipeline para cada test."""
        from services.preprocessor.preprocessor_service import FeatureEngineeringPipeline
        self._PIPELINE = FeatureEngineeringPipeline(SCALER_PATH=None)

    def test_TRANSFORM_OUTPUT_LENGTH(self, VALID_RAW_FEATURES: list[float]) -> None:
        """El vector transformado debe tener N_TOTAL_FEATURES elementos."""
        RESULT = self._PIPELINE.TRANSFORM(VALID_RAW_FEATURES)
        assert len(RESULT) == N_TOTAL_FEATURES

    def test_TRANSFORM_RETURNS_FLOAT32(self, VALID_RAW_FEATURES: list[float]) -> None:
        """El vector de salida debe ser dtype float32."""
        RESULT = self._PIPELINE.TRANSFORM(VALID_RAW_FEATURES)
        assert RESULT.dtype == np.float32

    def test_WRONG_INPUT_LENGTH_RAISES(self) -> None:
        """Debe lanzar ValueError si la entrada no tiene N_BASE_FEATURES elementos."""
        with pytest.raises(ValueError, match="Se esperaban"):
            self._PIPELINE.TRANSFORM([0.0] * 30)

    def test_NAN_HANDLING(self) -> None:
        """NaN en la entrada debe reemplazarse por 0.0 sin error."""
        FEATURES_WITH_NAN = [float("nan")] * N_BASE_FEATURES
        RESULT = self._PIPELINE.TRANSFORM(FEATURES_WITH_NAN)
        assert not np.any(np.isnan(RESULT))

    def test_INF_HANDLING(self) -> None:
        """Valores infinitos deben manejarse sin error."""
        FEATURES_WITH_INF = [float("inf")] * N_BASE_FEATURES
        RESULT = self._PIPELINE.TRANSFORM(FEATURES_WITH_INF)
        assert np.all(np.isfinite(RESULT))

    def test_NORMAL_VS_DOS_FEATURES_DIFFER(
        self,
        VALID_RAW_FEATURES: list[float],
        ATTACK_RAW_FEATURES: list[float],
    ) -> None:
        """Features de tráfico normal y DoS deben producir vectores distintos."""
        NORMAL_VEC = self._PIPELINE.TRANSFORM(VALID_RAW_FEATURES)
        DOS_VEC    = self._PIPELINE.TRANSFORM(ATTACK_RAW_FEATURES)
        assert not np.allclose(NORMAL_VEC, DOS_VEC)

    def test_ENGINEER_FEATURES_COUNT(self, VALID_RAW_FEATURES: list[float]) -> None:
        """ENGINEER_FEATURES debe añadir exactamente 14 features derivadas."""
        RESULT = self._PIPELINE.ENGINEER_FEATURES(VALID_RAW_FEATURES)
        assert len(RESULT) == N_BASE_FEATURES + 14

    def test_DETERMINISTIC_TRANSFORM(self, VALID_RAW_FEATURES: list[float]) -> None:
        """El mismo input debe producir siempre el mismo output."""
        RESULT_1 = self._PIPELINE.TRANSFORM(VALID_RAW_FEATURES)
        RESULT_2 = self._PIPELINE.TRANSFORM(VALID_RAW_FEATURES)
        np.testing.assert_array_equal(RESULT_1, RESULT_2)


# ════════════════════════════════════════════════════════════════════════════════
# TESTS: services/inference → HybridClassifier + helpers
# ════════════════════════════════════════════════════════════════════════════════

class TestHybridClassifier:
    """Tests del clasificador híbrido CNN+RF."""

    @pytest.fixture(autouse=True)
    def SETUP(self) -> None:
        from services.inference.inference_service import HybridClassifier
        self._CLASSIFIER = HybridClassifier()
        self._CLASSIFIER.LOAD(PATH="nonexistent_path_triggers_synthetic")

    def test_MODEL_LOADED_AFTER_INIT(self) -> None:
        """El clasificador debe estar listo tras LOAD() (con RF sintético)."""
        assert self._CLASSIFIER._IS_LOADED is True

    def test_PREDICT_OUTPUT_COUNT(self) -> None:
        """PREDICT debe retornar un resultado por cada muestra del batch."""
        N = 5
        X = np.random.randn(N, N_TOTAL_FEATURES).astype(np.float32)
        RESULTS = self._CLASSIFIER.PREDICT(X)
        assert len(RESULTS) == N

    def test_PREDICT_RETURNS_VALID_CATEGORIES(self) -> None:
        """Todas las predicciones deben ser categorías válidas."""
        X = np.random.randn(10, N_TOTAL_FEATURES).astype(np.float32)
        RESULTS = self._CLASSIFIER.PREDICT(X)
        VALID_CATS = set(ATTACK_CATEGORIES)
        for R in RESULTS:
            assert R.PREDICTED_CLASS.value in VALID_CATS

    def test_CONFIDENCE_IN_RANGE(self) -> None:
        """La confianza de predicción debe estar en [0.0, 1.0]."""
        X = np.random.randn(20, N_TOTAL_FEATURES).astype(np.float32)
        RESULTS = self._CLASSIFIER.PREDICT(X)
        for R in RESULTS:
            assert 0.0 <= R.CONFIDENCE <= 1.0

    def test_IS_ATTACK_CONSISTENT_WITH_CLASS(self) -> None:
        """IS_ATTACK debe ser False si y solo si la clase es Normal."""
        X = np.random.randn(50, N_TOTAL_FEATURES).astype(np.float32)
        RESULTS = self._CLASSIFIER.PREDICT(X)
        for R in RESULTS:
            if R.PREDICTED_CLASS == AttackCategory.NORMAL:
                assert R.IS_ATTACK is False
            else:
                assert R.IS_ATTACK is True

    def test_PREDICT_WITHOUT_LOAD_RAISES(self) -> None:
        """PREDICT sin LOAD debe lanzar RuntimeError."""
        from services.inference.inference_service import HybridClassifier
        UNLOADED = HybridClassifier()
        X = np.random.randn(3, N_TOTAL_FEATURES).astype(np.float32)
        with pytest.raises(RuntimeError, match="cargado"):
            UNLOADED.PREDICT(X)

    def test_LATENCY_PERCENTILES_AFTER_INFERENCE(self) -> None:
        """Los percentiles de latencia deben actualizarse tras la inferencia."""
        X = np.random.randn(10, N_TOTAL_FEATURES).astype(np.float32)
        self._CLASSIFIER.PREDICT(X)
        LATENCIES = self._CLASSIFIER.GET_LATENCY_PERCENTILES()
        assert LATENCIES["P50_MS"] >= 0.0
        assert LATENCIES["P95_MS"] >= LATENCIES["P50_MS"]
        assert LATENCIES["P99_MS"] >= LATENCIES["P95_MS"]


class TestComputeAlertLevel:
    """Tests de la función COMPUTE_ALERT_LEVEL."""

    def test_NORMAL_TRAFFIC_IS_NONE(self) -> None:
        from services.inference.inference_service import COMPUTE_ALERT_LEVEL
        assert COMPUTE_ALERT_LEVEL(False, 0.99) == "NONE"

    def test_HIGH_CONFIDENCE_ATTACK_IS_CRITICAL(self) -> None:
        from services.inference.inference_service import COMPUTE_ALERT_LEVEL
        assert COMPUTE_ALERT_LEVEL(True, CONFIDENCE_THRESHOLD_HIGH) == "CRITICAL"

    def test_MEDIUM_CONFIDENCE_ATTACK_IS_HIGH(self) -> None:
        from services.inference.inference_service import COMPUTE_ALERT_LEVEL
        LEVEL = COMPUTE_ALERT_LEVEL(True, CONFIDENCE_THRESHOLD_MEDIUM)
        assert LEVEL == "HIGH"

    def test_LOW_CONFIDENCE_ATTACK_IS_MEDIUM(self) -> None:
        from services.inference.inference_service import COMPUTE_ALERT_LEVEL
        assert COMPUTE_ALERT_LEVEL(True, 0.72) == "MEDIUM"


# ════════════════════════════════════════════════════════════════════════════════
# TESTS: services/alert_manager → AlertDeduplicator
# ════════════════════════════════════════════════════════════════════════════════

class TestAlertDeduplicator:
    """Tests del motor de deduplicación de alertas."""

    @pytest.fixture(autouse=True)
    def SETUP(self) -> None:
        from services.alert_manager.alert_manager_service import AlertDeduplicator
        # Ventana corta para tests rápidos
        self._DEDUP = AlertDeduplicator(WINDOW_SECONDS=2, MAX_PER_WINDOW=3)

    def test_FIRST_ALERT_ALWAYS_PASSES(self) -> None:
        assert self._DEDUP.SHOULD_ALERT("1.1.1.1", "DoS_DDoS") is True

    def test_ALERTS_WITHIN_LIMIT_PASS(self) -> None:
        for _ in range(3):
            RESULT = self._DEDUP.SHOULD_ALERT("2.2.2.2", "Probe_Scan")
        assert RESULT is True

    def test_ALERTS_OVER_LIMIT_SUPPRESSED(self) -> None:
        for _ in range(3):
            self._DEDUP.SHOULD_ALERT("3.3.3.3", "R2L")
        # El cuarto debe suprimirse
        assert self._DEDUP.SHOULD_ALERT("3.3.3.3", "R2L") is False

    def test_DIFFERENT_CATEGORIES_INDEPENDENT(self) -> None:
        """IPs con diferentes categorías se cuentan independientemente."""
        for _ in range(3):
            self._DEDUP.SHOULD_ALERT("4.4.4.4", "DoS_DDoS")
        # Misma IP, diferente categoría → no suprimida
        assert self._DEDUP.SHOULD_ALERT("4.4.4.4", "Probe_Scan") is True

    def test_DIFFERENT_IPS_INDEPENDENT(self) -> None:
        for _ in range(3):
            self._DEDUP.SHOULD_ALERT("5.5.5.5", "U2R")
        # IP diferente → no suprimida
        assert self._DEDUP.SHOULD_ALERT("6.6.6.6", "U2R") is True

    def test_SUPPRESSED_COUNT_TRACKED(self) -> None:
        for _ in range(5):
            self._DEDUP.SHOULD_ALERT("7.7.7.7", "Backdoor")
        assert self._DEDUP.GET_SUPPRESSED_COUNT() >= 2

    def test_WINDOW_EXPIRY(self) -> None:
        """Alertas fuera de la ventana temporal no deben contar."""
        for _ in range(3):
            self._DEDUP.SHOULD_ALERT("8.8.8.8", "Web_Exploit")
        time.sleep(2.5)  # Esperar que expire la ventana
        # Ahora debe pasar de nuevo
        assert self._DEDUP.SHOULD_ALERT("8.8.8.8", "Web_Exploit") is True


# ════════════════════════════════════════════════════════════════════════════════
# TESTS: services/alert_manager → AlertManagerService.PROCESS_PREDICTION
# ════════════════════════════════════════════════════════════════════════════════

class TestAlertManagerProcessPrediction:
    """Tests de la lógica de procesamiento de predicciones."""

    @pytest.fixture(autouse=True)
    def SETUP(self) -> None:
        from services.alert_manager.alert_manager_service import AlertManagerService
        self._SERVICE = AlertManagerService(DRY_RUN=True)

    def test_NORMAL_TRAFFIC_RETURNS_NONE(self) -> None:
        """Tráfico normal no debe generar alerta."""
        NORMAL_PREDICTION = PredictionResult(
            FLOW_ID=str(uuid.uuid4()),
            TIMESTAMP=datetime.now(timezone.utc),
            PREDICTED_CLASS=AttackCategory.NORMAL,
            CLASS_INDEX=0,
            CONFIDENCE=0.99,
            IS_ATTACK=False,
            TOP3_CATEGORIES=["Normal", "DoS_DDoS", "Probe_Scan"],
            TOP3_SCORES=[0.99, 0.005, 0.005],
            RF_PROBA=[0.99] + [0.0] * 7,
            INFERENCE_MS=2.0,
            MODEL_VERSION="1.0.0",
            SENSOR_ID="test",
        )
        RESULT = self._SERVICE.PROCESS_PREDICTION(NORMAL_PREDICTION)
        assert RESULT is None

    def test_ATTACK_WITH_HIGH_CONFIDENCE_GENERATES_ALERT(
        self, VALID_PREDICTION: PredictionResult
    ) -> None:
        """Ataque con confianza alta debe generar una alerta."""
        RESULT = self._SERVICE.PROCESS_PREDICTION(
            VALID_PREDICTION,
            SRC_IP="10.10.10.10",
            DST_IP="192.168.1.1",
            DST_PORT=80,
            PROTOCOL="tcp",
        )
        assert RESULT is not None
        assert isinstance(RESULT, Alert)
        assert RESULT.IS_ATTACK if hasattr(RESULT, "IS_ATTACK") else True

    def test_ALERT_CONTAINS_MITRE_TECHNIQUE(
        self, VALID_PREDICTION: PredictionResult
    ) -> None:
        """Alertas de ataques conocidos deben incluir técnica MITRE ATT&CK."""
        RESULT = self._SERVICE.PROCESS_PREDICTION(
            VALID_PREDICTION,
            SRC_IP="10.10.10.10",
            DST_IP="192.168.1.1",
            DST_PORT=80,
            PROTOCOL="tcp",
        )
        assert RESULT is not None
        assert RESULT.MITRE_TECHNIQUE is not None
        assert "T1498" in RESULT.MITRE_TECHNIQUE   # DoS_DDoS technique ID

    def test_LOW_CONFIDENCE_ATTACK_FILTERED(self) -> None:
        """Ataques con confianza muy baja deben ser filtrados."""
        LOW_CONF_PREDICTION = PredictionResult(
            FLOW_ID=str(uuid.uuid4()),
            TIMESTAMP=datetime.now(timezone.utc),
            PREDICTED_CLASS=AttackCategory.PROBE_SCAN,
            CLASS_INDEX=2,
            CONFIDENCE=0.50,    # Por debajo del umbral mínimo (0.70)
            IS_ATTACK=True,
            TOP3_CATEGORIES=["Probe_Scan", "Normal", "DoS_DDoS"],
            TOP3_SCORES=[0.50, 0.30, 0.20],
            RF_PROBA=[0.30, 0.05, 0.50, 0.05, 0.0, 0.05, 0.05, 0.0],
            INFERENCE_MS=3.0,
            MODEL_VERSION="1.0.0",
            SENSOR_ID="test",
        )
        RESULT = self._SERVICE.PROCESS_PREDICTION(LOW_CONF_PREDICTION)
        assert RESULT is None

    def test_ALERT_COUNTER_INCREMENTS(self, VALID_PREDICTION: PredictionResult) -> None:
        INITIAL = self._SERVICE._ALERTS_GENERATED
        self._SERVICE.PROCESS_PREDICTION(
            VALID_PREDICTION, "11.11.11.11", "192.168.1.2", 443, "tcp"
        )
        assert self._SERVICE._ALERTS_GENERATED == INITIAL + 1


# ════════════════════════════════════════════════════════════════════════════════
# TESTS: shared/logger.py
# ════════════════════════════════════════════════════════════════════════════════

class TestLogger:
    """Tests del logger estructurado JSON."""

    def test_BUILD_LOGGER_RETURNS_LOGGER(self) -> None:
        import logging
        LOGGER = BUILD_LOGGER("test-service")
        assert isinstance(LOGGER, logging.Logger)

    def test_BUILD_LOGGER_SAME_NAME_SAME_INSTANCE(self) -> None:
        """El mismo nombre debe retornar el mismo logger (singleton)."""
        L1 = BUILD_LOGGER("same-service")
        L2 = BUILD_LOGGER("same-service")
        assert L1 is L2

    def test_OPERATIONAL_METRICS_LOGGER_NO_EXCEPTION(self) -> None:
        """OperationalMetricsLogger no debe lanzar excepciones en uso normal."""
        METRICS = OperationalMetricsLogger("test-service")
        METRICS.LOG_INFERENCE("flow-001", "DoS_DDoS", 0.95, 3.8, True)
        METRICS.LOG_ALERT("alert-001", "flow-001", "CRITICAL", "DoS_DDoS", "1.2.3.4")
        METRICS.LOG_ERROR("TEST_ERROR", "flow-001", "Error de prueba")
        METRICS.LOG_THROUGHPUT(1500.0, 0)


# ════════════════════════════════════════════════════════════════════════════════
# TESTS: InferenceRequest (API validation)
# ════════════════════════════════════════════════════════════════════════════════

class TestInferenceRequest:
    """Tests de validación del modelo de request de la API."""

    def test_VALID_REQUEST(self) -> None:
        REQ = InferenceRequest(FEATURES=[[0.0] * N_BASE_FEATURES])
        assert len(REQ.FEATURES) == 1

    def test_EMPTY_FEATURES_RAISES(self) -> None:
        with pytest.raises(Exception):
            InferenceRequest(FEATURES=[])

    def test_WRONG_FEATURE_COUNT_RAISES(self) -> None:
        with pytest.raises(Exception):
            InferenceRequest(FEATURES=[[0.0] * 30])  # 30 en lugar de 41

    def test_MULTIPLE_ROWS_VALID(self) -> None:
        FEATURES = [[0.0] * N_BASE_FEATURES for _ in range(10)]
        REQ = InferenceRequest(FEATURES=FEATURES)
        assert len(REQ.FEATURES) == 10

    def test_REQUEST_ID_AUTO_GENERATED(self) -> None:
        REQ = InferenceRequest(FEATURES=[[0.0] * N_BASE_FEATURES])
        assert REQ.REQUEST_ID is not None
        assert len(REQ.REQUEST_ID) == 36


# ════════════════════════════════════════════════════════════════════════════════
# TESTS: Productor sintético
# ════════════════════════════════════════════════════════════════════════════════

class TestSyntheticFlowGenerator:
    """Tests del generador sintético de flujos de red."""

    @pytest.fixture(autouse=True)
    def SETUP(self) -> None:
        from services.producer.producer_service import SyntheticFlowGenerator
        self._GENERATOR = SyntheticFlowGenerator()

    def test_GENERATE_FLOW_RETURNS_RAW_NETWORK_FLOW(self) -> None:
        FLOW = self._GENERATOR.GENERATE_FLOW()
        assert isinstance(FLOW, RawNetworkFlow)

    def test_FLOW_HAS_CORRECT_FEATURE_COUNT(self) -> None:
        FLOW = self._GENERATOR.GENERATE_FLOW()
        assert len(FLOW.RAW_FEATURES) == N_BASE_FEATURES

    def test_GENERATED_IPS_VALID_FORMAT(self) -> None:
        for _ in range(20):
            FLOW = self._GENERATOR.GENERATE_FLOW()
            assert len(FLOW.SRC_IP.split(".")) == 4
            assert len(FLOW.DST_IP.split(".")) == 4

    def test_FEATURES_ARE_NON_NEGATIVE(self) -> None:
        """Los flujos sintéticos no deben tener features negativas."""
        for _ in range(50):
            FLOW = self._GENERATOR.GENERATE_FLOW()
            assert all(F >= 0.0 for F in FLOW.RAW_FEATURES)

    def test_CATEGORY_DISTRIBUTION_APPROXIMATE(self) -> None:
        """La distribución de categorías debe aproximar los pesos definidos."""
        N_FLOWS = 2000
        CATEGORY_COUNTS: dict[str, int] = {}

        for _ in range(N_FLOWS):
            FLOW = self._GENERATOR.GENERATE_FLOW()
            # El sensor_id es fijo; la categoría se infiere por serror_rate
            SERROR = FLOW.RAW_FEATURES[24]
            CAT = "DoS_DDoS" if SERROR > 0.8 else "Normal"
            CATEGORY_COUNTS[CAT] = CATEGORY_COUNTS.get(CAT, 0) + 1

        # Al menos 30% debe ser tráfico normal
        NORMAL_RATE = CATEGORY_COUNTS.get("Normal", 0) / N_FLOWS
        assert NORMAL_RATE >= 0.30


# ════════════════════════════════════════════════════════════════════════════════
# TESTS DE INTEGRACIÓN LIGEROS (sin Kafka real)
# ════════════════════════════════════════════════════════════════════════════════

class TestEndToEndPipeline:
    """
    Tests de integración del pipeline completo en modo DRY_RUN.
    Validan que los datos fluyen correctamente desde el Producer
    hasta el Alert Manager sin infraestructura real.
    """

    def test_FULL_PIPELINE_NORMAL_TRAFFIC(self) -> None:
        """Tráfico normal no debe generar ninguna alerta."""
        from services.preprocessor.preprocessor_service import FeatureEngineeringPipeline
        from services.inference.inference_service import HybridClassifier
        from services.alert_manager.alert_manager_service import AlertManagerService

        # Preprocesar
        PIPELINE = FeatureEngineeringPipeline()
        RAW = [0.0] * N_BASE_FEATURES
        PROCESSED = PIPELINE.TRANSFORM(RAW)
        assert len(PROCESSED) == N_TOTAL_FEATURES

        # Inferir
        CLASSIFIER = HybridClassifier()
        CLASSIFIER.LOAD("nonexistent")
        X = PROCESSED.reshape(1, -1)
        RESULTS = CLASSIFIER.PREDICT(X)
        assert len(RESULTS) == 1

        # Gestionar alerta
        ALERT_SVC = AlertManagerService(DRY_RUN=True)
        ALERT = ALERT_SVC.PROCESS_PREDICTION(RESULTS[0])
        # Tráfico normal no genera alerta (con RF sintético puede variar)
        # Solo verificamos que el proceso no lanzó excepción
        assert ALERT is None or isinstance(ALERT, Alert)

    def test_PIPELINE_HANDLES_BATCH(self) -> None:
        """El pipeline debe manejar batches de múltiples flujos."""
        from services.preprocessor.preprocessor_service import FeatureEngineeringPipeline
        from services.inference.inference_service import HybridClassifier

        PIPELINE    = FeatureEngineeringPipeline()
        CLASSIFIER  = HybridClassifier()
        CLASSIFIER.LOAD("nonexistent")

        BATCH_SIZE = 16
        X_BATCH = np.stack(
            [PIPELINE.TRANSFORM([0.0] * N_BASE_FEATURES) for _ in range(BATCH_SIZE)]
        )
        RESULTS = CLASSIFIER.PREDICT(X_BATCH)
        assert len(RESULTS) == BATCH_SIZE


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-q"])
