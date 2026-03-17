"""
shared/models.py
════════════════
Modelos de dominio del sistema JeiGuard AI.
Define los contratos de datos entre servicios mediante Pydantic v2.

Todos los modelos son inmutables (frozen=True) para garantizar
consistencia en el pipeline de eventos.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ── Enumeraciones ─────────────────────────────────────────────────────────────

class AlertLevel(str, Enum):
    """Niveles de severidad de alerta del sistema IDS."""
    NONE     = "NONE"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class AttackCategory(str, Enum):
    """Categorías de ataque clasificadas por el modelo JeiGuard AI."""
    NORMAL      = "Normal"
    DOS_DDOS    = "DoS_DDoS"
    PROBE_SCAN  = "Probe_Scan"
    R2L         = "R2L"
    U2R         = "U2R"
    BACKDOOR    = "Backdoor"
    WEB_EXPLOIT = "Web_Exploit"
    CC_TRAFFIC  = "CC_Traffic"


class Protocol(str, Enum):
    """Protocolos de red soportados."""
    TCP  = "tcp"
    UDP  = "udp"
    ICMP = "icmp"


# ── Modelos de eventos Kafka ──────────────────────────────────────────────────

class RawNetworkFlow(BaseModel):
    """
    Flujo de red crudo capturado por el Producer.
    Publicado en: KAFKA_TOPIC_RAW_FLOWS
    """
    model_config = {"frozen": True}

    FLOW_ID:        str      = Field(default_factory=lambda: str(uuid.uuid4()))
    TIMESTAMP:      datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    SRC_IP:         str
    DST_IP:         str
    SRC_PORT:       int      = Field(ge=0, le=65535)
    DST_PORT:       int      = Field(ge=0, le=65535)
    PROTOCOL:       Protocol
    DURATION:       float    = Field(ge=0.0)
    SRC_BYTES:      int      = Field(ge=0)
    DST_BYTES:      int      = Field(ge=0)
    N_PACKETS:      int      = Field(ge=0)
    FLAGS:          str      = Field(default="")
    RAW_FEATURES:   list[float]
    SENSOR_ID:      str      = Field(default="default-sensor")

    @field_validator("RAW_FEATURES")
    @classmethod
    def validate_feature_length(cls, VALUE: list[float]) -> list[float]:
        """Valida que el vector de features tenga exactamente 41 elementos."""
        if len(VALUE) != 41:
            raise ValueError(
                f"RAW_FEATURES debe tener 41 elementos, recibidos: {len(VALUE)}"
            )
        return VALUE

    @field_validator("SRC_IP", "DST_IP")
    @classmethod
    def validate_ip_format(cls, VALUE: str) -> str:
        """Validación básica de formato IP."""
        PARTS = VALUE.split(".")
        if len(PARTS) != 4:
            raise ValueError(f"IP inválida: {VALUE}")
        return VALUE


class ProcessedFeatures(BaseModel):
    """
    Features procesadas y normalizadas por el Preprocessor.
    Publicado en: KAFKA_TOPIC_PROCESSED_FEATURES
    """
    model_config = {"frozen": True}

    FLOW_ID:            str
    TIMESTAMP:          datetime
    NORMALIZED_VECTOR:  list[float]
    N_FEATURES:         int
    SENSOR_ID:          str
    PREPROCESSING_MS:   float = Field(ge=0.0)

    @model_validator(mode="after")
    def validate_vector_length(self) -> "ProcessedFeatures":
        if len(self.NORMALIZED_VECTOR) != self.N_FEATURES:
            raise ValueError(
                f"NORMALIZED_VECTOR tiene {len(self.NORMALIZED_VECTOR)} "
                f"elementos pero N_FEATURES dice {self.N_FEATURES}"
            )
        return self


class PredictionResult(BaseModel):
    """
    Resultado de inferencia del modelo híbrido CNN+RF.
    Publicado en: KAFKA_TOPIC_PREDICTIONS
    """
    model_config = {"frozen": True}

    FLOW_ID:          str
    TIMESTAMP:        datetime
    PREDICTED_CLASS:  AttackCategory
    CLASS_INDEX:      int             = Field(ge=0)
    CONFIDENCE:       float           = Field(ge=0.0, le=1.0)
    IS_ATTACK:        bool
    TOP3_CATEGORIES:  list[str]
    TOP3_SCORES:      list[float]
    CNN_PROBA:        Optional[list[float]] = None
    RF_PROBA:         list[float]
    INFERENCE_MS:     float           = Field(ge=0.0)
    MODEL_VERSION:    str
    SENSOR_ID:        str

    @model_validator(mode="after")
    def validate_top3_consistency(self) -> "PredictionResult":
        if len(self.TOP3_CATEGORIES) != 3 or len(self.TOP3_SCORES) != 3:
            raise ValueError("TOP3_CATEGORIES y TOP3_SCORES deben tener 3 elementos.")
        return self


class Alert(BaseModel):
    """
    Alerta generada por el Alert Manager.
    Publicado en: KAFKA_TOPIC_ALERTS e indexado en Elasticsearch.
    """
    model_config = {"frozen": True}

    ALERT_ID:         str      = Field(default_factory=lambda: str(uuid.uuid4()))
    FLOW_ID:          str
    TIMESTAMP:        datetime
    ALERT_LEVEL:      AlertLevel
    ATTACK_CATEGORY:  AttackCategory
    CONFIDENCE:       float    = Field(ge=0.0, le=1.0)
    SRC_IP:           str
    DST_IP:           str
    DST_PORT:         int
    PROTOCOL:         str
    SENSOR_ID:        str
    DESCRIPTION:      str
    RECOMMENDED_ACTION: str
    MITRE_TECHNIQUE:  Optional[str] = None
    FALSE_POSITIVE_PROBABILITY: float = Field(ge=0.0, le=1.0, default=0.0)


# ── Modelos de la API REST ────────────────────────────────────────────────────

class InferenceRequest(BaseModel):
    """Cuerpo de solicitud al endpoint POST /api/v1/predict."""
    FEATURES:     list[list[float]]
    SENSOR_ID:    str = Field(default="api-direct")
    REQUEST_ID:   str = Field(default_factory=lambda: str(uuid.uuid4()))

    @field_validator("FEATURES")
    @classmethod
    def validate_features_matrix(cls, VALUE: list[list[float]]) -> list[list[float]]:
        if not VALUE:
            raise ValueError("FEATURES no puede estar vacío.")
        for ROW in VALUE:
            if len(ROW) != 41:
                raise ValueError(
                    f"Cada fila debe tener 41 features, encontrado: {len(ROW)}"
                )
        return VALUE


class InferenceResponse(BaseModel):
    """Respuesta del endpoint POST /api/v1/predict."""
    REQUEST_ID:   str
    PREDICTIONS:  list[str]
    CONFIDENCES:  list[float]
    IS_ATTACK:    list[bool]
    ALERT_LEVELS: list[str]
    TOP3:         list[dict]
    LATENCY_MS:   float
    MODEL_VERSION: str
    N_SAMPLES:    int


class HealthResponse(BaseModel):
    """Respuesta del endpoint GET /health."""
    STATUS:        str
    SERVICE:       str
    VERSION:       str
    MODEL_LOADED:  bool
    UPTIME_S:      float
    KAFKA_HEALTHY: bool
    TIMESTAMP:     datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MetricsSnapshot(BaseModel):
    """Snapshot de métricas operacionales del servicio."""
    TIMESTAMP:            datetime
    SERVICE:              str
    REQUESTS_TOTAL:       int      = Field(ge=0)
    REQUESTS_PER_SECOND:  float    = Field(ge=0.0)
    LATENCY_P50_MS:       float    = Field(ge=0.0)
    LATENCY_P95_MS:       float    = Field(ge=0.0)
    LATENCY_P99_MS:       float    = Field(ge=0.0)
    ERRORS_TOTAL:         int      = Field(ge=0)
    ALERTS_GENERATED:     int      = Field(ge=0)
    FALSE_POSITIVE_RATE:  float    = Field(ge=0.0, le=1.0)
