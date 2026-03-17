"""
shared/logger.py
════════════════
Logger estructurado en formato JSON para producción enterprise.
Compatible con ELK Stack (Elasticsearch, Logstash, Kibana) y Datadog.

Uso:
    from shared.logger import BUILD_LOGGER
    LOG = BUILD_LOGGER("jeiguard-inference")
    LOG.info("Predicción completada", extra={"FLOW_ID": "abc", "LATENCY_MS": 3.8})
"""

import json
import logging
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Optional


class JsonFormatter(logging.Formatter):
    """
    Formateador de logs en JSON estructurado.
    Cada log incluye timestamp, nivel, servicio, mensaje y campos extra.
    """

    def __init__(self, SERVICE_NAME: str) -> None:
        super().__init__()
        self._SERVICE_NAME = SERVICE_NAME

    def format(self, RECORD: logging.LogRecord) -> str:
        LOG_ENTRY: dict[str, Any] = {
            "TIMESTAMP":   datetime.now(timezone.utc).isoformat(),
            "LEVEL":       RECORD.levelname,
            "SERVICE":     self._SERVICE_NAME,
            "MODULE":      RECORD.module,
            "FUNCTION":    RECORD.funcName,
            "LINE":        RECORD.lineno,
            "MESSAGE":     RECORD.getMessage(),
        }

        # Campos extra pasados con extra={...}
        RESERVED_KEYS = {
            "name", "msg", "args", "levelname", "levelno",
            "pathname", "filename", "module", "funcName",
            "lineno", "created", "msecs", "relativeCreated",
            "thread", "threadName", "processName", "process",
            "message", "exc_info", "exc_text", "stack_info",
        }
        for KEY, VALUE in RECORD.__dict__.items():
            if KEY not in RESERVED_KEYS:
                LOG_ENTRY[KEY] = VALUE

        if RECORD.exc_info:
            LOG_ENTRY["EXCEPTION"] = self.formatException(RECORD.exc_info)
            LOG_ENTRY["TRACEBACK"] = traceback.format_exc()

        return json.dumps(LOG_ENTRY, default=str, ensure_ascii=False)


def BUILD_LOGGER(
    SERVICE_NAME: str,
    LEVEL: int = logging.INFO,
    ENABLE_CONSOLE: bool = True,
) -> logging.Logger:
    """
    Construye un logger estructurado para un servicio.

    Args:
        SERVICE_NAME:    Nombre del microservicio (ej: "jeiguard-inference").
        LEVEL:           Nivel de logging (logging.INFO por defecto).
        ENABLE_CONSOLE:  Si emitir logs por stdout.

    Returns:
        Logger configurado con formato JSON estructurado.
    """
    LOGGER = logging.getLogger(SERVICE_NAME)
    LOGGER.setLevel(LEVEL)

    if LOGGER.handlers:
        return LOGGER

    if ENABLE_CONSOLE:
        HANDLER = logging.StreamHandler(sys.stdout)
        HANDLER.setFormatter(JsonFormatter(SERVICE_NAME))
        LOGGER.addHandler(HANDLER)

    LOGGER.propagate = False
    return LOGGER


class OperationalMetricsLogger:
    """
    Logger especializado para métricas operacionales del sistema IDS.
    Registra latencias, throughput y tasas de error por servicio.
    """

    def __init__(self, SERVICE_NAME: str) -> None:
        self._LOG = BUILD_LOGGER(f"{SERVICE_NAME}.metrics")
        self._SERVICE = SERVICE_NAME

    def LOG_INFERENCE(
        self,
        FLOW_ID: str,
        PREDICTED_CLASS: str,
        CONFIDENCE: float,
        LATENCY_MS: float,
        IS_ATTACK: bool,
    ) -> None:
        self._LOG.info(
            "Inferencia completada",
            extra={
                "EVENT_TYPE":      "INFERENCE",
                "FLOW_ID":         FLOW_ID,
                "PREDICTED_CLASS": PREDICTED_CLASS,
                "CONFIDENCE":      round(CONFIDENCE, 4),
                "LATENCY_MS":      round(LATENCY_MS, 3),
                "IS_ATTACK":       IS_ATTACK,
            },
        )

    def LOG_ALERT(
        self,
        ALERT_ID: str,
        FLOW_ID: str,
        ALERT_LEVEL: str,
        ATTACK_CATEGORY: str,
        SRC_IP: str,
    ) -> None:
        self._LOG.warning(
            "Alerta generada",
            extra={
                "EVENT_TYPE":      "ALERT",
                "ALERT_ID":        ALERT_ID,
                "FLOW_ID":         FLOW_ID,
                "ALERT_LEVEL":     ALERT_LEVEL,
                "ATTACK_CATEGORY": ATTACK_CATEGORY,
                "SRC_IP":          SRC_IP,
            },
        )

    def LOG_ERROR(
        self,
        EVENT_TYPE: str,
        FLOW_ID: Optional[str],
        ERROR_MESSAGE: str,
    ) -> None:
        self._LOG.error(
            "Error en procesamiento",
            extra={
                "EVENT_TYPE":    EVENT_TYPE,
                "FLOW_ID":       FLOW_ID or "UNKNOWN",
                "ERROR_MESSAGE": ERROR_MESSAGE,
            },
        )

    def LOG_THROUGHPUT(
        self,
        FLOWS_PER_SECOND: float,
        QUEUE_LAG: int,
    ) -> None:
        self._LOG.info(
            "Métricas de throughput",
            extra={
                "EVENT_TYPE":       "THROUGHPUT",
                "FLOWS_PER_SECOND": round(FLOWS_PER_SECOND, 2),
                "QUEUE_LAG":        QUEUE_LAG,
            },
        )
