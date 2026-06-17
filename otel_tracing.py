"""
otel_tracing.py
════════════════
OpenTelemetry — Observabilidad Distribuida para JeiGuard AI.

Instrumenta todo el pipeline con trazas distribuidas:
  Producer → Preprocessor → Inference → Alert Manager → SOAR → LLM Analyst

Señales exportadas:
  • Trazas   → Jaeger (OTLP gRPC port 4317)
  • Métricas → Prometheus (port 8888) / OTLP
  • Logs     → stdout (JSON) integrado con ELK Stack

Convenciones de nombres OpenTelemetry:
  • Servicios: jeiguard.{nombre_servicio}
  • Spans:     {verbo}.{recurso} (ej: kafka.consume, model.infer, alert.create)
  • Atributos: snake_case con namespacing (jeiguard.*)
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from functools import wraps
from typing import Any, Callable, Generator, Optional

# ── Imports condicionales — OpenTelemetry es opcional ────────────────────────

try:
    from opentelemetry import metrics, trace
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.semconv.trace import SpanAttributes
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False

# ── Configuración ─────────────────────────────────────────────────────────────

SERVICE_NAME:    str = os.getenv("OTEL_SERVICE_NAME",    "jeiguard-ai")
SERVICE_VERSION: str = os.getenv("OTEL_SERVICE_VERSION", "2.0.0")
OTLP_ENDPOINT:   str = os.getenv("OTLP_ENDPOINT",        "http://jaeger:4317")
JAEGER_HOST:     str = os.getenv("JAEGER_AGENT_HOST",    "localhost")
JAEGER_PORT:     int = int(os.getenv("JAEGER_AGENT_PORT", "6831"))
OTEL_ENABLED:    bool = os.getenv("OTEL_ENABLED", "true").lower() == "true"

# ── Globals — instancias de tracer y meter ────────────────────────────────────

_tracer: Optional[Any] = None
_meter:  Optional[Any] = None


class _NoopSpan:
    """Span no-op para cuando OTEL no está disponible."""

    def __enter__(self) -> "_NoopSpan":
        return self

    def __exit__(self, *ARGS: Any) -> None:
        pass

    def set_attribute(self, *ARGS: Any) -> None:
        pass

    def set_status(self, *ARGS: Any) -> None:
        pass

    def record_exception(self, *ARGS: Any) -> None:
        pass

    def add_event(self, *ARGS: Any) -> None:
        pass


class _NoopTracer:
    def start_as_current_span(self, NAME: str, **KWARGS: Any) -> Any:
        return _NoopSpan()

    def start_span(self, NAME: str, **KWARGS: Any) -> Any:
        return _NoopSpan()


class _NoopCounter:
    def add(self, AMOUNT: float, ATTRS: Optional[dict] = None) -> None:
        pass


class _NoopHistogram:
    def record(self, AMOUNT: float, ATTRS: Optional[dict] = None) -> None:
        pass


class _NoopMeter:
    def create_counter(self, *ARGS: Any, **KWARGS: Any) -> _NoopCounter:
        return _NoopCounter()

    def create_histogram(self, *ARGS: Any, **KWARGS: Any) -> _NoopHistogram:
        return _NoopHistogram()

    def create_up_down_counter(self, *ARGS: Any, **KWARGS: Any) -> _NoopCounter:
        return _NoopCounter()


# ── Inicialización ────────────────────────────────────────────────────────────


def setup_telemetry(APP: Optional[Any] = None) -> None:
    """Configura OpenTelemetry para la aplicación FastAPI."""
    global _tracer, _meter

    if not OTEL_AVAILABLE or not OTEL_ENABLED:
        _tracer = _NoopTracer()
        _meter  = _NoopMeter()
        return

    RESOURCE = Resource.create({
        "service.name":    SERVICE_NAME,
        "service.version": SERVICE_VERSION,
        "deployment.environment": os.getenv("ENVIRONMENT", "development"),
        "jeiguard.component": "api-gateway",
    })

    OTLP_EXPORTER = OTLPSpanExporter(endpoint=OTLP_ENDPOINT, insecure=True)
    TP = TracerProvider(resource=RESOURCE)
    TP.add_span_processor(BatchSpanProcessor(OTLP_EXPORTER))

    if os.getenv("OTEL_DEBUG_CONSOLE", "false").lower() == "true":
        TP.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(TP)
    _tracer = trace.get_tracer(SERVICE_NAME, SERVICE_VERSION)

    METRIC_READER = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=OTLP_ENDPOINT, insecure=True),
        export_interval_millis=10_000,
    )
    MP = MeterProvider(resource=RESOURCE, metric_readers=[METRIC_READER])
    metrics.set_meter_provider(MP)
    _meter = metrics.get_meter(SERVICE_NAME, SERVICE_VERSION)

    if APP is not None:
        FastAPIInstrumentor.instrument_app(APP)
        HTTPXClientInstrumentor().instrument()

    SQLAlchemyInstrumentor().instrument(enable_commenter=True)


def get_tracer() -> Any:
    """Retorna el tracer global (o noop si OTEL no está disponible)."""
    global _tracer
    if _tracer is None:
        _tracer = _NoopTracer()
    return _tracer


def get_meter() -> Any:
    """Retorna el meter global (o noop si OTEL no está disponible)."""
    global _meter
    if _meter is None:
        _meter = _NoopMeter()
    return _meter


# ── Métricas JeiGuard AI ──────────────────────────────────────────────────────


class JeiGuardMetrics:
    """Métricas instrumentadas del sistema IDS."""

    _instance: Optional["JeiGuardMetrics"] = None

    def __init__(self) -> None:
        METER = get_meter()

        self.flows_processed = METER.create_counter(
            name="jeiguard.flows.processed.total",
            description="Total de flujos de red procesados",
            unit="1",
        )
        self.alerts_generated = METER.create_counter(
            name="jeiguard.alerts.generated.total",
            description="Total de alertas generadas por nivel",
            unit="1",
        )
        self.inference_duration = METER.create_histogram(
            name="jeiguard.inference.duration.ms",
            description="Latencia de inferencia del modelo en milisegundos",
            unit="ms",
        )
        self.kafka_lag = METER.create_up_down_counter(
            name="jeiguard.kafka.consumer.lag",
            description="Lag del consumer Kafka por topic",
            unit="1",
        )
        self.active_users = METER.create_up_down_counter(
            name="jeiguard.auth.active_sessions",
            description="Sesiones de usuario activas",
            unit="1",
        )
        self.api_requests = METER.create_counter(
            name="jeiguard.api.requests.total",
            description="Total de requests HTTP a la API",
            unit="1",
        )
        self.model_accuracy = METER.create_histogram(
            name="jeiguard.model.accuracy",
            description="Precisión del modelo medida en evaluaciones periódicas",
            unit="1",
        )
        self.false_positives = METER.create_counter(
            name="jeiguard.alerts.false_positives.total",
            description="Total de falsos positivos confirmados",
            unit="1",
        )
        self.soar_actions = METER.create_counter(
            name="jeiguard.soar.actions.total",
            description="Total de acciones de respuesta automatizadas ejecutadas",
            unit="1",
        )

    @classmethod
    def instance(cls) -> "JeiGuardMetrics":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def record_flow(self, SENSOR_ID: str, CATEGORY: str) -> None:
        self.flows_processed.add(1, {
            "sensor_id":       SENSOR_ID,
            "attack_category": CATEGORY,
        })

    def record_alert(self, LEVEL: str, CATEGORY: str, SENSOR_ID: str) -> None:
        self.alerts_generated.add(1, {
            "alert_level":     LEVEL,
            "attack_category": CATEGORY,
            "sensor_id":       SENSOR_ID,
        })

    def record_inference(self, LATENCY_MS: float, MODEL_TYPE: str, BATCH_SIZE: int) -> None:
        self.inference_duration.record(LATENCY_MS, {
            "model_type": MODEL_TYPE,
            "batch_size": str(BATCH_SIZE),
        })

    def record_false_positive(self, CATEGORY: str, SENSOR_ID: str) -> None:
        self.false_positives.add(1, {
            "attack_category": CATEGORY,
            "sensor_id":       SENSOR_ID,
        })

    def record_soar_action(self, ACTION_TYPE: str, SUCCESS: bool) -> None:
        self.soar_actions.add(1, {
            "action_type": ACTION_TYPE,
            "success":     str(SUCCESS),
        })


# ── Decoradores de trazado ────────────────────────────────────────────────────


def trace_span(SPAN_NAME: str, ATTRS: Optional[dict[str, Any]] = None) -> Callable:
    """Decorador que envuelve una función en un span OpenTelemetry."""
    def _decorator(FUNC: Callable) -> Callable:
        @wraps(FUNC)
        async def _async_wrapper(*ARGS: Any, **KWARGS: Any) -> Any:
            TRACER = get_tracer()
            with TRACER.start_as_current_span(SPAN_NAME) as SPAN:
                if ATTRS:
                    for K, V in ATTRS.items():
                        SPAN.set_attribute(K, str(V))
                START = time.perf_counter()
                try:
                    RESULT = await FUNC(*ARGS, **KWARGS)
                    SPAN.set_attribute("jeiguard.duration_ms", round((time.perf_counter() - START) * 1000, 2))
                    return RESULT
                except Exception as EXC:
                    SPAN.record_exception(EXC)
                    if OTEL_AVAILABLE:
                        SPAN.set_status(trace.Status(trace.StatusCode.ERROR, str(EXC)))
                    raise

        @wraps(FUNC)
        def _sync_wrapper(*ARGS: Any, **KWARGS: Any) -> Any:
            TRACER = get_tracer()
            with TRACER.start_as_current_span(SPAN_NAME) as SPAN:
                if ATTRS:
                    for K, V in ATTRS.items():
                        SPAN.set_attribute(K, str(V))
                START = time.perf_counter()
                try:
                    RESULT = FUNC(*ARGS, **KWARGS)
                    SPAN.set_attribute("jeiguard.duration_ms", round((time.perf_counter() - START) * 1000, 2))
                    return RESULT
                except Exception as EXC:
                    SPAN.record_exception(EXC)
                    if OTEL_AVAILABLE:
                        SPAN.set_status(trace.Status(trace.StatusCode.ERROR, str(EXC)))
                    raise

        import asyncio
        if asyncio.iscoroutinefunction(FUNC):
            return _async_wrapper
        return _sync_wrapper
    return _decorator


@contextmanager
def create_span(
    NAME: str,
    ATTRS: Optional[dict[str, Any]] = None,
) -> Generator[Any, None, None]:
    """Context manager para crear un span OpenTelemetry manualmente."""
    TRACER = get_tracer()
    with TRACER.start_as_current_span(NAME) as SPAN:
        if ATTRS:
            for K, V in ATTRS.items():
                SPAN.set_attribute(K, str(V))
        try:
            yield SPAN
        except Exception as EXC:
            SPAN.record_exception(EXC)
            if OTEL_AVAILABLE:
                SPAN.set_status(trace.Status(trace.StatusCode.ERROR, str(EXC)))
            raise


# ── Spans predefinidos del pipeline IDS ──────────────────────────────────────


def span_kafka_produce(TOPIC: str, FLOW_ID: str) -> Any:
    return create_span("kafka.produce", {"kafka.topic": TOPIC, "jeiguard.flow_id": FLOW_ID})


def span_kafka_consume(TOPIC: str, GROUP_ID: str) -> Any:
    return create_span("kafka.consume", {"kafka.topic": TOPIC, "kafka.consumer_group": GROUP_ID})


def span_preprocess(FLOW_ID: str, N_FEATURES: int) -> Any:
    return create_span("preprocess.features", {
        "jeiguard.flow_id":  FLOW_ID,
        "jeiguard.n_features": N_FEATURES,
    })


def span_model_inference(FLOW_ID: str, BATCH_SIZE: int, MODEL_TYPE: str) -> Any:
    return create_span("model.infer", {
        "jeiguard.flow_id":   FLOW_ID,
        "jeiguard.batch_size": BATCH_SIZE,
        "jeiguard.model_type": MODEL_TYPE,
    })


def span_alert_create(ALERT_ID: str, LEVEL: str) -> Any:
    return create_span("alert.create", {
        "jeiguard.alert_id":    ALERT_ID,
        "jeiguard.alert_level": LEVEL,
    })


def span_soar_action(ACTION_TYPE: str, DRY_RUN: bool = False) -> Any:
    return create_span("soar.action", {
        "jeiguard.action_type": ACTION_TYPE,
        "jeiguard.dry_run":     DRY_RUN,
    })


def span_llm_analysis(N_ALERTS: int) -> Any:
    return create_span("llm.analyze", {"jeiguard.n_alerts": N_ALERTS})
