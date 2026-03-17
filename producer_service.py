"""
services/producer/producer_service.py
══════════════════════════════════════
Servicio Producer — JeiGuard AI
══════════════════════════════════════
Responsabilidad única: capturar flujos de red (real o simulado)
y publicarlos en el topic Kafka KAFKA_TOPIC_RAW_FLOWS.

Este servicio es el único con acceso directo a la interfaz de red.
El resto de servicios solo consumen de Kafka → total desacoplamiento.

Modos de operación:
  MODE_LIVE:      Captura real con Scapy/libpcap (requiere privilegios root)
  MODE_SYNTHETIC: Genera flujos sintéticos para demo/test
  MODE_FILE:      Reproduce tráfico desde archivo .pcap
"""

from __future__ import annotations

import json
import os
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Generator, Optional

# Importaciones del proyecto
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from shared.constants import (
    ATTACK_CATEGORIES,
    KAFKA_TOPIC_RAW_FLOWS,
    N_BASE_FEATURES,
)
from shared.logger import BUILD_LOGGER, OperationalMetricsLogger
from shared.models import Protocol, RawNetworkFlow

# ── Logger ────────────────────────────────────────────────────────────────────
LOG = BUILD_LOGGER("jeiguard-producer")
METRICS_LOG = OperationalMetricsLogger("jeiguard-producer")

# ── Constantes del servicio ───────────────────────────────────────────────────
MODE_LIVE:      str = "live"
MODE_SYNTHETIC: str = "synthetic"
MODE_FILE:      str = "file"

DEFAULT_FLOWS_PER_SECOND: int   = 1000
KAFKA_LINGER_MS:          int   = 5
KAFKA_BATCH_SIZE_BYTES:   int   = 65536
METRICS_INTERVAL_S:       float = 10.0


# ── Generador sintético de flujos ─────────────────────────────────────────────

@dataclass
class FlowProfile:
    """Perfil estadístico de un tipo de tráfico para generación sintética."""
    CATEGORY:         str
    DURATION_MEAN:    float
    DURATION_STD:     float
    SRC_BYTES_MEAN:   float
    SRC_BYTES_STD:    float
    DST_BYTES_MEAN:   float
    DST_BYTES_STD:    float
    COUNT_MEAN:       float
    SERROR_RATE_MEAN: float
    SAME_SRV_RATE:    float
    WEIGHT:           float     # Proporción en el tráfico total


FLOW_PROFILES: tuple[FlowProfile, ...] = (
    FlowProfile("Normal",      2.0, 1.5, 1200.0, 800.0, 900.0, 600.0, 10.0, 0.02, 0.90, 0.53),
    FlowProfile("DoS_DDoS",    0.0, 0.0,   20.0,  10.0,   0.0,   0.0,500.0, 0.98, 1.00, 0.23),
    FlowProfile("Probe_Scan",  0.3, 0.2,  100.0,  50.0, 100.0,  50.0, 60.0, 0.10, 0.20, 0.12),
    FlowProfile("R2L",         5.0, 3.0,  400.0, 200.0, 300.0, 150.0,  3.0, 0.05, 0.60, 0.05),
    FlowProfile("U2R",        10.0, 5.0,  800.0, 400.0, 600.0, 300.0,  2.0, 0.03, 0.50, 0.01),
    FlowProfile("Backdoor",    8.0, 4.0,  600.0, 300.0, 400.0, 200.0,  4.0, 0.04, 0.55, 0.02),
    FlowProfile("Web_Exploit", 1.5, 0.8,  500.0, 250.0, 700.0, 350.0,  5.0, 0.06, 0.40, 0.03),
    FlowProfile("CC_Traffic",  3.0, 1.5,  200.0, 100.0, 150.0,  75.0, 30.0, 0.08, 0.30, 0.01),
)

PROFILE_WEIGHTS: tuple[float, ...] = tuple(P.WEIGHT for P in FLOW_PROFILES)


class SyntheticFlowGenerator:
    """
    Genera flujos de red sintéticos con distribuciones estadísticas
    que aproximan el comportamiento real de tráfico de red.

    Útil para:
      - Demo sin hardware de red
      - Tests de integración
      - Benchmarking del pipeline
    """

    def __init__(self, SENSOR_ID: str = "synthetic-sensor-01") -> None:
        self._SENSOR_ID = SENSOR_ID
        self._PRIVATE_SUBNETS: tuple[str, ...] = (
            "192.168.1.", "10.0.0.", "172.16.0.", "192.168.100."
        )
        self._COMMON_PORTS: tuple[int, ...] = (
            80, 443, 22, 3389, 8080, 53, 25, 110, 3306, 5432
        )

    def _RANDOM_IP(self, INTERNAL: bool = True) -> str:
        """Genera una IP aleatoria interna o externa."""
        if INTERNAL:
            SUBNET = random.choice(self._PRIVATE_SUBNETS)
            return f"{SUBNET}{random.randint(1, 254)}"
        return (
            f"{random.randint(1, 223)}."
            f"{random.randint(0, 255)}."
            f"{random.randint(0, 255)}."
            f"{random.randint(1, 254)}"
        )

    def _BUILD_FEATURE_VECTOR(self, PROFILE: FlowProfile) -> list[float]:
        """Construye el vector de 41 features a partir del perfil de tráfico."""
        DURATION = max(0.0, random.gauss(PROFILE.DURATION_MEAN, PROFILE.DURATION_STD))
        SRC_BYTES = max(0.0, random.gauss(PROFILE.SRC_BYTES_MEAN, PROFILE.SRC_BYTES_STD))
        DST_BYTES = max(0.0, random.gauss(PROFILE.DST_BYTES_MEAN, PROFILE.DST_BYTES_STD))
        COUNT = max(1.0, random.gauss(PROFILE.COUNT_MEAN, PROFILE.COUNT_MEAN * 0.2))
        SERROR = min(1.0, max(0.0, random.gauss(PROFILE.SERROR_RATE_MEAN, 0.05)))
        SAME_SRV = min(1.0, max(0.0, random.gauss(PROFILE.SAME_SRV_RATE, 0.10)))

        VECTOR: list[float] = [0.0] * N_BASE_FEATURES
        VECTOR[0]  = DURATION
        VECTOR[4]  = SRC_BYTES
        VECTOR[5]  = DST_BYTES
        VECTOR[9]  = random.randint(0, 5) if PROFILE.CATEGORY in ("U2R", "R2L") else 0.0
        VECTOR[10] = random.randint(0, 8) if PROFILE.CATEGORY == "R2L" else 0.0
        VECTOR[11] = 1.0 if PROFILE.CATEGORY == "Normal" else 0.0
        VECTOR[13] = 1.0 if PROFILE.CATEGORY == "U2R" and random.random() < 0.3 else 0.0
        VECTOR[15] = random.randint(0, 4) if PROFILE.CATEGORY == "U2R" else 0.0
        VECTOR[22] = COUNT
        VECTOR[23] = COUNT * SAME_SRV
        VECTOR[24] = SERROR
        VECTOR[25] = SERROR * 0.9
        VECTOR[26] = random.uniform(0.0, 0.2)
        VECTOR[28] = SAME_SRV
        VECTOR[29] = 1.0 - SAME_SRV
        VECTOR[31] = random.randint(1, 255)
        VECTOR[32] = max(1, int(COUNT * SAME_SRV * 0.5))

        # Añadir ruido gaussiano para realismo
        NOISE = [random.gauss(0, 0.05) for _ in range(N_BASE_FEATURES)]
        return [max(0.0, V + N) for V, N in zip(VECTOR, NOISE)]

    def GENERATE_FLOW(self) -> RawNetworkFlow:
        """Genera un único flujo de red sintético."""
        PROFILE = random.choices(FLOW_PROFILES, weights=PROFILE_WEIGHTS, k=1)[0]

        return RawNetworkFlow(
            FLOW_ID=str(uuid.uuid4()),
            TIMESTAMP=datetime.now(timezone.utc),
            SRC_IP=self._RANDOM_IP(INTERNAL=PROFILE.CATEGORY == "Normal"),
            DST_IP=self._RANDOM_IP(INTERNAL=True),
            SRC_PORT=random.randint(1024, 65535),
            DST_PORT=random.choice(self._COMMON_PORTS),
            PROTOCOL=random.choice(list(Protocol)),
            DURATION=max(0.0, random.gauss(PROFILE.DURATION_MEAN, PROFILE.DURATION_STD)),
            SRC_BYTES=int(max(0, random.gauss(PROFILE.SRC_BYTES_MEAN, PROFILE.SRC_BYTES_STD))),
            DST_BYTES=int(max(0, random.gauss(PROFILE.DST_BYTES_MEAN, PROFILE.DST_BYTES_STD))),
            N_PACKETS=random.randint(1, 100),
            FLAGS="SYN" if PROFILE.CATEGORY == "DoS_DDoS" else "ACK",
            RAW_FEATURES=self._BUILD_FEATURE_VECTOR(PROFILE),
            SENSOR_ID=self._SENSOR_ID,
        )

    def STREAM(self, FLOWS_PER_SECOND: int = 100) -> Generator[RawNetworkFlow, None, None]:
        """Genera un stream continuo de flujos a la tasa especificada."""
        INTERVAL = 1.0 / FLOWS_PER_SECOND
        while True:
            yield self.GENERATE_FLOW()
            time.sleep(INTERVAL)


# ── Kafka Producer ────────────────────────────────────────────────────────────

class KafkaFlowProducer:
    """
    Producer Kafka para publicación de flujos de red.
    Implementa serialización JSON, manejo de errores y métricas.

    En producción usa confluent-kafka. En modo test/demo,
    simula el comportamiento sin conexión real a Kafka.
    """

    def __init__(
        self,
        BOOTSTRAP_SERVERS: str,
        TOPIC: str = KAFKA_TOPIC_RAW_FLOWS,
        DRY_RUN: bool = False,
    ) -> None:
        self._BOOTSTRAP_SERVERS = BOOTSTRAP_SERVERS
        self._TOPIC = TOPIC
        self._DRY_RUN = DRY_RUN
        self._PRODUCER = None
        self._PUBLISHED_COUNT: int = 0
        self._ERROR_COUNT: int = 0
        self._START_TIME: float = time.time()

        if not DRY_RUN:
            self._INIT_KAFKA()

        LOG.info(
            "KafkaFlowProducer inicializado",
            extra={
                "BOOTSTRAP_SERVERS": BOOTSTRAP_SERVERS,
                "TOPIC":             TOPIC,
                "DRY_RUN":           DRY_RUN,
            },
        )

    def _INIT_KAFKA(self) -> None:
        """Inicializa el cliente Kafka con configuración optimizada para throughput."""
        try:
            from confluent_kafka import Producer as ConfluentProducer

            KAFKA_CONFIG: dict = {
                "bootstrap.servers":  self._BOOTSTRAP_SERVERS,
                "linger.ms":          KAFKA_LINGER_MS,
                "batch.size":         KAFKA_BATCH_SIZE_BYTES,
                "compression.type":   "lz4",
                "acks":               "1",           # balance velocidad/durabilidad
                "retries":            5,
                "retry.backoff.ms":   200,
            }
            self._PRODUCER = ConfluentProducer(KAFKA_CONFIG)
            LOG.info("Conexión Kafka establecida", extra={"CONFIG": KAFKA_CONFIG})

        except ImportError:
            LOG.warning("confluent-kafka no instalado. Activando modo DRY_RUN.")
            self._DRY_RUN = True

    def _DELIVERY_CALLBACK(self, ERROR: Optional[Exception], MSG: object) -> None:
        """Callback de confirmación de entrega por parte de Kafka."""
        if ERROR:
            self._ERROR_COUNT += 1
            LOG.error(
                "Error de entrega Kafka",
                extra={"KAFKA_ERROR": str(ERROR), "TOPIC": self._TOPIC},
            )

    def PUBLISH(self, FLOW: RawNetworkFlow) -> bool:
        """
        Publica un flujo de red en el topic Kafka.

        Args:
            FLOW: Flujo de red validado a publicar.

        Returns:
            True si la publicación fue exitosa, False en caso contrario.
        """
        try:
            PAYLOAD = FLOW.model_dump_json().encode("utf-8")

            if self._DRY_RUN:
                # Modo demo: simular publicación exitosa
                self._PUBLISHED_COUNT += 1
                if self._PUBLISHED_COUNT % 500 == 0:
                    ELAPSED = time.time() - self._START_TIME
                    RATE = self._PUBLISHED_COUNT / ELAPSED
                    METRICS_LOG.LOG_THROUGHPUT(RATE, 0)
                return True

            self._PRODUCER.produce(
                topic=self._TOPIC,
                key=FLOW.FLOW_ID.encode("utf-8"),
                value=PAYLOAD,
                callback=self._DELIVERY_CALLBACK,
            )
            self._PRODUCER.poll(0)  # Non-blocking: procesar callbacks pendientes
            self._PUBLISHED_COUNT += 1
            return True

        except Exception as EXC:
            self._ERROR_COUNT += 1
            METRICS_LOG.LOG_ERROR("PUBLISH_ERROR", FLOW.FLOW_ID, str(EXC))
            return False

    def FLUSH(self, TIMEOUT_S: float = 10.0) -> None:
        """Espera a que todos los mensajes pendientes sean entregados."""
        if self._PRODUCER and not self._DRY_RUN:
            self._PRODUCER.flush(TIMEOUT_S)

    def GET_STATS(self) -> dict:
        """Retorna estadísticas de publicación del producer."""
        ELAPSED = max(time.time() - self._START_TIME, 0.001)
        return {
            "PUBLISHED_TOTAL":   self._PUBLISHED_COUNT,
            "ERROR_TOTAL":       self._ERROR_COUNT,
            "FLOWS_PER_SECOND":  round(self._PUBLISHED_COUNT / ELAPSED, 2),
            "ERROR_RATE":        round(self._ERROR_COUNT / max(self._PUBLISHED_COUNT, 1), 4),
            "UPTIME_S":          round(ELAPSED, 1),
        }

    def __del__(self) -> None:
        self.FLUSH()


# ── Entrypoint del servicio ───────────────────────────────────────────────────

class ProducerService:
    """
    Servicio completo de captura y publicación de tráfico de red.
    Orquesta el generador de flujos y el producer Kafka.
    """

    def __init__(
        self,
        BOOTSTRAP_SERVERS: str   = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092"),
        MODE: str                = os.getenv("PRODUCER_MODE", MODE_SYNTHETIC),
        FLOWS_PER_SECOND: int    = int(os.getenv("FLOWS_PER_SECOND", "1000")),
        SENSOR_ID: str           = os.getenv("SENSOR_ID", "sensor-01"),
        DRY_RUN: bool            = os.getenv("DRY_RUN", "false").lower() == "true",
    ) -> None:
        self._MODE = MODE
        self._FLOWS_PER_SECOND = FLOWS_PER_SECOND
        self._SENSOR_ID = SENSOR_ID
        self._RUNNING = False

        self._GENERATOR = SyntheticFlowGenerator(SENSOR_ID=SENSOR_ID)
        self._PRODUCER = KafkaFlowProducer(
            BOOTSTRAP_SERVERS=BOOTSTRAP_SERVERS,
            DRY_RUN=DRY_RUN,
        )

        LOG.info(
            "ProducerService inicializado",
            extra={
                "MODE":             MODE,
                "FLOWS_PER_SECOND": FLOWS_PER_SECOND,
                "SENSOR_ID":        SENSOR_ID,
            },
        )

    def RUN(self) -> None:
        """Inicia el loop principal del servicio producer."""
        self._RUNNING = True
        LOG.info("ProducerService iniciado", extra={"MODE": self._MODE})

        LAST_METRICS_TIME = time.time()

        try:
            for FLOW in self._GENERATOR.STREAM(self._FLOWS_PER_SECOND):
                if not self._RUNNING:
                    break

                self._PRODUCER.PUBLISH(FLOW)

                # Reportar métricas cada METRICS_INTERVAL_S segundos
                NOW = time.time()
                if NOW - LAST_METRICS_TIME >= METRICS_INTERVAL_S:
                    STATS = self._PRODUCER.GET_STATS()
                    METRICS_LOG.LOG_THROUGHPUT(
                        STATS["FLOWS_PER_SECOND"],
                        0,
                    )
                    LAST_METRICS_TIME = NOW

        except KeyboardInterrupt:
            LOG.info("ProducerService detenido por el usuario.")
        finally:
            self._PRODUCER.FLUSH()
            FINAL_STATS = self._PRODUCER.GET_STATS()
            LOG.info("Estadísticas finales", extra=FINAL_STATS)

    def STOP(self) -> None:
        """Detiene el servicio de forma ordenada (graceful shutdown)."""
        self._RUNNING = False
        LOG.info("ProducerService: señal de parada recibida.")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SERVICE = ProducerService()
    SERVICE.RUN()
