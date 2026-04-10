"""
JeiGuard AI v1.0.2 — Mejora 2: SIEM Correlation Engine
Detecta campañas de ataque multi-etapa correlacionando eventos en el tiempo.
Copyright © 2026 Jeiner Tello Nuñez — MIT License
"""
from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Constantes ─────────────────────────────────────────────────────────────────
CORRELATION_WINDOW_S   = 300       # 5 minutos ventana de correlación
CAMPAIGN_THRESHOLD     = 3         # mín. alertas para declarar campaña
MAX_EVENTS_PER_IP      = 1000      # buffer circular por IP
KILL_CHAIN_DECAY_S     = 600       # 10 min para resetear kill chain
SERVICE_VERSION        = "1.0.2"


class KillChainStage(str, Enum):
    RECONNAISSANCE   = "Reconnaissance"
    WEAPONIZATION    = "Weaponization"
    DELIVERY         = "Delivery"
    EXPLOITATION     = "Exploitation"
    INSTALLATION     = "Installation"
    COMMAND_CONTROL  = "Command & Control"
    ACTIONS          = "Actions on Objectives"


# Mapa de categoría IDS → etapa del kill chain
CATEGORY_TO_KILLCHAIN: dict[str, KillChainStage] = {
    "Probe_Scan":  KillChainStage.RECONNAISSANCE,
    "R2L":         KillChainStage.DELIVERY,
    "Web_Exploit": KillChainStage.EXPLOITATION,
    "U2R":         KillChainStage.INSTALLATION,
    "Backdoor":    KillChainStage.INSTALLATION,
    "CC_Traffic":  KillChainStage.COMMAND_CONTROL,
    "DoS_DDoS":    KillChainStage.ACTIONS,
}

# Secuencias de ataque conocidas (patrones APT)
ATTACK_PATTERNS = [
    {
        "name":     "APT Lateral Movement",
        "sequence": ["Probe_Scan", "R2L", "U2R"],
        "risk":     95,
        "desc":     "Reconocimiento seguido de fuerza bruta y escalada de privilegios — patrón APT clásico",
    },
    {
        "name":     "Web Application Attack",
        "sequence": ["Probe_Scan", "Web_Exploit", "Backdoor"],
        "risk":     90,
        "desc":     "Escaneo de vulnerabilidades web, explotación y establecimiento de persistencia",
    },
    {
        "name":     "Ransomware Campaign",
        "sequence": ["R2L", "U2R", "CC_Traffic", "DoS_DDoS"],
        "risk":     98,
        "desc":     "Acceso inicial, escalada, contacto C2 y acción destructiva — patrón ransomware",
    },
    {
        "name":     "Data Exfiltration",
        "sequence": ["Probe_Scan", "Web_Exploit", "CC_Traffic"],
        "risk":     88,
        "desc":     "Reconocimiento, explotación web y exfiltración de datos via C2",
    },
    {
        "name":     "DDoS Preparation",
        "sequence": ["Probe_Scan", "DoS_DDoS"],
        "risk":     80,
        "desc":     "Escaneo de capacidad previo a ataque volumétrico",
    },
]

KILL_CHAIN_ORDER = [
    KillChainStage.RECONNAISSANCE,
    KillChainStage.WEAPONIZATION,
    KillChainStage.DELIVERY,
    KillChainStage.EXPLOITATION,
    KillChainStage.INSTALLATION,
    KillChainStage.COMMAND_CONTROL,
    KillChainStage.ACTIONS,
]


@dataclass
class SecurityEvent:
    event_id:   str
    timestamp:  float
    src_ip:     str
    dst_ip:     str
    category:   str
    confidence: float
    port:       int
    protocol:   str
    sensor_id:  str = "sensor-01"


@dataclass
class CorrelatedCampaign:
    campaign_id:     str
    pattern_name:    str
    description:     str
    src_ips:         list[str]
    dst_ips:         list[str]
    events:          list[SecurityEvent]
    kill_chain_stage: KillChainStage
    risk_score:      int
    start_time:      float
    last_seen:       float
    is_active:       bool = True
    recommended_actions: list[str] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return self.last_seen - self.start_time

    @property
    def progression_pct(self) -> int:
        idx = KILL_CHAIN_ORDER.index(self.kill_chain_stage)
        return int((idx + 1) / len(KILL_CHAIN_ORDER) * 100)


@dataclass
class IPRiskProfile:
    ip:              str
    total_alerts:    int      = 0
    categories_seen: set      = field(default_factory=set)
    risk_score:      int      = 0
    first_seen:      float    = 0.0
    last_seen:       float    = 0.0
    kill_chain_stage: Optional[KillChainStage] = None
    active_campaigns: list[str] = field(default_factory=list)


class SIEMCorrelationEngine:
    """
    Motor de correlación de eventos que detecta campañas de ataque multi-etapa.
    Implementa el modelo Cyber Kill Chain de Lockheed Martin.
    """

    def __init__(self):
        self._events_by_ip:   dict[str, deque]              = defaultdict(
            lambda: deque(maxlen=MAX_EVENTS_PER_IP))
        self._ip_profiles:    dict[str, IPRiskProfile]      = {}
        self._campaigns:      dict[str, CorrelatedCampaign] = {}
        self._stats = {
            "events_processed": 0,
            "campaigns_detected": 0,
            "patterns_matched": 0,
        }

    # ── API pública ────────────────────────────────────────────────────────────

    def ingest_event(self, event: SecurityEvent) -> list[CorrelatedCampaign]:
        """Ingesta un evento y retorna las campañas detectadas o actualizadas."""
        self._store_event(event)
        self._update_ip_profile(event)
        new_campaigns = self._correlate(event)
        self._stats["events_processed"] += 1
        return new_campaigns

    def get_active_campaigns(self) -> list[CorrelatedCampaign]:
        """Retorna campañas activas ordenadas por riesgo."""
        now = time.time()
        active = [
            c for c in self._campaigns.values()
            if c.is_active and (now - c.last_seen) < KILL_CHAIN_DECAY_S
        ]
        return sorted(active, key=lambda c: -c.risk_score)

    def get_ip_risk_profile(self, ip: str) -> Optional[IPRiskProfile]:
        return self._ip_profiles.get(ip)

    def get_top_risky_ips(self, n: int = 10) -> list[IPRiskProfile]:
        profiles = sorted(
            self._ip_profiles.values(),
            key=lambda p: -p.risk_score
        )
        return profiles[:n]

    def get_kill_chain_summary(self) -> dict[str, int]:
        """Retorna conteo de eventos por etapa del kill chain."""
        summary: dict[str, int] = {stage.value: 0 for stage in KillChainStage}
        for ip_events in self._events_by_ip.values():
            for event in ip_events:
                stage = CATEGORY_TO_KILLCHAIN.get(event.category)
                if stage:
                    summary[stage.value] += 1
        return summary

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "active_campaigns":     len(self.get_active_campaigns()),
            "tracked_ips":          len(self._ip_profiles),
            "total_campaigns_ever": len(self._campaigns),
        }

    # ── Internals ──────────────────────────────────────────────────────────────

    def _store_event(self, event: SecurityEvent) -> None:
        self._events_by_ip[event.src_ip].append(event)

    def _update_ip_profile(self, event: SecurityEvent) -> None:
        ip = event.src_ip
        if ip not in self._ip_profiles:
            self._ip_profiles[ip] = IPRiskProfile(ip=ip, first_seen=event.timestamp)

        profile = self._ip_profiles[ip]
        profile.total_alerts += 1
        profile.categories_seen.add(event.category)
        profile.last_seen = event.timestamp

        stage = CATEGORY_TO_KILLCHAIN.get(event.category)
        if stage:
            profile.kill_chain_stage = stage

        profile.risk_score = self._compute_ip_risk(profile)

    def _compute_ip_risk(self, profile: IPRiskProfile) -> int:
        score = 0
        score += min(profile.total_alerts * 3, 40)
        score += len(profile.categories_seen) * 8
        if profile.kill_chain_stage:
            idx = KILL_CHAIN_ORDER.index(profile.kill_chain_stage)
            score += idx * 7
        score += len(profile.active_campaigns) * 10
        return min(score, 100)

    def _correlate(self, event: SecurityEvent) -> list[CorrelatedCampaign]:
        detected: list[CorrelatedCampaign] = []
        window_start = event.timestamp - CORRELATION_WINDOW_S
        recent = [
            e for e in self._events_by_ip[event.src_ip]
            if e.timestamp >= window_start
        ]

        if len(recent) < 2:
            return detected

        cat_sequence = [e.category for e in recent]

        for pattern in ATTACK_PATTERNS:
            if self._matches_pattern(cat_sequence, pattern["sequence"]):
                campaign = self._get_or_create_campaign(
                    event, recent, pattern)
                detected.append(campaign)
                self._stats["patterns_matched"] += 1

        return detected

    def _matches_pattern(self, sequence: list[str],
                          pattern: list[str]) -> bool:
        """Verifica si el patrón aparece como subsecuencia en los eventos."""
        it = iter(sequence)
        return all(cat in it for cat in pattern)

    def _get_or_create_campaign(self, event: SecurityEvent,
                                 recent: list[SecurityEvent],
                                 pattern: dict) -> CorrelatedCampaign:
        # Buscar campaña existente para esta IP + patrón
        existing_id = next(
            (cid for cid, c in self._campaigns.items()
             if event.src_ip in c.src_ips
             and c.pattern_name == pattern["name"]
             and c.is_active),
            None
        )

        if existing_id:
            campaign = self._campaigns[existing_id]
            campaign.last_seen = event.timestamp
            stage = CATEGORY_TO_KILLCHAIN.get(event.category)
            if stage and KILL_CHAIN_ORDER.index(stage) > \
               KILL_CHAIN_ORDER.index(campaign.kill_chain_stage):
                campaign.kill_chain_stage = stage
            if event not in campaign.events:
                campaign.events.append(event)
            return campaign

        # Nueva campaña
        campaign_id = f"CAMP-{uuid.uuid4().hex[:8].upper()}"
        stage = CATEGORY_TO_KILLCHAIN.get(
            event.category, KillChainStage.RECONNAISSANCE)

        campaign = CorrelatedCampaign(
            campaign_id=campaign_id,
            pattern_name=pattern["name"],
            description=pattern["desc"],
            src_ips=[event.src_ip],
            dst_ips=list(set(e.dst_ip for e in recent)),
            events=list(recent),
            kill_chain_stage=stage,
            risk_score=pattern["risk"],
            start_time=recent[0].timestamp,
            last_seen=event.timestamp,
            recommended_actions=self._get_campaign_actions(pattern["name"]),
        )
        self._campaigns[campaign_id] = campaign
        self._ip_profiles[event.src_ip].active_campaigns.append(campaign_id)
        self._stats["campaigns_detected"] += 1
        return campaign

    def _get_campaign_actions(self, pattern_name: str) -> list[str]:
        actions = {
            "APT Lateral Movement": [
                "Aislar inmediatamente los hosts comprometidos de la red.",
                "Resetear credenciales de todas las cuentas afectadas.",
                "Iniciar análisis forense completo del sistema.",
                "Activar plan de respuesta a incidentes nivel 1.",
                "Notificar al CISO y equipo directivo.",
            ],
            "Web Application Attack": [
                "Bloquear IP atacante en WAF y firewall.",
                "Revisar logs del servidor web por accesos no autorizados.",
                "Verificar integridad de archivos del servidor.",
                "Parchear vulnerabilidades explotadas inmediatamente.",
            ],
            "Ransomware Campaign": [
                "ALERTA MÁXIMA: posible ransomware en progreso.",
                "Aislar TODOS los sistemas afectados de la red inmediatamente.",
                "Activar backups offsite y verificar su integridad.",
                "Contactar equipo de respuesta a incidentes externo.",
                "Documentar todo para el reporte post-incidente.",
            ],
            "Data Exfiltration": [
                "Bloquear comunicación con servidores C2 identificados.",
                "Revisar qué datos pudieron haber sido exfiltrados.",
                "Notificar al DPO sobre posible brecha de datos.",
                "Iniciar protocolo de notificación a autoridades si corresponde.",
            ],
            "DDoS Preparation": [
                "Activar protección DDoS en la CDN si disponible.",
                "Coordinar con ISP para filtrado upstream.",
                "Verificar capacidad de infraestructura actual.",
            ],
        }
        return actions.get(pattern_name, ["Revisar manualmente la campaña detectada."])


# ── Demo ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import random
    print("=" * 60)
    print("  JeiGuard AI v1.0.2 — SIEM Correlation Engine")
    print("=" * 60)

    engine = SIEMCorrelationEngine()
    now    = time.time()

    # Simular una campaña APT: Probe → R2L → U2R
    scenario = [
        ("Probe_Scan",  "10.42.183.97", "192.168.1.15", now - 240, 0.88),
        ("Probe_Scan",  "10.42.183.97", "192.168.1.20", now - 220, 0.91),
        ("R2L",         "10.42.183.97", "192.168.1.15", now - 180, 0.85),
        ("R2L",         "10.42.183.97", "192.168.1.15", now - 120, 0.87),
        ("U2R",         "10.42.183.97", "192.168.1.15", now -  60, 0.79),
        ("CC_Traffic",  "10.42.183.97", "192.168.1.15", now -  10, 0.82),
    ]

    for cat, src, dst, ts, conf in scenario:
        event = SecurityEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:8]}",
            timestamp=ts, src_ip=src, dst_ip=dst,
            category=cat, confidence=conf, port=22, protocol="TCP"
        )
        campaigns = engine.ingest_event(event)
        if campaigns:
            print(f"\nCAMPANA DETECTADA: {campaigns[0].pattern_name}")
            print(f"  Riesgo: {campaigns[0].risk_score}/100")
            print(f"  Etapa kill chain: {campaigns[0].kill_chain_stage.value}")
            print(f"  Progresion: {campaigns[0].progression_pct}%")

    print(f"\nStats finales: {engine.get_stats()}")
    print(f"\nTop IPs riesgosas:")
    for p in engine.get_top_risky_ips(3):
        print(f"  {p.ip}: riesgo={p.risk_score}, alertas={p.total_alerts}, etapa={p.kill_chain_stage}")
