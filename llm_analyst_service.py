"""
JeiGuard AI v1.0.2 — Mejora 1: LLM Security Analyst Service
Analiza alertas de seguridad usando Claude como analista forense inteligente.
Copyright © 2026 Jeiner Tello Nuñez — MIT License
"""
from __future__ import annotations

import json
import time
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum

import anthropic

# ── Constantes ─────────────────────────────────────────────────────────────────
LLM_MODEL              = "claude-opus-4-5"
LLM_MAX_TOKENS         = 1500
LLM_CACHE_TTL_S        = 3600        # 1 hora de caché
LLM_MAX_RETRIES        = 3
LLM_RETRY_DELAY_S      = 2.0
SERVICE_VERSION        = "1.0.2"

MITRE_CONTEXT = {
    "DoS_DDoS":    ("T1498", "Network Denial of Service",               "Impact"),
    "Probe_Scan":  ("T1046", "Network Service Discovery",               "Discovery"),
    "R2L":         ("T1110", "Brute Force",                             "Credential Access"),
    "U2R":         ("T1068", "Exploitation for Privilege Escalation",   "Privilege Escalation"),
    "Backdoor":    ("T1543", "Create or Modify System Process",         "Persistence"),
    "Web_Exploit": ("T1190", "Exploit Public-Facing Application",       "Initial Access"),
    "CC_Traffic":  ("T1071", "Application Layer Protocol",              "Command & Control"),
    "Normal":      ("—",     "Normal traffic",                          "—"),
}

PLAYBOOKS = {
    "DoS_DDoS":    ["Activar rate limiting en firewall perimetral.",
                    "Contactar ISP upstream para filtrado de tráfico.",
                    "Redirigir tráfico a servicio de scrubbing DDoS.",
                    "Activar CDN con protección DDoS si disponible."],
    "Probe_Scan":  ["Revisar logs de firewall para identificar alcance del escaneo.",
                    "Bloquear IP origen en firewall si el escaneo es agresivo.",
                    "Verificar que no haya servicios expuestos innecesariamente.",
                    "Activar alerta de vigilancia incrementada por 24h."],
    "R2L":         ["Forzar cambio de contraseñas de cuentas afectadas.",
                    "Activar MFA si no está habilitado.",
                    "Revisar logs de autenticación de las últimas 24h.",
                    "Bloquear IP origen temporalmente."],
    "U2R":         ["Aislar el sistema comprometido de la red inmediatamente.",
                    "Revisar procesos en ejecución con privilegios elevados.",
                    "Auditar cambios de configuración recientes.",
                    "Iniciar análisis forense del sistema afectado."],
    "Backdoor":    ["Aislar el host comprometido de la red.",
                    "Realizar análisis de malware completo.",
                    "Revisar servicios de inicio y tareas programadas.",
                    "Restaurar desde backup limpio si se confirma la infección."],
    "Web_Exploit": ["Parchear inmediatamente la vulnerabilidad explotada.",
                    "Revisar logs del servidor web por accesos no autorizados.",
                    "Verificar integridad de archivos del servidor.",
                    "Activar WAF si no está habilitado."],
    "CC_Traffic":  ["Bloquear comunicación con servidor C2 en firewall.",
                    "Aislar host infectado de la red.",
                    "Realizar análisis de malware completo del host.",
                    "Buscar otros hosts con patrones similares de comunicación."],
}


class AnalysisType(str, Enum):
    SINGLE_ALERT    = "single_alert"
    CAMPAIGN        = "campaign"
    FORENSIC_REPORT = "forensic_report"
    CHAT_QUERY      = "chat_query"


@dataclass
class AlertContext:
    alert_id:      str
    category:      str
    confidence:    float
    src_ip:        str
    dst_ip:        str
    port:          int
    protocol:      str
    timestamp:     str
    bytes_sent:    int   = 0
    duration_s:    float = 0.0
    sensor_id:     str   = "sensor-01"
    related_alerts: list = field(default_factory=list)


@dataclass
class LLMAnalysis:
    alert_id:         str
    summary:          str
    attack_narrative: str
    severity_reason:  str
    recommended_actions: list[str]
    mitre_technique:  str
    mitre_tactic:     str
    estimated_impact: str
    confidence_explanation: str
    follow_up_questions: list[str]
    analysis_time_ms: float
    model_used:       str


@dataclass
class CampaignAnalysis:
    campaign_id:      str
    title:            str
    narrative:        str
    kill_chain_stage: str
    affected_ips:     list[str]
    timeline:         str
    risk_score:       int
    recommended_actions: list[str]
    analysis_time_ms: float


class LLMAnalystService:
    """
    Servicio que usa Claude como analista forense de seguridad.
    Genera narrativas de ataque, correlaciones y playbooks en lenguaje natural.
    """

    def __init__(self, api_key: Optional[str] = None):
        self._client    = anthropic.Anthropic(api_key=api_key)
        self._cache:    dict[str, tuple[any, float]] = {}
        self._stats     = {"total_analyses": 0, "cache_hits": 0, "errors": 0}

    # ── API pública ────────────────────────────────────────────────────────────

    def analyze_alert(self, alert: AlertContext) -> LLMAnalysis:
        """Analiza una alerta individual y genera informe forense."""
        cache_key = self._cache_key("alert", asdict(alert))
        cached    = self._get_cache(cache_key)
        if cached:
            return cached

        t0      = time.time()
        prompt  = self._build_alert_prompt(alert)
        raw     = self._call_llm(prompt, AnalysisType.SINGLE_ALERT)
        parsed  = self._parse_alert_response(raw, alert)
        elapsed = (time.time() - t0) * 1000
        parsed.analysis_time_ms = elapsed

        self._set_cache(cache_key, parsed)
        self._stats["total_analyses"] += 1
        return parsed

    def analyze_campaign(self, alerts: list[AlertContext]) -> CampaignAnalysis:
        """Detecta y analiza campañas de ataque multi-etapa."""
        cache_key = self._cache_key("campaign", [a.alert_id for a in alerts])
        cached    = self._get_cache(cache_key)
        if cached:
            return cached

        t0      = time.time()
        prompt  = self._build_campaign_prompt(alerts)
        raw     = self._call_llm(prompt, AnalysisType.CAMPAIGN)
        parsed  = self._parse_campaign_response(raw, alerts)
        elapsed = (time.time() - t0) * 1000
        parsed.analysis_time_ms = elapsed

        self._set_cache(cache_key, parsed)
        return parsed

    def generate_forensic_report(self, alerts: list[AlertContext],
                                  period_hours: int = 24) -> str:
        """Genera un informe forense ejecutivo en lenguaje natural."""
        prompt = self._build_forensic_prompt(alerts, period_hours)
        return self._call_llm(prompt, AnalysisType.FORENSIC_REPORT)

    def answer_security_question(self, question: str,
                                  context_alerts: list[AlertContext]) -> str:
        """Responde preguntas en lenguaje natural sobre el estado de la red."""
        prompt = self._build_chat_prompt(question, context_alerts)
        return self._call_llm(prompt, AnalysisType.CHAT_QUERY)

    def get_stats(self) -> dict:
        return {**self._stats, "cache_size": len(self._cache)}

    # ── Construcción de prompts ────────────────────────────────────────────────

    def _build_alert_prompt(self, alert: AlertContext) -> str:
        mitre_id, mitre_name, mitre_tactic = MITRE_CONTEXT.get(
            alert.category, ("—", "Unknown", "—"))
        playbook = PLAYBOOKS.get(alert.category, ["Investigar manualmente."])

        return f"""Eres un analista senior de ciberseguridad con 15 años de experiencia en respuesta a incidentes.
Analiza la siguiente alerta de seguridad generada por JeiGuard AI v1.0.2 y proporciona un análisis forense detallado.

DATOS DE LA ALERTA:
- ID: {alert.alert_id}
- Categoría detectada: {alert.category}
- Confianza del modelo: {alert.confidence:.1%}
- IP Origen: {alert.src_ip}:{alert.port}
- IP Destino: {alert.dst_ip}
- Protocolo: {alert.protocol}
- Timestamp: {alert.timestamp}
- Bytes enviados: {alert.bytes_sent:,}
- Duración: {alert.duration_s:.3f}s
- Sensor: {alert.sensor_id}
- Técnica MITRE: {mitre_id} — {mitre_name} [{mitre_tactic}]
- Alertas relacionadas: {len(alert.related_alerts)} alertas previas de esta IP

Responde EXACTAMENTE en este formato JSON (sin markdown, solo JSON puro):
{{
  "summary": "Resumen ejecutivo de 2 oraciones máximo",
  "attack_narrative": "Narrativa detallada de lo que ocurrió, cómo se propagó y cuál es el objetivo probable del atacante. Mínimo 3 oraciones.",
  "severity_reason": "Por qué tiene este nivel de severidad dado el contexto específico",
  "recommended_actions": ["Acción 1 específica y ejecutable", "Acción 2", "Acción 3", "Acción 4"],
  "estimated_impact": "Impacto potencial si no se actúa en las próximas horas",
  "confidence_explanation": "Por qué el modelo tiene este nivel de confianza para esta clasificación específica",
  "follow_up_questions": ["Pregunta que un analista debería investigar", "Pregunta 2", "Pregunta 3"]
}}"""

    def _build_campaign_prompt(self, alerts: list[AlertContext]) -> str:
        alert_summary = "\n".join([
            f"  [{i+1}] {a.timestamp} | {a.category} | {a.src_ip} → {a.dst_ip}:{a.port} | conf={a.confidence:.1%}"
            for i, a in enumerate(alerts[:20])
        ])
        unique_ips = list(set(a.src_ip for a in alerts))
        categories = list(set(a.category for a in alerts))

        return f"""Eres un analista de threat hunting especializado en detección de APTs y campañas de ataque complejas.

Analiza la siguiente secuencia de alertas de JeiGuard AI y determina si constituyen una campaña de ataque coordinada.

ALERTAS ({len(alerts)} total):
{alert_summary}

IPs origen únicas: {unique_ips}
Categorías detectadas: {categories}
Período: {alerts[0].timestamp} → {alerts[-1].timestamp}

Responde en JSON puro:
{{
  "title": "Título descriptivo de la campaña detectada",
  "narrative": "Narrativa completa del ataque: qué hizo el atacante, en qué orden, cuál es el objetivo final probable. Mínimo 4 oraciones.",
  "kill_chain_stage": "Etapa actual del Cyber Kill Chain: Reconnaissance/Weaponization/Delivery/Exploitation/Installation/C2/Actions",
  "affected_ips": ["lista de IPs víctima afectadas"],
  "timeline": "Descripción cronológica del ataque",
  "risk_score": 85,
  "recommended_actions": ["Acción inmediata 1", "Acción 2", "Acción 3", "Acción 4", "Acción 5"]
}}"""

    def _build_forensic_prompt(self, alerts: list[AlertContext],
                                period_hours: int) -> str:
        categories = {}
        for a in alerts:
            categories[a.category] = categories.get(a.category, 0) + 1

        return f"""Genera un informe forense ejecutivo de seguridad para las últimas {period_hours} horas.

RESUMEN DE ACTIVIDAD:
- Total alertas: {len(alerts)}
- Distribución: {json.dumps(categories, indent=2)}
- IPs únicas atacantes: {len(set(a.src_ip for a in alerts))}
- Alertas críticas (conf > 95%): {sum(1 for a in alerts if a.confidence > 0.95)}

El informe debe incluir:
1. Resumen ejecutivo (para directivos no técnicos)
2. Análisis de amenazas principales
3. Tendencias detectadas
4. Estado de seguridad general (escala 1-10)
5. Recomendaciones prioritarias
6. Próximos pasos

Escribe el informe en español, lenguaje profesional pero accesible."""

    def _build_chat_prompt(self, question: str,
                            context_alerts: list[AlertContext]) -> str:
        context = "\n".join([
            f"- {a.timestamp}: {a.category} desde {a.src_ip} (conf={a.confidence:.1%})"
            for a in context_alerts[-10:]
        ])
        return f"""Eres el analista de seguridad de JeiGuard AI. Responde la siguiente pregunta
basándote en el contexto de alertas recientes. Sé directo, técnico y útil.

CONTEXTO (últimas 10 alertas):
{context}

PREGUNTA: {question}

Responde de forma concisa y accionable."""

    # ── Llamada al LLM ─────────────────────────────────────────────────────────

    def _call_llm(self, prompt: str, analysis_type: AnalysisType) -> str:
        for attempt in range(LLM_MAX_RETRIES):
            try:
                response = self._client.messages.create(
                    model=LLM_MODEL,
                    max_tokens=LLM_MAX_TOKENS,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
            except anthropic.RateLimitError:
                if attempt < LLM_MAX_RETRIES - 1:
                    time.sleep(LLM_RETRY_DELAY_S * (attempt + 1))
            except Exception as e:
                self._stats["errors"] += 1
                if attempt == LLM_MAX_RETRIES - 1:
                    return self._fallback_response(analysis_type, str(e))
        return self._fallback_response(analysis_type, "Max retries reached")

    def _fallback_response(self, analysis_type: AnalysisType, error: str) -> str:
        if analysis_type == AnalysisType.SINGLE_ALERT:
            return json.dumps({
                "summary": "Análisis automático no disponible temporalmente.",
                "attack_narrative": "Revisar manualmente los detalles de la alerta.",
                "severity_reason": "Evaluación manual requerida.",
                "recommended_actions": ["Revisar logs manualmente", "Contactar analista de turno"],
                "estimated_impact": "Desconocido — requiere análisis manual",
                "confidence_explanation": f"Error en servicio LLM: {error}",
                "follow_up_questions": ["¿Cuál es el contexto de esta IP?"]
            })
        return f"Análisis no disponible temporalmente. Error: {error}"

    # ── Parsers de respuesta ───────────────────────────────────────────────────

    def _parse_alert_response(self, raw: str, alert: AlertContext) -> LLMAnalysis:
        mitre_id, mitre_name, mitre_tactic = MITRE_CONTEXT.get(
            alert.category, ("—", "Unknown", "—"))
        try:
            data = json.loads(raw.strip())
        except json.JSONDecodeError:
            data = {
                "summary":                "Análisis completado.",
                "attack_narrative":       raw[:500],
                "severity_reason":        "Ver narrativa completa.",
                "recommended_actions":    PLAYBOOKS.get(alert.category, []),
                "estimated_impact":       "Revisar manualmente.",
                "confidence_explanation": "Respuesta no estructurada del LLM.",
                "follow_up_questions":    [],
            }
        return LLMAnalysis(
            alert_id=alert.alert_id,
            summary=data.get("summary", ""),
            attack_narrative=data.get("attack_narrative", ""),
            severity_reason=data.get("severity_reason", ""),
            recommended_actions=data.get("recommended_actions",
                                         PLAYBOOKS.get(alert.category, [])),
            mitre_technique=f"{mitre_id} — {mitre_name}",
            mitre_tactic=mitre_tactic,
            estimated_impact=data.get("estimated_impact", ""),
            confidence_explanation=data.get("confidence_explanation", ""),
            follow_up_questions=data.get("follow_up_questions", []),
            analysis_time_ms=0.0,
            model_used=LLM_MODEL,
        )

    def _parse_campaign_response(self, raw: str,
                                  alerts: list[AlertContext]) -> CampaignAnalysis:
        campaign_id = f"CAMP-{int(time.time())}"
        try:
            data = json.loads(raw.strip())
        except json.JSONDecodeError:
            data = {
                "title":              "Campaña de ataque detectada",
                "narrative":          raw[:500],
                "kill_chain_stage":   "Unknown",
                "affected_ips":       list(set(a.dst_ip for a in alerts)),
                "timeline":           "Ver alertas individuales",
                "risk_score":         75,
                "recommended_actions": ["Revisar alertas individuales"],
            }
        return CampaignAnalysis(
            campaign_id=campaign_id,
            title=data.get("title", "Campaña detectada"),
            narrative=data.get("narrative", ""),
            kill_chain_stage=data.get("kill_chain_stage", "Unknown"),
            affected_ips=data.get("affected_ips", []),
            timeline=data.get("timeline", ""),
            risk_score=int(data.get("risk_score", 75)),
            recommended_actions=data.get("recommended_actions", []),
            analysis_time_ms=0.0,
        )

    # ── Caché ──────────────────────────────────────────────────────────────────

    def _cache_key(self, prefix: str, data: any) -> str:
        raw = json.dumps(data, sort_keys=True, default=str)
        return f"{prefix}:{hashlib.md5(raw.encode()).hexdigest()[:16]}"

    def _get_cache(self, key: str) -> Optional[any]:
        entry = self._cache.get(key)
        if entry and (time.time() - entry[1]) < LLM_CACHE_TTL_S:
            self._stats["cache_hits"] += 1
            return entry[0]
        return None

    def _set_cache(self, key: str, value: any) -> None:
        self._cache[key] = (value, time.time())
        if len(self._cache) > 500:
            oldest = sorted(self._cache, key=lambda k: self._cache[k][1])[:50]
            for k in oldest:
                del self._cache[k]


# ── Demo / test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  JeiGuard AI v1.0.2 — LLM Analyst Service")
    print("=" * 60)

    analyst = LLMAnalystService()

    demo_alert = AlertContext(
        alert_id="a7f3c2d1",
        category="DoS_DDoS",
        confidence=0.948,
        src_ip="10.42.183.97",
        dst_ip="192.168.1.15",
        port=80,
        protocol="TCP",
        timestamp="2026-05-15T14:23:07Z",
        bytes_sent=18432,
        duration_s=0.003,
        sensor_id="sensor-datacenter-01",
    )

    print("\nAnalizando alerta con LLM...")
    analysis = analyst.analyze_alert(demo_alert)
    print(f"\nResumen: {analysis.summary}")
    print(f"Narrativa: {analysis.attack_narrative[:200]}...")
    print(f"Acciones recomendadas:")
    for i, action in enumerate(analysis.recommended_actions, 1):
        print(f"  {i}. {action}")
    print(f"\nTiempo de análisis: {analysis.analysis_time_ms:.1f}ms")
    print(f"Stats: {analyst.get_stats()}")
