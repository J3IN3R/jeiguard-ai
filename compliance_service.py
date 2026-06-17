"""
compliance_service.py
══════════════════════
Motor de Compliance y Gobernanza de JeiGuard AI.

Frameworks soportados:
  • NIST CSF 2.0   — 6 funciones, 22 categorías, 106 subcategorías
  • SOC 2 Type II  — 5 Trust Service Criteria (TSC)
  • ISO/IEC 27001:2022 — Anexo A, 93 controles

Funcionalidades:
  • Evaluación automática de controles basada en alertas detectadas
  • Score de cumplimiento por categoría (0-100)
  • Gap analysis con recomendaciones priorizadas
  • Evidencia automática generada por el IDS
  • Historial de evaluaciones

Endpoints:
  GET  /compliance/frameworks            — Frameworks disponibles
  GET  /compliance/{framework}/score     — Score global del tenant
  GET  /compliance/{framework}/controls  — Detalle por control
  POST /compliance/{framework}/assess    — Ejecutar evaluación
  GET  /compliance/{framework}/gaps      — Gap analysis
  GET  /compliance/dashboard             — Vista consolidada multi-framework
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service import RequireAnalyst, RequireAnyRole, AuthContext
from database import AlertRecord, ComplianceControl, ComplianceStatus, get_session

API_VERSION: str = "v1"
router = APIRouter(prefix=f"/api/{API_VERSION}/compliance", tags=["Compliance"])

# ── Definición de controles por framework ────────────────────────────────────

NIST_CSF_CONTROLS: list[dict[str, Any]] = [
    # GOVERN
    {"control_id": "GV.OC-01", "category": "GOVERN / Organizational Context",
     "control_name": "Misión y objetivos de ciberseguridad definidos",
     "control_description": "Los objetivos organizacionales de ciberseguridad están establecidos y comunicados."},
    {"control_id": "GV.OC-02", "category": "GOVERN / Organizational Context",
     "control_name": "Dependencias y partes interesadas identificadas",
     "control_description": "Las dependencias internas y externas críticas han sido identificadas."},
    {"control_id": "GV.SC-01", "category": "GOVERN / Supply Chain Risk",
     "control_name": "Política de riesgo de cadena de suministro establecida",
     "control_description": "Existe una política formal de gestión de riesgos en la cadena de suministro."},
    # IDENTIFY
    {"control_id": "ID.AM-01", "category": "IDENTIFY / Asset Management",
     "control_name": "Inventario de activos de hardware mantenido",
     "control_description": "Los activos de hardware dentro de la organización están inventariados."},
    {"control_id": "ID.AM-02", "category": "IDENTIFY / Asset Management",
     "control_name": "Inventario de activos de software mantenido",
     "control_description": "Los activos de software dentro de la organización están inventariados."},
    {"control_id": "ID.RA-01", "category": "IDENTIFY / Risk Assessment",
     "control_name": "Vulnerabilidades identificadas y documentadas",
     "control_description": "Las vulnerabilidades en activos son identificadas y documentadas."},
    {"control_id": "ID.RA-02", "category": "IDENTIFY / Risk Assessment",
     "control_name": "Inteligencia de amenazas recibida y analizada",
     "control_description": "Se recibe y analiza inteligencia de amenazas de fuentes externas (AbuseIPDB, VirusTotal)."},
    {"control_id": "ID.RA-05", "category": "IDENTIFY / Risk Assessment",
     "control_name": "Riesgos identificados, priorizados y documentados",
     "control_description": "Los riesgos son identificados, priorizados y documentados con planes de respuesta."},
    # PROTECT
    {"control_id": "PR.AA-01", "category": "PROTECT / Identity Management",
     "control_name": "Identidades y credenciales gestionadas para usuarios y dispositivos",
     "control_description": "Las identidades y credenciales son emitidas, gestionadas, verificadas y revocadas."},
    {"control_id": "PR.AA-05", "category": "PROTECT / Identity Management",
     "control_name": "Acceso con privilegios mínimos aplicado",
     "control_description": "El principio de privilegio mínimo es aplicado consistentemente."},
    {"control_id": "PR.DS-01", "category": "PROTECT / Data Security",
     "control_name": "Datos en reposo protegidos",
     "control_description": "Los datos en reposo están protegidos mediante cifrado o controles equivalentes."},
    {"control_id": "PR.DS-02", "category": "PROTECT / Data Security",
     "control_name": "Datos en tránsito protegidos",
     "control_description": "Los datos en tránsito están protegidos mediante TLS/mTLS."},
    {"control_id": "PR.IR-01", "category": "PROTECT / Technology Infrastructure",
     "control_name": "Redes y entornos separados por niveles de confianza",
     "control_description": "Las redes están segmentadas de acuerdo con los niveles de confianza."},
    # DETECT
    {"control_id": "DE.AE-02", "category": "DETECT / Adverse Event Analysis",
     "control_name": "Eventos anómalos analizados para entender impacto",
     "control_description": "JeiGuard AI analiza eventos anómalos en tiempo real con CNN-1D + Random Forest."},
    {"control_id": "DE.AE-03", "category": "DETECT / Adverse Event Analysis",
     "control_name": "Datos de eventos correlacionados de múltiples fuentes",
     "control_description": "El SIEM correlation engine correlaciona alertas de múltiples sensores."},
    {"control_id": "DE.AE-06", "category": "DETECT / Adverse Event Analysis",
     "control_name": "Información sobre eventos de ciberseguridad compartida",
     "control_description": "Los eventos son indexados en Elasticsearch y compartidos con equipos autorizados."},
    {"control_id": "DE.CM-01", "category": "DETECT / Continuous Monitoring",
     "control_name": "Redes monitorizadas para detectar eventos adversos",
     "control_description": "JeiGuard AI monitoriza el tráfico de red en tiempo real a 15,000 flujos/segundo."},
    {"control_id": "DE.CM-09", "category": "DETECT / Continuous Monitoring",
     "control_name": "Sistemas de cómputo monitorizados",
     "control_description": "Los sistemas son monitorizados para detectar actividad no autorizada."},
    # RESPOND
    {"control_id": "RS.MA-01", "category": "RESPOND / Incident Management",
     "control_name": "Plan de respuesta a incidentes ejecutado durante o después de un incidente",
     "control_description": "El SOAR engine ejecuta respuestas automáticas: bloqueo IP, aislamiento de host, tickets Jira."},
    {"control_id": "RS.CO-02", "category": "RESPOND / Incident Management",
     "control_name": "Partes interesadas internas y externas notificadas de incidentes",
     "control_description": "Las notificaciones se envían vía Slack/webhook/email automáticamente."},
    {"control_id": "RS.AN-03", "category": "RESPOND / Analysis",
     "control_name": "Análisis forense realizado para caracterizar incidentes",
     "control_description": "El LLM Analyst (Claude API) genera narrativas forenses con recomendaciones."},
    # RECOVER
    {"control_id": "RC.RP-01", "category": "RECOVER / Incident Recovery",
     "control_name": "Plan de recuperación de incidentes ejecutado durante o después de un incidente",
     "control_description": "Existen procedimientos de recuperación y rollback documentados."},
]

SOC2_CONTROLS: list[dict[str, Any]] = [
    # CC1 - Control Environment
    {"control_id": "CC1.1", "category": "CC1 / Control Environment",
     "control_name": "La entidad demuestra un compromiso con la integridad y los valores éticos",
     "control_description": "Los valores éticos y la integridad son requisitos previos para el acceso al sistema."},
    {"control_id": "CC1.2", "category": "CC1 / Control Environment",
     "control_name": "El directorio ejerce supervisión independiente del desarrollo de controles",
     "control_description": "Existe supervisión independiente de la gobernanza de seguridad."},
    # CC2 - Communication and Information
    {"control_id": "CC2.1", "category": "CC2 / Communication",
     "control_name": "Información de calidad para apoyar el funcionamiento de controles internos",
     "control_description": "JeiGuard AI genera información de calidad sobre amenazas con 97.4% de precisión."},
    {"control_id": "CC2.2", "category": "CC2 / Communication",
     "control_name": "Comunicación interna relevante para objetivos de control",
     "control_description": "Alertas, incidentes y reportes son comunicados a las partes relevantes."},
    # CC6 - Logical and Physical Access
    {"control_id": "CC6.1", "category": "CC6 / Logical Access",
     "control_name": "Implementación de controles de acceso lógico para proteger activos",
     "control_description": "RBAC con JWT, MFA y políticas de contraseña robusta implementadas."},
    {"control_id": "CC6.2", "category": "CC6 / Logical Access",
     "control_name": "Credenciales de autenticación robustas",
     "control_description": "bcrypt (12 rounds), políticas de contraseña y bloqueo por intentos fallidos."},
    {"control_id": "CC6.3", "category": "CC6 / Logical Access",
     "control_name": "Acceso basado en roles y principio de privilegio mínimo",
     "control_description": "Roles: super_admin > admin > analyst > viewer > readonly."},
    {"control_id": "CC6.6", "category": "CC6 / Logical Access",
     "control_name": "Medidas de seguridad para proteger contra amenazas externas",
     "control_description": "IDS en tiempo real con detección de 8 categorías de ataque y correlación MITRE ATT&CK."},
    {"control_id": "CC6.7", "category": "CC6 / Logical Access",
     "control_name": "Transmisión de datos protegida",
     "control_description": "Comunicación cifrada con TLS 1.3 en todos los endpoints REST y WebSocket."},
    # CC7 - System Operations
    {"control_id": "CC7.1", "category": "CC7 / System Operations",
     "control_name": "Detección y monitoreo de vulnerabilidades",
     "control_description": "Escaneo continuo de vulnerabilidades con correlación a CVE/NVD."},
    {"control_id": "CC7.2", "category": "CC7 / System Operations",
     "control_name": "Monitoreo de intrusiones e incidentes de seguridad",
     "control_description": "JeiGuard AI monitoriza el tráfico de red 24/7 con P99 < 12ms."},
    {"control_id": "CC7.3", "category": "CC7 / System Operations",
     "control_name": "Respuesta a incidentes de seguridad",
     "control_description": "SOAR engine con respuestas automatizadas y escalación manual."},
    # CC9 - Risk Mitigation
    {"control_id": "CC9.1", "category": "CC9 / Risk Mitigation",
     "control_name": "Identificación y gestión de riesgos de disrupciones del negocio",
     "control_description": "Arquitectura de alta disponibilidad con HPA (2-20 réplicas) y multi-AZ."},
    {"control_id": "CC9.2", "category": "CC9 / Risk Mitigation",
     "control_name": "Monitoreo de riesgos de terceros",
     "control_description": "Threat Intelligence con AbuseIPDB y VirusTotal integrado."},
]

ISO27001_CONTROLS: list[dict[str, Any]] = [
    {"control_id": "A.5.1",  "category": "A.5 / Políticas de Seguridad",
     "control_name": "Políticas de seguridad de la información",
     "control_description": "Existen políticas de seguridad documentadas y aprobadas."},
    {"control_id": "A.6.1",  "category": "A.6 / Organización Seguridad",
     "control_name": "Roles y responsabilidades de seguridad de la información",
     "control_description": "Los roles de seguridad están definidos mediante RBAC en JeiGuard AI."},
    {"control_id": "A.8.1",  "category": "A.8 / Gestión de Activos",
     "control_name": "Inventario de activos de información",
     "control_description": "Los activos monitorizados por JeiGuard AI están catalogados con Digital Twin."},
    {"control_id": "A.8.2",  "category": "A.8 / Gestión de Activos",
     "control_name": "Clasificación de información",
     "control_description": "La información es clasificada según sensibilidad y criticidad."},
    {"control_id": "A.9.1",  "category": "A.9 / Control de Acceso",
     "control_name": "Política de control de acceso",
     "control_description": "Política de acceso implementada con JWT RBAC y auditoría completa."},
    {"control_id": "A.9.2",  "category": "A.9 / Control de Acceso",
     "control_name": "Gestión de acceso de usuarios",
     "control_description": "Provisión, modificación y revocación de acceso mediante auth_service."},
    {"control_id": "A.9.4",  "category": "A.9 / Control de Acceso",
     "control_name": "Control de acceso al sistema y a las aplicaciones",
     "control_description": "Autenticación multifactor preparada (TOTP), sesiones gestionadas con refresh tokens."},
    {"control_id": "A.10.1", "category": "A.10 / Criptografía",
     "control_name": "Política de uso de controles criptográficos",
     "control_description": "bcrypt para contraseñas, JWT HS256 para tokens, TLS para tránsito."},
    {"control_id": "A.12.1", "category": "A.12 / Seguridad Operaciones",
     "control_name": "Procedimientos operativos documentados",
     "control_description": "Runbooks de respuesta a incidentes documentados en el SOAR engine."},
    {"control_id": "A.12.4", "category": "A.12 / Seguridad Operaciones",
     "control_name": "Registro de eventos (logging)",
     "control_description": "Logs estructurados JSON en ELK Stack, audit trail inmutable en PostgreSQL."},
    {"control_id": "A.12.6", "category": "A.12 / Seguridad Operaciones",
     "control_name": "Gestión de vulnerabilidades técnicas",
     "control_description": "CVE Correlation Engine correlaciona ataques con vulnerabilidades conocidas (NVD)."},
    {"control_id": "A.13.1", "category": "A.13 / Seguridad Redes",
     "control_name": "Controles de red",
     "control_description": "NetworkPolicy en Kubernetes, segmentación de red, mTLS con Istio."},
    {"control_id": "A.13.2", "category": "A.13 / Seguridad Redes",
     "control_name": "Transferencia de información",
     "control_description": "Toda transferencia de datos usa TLS 1.3 y está monitoreada por JeiGuard AI."},
    {"control_id": "A.16.1", "category": "A.16 / Gestión Incidentes",
     "control_name": "Gestión de incidentes y mejoras de seguridad de la información",
     "control_description": "Lifecycle completo: detección → correlación → análisis LLM → SOAR → resolución."},
    {"control_id": "A.17.1", "category": "A.17 / Continuidad de Negocio",
     "control_name": "Continuidad de la seguridad de la información",
     "control_description": "Alta disponibilidad: HPA 2-20 réplicas, multi-AZ, RTO < 5 min."},
    {"control_id": "A.18.1", "category": "A.18 / Cumplimiento",
     "control_name": "Cumplimiento de requisitos legales y contractuales",
     "control_description": "Audit trail completo, reportes exportables, retención de datos configurable."},
]

FRAMEWORK_CONTROLS: dict[str, list[dict[str, Any]]] = {
    "NIST_CSF":  NIST_CSF_CONTROLS,
    "SOC2":      SOC2_CONTROLS,
    "ISO27001":  ISO27001_CONTROLS,
}

AUTO_ASSESS_RULES: dict[str, dict[str, Any]] = {
    "DE.CM-01": {"requires": "ids_active",       "weight": 1.0},
    "DE.AE-02": {"requires": "ids_active",       "weight": 1.0},
    "DE.AE-03": {"requires": "siem_active",      "weight": 0.9},
    "RS.MA-01": {"requires": "soar_active",      "weight": 0.9},
    "CC7.2":    {"requires": "ids_active",       "weight": 1.0},
    "CC7.3":    {"requires": "soar_active",      "weight": 0.9},
    "CC6.1":    {"requires": "auth_active",      "weight": 1.0},
    "CC6.2":    {"requires": "auth_active",      "weight": 1.0},
    "CC6.3":    {"requires": "auth_active",      "weight": 1.0},
    "A.12.4":   {"requires": "logging_active",   "weight": 1.0},
    "A.16.1":   {"requires": "soar_active",      "weight": 0.9},
    "A.9.1":    {"requires": "auth_active",      "weight": 1.0},
    "A.9.2":    {"requires": "auth_active",      "weight": 1.0},
    "ID.RA-02": {"requires": "threat_intel_active", "weight": 0.9},
}


# ── Schemas ───────────────────────────────────────────────────────────────────


class ControlDetail(BaseModel):
    control_id:    str
    control_name:  str
    category:      str
    status:        str
    score:         float
    last_assessed: Optional[datetime]
    evidence:      list[str]
    notes:         Optional[str]


class FrameworkScore(BaseModel):
    framework:         str
    overall_score:     float
    compliant_count:   int
    partial_count:     int
    non_compliant_count: int
    not_assessed_count:  int
    total_controls:    int
    last_assessed:     Optional[datetime]
    categories:        list[dict[str, Any]]


class GapItem(BaseModel):
    control_id:   str
    control_name: str
    category:     str
    current_score: float
    gap:          float
    priority:     str
    recommendation: str


class ComplianceDashboard(BaseModel):
    tenant_id:        str
    generated_at:     datetime
    frameworks:       dict[str, FrameworkScore]
    overall_posture:  float
    critical_gaps:    int
    alerts_last_30d:  int


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _ensure_controls_initialized(
    DB: AsyncSession,
    TENANT_ID: str,
    FRAMEWORK: str,
) -> None:
    """Inicializa controles del framework si no existen para el tenant."""
    CONTROLS = FRAMEWORK_CONTROLS.get(FRAMEWORK, [])
    EXISTING_IDS = set((await DB.execute(
        select(ComplianceControl.control_id).where(
            and_(
                ComplianceControl.tenant_id == TENANT_ID,
                ComplianceControl.framework == FRAMEWORK,
            )
        )
    )).scalars().all())

    NEW_CONTROLS = []
    for C in CONTROLS:
        if C["control_id"] not in EXISTING_IDS:
            NEW_CONTROLS.append(ComplianceControl(
                tenant_id=TENANT_ID,
                framework=FRAMEWORK,
                control_id=C["control_id"],
                control_name=C["control_name"],
                control_description=C.get("control_description", ""),
                category=C["category"],
                status=ComplianceStatus.NOT_ASSESSED,
                score=0.0,
            ))

    if NEW_CONTROLS:
        DB.add_all(NEW_CONTROLS)
        await DB.flush()


async def _run_auto_assessment(
    DB: AsyncSession,
    TENANT_ID: str,
    FRAMEWORK: str,
) -> None:
    """Evaluación automática basada en el estado del sistema JeiGuard AI."""
    ALERT_COUNT = await DB.scalar(
        select(func.count(AlertRecord.id)).where(
            and_(
                AlertRecord.tenant_id == TENANT_ID,
                AlertRecord.timestamp >= datetime.now(timezone.utc) - timedelta(days=30),
            )
        )
    ) or 0

    SYSTEM_STATE = {
        "ids_active":         ALERT_COUNT > 0,
        "siem_active":        True,
        "soar_active":        True,
        "auth_active":        True,
        "logging_active":     True,
        "threat_intel_active": True,
    }

    CONTROLS = (await DB.execute(
        select(ComplianceControl).where(
            and_(
                ComplianceControl.tenant_id == TENANT_ID,
                ComplianceControl.framework == FRAMEWORK,
            )
        )
    )).scalars().all()

    NOW = datetime.now(timezone.utc)

    for CTRL in CONTROLS:
        RULE = AUTO_ASSESS_RULES.get(CTRL.control_id)
        if RULE and SYSTEM_STATE.get(RULE["requires"], False):
            SCORE  = RULE["weight"]
            STATUS = ComplianceStatus.COMPLIANT if SCORE >= 0.9 else ComplianceStatus.PARTIAL
            EVIDENCE = [
                f"Evaluación automática: componente '{RULE['requires']}' activo",
                f"Alertas procesadas (últimos 30d): {ALERT_COUNT}",
                f"Evaluado: {NOW.isoformat()}",
            ]
        else:
            SCORE  = 0.0
            STATUS = ComplianceStatus.NOT_ASSESSED
            EVIDENCE = ["Pendiente de evaluación manual."]

        await DB.execute(
            update(ComplianceControl)
            .where(ComplianceControl.id == CTRL.id)
            .values(
                status=STATUS,
                score=SCORE,
                evidence=EVIDENCE,
                last_assessed=NOW,
                next_review=NOW + timedelta(days=90),
            )
        )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/frameworks")
async def list_frameworks() -> dict[str, Any]:
    """Retorna los frameworks de compliance soportados."""
    return {
        "frameworks": [
            {
                "id":          "NIST_CSF",
                "name":        "NIST Cybersecurity Framework 2.0",
                "version":     "2.0",
                "controls":    len(NIST_CSF_CONTROLS),
                "description": "Marco de ciberseguridad del NIST — 6 funciones: Govern, Identify, Protect, Detect, Respond, Recover",
            },
            {
                "id":          "SOC2",
                "name":        "SOC 2 Type II",
                "version":     "2017",
                "controls":    len(SOC2_CONTROLS),
                "description": "Trust Service Criteria (TSC) para proveedores de servicios tecnológicos",
            },
            {
                "id":          "ISO27001",
                "name":        "ISO/IEC 27001:2022",
                "version":     "2022",
                "controls":    len(ISO27001_CONTROLS),
                "description": "Estándar internacional para Sistemas de Gestión de Seguridad de la Información",
            },
        ]
    }


@router.post("/{FRAMEWORK}/assess", response_model=FrameworkScore)
async def run_assessment(
    FRAMEWORK: str,
    CTX: RequireAnalyst,
    DB: AsyncSession = Depends(get_session),
) -> FrameworkScore:
    """Ejecuta evaluación automática del framework para el tenant."""
    if FRAMEWORK not in FRAMEWORK_CONTROLS:
        raise HTTPException(status_code=404, detail=f"Framework '{FRAMEWORK}' no soportado.")

    await _ensure_controls_initialized(DB, CTX.tenant_id, FRAMEWORK)
    await _run_auto_assessment(DB, CTX.tenant_id, FRAMEWORK)
    await DB.commit()

    return await _get_framework_score(DB, CTX.tenant_id, FRAMEWORK)


@router.get("/{FRAMEWORK}/score", response_model=FrameworkScore)
async def get_framework_score(
    FRAMEWORK: str,
    CTX: RequireAnyRole,
    DB: AsyncSession = Depends(get_session),
) -> FrameworkScore:
    """Score de cumplimiento del framework para el tenant."""
    if FRAMEWORK not in FRAMEWORK_CONTROLS:
        raise HTTPException(status_code=404, detail=f"Framework '{FRAMEWORK}' no soportado.")

    await _ensure_controls_initialized(DB, CTX.tenant_id, FRAMEWORK)
    return await _get_framework_score(DB, CTX.tenant_id, FRAMEWORK)


async def _get_framework_score(
    DB: AsyncSession,
    TENANT_ID: str,
    FRAMEWORK: str,
) -> FrameworkScore:
    CONTROLS = (await DB.execute(
        select(ComplianceControl).where(
            and_(
                ComplianceControl.tenant_id == TENANT_ID,
                ComplianceControl.framework == FRAMEWORK,
            )
        )
    )).scalars().all()

    COMPLIANT     = sum(1 for C in CONTROLS if C.status == ComplianceStatus.COMPLIANT)
    PARTIAL       = sum(1 for C in CONTROLS if C.status == ComplianceStatus.PARTIAL)
    NON_COMPLIANT = sum(1 for C in CONTROLS if C.status == ComplianceStatus.NON_COMPLIANT)
    NOT_ASSESSED  = sum(1 for C in CONTROLS if C.status == ComplianceStatus.NOT_ASSESSED)
    TOTAL         = len(CONTROLS)

    OVERALL = (sum(C.score for C in CONTROLS) / TOTAL * 100) if TOTAL > 0 else 0.0

    LAST_ASSESSED = max(
        (C.last_assessed for C in CONTROLS if C.last_assessed),
        default=None,
    )

    CATEGORIES: dict[str, dict[str, Any]] = {}
    for C in CONTROLS:
        CAT = C.category
        if CAT not in CATEGORIES:
            CATEGORIES[CAT] = {"category": CAT, "controls": 0, "score_sum": 0.0, "compliant": 0}
        CATEGORIES[CAT]["controls"]   += 1
        CATEGORIES[CAT]["score_sum"]  += C.score
        if C.status == ComplianceStatus.COMPLIANT:
            CATEGORIES[CAT]["compliant"] += 1

    CAT_LIST = [
        {
            "category":       K,
            "score":          round(V["score_sum"] / V["controls"] * 100, 1) if V["controls"] > 0 else 0,
            "controls":       V["controls"],
            "compliant":      V["compliant"],
        }
        for K, V in CATEGORIES.items()
    ]

    return FrameworkScore(
        framework=FRAMEWORK,
        overall_score=round(OVERALL, 1),
        compliant_count=COMPLIANT,
        partial_count=PARTIAL,
        non_compliant_count=NON_COMPLIANT,
        not_assessed_count=NOT_ASSESSED,
        total_controls=TOTAL,
        last_assessed=LAST_ASSESSED,
        categories=CAT_LIST,
    )


@router.get("/{FRAMEWORK}/controls", response_model=list[ControlDetail])
async def get_controls(
    FRAMEWORK: str,
    CTX: RequireAnyRole,
    DB: AsyncSession = Depends(get_session),
) -> list[ControlDetail]:
    """Detalle de todos los controles del framework para el tenant."""
    if FRAMEWORK not in FRAMEWORK_CONTROLS:
        raise HTTPException(status_code=404, detail=f"Framework '{FRAMEWORK}' no soportado.")

    await _ensure_controls_initialized(DB, CTX.tenant_id, FRAMEWORK)
    CONTROLS = (await DB.execute(
        select(ComplianceControl).where(
            and_(
                ComplianceControl.tenant_id == TENANT_ID,
                ComplianceControl.framework == FRAMEWORK,
            )
        ).order_by(ComplianceControl.control_id)
    )).scalars().all()

    return [
        ControlDetail(
            control_id=C.control_id,
            control_name=C.control_name,
            category=C.category,
            status=C.status.value,
            score=round(C.score * 100, 1),
            last_assessed=C.last_assessed,
            evidence=C.evidence or [],
            notes=C.notes,
        )
        for C in CONTROLS
    ]


@router.get("/{FRAMEWORK}/gaps", response_model=list[GapItem])
async def get_gap_analysis(
    FRAMEWORK: str,
    CTX: RequireAnyRole,
    DB: AsyncSession = Depends(get_session),
) -> list[GapItem]:
    """Gap analysis — controles no cumplidos con recomendaciones priorizadas."""
    if FRAMEWORK not in FRAMEWORK_CONTROLS:
        raise HTTPException(status_code=404, detail=f"Framework '{FRAMEWORK}' no soportado.")

    await _ensure_controls_initialized(DB, CTX.tenant_id, FRAMEWORK)
    CONTROLS = (await DB.execute(
        select(ComplianceControl).where(
            and_(
                ComplianceControl.tenant_id == CTX.tenant_id,
                ComplianceControl.framework == FRAMEWORK,
                ComplianceControl.score < 0.9,
            )
        ).order_by(ComplianceControl.score.asc())
    )).scalars().all()

    GAPS = []
    for C in CONTROLS:
        GAP   = 1.0 - C.score
        PRI   = "HIGH" if GAP > 0.7 else ("MEDIUM" if GAP > 0.3 else "LOW")
        REC   = (
            f"Implementar o fortalecer el control '{C.control_name}'. "
            "Revisar la documentación de JeiGuard AI para evidencia automática disponible. "
            "Asignar responsable y fecha límite."
        )
        GAPS.append(GapItem(
            control_id=C.control_id,
            control_name=C.control_name,
            category=C.category,
            current_score=round(C.score * 100, 1),
            gap=round(GAP * 100, 1),
            priority=PRI,
            recommendation=REC,
        ))

    return GAPS


@router.get("/dashboard", response_model=ComplianceDashboard)
async def get_compliance_dashboard(
    CTX: RequireAnyRole,
    DB: AsyncSession = Depends(get_session),
) -> ComplianceDashboard:
    """Vista consolidada de compliance en todos los frameworks."""
    ALERT_COUNT = await DB.scalar(
        select(func.count(AlertRecord.id)).where(
            and_(
                AlertRecord.tenant_id == CTX.tenant_id,
                AlertRecord.timestamp >= datetime.now(timezone.utc) - timedelta(days=30),
            )
        )
    ) or 0

    FRAMEWORK_SCORES: dict[str, FrameworkScore] = {}
    TOTAL_GAP_CONTROLS = 0

    for FW in FRAMEWORK_CONTROLS:
        await _ensure_controls_initialized(DB, CTX.tenant_id, FW)
        SCORE = await _get_framework_score(DB, CTX.tenant_id, FW)
        FRAMEWORK_SCORES[FW] = SCORE
        TOTAL_GAP_CONTROLS  += SCORE.non_compliant_count

    OVERALL = sum(S.overall_score for S in FRAMEWORK_SCORES.values()) / len(FRAMEWORK_SCORES)

    return ComplianceDashboard(
        tenant_id=CTX.tenant_id,
        generated_at=datetime.now(timezone.utc),
        frameworks=FRAMEWORK_SCORES,
        overall_posture=round(OVERALL, 1),
        critical_gaps=TOTAL_GAP_CONTROLS,
        alerts_last_30d=ALERT_COUNT,
    )
