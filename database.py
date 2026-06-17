"""
database.py
════════════
Capa de persistencia relacional de JeiGuard AI.
PostgreSQL + SQLAlchemy 2.0 async — multi-tenant, RBAC, audit trail, compliance.

Entidades principales:
  Tenant → User → UserSession → AuditLog
  Tenant → AlertRecord → IncidentAlert → Incident
  Tenant → Report
  Tenant → ComplianceControl
  CVECorrelation (global)
  ModelRegistry (global)
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import AsyncGenerator

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship

# ── Variables de entorno ──────────────────────────────────────────────────────

_raw_db_url: str = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://jeiguard:jeiguard2026@localhost:5432/jeiguard_ai",
)
# Railway entrega postgresql:// — asyncpg necesita postgresql+asyncpg://
DATABASE_URL: str = _raw_db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

# ── Base ORM ──────────────────────────────────────────────────────────────────


class Base(DeclarativeBase):
    pass


# ── Enumeraciones ─────────────────────────────────────────────────────────────


class UserRole(str, PyEnum):
    SUPER_ADMIN = "super_admin"
    ADMIN       = "admin"
    ANALYST     = "analyst"
    VIEWER      = "viewer"
    READONLY    = "readonly"


class TenantTier(str, PyEnum):
    FREE         = "free"
    STARTER      = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE   = "enterprise"


class IncidentStatus(str, PyEnum):
    OPEN         = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED    = "CONTAINED"
    RESOLVED     = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ReportType(str, PyEnum):
    EXECUTIVE   = "executive"
    TECHNICAL   = "technical"
    COMPLIANCE  = "compliance"
    INCIDENT    = "incident"
    THREAT_HUNT = "threat_hunt"


class ComplianceStatus(str, PyEnum):
    COMPLIANT     = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIAL       = "PARTIAL"
    NOT_ASSESSED  = "NOT_ASSESSED"


# ── Modelos ───────────────────────────────────────────────────────────────────


class Tenant(Base):
    """Organización cliente — unidad fundamental de aislamiento multi-tenant."""

    __tablename__ = "tenants"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name            = Column(String(255), unique=True, nullable=False, index=True)
    slug            = Column(String(100), unique=True, nullable=False)
    tier            = Column(Enum(TenantTier), default=TenantTier.FREE, nullable=False)
    api_key_hash    = Column(String(64), unique=True, nullable=False)
    is_active       = Column(Boolean, default=True, nullable=False)
    config          = Column(JSONB, default=dict)
    max_sensors     = Column(Integer, default=5)
    max_users       = Column(Integer, default=10)
    webhook_url     = Column(String(500), nullable=True)
    contact_email   = Column(String(255), nullable=True)
    created_at      = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at      = Column(DateTime(timezone=True), nullable=True)

    users       = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    alerts      = relationship("AlertRecord", back_populates="tenant")
    incidents   = relationship("Incident", back_populates="tenant")
    reports     = relationship("Report", back_populates="tenant")


class User(Base):
    """Usuario del sistema con rol RBAC y soporte MFA."""

    __tablename__ = "users"

    id                    = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id             = Column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    username              = Column(String(100), nullable=False, index=True)
    email                 = Column(String(255), nullable=False, index=True)
    hashed_password       = Column(String(255), nullable=False)
    full_name             = Column(String(255), default="")
    role                  = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active             = Column(Boolean, default=True, nullable=False)
    is_email_verified     = Column(Boolean, default=False)
    last_login            = Column(DateTime(timezone=True), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until          = Column(DateTime(timezone=True), nullable=True)
    mfa_enabled           = Column(Boolean, default=False)
    mfa_secret            = Column(String(32), nullable=True)
    avatar_url            = Column(String(500), nullable=True)
    timezone_pref         = Column(String(50), default="UTC")
    created_at            = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at            = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("tenant_id", "email",    name="uq_tenant_user_email"),
        UniqueConstraint("tenant_id", "username", name="uq_tenant_user_username"),
    )

    tenant      = relationship("Tenant", back_populates="users")
    sessions    = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    audit_logs  = relationship("AuditLog", back_populates="user")


class UserSession(Base):
    """Sesión activa de usuario — refresh token + JTI del access token."""

    __tablename__ = "user_sessions"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id             = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    refresh_token_hash  = Column(String(64), unique=True, nullable=False, index=True)
    access_jti          = Column(String(36), unique=True, nullable=False, index=True)
    ip_address          = Column(String(45), nullable=True)
    user_agent          = Column(String(500), nullable=True)
    is_active           = Column(Boolean, default=True, nullable=False)
    expires_at          = Column(DateTime(timezone=True), nullable=False)
    created_at          = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    last_used           = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="sessions")


class AlertRecord(Base):
    """Espejo SQL de las alertas IDS — permite queries relacionales y reportes."""

    __tablename__ = "alert_records"

    id                 = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id          = Column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    alert_id           = Column(String(36), unique=True, nullable=False, index=True)
    timestamp          = Column(DateTime(timezone=True), nullable=False, index=True)
    alert_level        = Column(String(20), nullable=False, index=True)
    attack_category    = Column(String(50), nullable=False, index=True)
    confidence         = Column(Float, nullable=False)
    src_ip             = Column(String(45), nullable=False, index=True)
    dst_ip             = Column(String(45), nullable=False)
    dst_port           = Column(Integer, nullable=False)
    protocol           = Column(String(10), nullable=False)
    sensor_id          = Column(String(100), nullable=False, index=True)
    description        = Column(Text, nullable=False)
    recommended_action = Column(Text, nullable=False)
    mitre_technique    = Column(String(20), nullable=True)
    false_positive     = Column(Boolean, default=False)
    acknowledged       = Column(Boolean, default=False)
    acknowledged_by    = Column(UUID(as_uuid=True), nullable=True)
    acknowledged_at    = Column(DateTime(timezone=True), nullable=True)
    cve_ids            = Column(JSONB, default=list)
    shap_features      = Column(JSONB, default=dict)
    threat_intel       = Column(JSONB, default=dict)

    __table_args__ = (
        Index("ix_alert_tenant_time",  "tenant_id", "timestamp"),
        Index("ix_alert_tenant_level", "tenant_id", "alert_level"),
        Index("ix_alert_tenant_cat",   "tenant_id", "attack_category"),
    )

    tenant          = relationship("Tenant", back_populates="alerts")
    incident_links  = relationship("IncidentAlert", back_populates="alert")


class Incident(Base):
    """Incidente de seguridad — agrupa alertas correlacionadas."""

    __tablename__ = "incidents"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id       = Column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    title           = Column(String(500), nullable=False)
    description     = Column(Text, nullable=True)
    severity        = Column(String(20), nullable=False, default="MEDIUM")
    status          = Column(
        Enum(IncidentStatus),
        default=IncidentStatus.OPEN,
        nullable=False,
        index=True,
    )
    assigned_to     = Column(UUID(as_uuid=True), nullable=True)
    kill_chain_phase = Column(String(100), nullable=True)
    tactics         = Column(JSONB, default=list)
    techniques      = Column(JSONB, default=list)
    affected_ips    = Column(JSONB, default=list)
    timeline        = Column(JSONB, default=list)
    llm_analysis    = Column(Text, nullable=True)
    response_actions = Column(JSONB, default=list)
    false_positive  = Column(Boolean, default=False)
    resolved_at     = Column(DateTime(timezone=True), nullable=True)
    created_at      = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at      = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_incident_tenant_status", "tenant_id", "status"),
    )

    tenant = relationship("Tenant", back_populates="incidents")
    alerts = relationship("IncidentAlert", back_populates="incident")


class IncidentAlert(Base):
    """Relación N:M entre Incidents y AlertRecords."""

    __tablename__ = "incident_alerts"

    incident_id = Column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        primary_key=True,
    )
    alert_id    = Column(
        UUID(as_uuid=True),
        ForeignKey("alert_records.id", ondelete="CASCADE"),
        primary_key=True,
    )
    added_at    = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    incident = relationship("Incident", back_populates="alerts")
    alert    = relationship("AlertRecord", back_populates="incident_links")


class Report(Base):
    """Reporte generado (PDF/HTML) — ejecutivo, técnico o de compliance."""

    __tablename__ = "reports"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id      = Column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    title          = Column(String(500), nullable=False)
    report_type    = Column(Enum(ReportType), nullable=False)
    period_start   = Column(DateTime(timezone=True), nullable=False)
    period_end     = Column(DateTime(timezone=True), nullable=False)
    generated_by   = Column(UUID(as_uuid=True), nullable=False)
    status         = Column(String(20), default="PENDING")
    file_path      = Column(String(500), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    summary_data   = Column(JSONB, default=dict)
    download_count = Column(Integer, default=0)
    created_at     = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    tenant = relationship("Tenant", back_populates="reports")


class AuditLog(Base):
    """Log de auditoría inmutable — toda acción de usuario queda registrada."""

    __tablename__ = "audit_logs"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id     = Column(UUID(as_uuid=True), nullable=False, index=True)
    user_id       = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    action        = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=False)
    resource_id   = Column(String(100), nullable=True)
    details       = Column(JSONB, default=dict)
    ip_address    = Column(String(45), nullable=True)
    user_agent    = Column(String(500), nullable=True)
    success       = Column(Boolean, default=True)
    timestamp     = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    __table_args__ = (
        Index("ix_audit_tenant_time",   "tenant_id", "timestamp"),
        Index("ix_audit_tenant_action", "tenant_id", "action"),
    )

    user = relationship("User", back_populates="audit_logs")


class CVECorrelation(Base):
    """Correlación global ataque ↔ CVE — cache de consultas a NVD/NIST."""

    __tablename__ = "cve_correlations"

    id                 = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attack_category    = Column(String(50), nullable=False, index=True)
    cve_id             = Column(String(20), nullable=False, index=True)
    cve_description    = Column(Text, nullable=True)
    cvss_v3_score      = Column(Float, nullable=True)
    cvss_v3_vector     = Column(String(100), nullable=True)
    cvss_severity      = Column(String(20), nullable=True)
    published_date     = Column(DateTime(timezone=True), nullable=True)
    last_modified      = Column(DateTime(timezone=True), nullable=True)
    references         = Column(JSONB, default=list)
    mapping_confidence = Column(Float, default=0.7)
    cached_at          = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        UniqueConstraint("attack_category", "cve_id", name="uq_attack_cve"),
    )


class ComplianceControl(Base):
    """Control de cumplimiento por framework y tenant."""

    __tablename__ = "compliance_controls"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id           = Column(UUID(as_uuid=True), nullable=False, index=True)
    framework           = Column(String(50), nullable=False, index=True)
    control_id          = Column(String(50), nullable=False)
    control_name        = Column(String(500), nullable=False)
    control_description = Column(Text, nullable=True)
    category            = Column(String(100), nullable=False)
    status              = Column(
        Enum(ComplianceStatus),
        default=ComplianceStatus.NOT_ASSESSED,
        nullable=False,
    )
    evidence            = Column(JSONB, default=list)
    last_assessed       = Column(DateTime(timezone=True), nullable=True)
    next_review         = Column(DateTime(timezone=True), nullable=True)
    score               = Column(Float, default=0.0)
    notes               = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "framework", "control_id",
            name="uq_tenant_framework_control",
        ),
    )


class ModelRegistry(Base):
    """Registro de versiones de modelos ML — historial de métricas y artifacts."""

    __tablename__ = "model_registry"

    id                   = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name                 = Column(String(100), nullable=False)
    version              = Column(String(20), nullable=False)
    model_type           = Column(String(50), nullable=False)
    mlflow_run_id        = Column(String(50), nullable=True)
    mlflow_experiment_id = Column(String(50), nullable=True)
    accuracy             = Column(Float, nullable=True)
    f1_macro             = Column(Float, nullable=True)
    false_positive_rate  = Column(Float, nullable=True)
    roc_auc              = Column(Float, nullable=True)
    latency_p99_ms       = Column(Float, nullable=True)
    is_production        = Column(Boolean, default=False)
    is_champion          = Column(Boolean, default=False)
    artifact_path        = Column(String(500), nullable=True)
    training_dataset     = Column(String(200), nullable=True)
    training_samples     = Column(Integer, nullable=True)
    hyperparameters      = Column(JSONB, default=dict)
    tags                 = Column(JSONB, default=dict)
    promoted_at          = Column(DateTime(timezone=True), nullable=True)
    created_at           = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_model_name_version"),
    )


# ── Motor async y fábrica de sesiones ────────────────────────────────────────

_engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=20,
    max_overflow=40,
    pool_pre_ping=True,
    pool_recycle=3600,
)

AsyncSessionLocal = async_sessionmaker(
    _engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency de FastAPI que provee una sesión de base de datos."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_tables() -> None:
    """Crea todas las tablas en la base de datos (solo para desarrollo/test)."""
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_tables() -> None:
    """Elimina todas las tablas (solo para tests de integración)."""
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
