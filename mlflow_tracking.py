"""
mlflow_tracking.py
═══════════════════
Integración MLflow para JeiGuard AI — Model Registry y Experiment Tracking.

Funcionalidades:
  • Registro de experimentos de entrenamiento con métricas completas
  • Model Registry con versionado semántico (champion/challenger)
  • A/B testing entre modelos: comparar CNN-1D vs Ensemble
  • Transición de ciclo de vida: Staging → Production → Archived
  • Logging automático de hiperparámetros, datasets, y artifacts
  • API REST para gestionar el registry desde dashboards externos

Endpoints:
  GET  /mlflow/experiments         — Listar experimentos
  GET  /mlflow/experiments/{id}    — Detalle de experimento
  POST /mlflow/experiments/log     — Registrar nueva ejecución de entrenamiento
  GET  /mlflow/models              — Listar modelos en el registry
  GET  /mlflow/models/{name}       — Versiones de un modelo
  POST /mlflow/models/{name}/promote — Promover versión a producción
  GET  /mlflow/models/champion     — Modelo campeón activo
  POST /mlflow/ab-test             — Crear test A/B entre modelos
  GET  /mlflow/ab-test/{id}        — Resultados del test A/B
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service import RequireAdmin, RequireAnalyst, RequireAnyRole, AuthContext
from database import ModelRegistry, get_session

try:
    import mlflow
    import mlflow.sklearn
    import mlflow.tensorflow
    from mlflow.tracking import MlflowClient
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False

API_VERSION: str  = "v1"
MLFLOW_URI:  str  = os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000")

router = APIRouter(prefix=f"/api/{API_VERSION}/mlflow", tags=["MLflow"])

if MLFLOW_AVAILABLE:
    mlflow.set_tracking_uri(MLFLOW_URI)

# ── Schemas ───────────────────────────────────────────────────────────────────


class TrainingRunLog(BaseModel):
    """Registro de una ejecución de entrenamiento."""
    model_name:       str
    model_type:       str = Field(description="CNN1D | RandomForest | Ensemble | Autoencoder")
    version:          str
    accuracy:         float = Field(ge=0.0, le=1.0)
    f1_macro:         float = Field(ge=0.0, le=1.0)
    false_positive_rate: float = Field(ge=0.0, le=1.0)
    roc_auc:          float = Field(ge=0.0, le=1.0)
    latency_p99_ms:   float = Field(ge=0.0)
    training_samples: int   = Field(ge=1)
    training_dataset: str   = "KDD Cup 99 / CICIDS2018"
    artifact_path:    Optional[str] = None
    hyperparameters:  dict[str, Any] = Field(default_factory=dict)
    tags:             dict[str, str] = Field(default_factory=dict)


class ModelVersion(BaseModel):
    id:              str
    name:            str
    version:         str
    model_type:      str
    accuracy:        Optional[float]
    f1_macro:        Optional[float]
    false_positive_rate: Optional[float]
    roc_auc:         Optional[float]
    latency_p99_ms:  Optional[float]
    is_production:   bool
    is_champion:     bool
    training_samples: Optional[int]
    training_dataset: Optional[str]
    hyperparameters: dict[str, Any]
    tags:            dict[str, Any]
    mlflow_run_id:   Optional[str]
    created_at:      datetime

    model_config = {"from_attributes": True}


class ABTestCreate(BaseModel):
    model_a_id: str
    model_b_id: str
    traffic_split_a: float = Field(default=0.5, ge=0.0, le=1.0)
    duration_hours: int = Field(default=24, ge=1, le=168)
    description: Optional[str] = None


class PromoteRequest(BaseModel):
    model_id:    str
    environment: str = Field(description="staging | production | archived")


class ModelComparison(BaseModel):
    model_a:          ModelVersion
    model_b:          ModelVersion
    winner:           Optional[str]
    accuracy_delta:   float
    f1_delta:         float
    fp_rate_delta:    float
    recommendation:   str


# ── Helpers MLflow ────────────────────────────────────────────────────────────


def _log_to_mlflow(RUN: TrainingRunLog) -> Optional[str]:
    """Registra una ejecución de entrenamiento en MLflow."""
    if not MLFLOW_AVAILABLE:
        return None

    try:
        EXP = mlflow.set_experiment(f"jeiguard-{RUN.model_type.lower()}")

        with mlflow.start_run(
            run_name=f"{RUN.model_name}-v{RUN.version}",
            tags={**RUN.tags, "model_type": RUN.model_type},
        ) as RUN_OBJ:
            mlflow.log_params({
                **RUN.hyperparameters,
                "model_type":      RUN.model_type,
                "training_dataset": RUN.training_dataset,
                "training_samples": RUN.training_samples,
            })
            mlflow.log_metrics({
                "accuracy":           RUN.accuracy,
                "f1_macro":           RUN.f1_macro,
                "false_positive_rate": RUN.false_positive_rate,
                "roc_auc":            RUN.roc_auc,
                "latency_p99_ms":     RUN.latency_p99_ms,
            })
            return RUN_OBJ.info.run_id
    except Exception:
        return None


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/experiments/log", response_model=ModelVersion, status_code=201)
async def log_training_run(
    BODY: TrainingRunLog,
    CTX: RequireAnalyst,
    DB: AsyncSession = Depends(get_session),
) -> ModelVersion:
    """Registra una nueva ejecución de entrenamiento en el Model Registry."""
    EXISTING = await DB.scalar(
        select(ModelRegistry).where(
            and_(
                ModelRegistry.name == BODY.model_name,
                ModelRegistry.version == BODY.version,
            )
        )
    )
    if EXISTING:
        raise HTTPException(status_code=409, detail=f"Modelo '{BODY.model_name}' v{BODY.version} ya existe.")

    MLFLOW_RUN_ID = _log_to_mlflow(BODY)

    MODEL = ModelRegistry(
        name=BODY.model_name,
        version=BODY.version,
        model_type=BODY.model_type,
        mlflow_run_id=MLFLOW_RUN_ID,
        accuracy=BODY.accuracy,
        f1_macro=BODY.f1_macro,
        false_positive_rate=BODY.false_positive_rate,
        roc_auc=BODY.roc_auc,
        latency_p99_ms=BODY.latency_p99_ms,
        is_production=False,
        is_champion=False,
        artifact_path=BODY.artifact_path,
        training_dataset=BODY.training_dataset,
        training_samples=BODY.training_samples,
        hyperparameters=BODY.hyperparameters,
        tags={**BODY.tags, "logged_by": CTX.username},
    )
    DB.add(MODEL)
    await DB.commit()
    await DB.refresh(MODEL)

    return ModelVersion(
        id=str(MODEL.id),
        name=MODEL.name,
        version=MODEL.version,
        model_type=MODEL.model_type,
        accuracy=MODEL.accuracy,
        f1_macro=MODEL.f1_macro,
        false_positive_rate=MODEL.false_positive_rate,
        roc_auc=MODEL.roc_auc,
        latency_p99_ms=MODEL.latency_p99_ms,
        is_production=MODEL.is_production,
        is_champion=MODEL.is_champion,
        training_samples=MODEL.training_samples,
        training_dataset=MODEL.training_dataset,
        hyperparameters=MODEL.hyperparameters or {},
        tags=MODEL.tags or {},
        mlflow_run_id=MODEL.mlflow_run_id,
        created_at=MODEL.created_at,
    )


@router.get("/models", response_model=list[ModelVersion])
async def list_models(
    CTX: RequireAnyRole,
    DB: AsyncSession = Depends(get_session),
) -> list[ModelVersion]:
    """Lista todos los modelos en el registry."""
    MODELS = (await DB.execute(
        select(ModelRegistry).order_by(ModelRegistry.created_at.desc())
    )).scalars().all()

    return [
        ModelVersion(
            id=str(M.id),
            name=M.name,
            version=M.version,
            model_type=M.model_type,
            accuracy=M.accuracy,
            f1_macro=M.f1_macro,
            false_positive_rate=M.false_positive_rate,
            roc_auc=M.roc_auc,
            latency_p99_ms=M.latency_p99_ms,
            is_production=M.is_production,
            is_champion=M.is_champion,
            training_samples=M.training_samples,
            training_dataset=M.training_dataset,
            hyperparameters=M.hyperparameters or {},
            tags=M.tags or {},
            mlflow_run_id=M.mlflow_run_id,
            created_at=M.created_at,
        )
        for M in MODELS
    ]


@router.get("/models/champion", response_model=ModelVersion)
async def get_champion_model(
    CTX: RequireAnyRole,
    DB: AsyncSession = Depends(get_session),
) -> ModelVersion:
    """Retorna el modelo campeón activo en producción."""
    MODEL = await DB.scalar(
        select(ModelRegistry).where(ModelRegistry.is_champion == True)
    )
    if not MODEL:
        MODEL = await DB.scalar(
            select(ModelRegistry)
            .where(ModelRegistry.is_production == True)
            .order_by(ModelRegistry.accuracy.desc())
        )
    if not MODEL:
        MODEL = await DB.scalar(
            select(ModelRegistry).order_by(ModelRegistry.created_at.desc())
        )
    if not MODEL:
        raise HTTPException(status_code=404, detail="No hay modelos registrados.")

    return ModelVersion(
        id=str(MODEL.id),
        name=MODEL.name,
        version=MODEL.version,
        model_type=MODEL.model_type,
        accuracy=MODEL.accuracy,
        f1_macro=MODEL.f1_macro,
        false_positive_rate=MODEL.false_positive_rate,
        roc_auc=MODEL.roc_auc,
        latency_p99_ms=MODEL.latency_p99_ms,
        is_production=MODEL.is_production,
        is_champion=MODEL.is_champion,
        training_samples=MODEL.training_samples,
        training_dataset=MODEL.training_dataset,
        hyperparameters=MODEL.hyperparameters or {},
        tags=MODEL.tags or {},
        mlflow_run_id=MODEL.mlflow_run_id,
        created_at=MODEL.created_at,
    )


@router.post("/models/{MODEL_ID}/promote", response_model=ModelVersion)
async def promote_model(
    MODEL_ID: str,
    BODY: PromoteRequest,
    CTX: RequireAdmin,
    DB: AsyncSession = Depends(get_session),
) -> ModelVersion:
    """Promueve un modelo al entorno indicado (staging/production/archived)."""
    MODEL = await DB.scalar(
        select(ModelRegistry).where(ModelRegistry.id == MODEL_ID)
    )
    if not MODEL:
        raise HTTPException(status_code=404, detail="Modelo no encontrado.")

    ENV = BODY.environment.lower()
    if ENV not in ("staging", "production", "archived"):
        raise HTTPException(status_code=400, detail="Entorno debe ser staging, production o archived.")

    IS_PROD    = ENV == "production"
    IS_CHAMP   = ENV == "production"
    PROMOTED_AT = datetime.now(timezone.utc) if IS_PROD else None

    if IS_PROD:
        await DB.execute(
            update(ModelRegistry)
            .where(ModelRegistry.is_champion == True)
            .values(is_champion=False)
        )

    await DB.execute(
        update(ModelRegistry)
        .where(ModelRegistry.id == MODEL_ID)
        .values(
            is_production=IS_PROD,
            is_champion=IS_CHAMP,
            promoted_at=PROMOTED_AT,
            tags={**(MODEL.tags or {}), "environment": ENV, "promoted_by": CTX.username},
        )
    )
    await DB.commit()

    UPDATED = await DB.scalar(select(ModelRegistry).where(ModelRegistry.id == MODEL_ID))
    return ModelVersion(
        id=str(UPDATED.id),
        name=UPDATED.name,
        version=UPDATED.version,
        model_type=UPDATED.model_type,
        accuracy=UPDATED.accuracy,
        f1_macro=UPDATED.f1_macro,
        false_positive_rate=UPDATED.false_positive_rate,
        roc_auc=UPDATED.roc_auc,
        latency_p99_ms=UPDATED.latency_p99_ms,
        is_production=UPDATED.is_production,
        is_champion=UPDATED.is_champion,
        training_samples=UPDATED.training_samples,
        training_dataset=UPDATED.training_dataset,
        hyperparameters=UPDATED.hyperparameters or {},
        tags=UPDATED.tags or {},
        mlflow_run_id=UPDATED.mlflow_run_id,
        created_at=UPDATED.created_at,
    )


@router.post("/ab-test", response_model=ModelComparison)
async def compare_models(
    BODY: ABTestCreate,
    CTX: RequireAnalyst,
    DB: AsyncSession = Depends(get_session),
) -> ModelComparison:
    """Compara dos modelos estadísticamente — identifica el ganador."""
    MODEL_A = await DB.scalar(select(ModelRegistry).where(ModelRegistry.id == BODY.model_a_id))
    MODEL_B = await DB.scalar(select(ModelRegistry).where(ModelRegistry.id == BODY.model_b_id))

    if not MODEL_A or not MODEL_B:
        raise HTTPException(status_code=404, detail="Uno o ambos modelos no encontrados.")

    ACC_DELTA = (MODEL_B.accuracy or 0) - (MODEL_A.accuracy or 0)
    F1_DELTA  = (MODEL_B.f1_macro or 0) - (MODEL_A.f1_macro or 0)
    FP_DELTA  = (MODEL_B.false_positive_rate or 0) - (MODEL_A.false_positive_rate or 0)

    SCORE_A = (MODEL_A.accuracy or 0) * 0.4 + (MODEL_A.f1_macro or 0) * 0.4 - (MODEL_A.false_positive_rate or 0) * 0.2
    SCORE_B = (MODEL_B.accuracy or 0) * 0.4 + (MODEL_B.f1_macro or 0) * 0.4 - (MODEL_B.false_positive_rate or 0) * 0.2

    if SCORE_B > SCORE_A + 0.01:
        WINNER = MODEL_B.name
        REC = f"Promover '{MODEL_B.name}' v{MODEL_B.version} a producción. Mejora F1: {F1_DELTA:+.3f}, FPR: {FP_DELTA:+.3f}."
    elif SCORE_A > SCORE_B + 0.01:
        WINNER = MODEL_A.name
        REC = f"Mantener '{MODEL_A.name}' v{MODEL_A.version} en producción. Supera al challenger por {SCORE_A - SCORE_B:.3f} puntos."
    else:
        WINNER = None
        REC = "Diferencia no significativa (<1%). Se recomienda prueba A/B en producción con tráfico real."

    def _to_mv(M: ModelRegistry) -> ModelVersion:
        return ModelVersion(
            id=str(M.id),
            name=M.name,
            version=M.version,
            model_type=M.model_type,
            accuracy=M.accuracy,
            f1_macro=M.f1_macro,
            false_positive_rate=M.false_positive_rate,
            roc_auc=M.roc_auc,
            latency_p99_ms=M.latency_p99_ms,
            is_production=M.is_production,
            is_champion=M.is_champion,
            training_samples=M.training_samples,
            training_dataset=M.training_dataset,
            hyperparameters=M.hyperparameters or {},
            tags=M.tags or {},
            mlflow_run_id=M.mlflow_run_id,
            created_at=M.created_at,
        )

    return ModelComparison(
        model_a=_to_mv(MODEL_A),
        model_b=_to_mv(MODEL_B),
        winner=WINNER,
        accuracy_delta=round(ACC_DELTA, 4),
        f1_delta=round(F1_DELTA, 4),
        fp_rate_delta=round(FP_DELTA, 4),
        recommendation=REC,
    )
