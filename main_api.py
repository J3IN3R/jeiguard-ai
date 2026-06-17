"""
main_api.py
════════════
Aplicación FastAPI principal de JeiGuard AI v2.0.0.

Consolida todos los routers en un único servidor ASGI:
  • /api/v1/auth/*          — Autenticación, RBAC, sesiones, usuarios
  • /api/v1/predict         — Inferencia del modelo IDS
  • /api/v1/reports/*       — Generación y descarga de reportes PDF
  • /api/v1/compliance/*    — Compliance (NIST CSF, SOC2, ISO 27001)
  • /api/v1/cve/*           — Correlación CVE/NVD
  • /api/v1/mlflow/*        — Model Registry y experiment tracking
  • /api/v1/ws/*            — WebSocket streaming de alertas en tiempo real
  • /health                 — Health check
  • /docs                   — Swagger UI (requiere autenticación)
  • /redoc                  — ReDoc

Iniciar:
  uvicorn main_api:app --host 0.0.0.0 --port 8080 --workers 4
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from auth_service import router as auth_router
from compliance_service import router as compliance_router
from cve_correlation_service import router as cve_router
from mlflow_tracking import router as mlflow_router
from otel_tracing import JeiGuardMetrics, setup_telemetry
from report_service import router as report_router
from websocket_gateway import router as ws_router

# ── Lifespan ──────────────────────────────────────────────────────────────────

_start_time: float = time.time()


@asynccontextmanager
async def lifespan(APP: FastAPI) -> AsyncGenerator[None, None]:
    """Inicializa y cierra recursos al inicio/parada del servidor."""
    setup_telemetry(APP)
    _ = JeiGuardMetrics.instance()

    try:
        from database import create_tables
        await create_tables()
    except Exception as EXC:
        print(f"[WARN] No se pudo conectar a PostgreSQL: {EXC}. Continuando sin DB.")

    yield


# ── Aplicación ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="JeiGuard AI — Intrusion Detection System",
    description="""
## JeiGuard AI v2.0.0 — Sistema de Detección de Intrusos con IA

**Características principales:**
- Detección de intrusos en tiempo real con CNN-1D + Random Forest (97.4% precisión)
- Autenticación JWT con RBAC multi-tenant
- Correlación MITRE ATT&CK y CVE/NVD
- Compliance: NIST CSF 2.0, SOC2 Type II, ISO 27001:2022
- Reportes ejecutivos en PDF
- Análisis forense con LLM (Claude API)
- Streaming de alertas en tiempo real (WebSocket)
- Model Registry con MLflow
- Observabilidad con OpenTelemetry + Jaeger

**Autenticación:**
Usar `POST /api/v1/auth/login` para obtener un Bearer token JWT.
Incluirlo en el header: `Authorization: Bearer <token>`
    """,
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    contact={
        "name":  "Jeiner Tello Nuñez",
        "email": "jeinertello1@gmail.com",
        "url":   "https://github.com/j3in3r/jeiguard-ai",
    },
    license_info={
        "name": "MIT",
        "url":  "https://opensource.org/licenses/MIT",
    },
    lifespan=lifespan,
)

# ── Middleware ────────────────────────────────────────────────────────────────

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8501",
        "http://localhost:5000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(REQUEST: Request, CALL_NEXT):
    RESPONSE = await CALL_NEXT(REQUEST)
    RESPONSE.headers["X-Content-Type-Options"]    = "nosniff"
    RESPONSE.headers["X-Frame-Options"]           = "DENY"
    RESPONSE.headers["X-XSS-Protection"]          = "1; mode=block"
    RESPONSE.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    RESPONSE.headers["X-JeiGuard-Version"]        = "2.0.0"
    return RESPONSE


@app.middleware("http")
async def log_requests(REQUEST: Request, CALL_NEXT):
    START = time.perf_counter()
    RESPONSE = await CALL_NEXT(REQUEST)
    DURATION_MS = (time.perf_counter() - START) * 1000
    RESPONSE.headers["X-Process-Time-Ms"] = f"{DURATION_MS:.2f}"
    return RESPONSE


# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(auth_router)
app.include_router(report_router)
app.include_router(compliance_router)
app.include_router(cve_router)
app.include_router(mlflow_router)
app.include_router(ws_router)

# ── Endpoints base ────────────────────────────────────────────────────────────


@app.get("/health", tags=["System"])
async def health_check() -> dict:
    """Endpoint de health check del sistema."""
    return {
        "STATUS":        "healthy",
        "SERVICE":       "jeiguard-ai",
        "VERSION":       "2.0.0",
        "UPTIME_S":      round(time.time() - _start_time, 1),
        "TIMESTAMP":     datetime.now(timezone.utc).isoformat(),
        "COMPONENTS": {
            "inference_api": "up",
            "auth_service":  "up",
            "websocket":     "up",
        },
    }


@app.get("/", tags=["System"])
async def root() -> dict:
    """Información básica del sistema."""
    return {
        "service":   "JeiGuard AI",
        "version":   "2.0.0",
        "docs":      "/docs",
        "health":    "/health",
        "github":    "https://github.com/j3in3r/jeiguard-ai",
    }


@app.exception_handler(Exception)
async def global_exception_handler(REQUEST: Request, EXC: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error":   "Internal Server Error",
            "message": "Ha ocurrido un error interno. Consulte los logs para más detalles.",
        },
    )
