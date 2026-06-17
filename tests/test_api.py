"""
tests/test_api.py
══════════════════
Comprehensive async test suite for JeiGuard AI v2.0.0 FastAPI application.

Covers:
  - GET  /health                              → 200, body has "STATUS"
  - POST /api/v1/auth/login valid creds       → 200 with access_token
  - POST /api/v1/auth/login invalid creds     → 401
  - GET  /api/v1/compliance/frameworks        → 200 (no auth needed)
  - GET  /api/v1/cve/attack/{category}        → 401 without token
  - GET  /api/v1/cve/attack/{category}        → 200 with valid token
  - GET  /api/v1/cve/exposure                 → 200 with valid token
  - GET  /api/v1/mlflow/models                → 200 with valid token
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

# ── Helpers ───────────────────────────────────────────────────────────────────

VALID_EMAIL = "admin@test.com"
VALID_PASSWORD = "Admin@12345!"


async def get_token(client: AsyncClient) -> str:
    """Obtain a JWT access token using valid credentials."""
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": VALID_EMAIL, "password": VALID_PASSWORD},
    )
    # If login fails (no DB in test env), skip auth-dependent tests
    if response.status_code != 200:
        pytest.skip("Auth service unavailable — no DB connection in test env")
    data = response.json()
    return data["access_token"]


# ── Health check ──────────────────────────────────────────────────────────────


async def test_health_returns_200(client: AsyncClient):
    """GET /health should return 200 with a STATUS field."""
    response = await client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert "STATUS" in body


async def test_health_body_fields(client: AsyncClient):
    """GET /health should include service name and version."""
    response = await client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body.get("SERVICE") == "jeiguard-ai"
    assert body.get("VERSION") == "2.0.0"


# ── Root endpoint ─────────────────────────────────────────────────────────────


async def test_root_returns_200(client: AsyncClient):
    """GET / should return basic service info."""
    response = await client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert "service" in body
    assert "version" in body


# ── Authentication ────────────────────────────────────────────────────────────


async def test_login_invalid_credentials_returns_401(client: AsyncClient):
    """POST /api/v1/auth/login with wrong password should return 401."""
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@test.com", "password": "WrongPass1!"},
    )
    assert response.status_code == 401


async def test_login_malformed_body_returns_422(client: AsyncClient):
    """POST /api/v1/auth/login with missing fields should return 422."""
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "notanemail"},
    )
    assert response.status_code == 422


async def test_login_valid_credentials_returns_access_token(client: AsyncClient):
    """POST /api/v1/auth/login with valid credentials should return access_token."""
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": VALID_EMAIL, "password": VALID_PASSWORD},
    )
    if response.status_code == 401:
        pytest.skip("No test user in DB — skipping valid-credentials test")
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data.get("token_type") == "bearer"


# ── Compliance ────────────────────────────────────────────────────────────────


async def test_compliance_frameworks_no_auth_returns_200(client: AsyncClient):
    """GET /api/v1/compliance/frameworks should be accessible without auth."""
    response = await client.get("/api/v1/compliance/frameworks")
    assert response.status_code == 200
    body = response.json()
    assert "frameworks" in body
    assert len(body["frameworks"]) >= 1


async def test_compliance_score_without_token_returns_401(client: AsyncClient):
    """GET /api/v1/compliance/NIST_CSF/score without token should return 401."""
    response = await client.get("/api/v1/compliance/NIST_CSF/score")
    assert response.status_code == 401


async def test_compliance_score_with_token_returns_200(client: AsyncClient):
    """GET /api/v1/compliance/NIST_CSF/score with valid token should return 200."""
    token = await get_token(client)
    response = await client.get(
        "/api/v1/compliance/NIST_CSF/score",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200


# ── CVE Correlation ───────────────────────────────────────────────────────────


async def test_cve_attack_without_token_returns_401(client: AsyncClient):
    """GET /api/v1/cve/attack/DoS_DDoS without token should return 401."""
    response = await client.get("/api/v1/cve/attack/DoS_DDoS")
    assert response.status_code == 401


async def test_cve_attack_with_token_returns_200(client: AsyncClient):
    """GET /api/v1/cve/attack/DoS_DDoS with valid token should return 200."""
    token = await get_token(client)
    response = await client.get(
        "/api/v1/cve/attack/DoS_DDoS",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


async def test_cve_exposure_without_token_returns_401(client: AsyncClient):
    """GET /api/v1/cve/exposure without token should return 401."""
    response = await client.get("/api/v1/cve/exposure")
    assert response.status_code == 401


async def test_cve_exposure_with_token_returns_200(client: AsyncClient):
    """GET /api/v1/cve/exposure with valid token should return 200."""
    token = await get_token(client)
    response = await client.get(
        "/api/v1/cve/exposure",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200


# ── MLflow / Model Registry ───────────────────────────────────────────────────


async def test_mlflow_models_without_token_returns_401(client: AsyncClient):
    """GET /api/v1/mlflow/models without token should return 401."""
    response = await client.get("/api/v1/mlflow/models")
    assert response.status_code == 401


async def test_mlflow_models_with_token_returns_200(client: AsyncClient):
    """GET /api/v1/mlflow/models with valid token should return 200."""
    token = await get_token(client)
    response = await client.get(
        "/api/v1/mlflow/models",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
