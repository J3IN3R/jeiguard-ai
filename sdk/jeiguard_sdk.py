"""
sdk/jeiguard_sdk.py
════════════════════
JeiGuard AI Python SDK — Cliente HTTP + WebSocket oficial.

Permite a equipos SOC, SIEMs externos, y aplicaciones de terceros
integrarse con JeiGuard AI sin necesidad de conocer los detalles
de la API REST o WebSocket.

Características:
  • Autenticación automática con renovación de tokens
  • Retry automático con exponential backoff
  • Streaming de alertas en tiempo real (WebSocket)
  • Soporte async/await y síncrono
  • Type hints completos (compatible con mypy strict)
  • Serialización/deserialización automática con Pydantic

Ejemplo de uso síncrono:
    client = JeiGuardClient(base_url="https://ids.empresa.com")
    client.login(email="analyst@empresa.com", password="Secret@2026!")

    # Predicción de flujo de red
    result = client.predict([[0.1, 0.2, ...]])  # 41 features
    print(result.predictions, result.confidences)

    # Listar alertas recientes
    alerts = client.get_alerts(level="CRITICAL", limit=10)

    # Descargar reporte ejecutivo en PDF
    client.download_report(period_days=30, output_path="./security_report.pdf")

Ejemplo async:
    async with JeiGuardAsyncClient(base_url="...") as client:
        await client.login(email="...", password="...")
        async for alert in client.stream_alerts():
            process(alert)
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator, Generator, Iterator, Optional

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import websockets
    WS_AVAILABLE = True
except ImportError:
    WS_AVAILABLE = False

# ── Data classes de dominio ───────────────────────────────────────────────────


@dataclass(frozen=True)
class AuthCredentials:
    access_token:  str
    refresh_token: str
    user_id:       str
    username:      str
    role:          str
    tenant_id:     str
    tenant_name:   str
    expires_in:    int


@dataclass(frozen=True)
class AlertFilter:
    levels:     Optional[list[str]] = None
    categories: Optional[list[str]] = None
    sensor_id:  Optional[str]       = None
    from_dt:    Optional[datetime]  = None
    to_dt:      Optional[datetime]  = None
    limit:      int                 = 100
    offset:     int                 = 0


@dataclass
class AlertSummary:
    alert_id:        str
    timestamp:       datetime
    alert_level:     str
    attack_category: str
    confidence:      float
    src_ip:          str
    dst_ip:          str
    dst_port:        int
    sensor_id:       str
    mitre_technique: Optional[str]
    description:     str


@dataclass
class PredictionResult:
    request_id:    str
    predictions:   list[str]
    confidences:   list[float]
    is_attack:     list[bool]
    alert_levels:  list[str]
    top3:          list[dict[str, Any]]
    latency_ms:    float
    model_version: str
    n_samples:     int


@dataclass
class ModelInfo:
    id:              str
    name:            str
    version:         str
    model_type:      str
    accuracy:        Optional[float]
    f1_macro:        Optional[float]
    false_positive_rate: Optional[float]
    roc_auc:         Optional[float]
    is_production:   bool
    is_champion:     bool
    created_at:      datetime


@dataclass
class ComplianceScore:
    framework:       str
    overall_score:   float
    compliant_count: int
    total_controls:  int
    last_assessed:   Optional[datetime]


@dataclass(frozen=True)
class CVEDetail:
    cve_id:           str
    cve_description:  str
    cvss_v3_score:    Optional[float]
    cvss_severity:    Optional[str]
    attack_category:  str


@dataclass(frozen=True)
class ReportRequest:
    report_type:     str = "executive"
    period_days:     int = 30
    title:           Optional[str] = None


# ── Excepciones ───────────────────────────────────────────────────────────────


class JeiGuardError(Exception):
    """Error base del SDK."""
    pass


class AuthenticationError(JeiGuardError):
    """Error de autenticación."""
    pass


class AuthorizationError(JeiGuardError):
    """Error de autorización (rol insuficiente)."""
    pass


class NotFoundError(JeiGuardError):
    """Recurso no encontrado."""
    pass


class RateLimitError(JeiGuardError):
    """Rate limit alcanzado."""
    pass


# ── Cliente HTTP síncrono ─────────────────────────────────────────────────────


class JeiGuardClient:
    """
    Cliente síncrono para la API REST de JeiGuard AI.

    Uso:
        client = JeiGuardClient(base_url="https://ids.empresa.com")
        client.login(email="user@empresa.com", password="Secret@2026!")
        alerts = client.get_alerts(levels=["CRITICAL"])
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        max_retries: int = 3,
        verify_ssl: bool = True,
    ) -> None:
        if not HTTPX_AVAILABLE:
            raise ImportError("httpx es requerido: pip install httpx")

        self.base_url    = base_url.rstrip("/")
        self.timeout     = timeout
        self.max_retries = max_retries
        self._creds:     Optional[AuthCredentials] = None
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            verify=verify_ssl,
            headers={"User-Agent": "JeiGuard-SDK/2.0.0 Python"},
        )

    def _headers(self) -> dict[str, str]:
        H: dict[str, str] = {"Content-Type": "application/json"}
        if self._creds:
            H["Authorization"] = f"Bearer {self._creds.access_token}"
        return H

    def _request(
        self,
        METHOD: str,
        PATH: str,
        **KWARGS: Any,
    ) -> dict[str, Any]:
        """Realiza una petición HTTP con retry y manejo de errores."""
        URL = f"/api/v1{PATH}"

        for ATTEMPT in range(self.max_retries):
            try:
                RESP = self._client.request(
                    METHOD, URL, headers=self._headers(), **KWARGS
                )
                if RESP.status_code == 401:
                    if ATTEMPT == 0 and self._creds:
                        self._refresh_token()
                        continue
                    raise AuthenticationError("Token inválido o expirado.")
                if RESP.status_code == 403:
                    raise AuthorizationError("Permisos insuficientes.")
                if RESP.status_code == 404:
                    raise NotFoundError(f"Recurso no encontrado: {PATH}")
                if RESP.status_code == 429:
                    raise RateLimitError("Rate limit alcanzado. Intente más tarde.")
                if RESP.status_code >= 500:
                    if ATTEMPT < self.max_retries - 1:
                        time.sleep(2 ** ATTEMPT)
                        continue
                    raise JeiGuardError(f"Error del servidor: {RESP.status_code}")

                RESP.raise_for_status()
                return RESP.json() if RESP.content else {}

            except (httpx.ConnectError, httpx.TimeoutException) as EXC:
                if ATTEMPT < self.max_retries - 1:
                    time.sleep(2 ** ATTEMPT)
                    continue
                raise JeiGuardError(f"Error de conexión: {EXC}") from EXC

        raise JeiGuardError("Máximo de reintentos alcanzado.")

    def _refresh_token(self) -> None:
        if not self._creds:
            return
        try:
            DATA = self._request(
                "POST", "/auth/refresh",
                json={"refresh_token": self._creds.refresh_token},
            )
            self._creds = AuthCredentials(
                access_token=DATA["access_token"],
                refresh_token=DATA["refresh_token"],
                user_id=DATA["user_id"],
                username=DATA["username"],
                role=DATA["role"],
                tenant_id=DATA["tenant_id"],
                tenant_name=DATA["tenant_name"],
                expires_in=DATA["expires_in"],
            )
        except Exception:
            self._creds = None

    def login(self, email: str, password: str) -> AuthCredentials:
        """Autentica al usuario y almacena las credenciales."""
        DATA = self._request(
            "POST", "/auth/login",
            json={"email": email, "password": password},
        )
        self._creds = AuthCredentials(
            access_token=DATA["access_token"],
            refresh_token=DATA["refresh_token"],
            user_id=DATA["user_id"],
            username=DATA["username"],
            role=DATA["role"],
            tenant_id=DATA["tenant_id"],
            tenant_name=DATA["tenant_name"],
            expires_in=DATA["expires_in"],
        )
        return self._creds

    def register(
        self,
        tenant_name: str,
        username: str,
        email: str,
        password: str,
        full_name: str = "",
    ) -> AuthCredentials:
        """Registra un nuevo tenant y usuario admin."""
        DATA = self._request(
            "POST", "/auth/register",
            json={
                "tenant_name": tenant_name,
                "username":    username,
                "email":       email,
                "password":    password,
                "full_name":   full_name,
            },
        )
        self._creds = AuthCredentials(
            access_token=DATA["access_token"],
            refresh_token=DATA["refresh_token"],
            user_id=DATA["user_id"],
            username=DATA["username"],
            role=DATA["role"],
            tenant_id=DATA["tenant_id"],
            tenant_name=DATA["tenant_name"],
            expires_in=DATA["expires_in"],
        )
        return self._creds

    def logout(self) -> None:
        """Cierra la sesión e invalida el token."""
        if self._creds:
            try:
                self._request("POST", "/auth/logout")
            except Exception:
                pass
            self._creds = None

    def predict(self, features: list[list[float]]) -> PredictionResult:
        """Clasifica flujos de red — acepta matriz de (N, 41) features."""
        DATA = self._request(
            "POST", "/predict",
            json={"FEATURES": features},
        )
        return PredictionResult(
            request_id=DATA["REQUEST_ID"],
            predictions=DATA["PREDICTIONS"],
            confidences=DATA["CONFIDENCES"],
            is_attack=DATA["IS_ATTACK"],
            alert_levels=DATA["ALERT_LEVELS"],
            top3=DATA["TOP3"],
            latency_ms=DATA["LATENCY_MS"],
            model_version=DATA["MODEL_VERSION"],
            n_samples=DATA["N_SAMPLES"],
        )

    def get_alerts(
        self,
        levels: Optional[list[str]] = None,
        categories: Optional[list[str]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AlertSummary]:
        """Retorna alertas del tenant con filtros opcionales."""
        PARAMS: dict[str, Any] = {"limit": limit, "offset": offset}
        if levels:
            PARAMS["levels"] = ",".join(levels)
        if categories:
            PARAMS["categories"] = ",".join(categories)

        DATA = self._request("GET", "/alerts", params=PARAMS)
        ALERTS = DATA if isinstance(DATA, list) else DATA.get("alerts", [])
        RESULT = []
        for A in ALERTS:
            try:
                RESULT.append(AlertSummary(
                    alert_id=A.get("alert_id", A.get("id", "")),
                    timestamp=datetime.fromisoformat(A.get("timestamp", "").replace("Z", "+00:00")),
                    alert_level=A.get("alert_level", ""),
                    attack_category=A.get("attack_category", ""),
                    confidence=float(A.get("confidence", 0)),
                    src_ip=A.get("src_ip", ""),
                    dst_ip=A.get("dst_ip", ""),
                    dst_port=int(A.get("dst_port", 0)),
                    sensor_id=A.get("sensor_id", ""),
                    mitre_technique=A.get("mitre_technique"),
                    description=A.get("description", ""),
                ))
            except Exception:
                continue
        return RESULT

    def get_models(self) -> list[ModelInfo]:
        """Lista los modelos en el Model Registry."""
        DATA = self._request("GET", "/mlflow/models")
        MODELS = DATA if isinstance(DATA, list) else []
        RESULT = []
        for M in MODELS:
            try:
                RESULT.append(ModelInfo(
                    id=M.get("id", ""),
                    name=M.get("name", ""),
                    version=M.get("version", ""),
                    model_type=M.get("model_type", ""),
                    accuracy=M.get("accuracy"),
                    f1_macro=M.get("f1_macro"),
                    false_positive_rate=M.get("false_positive_rate"),
                    roc_auc=M.get("roc_auc"),
                    is_production=M.get("is_production", False),
                    is_champion=M.get("is_champion", False),
                    created_at=datetime.fromisoformat(M.get("created_at", "").replace("Z", "+00:00")),
                ))
            except Exception:
                continue
        return RESULT

    def get_compliance_score(self, framework: str) -> ComplianceScore:
        """Retorna el score de compliance para el framework indicado."""
        DATA = self._request("GET", f"/compliance/{framework}/score")
        LAST = DATA.get("last_assessed")
        return ComplianceScore(
            framework=DATA.get("framework", framework),
            overall_score=DATA.get("overall_score", 0.0),
            compliant_count=DATA.get("compliant_count", 0),
            total_controls=DATA.get("total_controls", 0),
            last_assessed=datetime.fromisoformat(LAST.replace("Z", "+00:00")) if LAST else None,
        )

    def get_cves(self, attack_category: str) -> list[CVEDetail]:
        """Retorna CVEs correlacionados a una categoría de ataque."""
        DATA = self._request("GET", f"/cve/attack/{attack_category}")
        CVES = DATA if isinstance(DATA, list) else []
        return [
            CVEDetail(
                cve_id=C.get("cve_id", ""),
                cve_description=C.get("cve_description", ""),
                cvss_v3_score=C.get("cvss_v3_score"),
                cvss_severity=C.get("cvss_severity"),
                attack_category=C.get("attack_category", attack_category),
            )
            for C in CVES
        ]

    def download_report(
        self,
        output_path: str,
        report_type: str = "executive",
        period_days: int = 30,
    ) -> Path:
        """Genera y descarga un reporte PDF ejecutivo."""
        GEN_DATA = self._request(
            "POST", "/reports/generate",
            json={"report_type": report_type, "period_days": period_days},
        )
        REPORT_ID = GEN_DATA.get("id", "")

        RESP = self._client.get(
            f"/api/v1/reports/{REPORT_ID}/download",
            headers=self._headers(),
            follow_redirects=True,
        )
        RESP.raise_for_status()

        OUTPUT = Path(output_path)
        OUTPUT.write_bytes(RESP.content)
        return OUTPUT

    def health_check(self) -> dict[str, Any]:
        """Verifica el estado de salud del sistema."""
        return self._request("GET", "/health")

    def __enter__(self) -> "JeiGuardClient":
        return self

    def __exit__(self, *ARGS: Any) -> None:
        self.logout()
        self._client.close()


# ── Cliente async ─────────────────────────────────────────────────────────────


class JeiGuardAsyncClient:
    """
    Cliente async para la API REST + WebSocket de JeiGuard AI.

    Uso:
        async with JeiGuardAsyncClient(base_url="https://ids.empresa.com") as client:
            await client.login(email="...", password="...")
            async for alert in client.stream_alerts(levels=["CRITICAL"]):
                await handle_alert(alert)
    """

    def __init__(self, base_url: str, timeout: float = 30.0) -> None:
        if not HTTPX_AVAILABLE:
            raise ImportError("httpx es requerido: pip install httpx")
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self._creds:  Optional[AuthCredentials] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "JeiGuardAsyncClient":
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers={"User-Agent": "JeiGuard-SDK/2.0.0 Python-Async"},
        )
        return self

    async def __aexit__(self, *ARGS: Any) -> None:
        if self._creds:
            try:
                await self._request("POST", "/auth/logout")
            except Exception:
                pass
        if self._client:
            await self._client.aclose()

    def _headers(self) -> dict[str, str]:
        H: dict[str, str] = {"Content-Type": "application/json"}
        if self._creds:
            H["Authorization"] = f"Bearer {self._creds.access_token}"
        return H

    async def _request(self, METHOD: str, PATH: str, **KWARGS: Any) -> dict[str, Any]:
        assert self._client, "Usar como context manager: async with JeiGuardAsyncClient(...) as client"
        RESP = await self._client.request(
            METHOD, f"/api/v1{PATH}", headers=self._headers(), **KWARGS
        )
        if RESP.status_code == 401:
            raise AuthenticationError("Token inválido o expirado.")
        if RESP.status_code == 403:
            raise AuthorizationError("Permisos insuficientes.")
        RESP.raise_for_status()
        return RESP.json() if RESP.content else {}

    async def login(self, email: str, password: str) -> AuthCredentials:
        DATA = await self._request(
            "POST", "/auth/login",
            json={"email": email, "password": password},
        )
        self._creds = AuthCredentials(
            access_token=DATA["access_token"],
            refresh_token=DATA["refresh_token"],
            user_id=DATA["user_id"],
            username=DATA["username"],
            role=DATA["role"],
            tenant_id=DATA["tenant_id"],
            tenant_name=DATA["tenant_name"],
            expires_in=DATA["expires_in"],
        )
        return self._creds

    async def predict(self, features: list[list[float]]) -> PredictionResult:
        DATA = await self._request("POST", "/predict", json={"FEATURES": features})
        return PredictionResult(
            request_id=DATA["REQUEST_ID"],
            predictions=DATA["PREDICTIONS"],
            confidences=DATA["CONFIDENCES"],
            is_attack=DATA["IS_ATTACK"],
            alert_levels=DATA["ALERT_LEVELS"],
            top3=DATA["TOP3"],
            latency_ms=DATA["LATENCY_MS"],
            model_version=DATA["MODEL_VERSION"],
            n_samples=DATA["N_SAMPLES"],
        )

    async def stream_alerts(
        self,
        levels: Optional[list[str]] = None,
        categories: Optional[list[str]] = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Genera alertas en tiempo real desde el WebSocket de JeiGuard AI."""
        if not WS_AVAILABLE or not self._creds:
            return

        WS_URL = self.base_url.replace("http", "ws")
        PARAMS = [f"token={self._creds.access_token}"]
        if levels:
            PARAMS.append(f"level={','.join(levels)}")
        if categories:
            PARAMS.append(f"category={','.join(categories)}")

        URI = f"{WS_URL}/api/v1/ws/alerts?{'&'.join(PARAMS)}"

        try:
            async with websockets.connect(URI) as WS:
                while True:
                    try:
                        MSG = await asyncio.wait_for(WS.recv(), timeout=60.0)
                        DATA = json.loads(MSG)
                        if DATA.get("type") == "alert":
                            yield DATA.get("payload", DATA)
                    except asyncio.TimeoutError:
                        await WS.ping()
                    except Exception:
                        break
        except Exception:
            return
