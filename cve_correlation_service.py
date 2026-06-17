"""
cve_correlation_service.py
═══════════════════════════
Motor de Correlación CVE para JeiGuard AI.

Funcionalidades:
  • Correlación automática ataque detectado → CVEs conocidos (NVD/NIST)
  • Scores CVSS v3.1 por ataque
  • Cache en PostgreSQL (TTL 24h) para evitar rate-limiting de NVD API
  • Fallback con base de datos estática curada cuando la API no está disponible
  • Enriquecimiento de alertas con contexto de vulnerabilidades explotadas
  • Dashboard de exposición a vulnerabilidades críticas

Endpoints:
  GET  /cve/attack/{category}     — CVEs mapeados a categoría de ataque
  GET  /cve/alert/{alert_id}      — CVEs relevantes para una alerta específica
  GET  /cve/exposure              — Dashboard de exposición CVE del tenant
  POST /cve/refresh               — Actualizar cache desde NVD API
  GET  /cve/top10                 — Top 10 CVEs más activos en el tenant
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service import RequireAnyRole, RequireAnalyst, AuthContext
from database import AlertRecord, CVECorrelation, get_session

API_VERSION: str = "v1"
router = APIRouter(prefix=f"/api/{API_VERSION}/cve", tags=["CVE Correlation"])

NVD_API_BASE: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY:  str = os.getenv("NVD_API_KEY", "")
CVE_CACHE_TTL_HOURS: int = 24

# ── Base de datos estática curada — fallback sin API ─────────────────────────

STATIC_CVE_MAP: dict[str, list[dict[str, Any]]] = {
    "DoS_DDoS": [
        {
            "cve_id": "CVE-2023-44487",
            "cve_description": "HTTP/2 Rapid Reset — ataque DDoS explotando el mecanismo de reset de streams HTTP/2 para amplificar peticiones.",
            "cvss_v3_score": 7.5,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "cvss_severity": "HIGH",
            "published_date": "2023-10-10T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
            "mapping_confidence": 0.92,
        },
        {
            "cve_id": "CVE-2022-26143",
            "cve_description": "TP240 PhoneHome — amplificación DDoS con factor de amplificación de 4.3 billion:1.",
            "cvss_v3_score": 9.1,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "cvss_severity": "CRITICAL",
            "published_date": "2022-03-08T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-26143"],
            "mapping_confidence": 0.85,
        },
        {
            "cve_id": "CVE-2021-44228",
            "cve_description": "Log4Shell — puede ser usado en ataques DDoS de amplificación a través de JNDI injection.",
            "cvss_v3_score": 10.0,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cvss_severity": "CRITICAL",
            "published_date": "2021-12-10T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "mapping_confidence": 0.70,
        },
    ],
    "Probe_Scan": [
        {
            "cve_id": "CVE-2021-41773",
            "cve_description": "Apache HTTPD Path Traversal — explotado en reconocimiento activo para enumerar archivos del sistema.",
            "cvss_v3_score": 7.5,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_severity": "HIGH",
            "published_date": "2021-10-05T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
            "mapping_confidence": 0.80,
        },
        {
            "cve_id": "CVE-2022-1388",
            "cve_description": "F5 BIG-IP iControl REST — autenticación bypass activamente sondeado por actores maliciosos.",
            "cvss_v3_score": 9.8,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_severity": "CRITICAL",
            "published_date": "2022-05-04T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-1388"],
            "mapping_confidence": 0.78,
        },
    ],
    "R2L": [
        {
            "cve_id": "CVE-2023-23397",
            "cve_description": "Microsoft Outlook NTLM Hash Leakage — usado en ataques Remote-to-Local para robar credenciales.",
            "cvss_v3_score": 9.8,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_severity": "CRITICAL",
            "published_date": "2023-03-14T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-23397"],
            "mapping_confidence": 0.88,
        },
        {
            "cve_id": "CVE-2022-30190",
            "cve_description": "Microsoft MSDT Follina — RCE via documentos Office, frecuentemente en ataques R2L.",
            "cvss_v3_score": 7.8,
            "cvss_v3_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "cvss_severity": "HIGH",
            "published_date": "2022-05-30T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-30190"],
            "mapping_confidence": 0.82,
        },
    ],
    "U2R": [
        {
            "cve_id": "CVE-2022-0847",
            "cve_description": "Dirty Pipe — escalada de privilegios en kernel Linux ≤ 5.16.11.",
            "cvss_v3_score": 7.8,
            "cvss_v3_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "cvss_severity": "HIGH",
            "published_date": "2022-03-07T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0847"],
            "mapping_confidence": 0.90,
        },
        {
            "cve_id": "CVE-2023-32233",
            "cve_description": "Linux Kernel Netfilter — Use-after-free para escalada de privilegios.",
            "cvss_v3_score": 7.8,
            "cvss_v3_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "cvss_severity": "HIGH",
            "published_date": "2023-05-08T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-32233"],
            "mapping_confidence": 0.85,
        },
        {
            "cve_id": "CVE-2021-3156",
            "cve_description": "Sudo Baron Samedit — heap-based buffer overflow en sudo para escalada a root.",
            "cvss_v3_score": 7.8,
            "cvss_v3_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "cvss_severity": "HIGH",
            "published_date": "2021-01-26T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3156"],
            "mapping_confidence": 0.88,
        },
    ],
    "Backdoor": [
        {
            "cve_id": "CVE-2024-3094",
            "cve_description": "XZ Utils Supply Chain — backdoor en liblzma comprometiendo OpenSSH en distribuciones Linux.",
            "cvss_v3_score": 10.0,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cvss_severity": "CRITICAL",
            "published_date": "2024-03-29T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
            "mapping_confidence": 0.92,
        },
        {
            "cve_id": "CVE-2021-44228",
            "cve_description": "Log4Shell — explotado extensivamente para instalar backdoors y RATs.",
            "cvss_v3_score": 10.0,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cvss_severity": "CRITICAL",
            "published_date": "2021-12-10T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "mapping_confidence": 0.88,
        },
    ],
    "Web_Exploit": [
        {
            "cve_id": "CVE-2023-46805",
            "cve_description": "Ivanti Connect Secure Authentication Bypass — acceso no autorizado a recursos web.",
            "cvss_v3_score": 8.2,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "cvss_severity": "HIGH",
            "published_date": "2024-01-10T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-46805"],
            "mapping_confidence": 0.87,
        },
        {
            "cve_id": "CVE-2024-21413",
            "cve_description": "Microsoft Outlook Moniker Link — RCE via URL maliciosa en correos.",
            "cvss_v3_score": 9.8,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_severity": "CRITICAL",
            "published_date": "2024-02-13T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-21413"],
            "mapping_confidence": 0.82,
        },
        {
            "cve_id": "CVE-2021-44228",
            "cve_description": "Log4Shell — explotado en aplicaciones web Java para RCE.",
            "cvss_v3_score": 10.0,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cvss_severity": "CRITICAL",
            "published_date": "2021-12-10T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "mapping_confidence": 0.90,
        },
    ],
    "CC_Traffic": [
        {
            "cve_id": "CVE-2022-29799",
            "cve_description": "systemd networkd-dispatcher — usado por malware para establecer C&C en sistemas comprometidos.",
            "cvss_v3_score": 7.8,
            "cvss_v3_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "cvss_severity": "HIGH",
            "published_date": "2022-06-02T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-29799"],
            "mapping_confidence": 0.75,
        },
        {
            "cve_id": "CVE-2023-38545",
            "cve_description": "cURL SOCKS5 Heap Overflow — explotado por agentes APT para tráfico C&C encubierto.",
            "cvss_v3_score": 9.8,
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_severity": "CRITICAL",
            "published_date": "2023-10-11T00:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38545"],
            "mapping_confidence": 0.80,
        },
    ],
}


# ── Schemas ───────────────────────────────────────────────────────────────────


class CVEDetail(BaseModel):
    cve_id:            str
    cve_description:   str
    cvss_v3_score:     Optional[float]
    cvss_severity:     Optional[str]
    cvss_v3_vector:    Optional[str]
    published_date:    Optional[str]
    references:        list[str]
    attack_category:   str
    mapping_confidence: float


class AttackExposure(BaseModel):
    attack_category:   str
    alert_count:       int
    critical_cves:     int
    max_cvss_score:    float
    top_cves:          list[str]


class ExposureDashboard(BaseModel):
    tenant_id:         str
    generated_at:      datetime
    total_alerts:      int
    total_unique_cves: int
    critical_exposure: int
    attack_exposures:  list[AttackExposure]
    top10_cves:        list[CVEDetail]


# ── Lógica de correlación ─────────────────────────────────────────────────────


async def _fetch_cves_from_nvd(CATEGORY: str) -> list[dict[str, Any]]:
    """Intenta obtener CVEs desde NVD API — retorna lista vacía si falla."""
    KEYWORD_MAP: dict[str, str] = {
        "DoS_DDoS":    "denial of service DDoS",
        "Probe_Scan":  "network scanning reconnaissance",
        "R2L":         "remote code execution credential theft",
        "U2R":         "privilege escalation local root",
        "Backdoor":    "backdoor trojan malware persistence",
        "Web_Exploit": "web application exploit injection",
        "CC_Traffic":  "command and control botnet",
    }
    KEYWORD = KEYWORD_MAP.get(CATEGORY, CATEGORY)

    HEADERS = {}
    if NVD_API_KEY:
        HEADERS["apiKey"] = NVD_API_KEY

    try:
        async with httpx.AsyncClient(timeout=10.0) as CLIENT:
            RESP = await CLIENT.get(
                NVD_API_BASE,
                params={
                    "keywordSearch": KEYWORD,
                    "resultsPerPage": 5,
                    "cvssV3Severity": "HIGH",
                },
                headers=HEADERS,
            )
            if RESP.status_code != 200:
                return []

            DATA = RESP.json()
            CVES = []
            for VULN in DATA.get("vulnerabilities", []):
                CVE_DATA = VULN.get("cve", {})
                CVE_ID   = CVE_DATA.get("id", "")
                DESC     = ""
                for D in CVE_DATA.get("descriptions", []):
                    if D.get("lang") == "en":
                        DESC = D.get("value", "")
                        break

                METRICS   = CVE_DATA.get("metrics", {})
                CVSS_DATA = METRICS.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if METRICS.get("cvssMetricV31") else {}
                SCORE     = CVSS_DATA.get("baseScore")
                VECTOR    = CVSS_DATA.get("vectorString")
                SEVERITY  = CVSS_DATA.get("baseSeverity")
                PUB_DATE  = CVE_DATA.get("published", "")

                REFS = [
                    R.get("url", "") for R in CVE_DATA.get("references", [])[:3]
                    if R.get("url")
                ]

                CVES.append({
                    "cve_id":            CVE_ID,
                    "cve_description":   DESC[:500],
                    "cvss_v3_score":     SCORE,
                    "cvss_v3_vector":    VECTOR,
                    "cvss_severity":     SEVERITY,
                    "published_date":    PUB_DATE,
                    "references":        REFS,
                    "mapping_confidence": 0.75,
                })
            return CVES
    except Exception:
        return []


async def get_cves_for_category(
    DB: AsyncSession,
    CATEGORY: str,
    FORCE_REFRESH: bool = False,
) -> list[dict[str, Any]]:
    """Retorna CVEs correlacionados para una categoría de ataque con cache."""
    CUTOFF = datetime.now(timezone.utc) - timedelta(hours=CVE_CACHE_TTL_HOURS)
    CACHED = (await DB.execute(
        select(CVECorrelation).where(
            and_(
                CVECorrelation.attack_category == CATEGORY,
                CVECorrelation.cached_at > CUTOFF,
            )
        )
    )).scalars().all()

    if CACHED and not FORCE_REFRESH:
        return [
            {
                "cve_id":            C.cve_id,
                "cve_description":   C.cve_description,
                "cvss_v3_score":     C.cvss_v3_score,
                "cvss_v3_vector":    C.cvss_v3_vector,
                "cvss_severity":     C.cvss_severity,
                "published_date":    C.published_date.isoformat() if C.published_date else None,
                "references":        C.references or [],
                "mapping_confidence": C.mapping_confidence,
            }
            for C in CACHED
        ]

    NVD_CVES  = await _fetch_cves_from_nvd(CATEGORY)
    BASE_CVES = STATIC_CVE_MAP.get(CATEGORY, [])

    ALL_CVES_MAP: dict[str, dict[str, Any]] = {}
    for C in BASE_CVES:
        ALL_CVES_MAP[C["cve_id"]] = C
    for C in NVD_CVES:
        ALL_CVES_MAP[C["cve_id"]] = C

    ALL_CVES = list(ALL_CVES_MAP.values())

    NOW = datetime.now(timezone.utc)
    EXISTING_IDS = {C.cve_id for C in (await DB.execute(
        select(CVECorrelation.cve_id).where(
            CVECorrelation.attack_category == CATEGORY
        )
    )).scalars().all()}

    for CVE in ALL_CVES:
        if CVE["cve_id"] not in EXISTING_IDS:
            PUB_DT = None
            if CVE.get("published_date"):
                try:
                    PUB_DT = datetime.fromisoformat(
                        CVE["published_date"].replace("Z", "+00:00")
                    )
                except Exception:
                    pass

            DB.add(CVECorrelation(
                attack_category=CATEGORY,
                cve_id=CVE["cve_id"],
                cve_description=CVE.get("cve_description", ""),
                cvss_v3_score=CVE.get("cvss_v3_score"),
                cvss_v3_vector=CVE.get("cvss_v3_vector"),
                cvss_severity=CVE.get("cvss_severity"),
                published_date=PUB_DT,
                references=CVE.get("references", []),
                mapping_confidence=CVE.get("mapping_confidence", 0.75),
                cached_at=NOW,
            ))
        else:
            await DB.execute(
                __import__("sqlalchemy").update(CVECorrelation)
                .where(
                    and_(
                        CVECorrelation.attack_category == CATEGORY,
                        CVECorrelation.cve_id == CVE["cve_id"],
                    )
                )
                .values(cached_at=NOW)
            )

    return ALL_CVES


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/attack/{CATEGORY}", response_model=list[CVEDetail])
async def get_cves_by_attack(
    CATEGORY: str,
    CTX: RequireAnyRole,
    DB: AsyncSession = Depends(get_session),
) -> list[CVEDetail]:
    """CVEs correlacionados a una categoría de ataque."""
    VALID_CATEGORIES = list(STATIC_CVE_MAP.keys()) + ["Normal"]
    if CATEGORY not in VALID_CATEGORIES:
        raise HTTPException(status_code=404, detail=f"Categoría '{CATEGORY}' no reconocida.")

    CVES = await get_cves_for_category(DB, CATEGORY)
    await DB.commit()
    return [
        CVEDetail(
            cve_id=C["cve_id"],
            cve_description=C.get("cve_description", ""),
            cvss_v3_score=C.get("cvss_v3_score"),
            cvss_severity=C.get("cvss_severity"),
            cvss_v3_vector=C.get("cvss_v3_vector"),
            published_date=str(C.get("published_date", "")),
            references=C.get("references", []),
            attack_category=CATEGORY,
            mapping_confidence=C.get("mapping_confidence", 0.75),
        )
        for C in CVES
    ]


@router.get("/exposure", response_model=ExposureDashboard)
async def get_exposure_dashboard(
    CTX: RequireAnyRole,
    DB: AsyncSession = Depends(get_session),
) -> ExposureDashboard:
    """Dashboard de exposición CVE basado en alertas del tenant (últimos 30d)."""
    CUTOFF = datetime.now(timezone.utc) - timedelta(days=30)

    BREAKDOWN = (await DB.execute(
        select(AlertRecord.attack_category, func.count(AlertRecord.id).label("count"))
        .where(
            and_(
                AlertRecord.tenant_id == CTX.tenant_id,
                AlertRecord.timestamp >= CUTOFF,
                AlertRecord.attack_category != "Normal",
            )
        )
        .group_by(AlertRecord.attack_category)
        .order_by(func.count(AlertRecord.id).desc())
    )).all()

    TOTAL = sum(R.count for R in BREAKDOWN)
    ATTACK_EXPOSURES = []
    ALL_CVES_FLAT: list[CVEDetail] = []
    UNIQUE_CVE_IDS: set[str] = set()
    CRITICAL_EXP = 0

    for ROW in BREAKDOWN:
        CAT   = ROW.attack_category
        COUNT = ROW.count
        CVES  = await get_cves_for_category(DB, CAT)

        CRITICAL_COUNT = sum(
            1 for C in CVES if (C.get("cvss_v3_score") or 0) >= 9.0
        )
        MAX_SCORE = max(
            (C.get("cvss_v3_score") or 0.0 for C in CVES),
            default=0.0,
        )
        TOP3 = [C["cve_id"] for C in sorted(
            CVES, key=lambda X: X.get("cvss_v3_score") or 0, reverse=True
        )[:3]]

        CRITICAL_EXP += CRITICAL_COUNT

        ATTACK_EXPOSURES.append(AttackExposure(
            attack_category=CAT,
            alert_count=COUNT,
            critical_cves=CRITICAL_COUNT,
            max_cvss_score=MAX_SCORE,
            top_cves=TOP3,
        ))

        for C in CVES:
            CID = C["cve_id"]
            if CID not in UNIQUE_CVE_IDS:
                UNIQUE_CVE_IDS.add(CID)
                ALL_CVES_FLAT.append(CVEDetail(
                    cve_id=CID,
                    cve_description=C.get("cve_description", ""),
                    cvss_v3_score=C.get("cvss_v3_score"),
                    cvss_severity=C.get("cvss_severity"),
                    cvss_v3_vector=C.get("cvss_v3_vector"),
                    published_date=str(C.get("published_date", "")),
                    references=C.get("references", []),
                    attack_category=CAT,
                    mapping_confidence=C.get("mapping_confidence", 0.75),
                ))

    TOP10 = sorted(
        ALL_CVES_FLAT,
        key=lambda X: X.cvss_v3_score or 0,
        reverse=True,
    )[:10]

    await DB.commit()

    return ExposureDashboard(
        tenant_id=CTX.tenant_id,
        generated_at=datetime.now(timezone.utc),
        total_alerts=TOTAL,
        total_unique_cves=len(UNIQUE_CVE_IDS),
        critical_exposure=CRITICAL_EXP,
        attack_exposures=ATTACK_EXPOSURES,
        top10_cves=TOP10,
    )


@router.post("/refresh", status_code=202)
async def refresh_cve_cache(
    CTX: RequireAnalyst,
    DB: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Actualiza el cache de CVEs desde NVD API para todas las categorías."""
    RESULTS: dict[str, int] = {}
    for CATEGORY in STATIC_CVE_MAP:
        CVES = await get_cves_for_category(DB, CATEGORY, FORCE_REFRESH=True)
        RESULTS[CATEGORY] = len(CVES)

    await DB.commit()
    return {
        "status":     "refreshed",
        "categories": RESULTS,
        "total_cves": sum(RESULTS.values()),
        "refreshed_at": datetime.now(timezone.utc).isoformat(),
    }
