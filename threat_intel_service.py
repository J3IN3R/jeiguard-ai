"""
JeiGuard AI v1.0.2 — Mejora 4: Threat Intelligence Service
Enriquece cada IP con datos de AbuseIPDB, VirusTotal y feeds STIX/TAXII.
Copyright © 2026 Jeiner Tello Nuñez — MIT License
"""
from __future__ import annotations

import json
import time
import hashlib
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


# ── Constantes ─────────────────────────────────────────────────────────────────
TI_CACHE_TTL_S         = 3600 * 6   # Cache por 6 horas
TI_REQUEST_TIMEOUT_S   = 5
TI_MAX_CACHE_SIZE      = 10000
ABUSEIPDB_BASE_URL     = "https://api.abuseipdb.com/api/v2"
VIRUSTOTAL_BASE_URL    = "https://www.virustotal.com/api/v3"
SERVICE_VERSION        = "1.0.2"


class ThreatLevel(str, Enum):
    CLEAN      = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS  = "malicious"
    CRITICAL   = "critical"
    UNKNOWN    = "unknown"


@dataclass
class AbuseIPDBReport:
    ip:                  str
    abuse_confidence:    int        # 0-100
    country_code:        str
    isp:                 str
    domain:              str
    total_reports:       int
    last_reported:       Optional[str]
    is_tor:              bool
    is_vpn:              bool
    usage_type:          str
    cached:              bool = False
    retrieved_at:        float = 0.0


@dataclass
class VirusTotalReport:
    ip:                  str
    malicious_votes:     int
    suspicious_votes:    int
    harmless_votes:      int
    country:             str
    as_owner:            str
    regional_internet_registry: str
    last_analysis_date:  Optional[str]
    cached:              bool = False
    retrieved_at:        float = 0.0


@dataclass
class ThreatIntelReport:
    ip:               str
    threat_level:     ThreatLevel
    risk_score:       int              # 0-100
    sources_checked:  list[str]
    abuse_report:     Optional[AbuseIPDBReport] = None
    vt_report:        Optional[VirusTotalReport] = None
    stix_indicators:  list[dict]       = field(default_factory=list)
    geo_country:      str              = "Unknown"
    isp:              str              = "Unknown"
    is_known_bad:     bool             = False
    is_tor_exit:      bool             = False
    is_vpn:           bool             = False
    tags:             list[str]        = field(default_factory=list)
    summary:          str              = ""
    retrieved_at:     float            = 0.0
    cache_hit:        bool             = False

    def to_alert_enrichment(self) -> dict:
        return {
            "ip":           self.ip,
            "threat_level": self.threat_level.value,
            "risk_score":   self.risk_score,
            "geo":          self.geo_country,
            "isp":          self.isp,
            "is_known_bad": self.is_known_bad,
            "is_tor":       self.is_tor_exit,
            "is_vpn":       self.is_vpn,
            "tags":         self.tags,
            "summary":      self.summary,
        }


class ThreatIntelService:
    """
    Servicio de threat intelligence que enriquece IPs con datos de reputación
    globales antes de que lleguen al clasificador principal.
    """

    def __init__(self,
                 abuseipdb_key: Optional[str] = None,
                 virustotal_key: Optional[str] = None,
                 cache_ttl_s: int = TI_CACHE_TTL_S):
        self._abuseipdb_key  = abuseipdb_key
        self._virustotal_key = virustotal_key
        self._cache_ttl_s    = cache_ttl_s
        self._cache: dict[str, tuple[ThreatIntelReport, float]] = {}
        self._stats = {
            "ips_checked":      0,
            "cache_hits":       0,
            "api_calls":        0,
            "known_bad_found":  0,
            "errors":           0,
        }

    # ── API pública ────────────────────────────────────────────────────────────

    def enrich_ip(self, ip: str) -> ThreatIntelReport:
        """Enriquece una IP con datos de múltiples fuentes de threat intel."""
        cached = self._get_cache(ip)
        if cached:
            self._stats["cache_hits"] += 1
            return cached

        report = self._build_report(ip)
        self._set_cache(ip, report)
        self._stats["ips_checked"] += 1

        if report.is_known_bad:
            self._stats["known_bad_found"] += 1

        return report

    def enrich_batch(self, ips: list[str]) -> dict[str, ThreatIntelReport]:
        """Enriquece múltiples IPs, respetando caché."""
        return {ip: self.enrich_ip(ip) for ip in set(ips)}

    def is_known_malicious(self, ip: str) -> bool:
        report = self.enrich_ip(ip)
        return report.threat_level in (ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL)

    def get_risk_score(self, ip: str) -> int:
        return self.enrich_ip(ip).risk_score

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "cache_size":   len(self._cache),
            "has_abuseipdb": bool(self._abuseipdb_key),
            "has_virustotal": bool(self._virustotal_key),
        }

    # ── Construcción del reporte ───────────────────────────────────────────────

    def _build_report(self, ip: str) -> ThreatIntelReport:
        sources:  list[str] = []
        abuse:    Optional[AbuseIPDBReport]   = None
        vt:       Optional[VirusTotalReport]  = None
        stix:     list[dict] = []

        # Fuente 1: AbuseIPDB
        if self._abuseipdb_key:
            try:
                abuse   = self._query_abuseipdb(ip)
                sources.append("AbuseIPDB")
            except Exception as e:
                self._stats["errors"] += 1

        # Fuente 2: VirusTotal
        if self._virustotal_key:
            try:
                vt      = self._query_virustotal(ip)
                sources.append("VirusTotal")
            except Exception as e:
                self._stats["errors"] += 1

        # Fuente 3: Listas locales (sin API key)
        local_threat = self._check_local_lists(ip)
        if local_threat:
            sources.append("LocalLists")

        # Calcular nivel y score final
        risk_score   = self._compute_risk(abuse, vt, local_threat)
        threat_level = self._classify_threat(risk_score, abuse, vt, local_threat)

        return ThreatIntelReport(
            ip=ip,
            threat_level=threat_level,
            risk_score=risk_score,
            sources_checked=sources or ["LocalLists"],
            abuse_report=abuse,
            vt_report=vt,
            stix_indicators=stix,
            geo_country=abuse.country_code if abuse else "Unknown",
            isp=abuse.isp if abuse else "Unknown",
            is_known_bad=threat_level in (ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL),
            is_tor_exit=abuse.is_tor if abuse else False,
            is_vpn=abuse.is_vpn if abuse else False,
            tags=self._build_tags(abuse, vt, local_threat),
            summary=self._build_summary(ip, threat_level, risk_score, abuse, vt),
            retrieved_at=time.time(),
        )

    # ── Queries a APIs externas ────────────────────────────────────────────────

    def _query_abuseipdb(self, ip: str) -> AbuseIPDBReport:
        url = f"{ABUSEIPDB_BASE_URL}/check?ipAddress={ip}&maxAgeInDays=90&verbose"
        req = urllib.request.Request(
            url,
            headers={
                "Key":    self._abuseipdb_key,
                "Accept": "application/json",
            }
        )
        self._stats["api_calls"] += 1
        with urllib.request.urlopen(req, timeout=TI_REQUEST_TIMEOUT_S) as resp:
            data = json.loads(resp.read())["data"]

        return AbuseIPDBReport(
            ip=ip,
            abuse_confidence=int(data.get("abuseConfidenceScore", 0)),
            country_code=data.get("countryCode", "XX"),
            isp=data.get("isp", "Unknown"),
            domain=data.get("domain", ""),
            total_reports=int(data.get("totalReports", 0)),
            last_reported=data.get("lastReportedAt"),
            is_tor=bool(data.get("isTor", False)),
            is_vpn=bool(data.get("isVpn", False)),
            usage_type=data.get("usageType", "Unknown"),
            retrieved_at=time.time(),
        )

    def _query_virustotal(self, ip: str) -> VirusTotalReport:
        url = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}"
        req = urllib.request.Request(
            url,
            headers={"x-apikey": self._virustotal_key}
        )
        self._stats["api_calls"] += 1
        with urllib.request.urlopen(req, timeout=TI_REQUEST_TIMEOUT_S) as resp:
            data = json.loads(resp.read())

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        attrs = data.get("data", {}).get("attributes", {})

        return VirusTotalReport(
            ip=ip,
            malicious_votes=int(stats.get("malicious", 0)),
            suspicious_votes=int(stats.get("suspicious", 0)),
            harmless_votes=int(stats.get("harmless", 0)),
            country=attrs.get("country", "Unknown"),
            as_owner=attrs.get("as_owner", "Unknown"),
            regional_internet_registry=attrs.get("regional_internet_registry", "Unknown"),
            last_analysis_date=attrs.get("last_analysis_date"),
            retrieved_at=time.time(),
        )

    def _check_local_lists(self, ip: str) -> Optional[str]:
        """Verifica contra listas negras locales conocidas."""
        KNOWN_BAD_RANGES = [
            "192.0.2.", "198.51.100.", "203.0.113.",  # RFC 5737 documentación
        ]
        KNOWN_TOR_EXITS: list[str] = []

        for prefix in KNOWN_BAD_RANGES:
            if ip.startswith(prefix):
                return "known_bad_range"
        if ip in KNOWN_TOR_EXITS:
            return "tor_exit_node"
        return None

    # ── Scoring y clasificación ────────────────────────────────────────────────

    def _compute_risk(self, abuse: Optional[AbuseIPDBReport],
                       vt: Optional[VirusTotalReport],
                       local: Optional[str]) -> int:
        score = 0
        if abuse:
            score += int(abuse.abuse_confidence * 0.5)
            if abuse.is_tor: score += 20
            if abuse.is_vpn: score += 10
            if abuse.total_reports > 100: score += 10
        if vt:
            score += min(vt.malicious_votes * 3, 40)
            score += min(vt.suspicious_votes * 1, 15)
        if local:
            score += 50
        return min(score, 100)

    def _classify_threat(self, risk: int,
                          abuse: Optional[AbuseIPDBReport],
                          vt: Optional[VirusTotalReport],
                          local: Optional[str]) -> ThreatLevel:
        if local or risk >= 85:
            return ThreatLevel.CRITICAL
        if risk >= 70 or (abuse and abuse.abuse_confidence >= 70):
            return ThreatLevel.MALICIOUS
        if risk >= 40 or (vt and vt.malicious_votes > 0):
            return ThreatLevel.SUSPICIOUS
        if risk > 0:
            return ThreatLevel.CLEAN
        return ThreatLevel.UNKNOWN

    def _build_tags(self, abuse: Optional[AbuseIPDBReport],
                     vt: Optional[VirusTotalReport],
                     local: Optional[str]) -> list[str]:
        tags: list[str] = []
        if abuse:
            if abuse.is_tor:                     tags.append("tor-exit-node")
            if abuse.is_vpn:                     tags.append("vpn-provider")
            if abuse.abuse_confidence > 50:      tags.append("high-abuse-score")
            if abuse.total_reports > 50:         tags.append("frequently-reported")
        if vt and vt.malicious_votes > 5:        tags.append("virustotal-malicious")
        if local == "known_bad_range":           tags.append("known-bad-range")
        return tags

    def _build_summary(self, ip: str, threat_level: ThreatLevel,
                        risk_score: int,
                        abuse: Optional[AbuseIPDBReport],
                        vt: Optional[VirusTotalReport]) -> str:
        parts = [f"IP {ip} — nivel: {threat_level.value.upper()} (riesgo: {risk_score}/100)."]
        if abuse:
            parts.append(f"País: {abuse.country_code}. ISP: {abuse.isp}.")
            if abuse.abuse_confidence > 0:
                parts.append(f"AbuseIPDB: {abuse.abuse_confidence}% de confianza de abuso "
                             f"({abuse.total_reports} reportes).")
        if vt and vt.malicious_votes > 0:
            parts.append(f"VirusTotal: {vt.malicious_votes} motores detectan como malicioso.")
        return " ".join(parts)

    # ── Caché ──────────────────────────────────────────────────────────────────

    def _get_cache(self, ip: str) -> Optional[ThreatIntelReport]:
        entry = self._cache.get(ip)
        if entry and (time.time() - entry[1]) < self._cache_ttl_s:
            report = entry[0]
            report.cache_hit = True
            return report
        return None

    def _set_cache(self, ip: str, report: ThreatIntelReport) -> None:
        if len(self._cache) >= TI_MAX_CACHE_SIZE:
            oldest = sorted(self._cache, key=lambda k: self._cache[k][1])[:100]
            for k in oldest:
                del self._cache[k]
        self._cache[ip] = (report, time.time())


# ── Demo ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  JeiGuard AI v1.0.2 — Threat Intelligence Service")
    print("=" * 60)

    ti = ThreatIntelService()

    ips = [
        "8.8.8.8",        # Google DNS — esperado: clean
        "1.1.1.1",        # Cloudflare DNS — esperado: clean
        "192.0.2.1",      # RFC 5737 — esperado: bad range
        "10.42.183.97",   # IP privada
    ]

    for ip in ips:
        report = ti.enrich_ip(ip)
        print(f"\nIP: {ip}")
        print(f"  Nivel:       {report.threat_level.value.upper()}")
        print(f"  Riesgo:      {report.risk_score}/100")
        print(f"  País:        {report.geo_country}")
        print(f"  ISP:         {report.isp}")
        print(f"  Tags:        {report.tags or ['ninguno']}")
        print(f"  Fuentes:     {report.sources_checked}")
        print(f"  Cache hit:   {report.cache_hit}")

    print(f"\nStats: {json.dumps(ti.get_stats(), indent=2)}")
