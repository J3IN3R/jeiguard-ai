"""
JeiGuard AI Python SDK v2.0.0
════════════════════════════════
SDK oficial de Python para integrar JeiGuard AI en aplicaciones externas.

Uso básico:
    from sdk import JeiGuardClient

    client = JeiGuardClient(base_url="https://api.jeiguard.example.com")
    token  = client.login(email="analyst@empresa.com", password="...")

    for alert in client.stream_alerts(levels=["CRITICAL", "HIGH"]):
        print(alert)
"""

from .jeiguard_sdk import (
    AlertFilter,
    AlertSummary,
    AuthCredentials,
    CVEDetail,
    ComplianceScore,
    JeiGuardClient,
    ModelInfo,
    PredictionResult,
    ReportRequest,
)

__version__ = "2.0.0"
__author__  = "Jeiner Tello Nuñez"
__all__     = [
    "JeiGuardClient",
    "AuthCredentials",
    "AlertFilter",
    "AlertSummary",
    "PredictionResult",
    "ModelInfo",
    "ComplianceScore",
    "CVEDetail",
    "ReportRequest",
]
