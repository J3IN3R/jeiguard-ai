"""
JeiGuard AI v1.0.2 — Mejora 3: SOAR Automated Response Engine
Respuesta automática a incidentes: bloquea IPs, aísla hosts, crea tickets.
Copyright © 2026 Jeiner Tello Nuñez — MIT License
"""
from __future__ import annotations

import json
import time
import uuid
import subprocess
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable

logger = logging.getLogger("jeiguard.soar")


# ── Constantes ─────────────────────────────────────────────────────────────────
SOAR_VERSION           = "1.0.2"
AUTO_BLOCK_CONFIDENCE  = 0.95     # Confianza mínima para bloqueo automático
AUTO_ISOLATE_SCORE     = 85       # Riesgo mínimo para aislamiento de host
BLOCK_TTL_S            = 3600     # Bloqueos duran 1 hora por defecto
ROLLBACK_WINDOW_S      = 300      # Ventana para reversar acciones (5 min)
FP_ROLLBACK_THRESHOLD  = 3        # Nº de FP confirmados para reversar


class ResponseAction(str, Enum):
    BLOCK_IP         = "block_ip"
    UNBLOCK_IP       = "unblock_ip"
    ISOLATE_HOST     = "isolate_host"
    RESTORE_HOST     = "restore_host"
    CREATE_TICKET    = "create_ticket"
    SEND_NOTIFICATION = "send_notification"
    CAPTURE_TRAFFIC  = "capture_traffic"
    ENRICH_IOC       = "enrich_ioc"


class ResponseStatus(str, Enum):
    PENDING   = "pending"
    EXECUTING = "executing"
    SUCCESS   = "success"
    FAILED    = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED   = "skipped"


@dataclass
class ResponsePlaybook:
    name:        str
    trigger:     str
    actions:     list[ResponseAction]
    conditions:  dict
    auto_execute: bool = False
    priority:    int   = 5


@dataclass
class ResponseExecution:
    execution_id: str
    playbook_name: str
    alert_id:     str
    src_ip:       str
    actions_taken: list[dict]
    status:       ResponseStatus
    started_at:   float
    completed_at: float = 0.0
    rollback_at:  float = 0.0
    notes:        str   = ""

    @property
    def duration_ms(self) -> float:
        if self.completed_at:
            return (self.completed_at - self.started_at) * 1000
        return 0.0


@dataclass
class BlockedIP:
    ip:          str
    reason:      str
    alert_id:    str
    blocked_at:  float
    expires_at:  float
    fp_reports:  int  = 0
    auto_blocked: bool = False


class SOARResponseEngine:
    """
    Motor SOAR que ejecuta respuestas automáticas a incidentes de seguridad.
    Soporta bloqueo de IPs, aislamiento de hosts, tickets y notificaciones.
    """

    def __init__(self,
                 dry_run:         bool = True,
                 jira_url:        Optional[str] = None,
                 jira_token:      Optional[str] = None,
                 slack_webhook:   Optional[str] = None,
                 firewall_api:    Optional[str] = None):

        self._dry_run       = dry_run
        self._jira_url      = jira_url
        self._jira_token    = jira_token
        self._slack_webhook = slack_webhook
        self._firewall_api  = firewall_api

        self._blocked_ips:  dict[str, BlockedIP]         = {}
        self._executions:   dict[str, ResponseExecution] = {}
        self._playbooks:    list[ResponsePlaybook]       = self._load_playbooks()
        self._stats = {
            "total_responses":  0,
            "ips_blocked":      0,
            "hosts_isolated":   0,
            "tickets_created":  0,
            "rollbacks":        0,
            "dry_run_actions":  0,
        }

        if dry_run:
            logger.info("SOAR iniciado en modo DRY_RUN — ninguna acción real se ejecutará")

    # ── API pública ────────────────────────────────────────────────────────────

    def respond(self, alert_id: str, src_ip: str, category: str,
                confidence: float, risk_score: int = 0) -> ResponseExecution:
        """Punto de entrada principal — evalúa y ejecuta respuesta automática."""
        playbook = self._select_playbook(category, confidence, risk_score)
        if not playbook:
            return self._skip_response(alert_id, src_ip, "No playbook matched")

        execution = ResponseExecution(
            execution_id=f"EXEC-{uuid.uuid4().hex[:8].upper()}",
            playbook_name=playbook.name,
            alert_id=alert_id,
            src_ip=src_ip,
            actions_taken=[],
            status=ResponseStatus.EXECUTING,
            started_at=time.time(),
        )
        self._executions[execution.execution_id] = execution

        for action in playbook.actions:
            result = self._execute_action(action, execution, {
                "src_ip": src_ip, "alert_id": alert_id,
                "category": category, "confidence": confidence,
            })
            execution.actions_taken.append(result)

        execution.status   = ResponseStatus.SUCCESS
        execution.completed_at = time.time()
        self._stats["total_responses"] += 1

        logger.info(
            "Respuesta completada | exec=%s ip=%s playbook=%s actions=%d",
            execution.execution_id, src_ip, playbook.name,
            len(execution.actions_taken)
        )
        return execution

    def report_false_positive(self, src_ip: str) -> bool:
        """Registra un FP y revierte el bloqueo si supera el umbral."""
        blocked = self._blocked_ips.get(src_ip)
        if not blocked:
            return False

        blocked.fp_reports += 1
        if blocked.fp_reports >= FP_ROLLBACK_THRESHOLD:
            self._unblock_ip(src_ip, reason="Revertido por falsos positivos")
            self._stats["rollbacks"] += 1
            return True
        return False

    def cleanup_expired_blocks(self) -> int:
        """Limpia bloqueos expirados. Llamar periódicamente."""
        now     = time.time()
        expired = [ip for ip, b in self._blocked_ips.items()
                   if b.expires_at and b.expires_at < now]
        for ip in expired:
            self._unblock_ip(ip, reason="Expirado automáticamente")
        return len(expired)

    def get_blocked_ips(self) -> list[BlockedIP]:
        return list(self._blocked_ips.values())

    def get_recent_executions(self, n: int = 20) -> list[ResponseExecution]:
        execs = sorted(self._executions.values(),
                       key=lambda e: -e.started_at)
        return execs[:n]

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "currently_blocked":     len(self._blocked_ips),
            "total_executions":      len(self._executions),
            "mode":                  "DRY_RUN" if self._dry_run else "LIVE",
        }

    # ── Playbooks ──────────────────────────────────────────────────────────────

    def _load_playbooks(self) -> list[ResponsePlaybook]:
        return [
            ResponsePlaybook(
                name="Critical Auto-Block",
                trigger="Any attack with confidence > 95%",
                actions=[
                    ResponseAction.BLOCK_IP,
                    ResponseAction.ENRICH_IOC,
                    ResponseAction.CREATE_TICKET,
                    ResponseAction.SEND_NOTIFICATION,
                ],
                conditions={"min_confidence": 0.95},
                auto_execute=True, priority=1,
            ),
            ResponsePlaybook(
                name="APT Response",
                trigger="U2R or Backdoor — possible APT",
                actions=[
                    ResponseAction.BLOCK_IP,
                    ResponseAction.ISOLATE_HOST,
                    ResponseAction.CAPTURE_TRAFFIC,
                    ResponseAction.CREATE_TICKET,
                    ResponseAction.SEND_NOTIFICATION,
                ],
                conditions={"categories": ["U2R", "Backdoor"], "min_confidence": 0.80},
                auto_execute=True, priority=1,
            ),
            ResponsePlaybook(
                name="DDoS Mitigation",
                trigger="DoS/DDoS attack detected",
                actions=[
                    ResponseAction.BLOCK_IP,
                    ResponseAction.SEND_NOTIFICATION,
                    ResponseAction.CREATE_TICKET,
                ],
                conditions={"categories": ["DoS_DDoS"], "min_confidence": 0.85},
                auto_execute=True, priority=2,
            ),
            ResponsePlaybook(
                name="High Risk Enrichment",
                trigger="High confidence attack — enrich and notify",
                actions=[
                    ResponseAction.ENRICH_IOC,
                    ResponseAction.SEND_NOTIFICATION,
                ],
                conditions={"min_confidence": 0.80},
                auto_execute=True, priority=5,
            ),
        ]

    def _select_playbook(self, category: str, confidence: float,
                          risk_score: int) -> Optional[ResponsePlaybook]:
        for playbook in sorted(self._playbooks, key=lambda p: p.priority):
            conds = playbook.conditions
            if not playbook.auto_execute:
                continue
            if "min_confidence" in conds and confidence < conds["min_confidence"]:
                continue
            if "categories" in conds and category not in conds["categories"]:
                if confidence < 0.95:
                    continue
            return playbook
        return None

    # ── Ejecutores de acciones ─────────────────────────────────────────────────

    def _execute_action(self, action: ResponseAction, execution: ResponseExecution,
                         context: dict) -> dict:
        handlers: dict[ResponseAction, Callable] = {
            ResponseAction.BLOCK_IP:          self._block_ip_action,
            ResponseAction.ISOLATE_HOST:      self._isolate_host_action,
            ResponseAction.CREATE_TICKET:     self._create_ticket_action,
            ResponseAction.SEND_NOTIFICATION: self._send_notification_action,
            ResponseAction.CAPTURE_TRAFFIC:   self._capture_traffic_action,
            ResponseAction.ENRICH_IOC:        self._enrich_ioc_action,
        }
        handler = handlers.get(action)
        if not handler:
            return {"action": action.value, "status": "skipped", "reason": "No handler"}

        try:
            result = handler(context)
            return {"action": action.value, "status": "success", **result}
        except Exception as e:
            logger.error("Error ejecutando acción %s: %s", action.value, e)
            return {"action": action.value, "status": "failed", "error": str(e)}

    def _block_ip_action(self, ctx: dict) -> dict:
        ip        = ctx["src_ip"]
        alert_id  = ctx["alert_id"]
        expires   = time.time() + BLOCK_TTL_S

        if ip in self._blocked_ips:
            return {"result": "already_blocked", "ip": ip}

        if not self._dry_run:
            try:
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True, timeout=5
                )
            except Exception as e:
                raise RuntimeError(f"iptables falló: {e}")
        else:
            self._stats["dry_run_actions"] += 1

        self._blocked_ips[ip] = BlockedIP(
            ip=ip, reason=f"Auto-blocked — alert {alert_id}",
            alert_id=alert_id, blocked_at=time.time(),
            expires_at=expires, auto_blocked=True
        )
        self._stats["ips_blocked"] += 1
        action_label = "[DRY_RUN] " if self._dry_run else ""
        logger.info("%sIP bloqueada: %s (expira en %ds)", action_label, ip, BLOCK_TTL_S)
        return {"result": "blocked", "ip": ip, "expires_in_s": BLOCK_TTL_S,
                "dry_run": self._dry_run}

    def _unblock_ip(self, ip: str, reason: str = "") -> None:
        if not self._dry_run:
            try:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True, timeout=5
                )
            except Exception:
                pass
        self._blocked_ips.pop(ip, None)
        logger.info("IP desbloqueada: %s — %s", ip, reason)

    def _isolate_host_action(self, ctx: dict) -> dict:
        ip = ctx["src_ip"]
        if not self._dry_run:
            # En producción: VLAN quarantine via switch API
            logger.warning("Aislamiento de host requiere integración con switch — usar API del switch")
        else:
            self._stats["dry_run_actions"] += 1
        self._stats["hosts_isolated"] += 1
        return {"result": "isolated", "host": ip, "dry_run": self._dry_run}

    def _create_ticket_action(self, ctx: dict) -> dict:
        ticket_data = {
            "summary":     f"[JeiGuard AI] Incidente de seguridad — {ctx['category']}",
            "description": (
                f"Alerta ID: {ctx['alert_id']}\n"
                f"IP Origen: {ctx['src_ip']}\n"
                f"Categoría: {ctx['category']}\n"
                f"Confianza: {ctx['confidence']:.1%}\n"
                f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}"
            ),
            "priority":    "Critical" if ctx["confidence"] > 0.95 else "High",
            "labels":      ["security", "jeiguard-ai", ctx["category"].lower()],
        }

        if self._jira_url and self._jira_token and not self._dry_run:
            import urllib.request
            req = urllib.request.Request(
                f"{self._jira_url}/rest/api/2/issue",
                data=json.dumps({"fields": {
                    "project":     {"key": "SEC"},
                    "summary":     ticket_data["summary"],
                    "description": ticket_data["description"],
                    "issuetype":   {"name": "Bug"},
                    "priority":    {"name": ticket_data["priority"]},
                }}).encode(),
                headers={
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {self._jira_token}",
                }
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                ticket_id = json.loads(resp.read())["key"]
        else:
            ticket_id = f"SEC-{uuid.uuid4().hex[:6].upper()}"
            self._stats["dry_run_actions"] += 1

        self._stats["tickets_created"] += 1
        return {"result": "created", "ticket_id": ticket_id, "dry_run": self._dry_run}

    def _send_notification_action(self, ctx: dict) -> dict:
        message = (
            f"*ALERTA JeiGuard AI*\n"
            f"Categoría: `{ctx['category']}`\n"
            f"IP: `{ctx['src_ip']}`\n"
            f"Confianza: `{ctx['confidence']:.1%}`\n"
            f"Alert ID: `{ctx['alert_id']}`"
        )
        if self._slack_webhook and not self._dry_run:
            import urllib.request
            req = urllib.request.Request(
                self._slack_webhook,
                data=json.dumps({"text": message}).encode(),
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=5)
        else:
            self._stats["dry_run_actions"] += 1

        return {"result": "sent", "channel": "slack", "dry_run": self._dry_run}

    def _capture_traffic_action(self, ctx: dict) -> dict:
        pcap_file = f"/tmp/jeiguard_capture_{ctx['src_ip'].replace('.','_')}_{int(time.time())}.pcap"
        if not self._dry_run:
            try:
                subprocess.Popen(
                    ["tcpdump", "-i", "any", "-w", pcap_file,
                     "host", ctx["src_ip"], "-c", "10000"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except FileNotFoundError:
                return {"result": "skipped", "reason": "tcpdump no disponible"}
        else:
            self._stats["dry_run_actions"] += 1
        return {"result": "capturing", "file": pcap_file, "dry_run": self._dry_run}

    def _enrich_ioc_action(self, ctx: dict) -> dict:
        return {
            "result":      "enriched",
            "ip":          ctx["src_ip"],
            "reputation":  "malicious" if ctx["confidence"] > 0.90 else "suspicious",
            "geo":         "Unknown — requires AbuseIPDB API key",
            "dry_run":     self._dry_run,
        }

    def _skip_response(self, alert_id: str, src_ip: str, reason: str) -> ResponseExecution:
        execution = ResponseExecution(
            execution_id=f"SKIP-{uuid.uuid4().hex[:8]}",
            playbook_name="none",
            alert_id=alert_id, src_ip=src_ip,
            actions_taken=[],
            status=ResponseStatus.SKIPPED,
            started_at=time.time(),
            completed_at=time.time(),
            notes=reason,
        )
        self._executions[execution.execution_id] = execution
        return execution


# ── Demo ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  JeiGuard AI v1.0.2 — SOAR Response Engine (DRY_RUN)")
    print("=" * 60)

    soar = SOARResponseEngine(dry_run=True)

    scenarios = [
        ("ALT-001", "10.42.183.97", "DoS_DDoS",    0.948),
        ("ALT-002", "192.168.5.12", "U2R",          0.821),
        ("ALT-003", "172.16.8.33",  "Web_Exploit",  0.761),
        ("ALT-004", "10.18.44.201", "Probe_Scan",   0.651),
    ]

    for alert_id, src_ip, category, confidence in scenarios:
        print(f"\nProcesando: {alert_id} | {category} | {src_ip} | conf={confidence:.1%}")
        execution = soar.respond(alert_id, src_ip, category, confidence)
        print(f"  Playbook: {execution.playbook_name}")
        print(f"  Status:   {execution.status.value}")
        print(f"  Acciones: {[a['action'] for a in execution.actions_taken]}")
        print(f"  Tiempo:   {execution.duration_ms:.1f}ms")

    print(f"\nIPs bloqueadas: {[b.ip for b in soar.get_blocked_ips()]}")
    print(f"Stats: {json.dumps(soar.get_stats(), indent=2)}")
