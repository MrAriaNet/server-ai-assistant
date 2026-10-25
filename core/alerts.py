"""Webhook and Slack notifications for critical findings."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.models import AuditResult, Finding, Severity
from core.util import load_config


def _log(msg: str) -> None:
    try:
        from core.backup import log_action

        log_action(msg)
    except Exception:
        pass


def _min_severity(cfg: Optional[dict] = None) -> Severity:
    cfg = cfg or load_config()
    alerts = cfg.get("alerts") or {}
    raw = str(alerts.get("min_severity", "high")).lower()
    try:
        return Severity(raw)
    except ValueError:
        return Severity.HIGH


def filter_alert_findings(result: AuditResult, minimum: Optional[Severity] = None) -> List[Finding]:
    sev = minimum or _min_severity()
    return [f for f in result.findings if f.severity.at_or_above(sev)]


def build_payload(result: AuditResult, findings: List[Finding]) -> Dict[str, Any]:
    return {
        "source": "server-ai-assistant",
        "hostname": result.hostname,
        "os": f"{result.os_name} {result.os_version}".strip(),
        "modules": result.modules_run,
        "summary": result.summary(),
        "alert_count": len(findings),
        "findings": [
            {
                "id": f.id,
                "severity": f.severity.value,
                "module": f.module,
                "title": f.title,
                "detail": f.detail,
                "current": f.current,
                "recommended": f.recommended,
            }
            for f in findings[:50]
        ],
    }


def build_slack_payload(result: AuditResult, findings: List[Finding]) -> Dict[str, Any]:
    summary = result.summary()
    lines = [
        f"*Server AI Assistant* alert on `{result.hostname}`",
        f"OS: {result.os_name} {result.os_version}",
        (
            f"Summary — critical: {summary.get('critical', 0)}, "
            f"high: {summary.get('high', 0)}, total: {summary.get('total', 0)}"
        ),
        f"Alerting on {len(findings)} finding(s):",
    ]
    for f in findings[:15]:
        lines.append(f"• `[{f.severity.value.upper()}]` *{f.title}* — {f.id}")
    if len(findings) > 15:
        lines.append(f"_…and {len(findings) - 15} more_")
    return {"text": "\n".join(lines)}


def _post_json(url: str, payload: Dict[str, Any], timeout: int = 20) -> tuple[int, str]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return 1, f"unsupported URL scheme: {parsed.scheme}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "ServerAI-Assistant/1.2"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
        return exc.code, body
    except Exception as exc:  # noqa: BLE001
        return 1, str(exc)


def send_webhook(url: str, result: AuditResult, *, minimum: Optional[Severity] = None) -> tuple[bool, str]:
    findings = filter_alert_findings(result, minimum)
    if not findings:
        return True, "no findings at alert threshold; nothing sent"
    code, body = _post_json(url, build_payload(result, findings))
    ok = 200 <= int(code) < 300
    _log(f"webhook url={urlparse(url).netloc} status={code} findings={len(findings)}")
    return ok, f"HTTP {code}: {body[:300]}"


def send_slack(webhook_url: str, result: AuditResult, *, minimum: Optional[Severity] = None) -> tuple[bool, str]:
    findings = filter_alert_findings(result, minimum)
    if not findings:
        return True, "no findings at alert threshold; nothing sent"
    code, body = _post_json(webhook_url, build_slack_payload(result, findings))
    ok = 200 <= int(code) < 300 or body.strip().lower() == "ok"
    _log(f"slack webhook status={code} findings={len(findings)}")
    return ok, f"HTTP {code}: {body[:300]}"


def notify_from_config(result: AuditResult, cfg: Optional[dict] = None) -> List[str]:
    """Send configured alerts; return status messages."""
    cfg = cfg or load_config()
    alerts = cfg.get("alerts") or {}
    messages: List[str] = []
    if not alerts.get("enabled"):
        return ["alerts disabled in config"]
    try:
        minimum = Severity(str(alerts.get("min_severity", "high")).lower())
    except ValueError:
        minimum = Severity.HIGH
    webhook = alerts.get("webhook_url") or ""
    slack = alerts.get("slack_webhook_url") or ""
    if webhook:
        ok, msg = send_webhook(webhook, result, minimum=minimum)
        messages.append(f"webhook: {'OK' if ok else 'FAIL'} — {msg}")
    if slack:
        ok, msg = send_slack(slack, result, minimum=minimum)
        messages.append(f"slack: {'OK' if ok else 'FAIL'} — {msg}")
    if not webhook and not slack:
        messages.append("no webhook_url or slack_webhook_url configured")
    return messages
