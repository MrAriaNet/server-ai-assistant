"""Postfix and Dovecot checks (when present)."""

from __future__ import annotations

from pathlib import Path
from typing import List

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import read_text, service_is_active, which


@register_module("mail")
def check_mail(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []

    if which("postfix") or Path("/etc/postfix/main.cf").exists():
        active = service_is_active("postfix")
        main_cf = read_text("/etc/postfix/main.cf")
        inet = ""
        for line in main_cf.splitlines():
            if line.strip().startswith("inet_interfaces"):
                inet = line.split("=", 1)[-1].strip()
        findings.append(
            Finding(
                id="mail.postfix.present",
                module="mail",
                severity=Severity.INFO,
                title="Postfix detected",
                detail=f"active={active}",
                current=f"inet_interfaces={inet or 'default'}",
                recommended="Use inet_interfaces=loopback-only for non-mail hosts",
            )
        )
        if inet and inet not in {"loopback-only", "localhost"} and active:
            findings.append(
                Finding(
                    id="mail.postfix.open",
                    module="mail",
                    severity=Severity.MEDIUM,
                    title="Postfix not limited to loopback",
                    detail="Hosts that are not intended MX servers should not accept external mail.",
                    current=inet,
                    recommended="inet_interfaces = loopback-only (or restrict mynetworks)",
                )
            )

    if which("dovecot") or Path("/etc/dovecot").exists():
        active = service_is_active("dovecot")
        findings.append(
            Finding(
                id="mail.dovecot.present",
                module="mail",
                severity=Severity.INFO,
                title="Dovecot detected",
                detail=f"active={active}",
                current="active" if active else "installed",
                recommended="Require TLS for IMAP/POP; disable plaintext auth",
            )
        )

    if not findings:
        findings.append(
            Finding(
                id="mail.none",
                module="mail",
                severity=Severity.INFO,
                title="No mail server detected",
                detail="Postfix/Dovecot not found.",
                current="none",
                recommended="n/a",
            )
        )

    return findings
