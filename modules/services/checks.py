"""Enabled-but-failed and important service posture."""

from __future__ import annotations

from typing import List

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import run_cmd, service_is_active, service_is_enabled, which


IMPORTANT = [
    "sshd",
    "ssh",
    "cron",
    "crond",
    "rsyslog",
    "systemd-journald",
    "NetworkManager",
    "networking",
    "nginx",
    "httpd",
    "apache2",
    "mysql",
    "mariadb",
    "postgresql",
    "docker",
    "fail2ban",
    "firewalld",
]


@register_module("services")
def check_services(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []

    # Enabled but inactive/failed
    code, out, _ = run_cmd(
        ["systemctl", "list-units", "--type=service", "--state=failed", "--no-legend", "--no-pager"],
        timeout=30,
    )
    failed = []
    if code == 0 and out.strip():
        for line in out.splitlines():
            parts = line.split()
            if parts:
                failed.append(parts[0])
    if failed:
        findings.append(
            Finding(
                id="services.failed",
                module="services",
                severity=Severity.HIGH,
                title="Failed systemd services",
                detail="Services currently in failed state.",
                current=", ".join(failed[:30]),
                recommended="systemctl status/reset-failed; fix unit then start",
            )
        )

    # Important services: enabled but not active
    bad = []
    present_active = []
    for name in IMPORTANT:
        # skip if unit unknown
        c, o, _ = run_cmd(["systemctl", "status", name, "--no-pager"], timeout=10)
        if c == 4:
            continue
        enabled = service_is_enabled(name)
        active = service_is_active(name)
        if active:
            present_active.append(name)
        elif enabled and not active:
            bad.append(name)
    if bad:
        findings.append(
            Finding(
                id="services.enabled_inactive",
                module="services",
                severity=Severity.HIGH,
                title="Enabled services not running",
                detail="Unit is enabled at boot but currently inactive.",
                current=", ".join(bad),
                recommended="Start the service or disable if obsolete",
            )
        )
    if present_active:
        findings.append(
            Finding(
                id="services.important_active",
                module="services",
                severity=Severity.INFO,
                title="Important services running",
                detail="Subset of common production services that are active.",
                current=", ".join(present_active),
                recommended="Keep monitoring with systemd and SAI audits",
            )
        )

    # Cron daemon
    cron_ok = service_is_active("cron") or service_is_active("crond")
    if not cron_ok and (which("cron") or which("crond")):
        findings.append(
            Finding(
                id="services.cron",
                module="services",
                severity=Severity.MEDIUM,
                title="Cron daemon not active",
                detail="Scheduled jobs will not run.",
                current="inactive",
                recommended="systemctl enable --now cron||crond",
            )
        )

    # Timers list (info)
    code, out, _ = run_cmd(
        ["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"],
        timeout=20,
    )
    if code == 0 and out.strip():
        findings.append(
            Finding(
                id="services.timers",
                module="services",
                severity=Severity.INFO,
                title="systemd timers",
                detail="Scheduled timers (truncated).",
                current="\n".join(out.strip().splitlines()[:20]),
                recommended="Ensure backup/cert renew timers are present",
            )
        )

    return findings
