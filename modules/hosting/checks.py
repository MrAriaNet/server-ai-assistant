"""Detect common hosting control panels (presence only)."""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import which


PANELS: List[Tuple[str, List[str], List[str]]] = [
    # name, paths, binaries
    ("cPanel/WHM", ["/usr/local/cpanel", "/etc/cpanel"], ["whmapi1", "uapi"]),
    ("Plesk", ["/usr/local/psa", "/etc/psa"], ["plesk"]),
    ("DirectAdmin", ["/usr/local/directadmin"], ["directadmin"]),
    ("CyberPanel", ["/usr/local/CyberCP", "/usr/local/lsws"], []),
    ("Webmin", ["/etc/webmin", "/usr/share/webmin"], ["webmin"]),
    ("ISPConfig", ["/usr/local/ispconfig"], []),
    ("HestiaCP", ["/usr/local/hestia"], ["v-list-users"]),
    ("aaPanel", ["/www/server/panel"], []),
]


@register_module("hosting")
def check_hosting(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []
    detected = []

    for name, paths, bins in PANELS:
        hit = any(Path(p).exists() for p in paths) or any(which(b) for b in bins)
        if hit:
            detected.append(name)
            findings.append(
                Finding(
                    id=f"hosting.panel.{name.split('/')[0].lower()}",
                    module="hosting",
                    severity=Severity.INFO,
                    title=f"Control panel detected: {name}",
                    detail="Presence-only detection; panel APIs are not queried in v1.",
                    current="installed",
                    recommended="Keep the panel and its components fully patched; restrict admin ports",
                )
            )

    # Common web roots / hosting layout hints
    webroots = [p for p in ("/var/www", "/home", "/usr/share/nginx/html") if Path(p).exists()]
    if webroots:
        findings.append(
            Finding(
                id="hosting.webroots",
                module="hosting",
                severity=Severity.INFO,
                title="Common web root paths present",
                detail="Useful for shared hosting / vhost layout awareness.",
                current=", ".join(webroots),
                recommended="Ensure correct ownership and disable directory listing",
            )
        )

    if not detected:
        findings.append(
            Finding(
                id="hosting.none",
                module="hosting",
                severity=Severity.INFO,
                title="No major control panel detected",
                detail="cPanel/Plesk/DirectAdmin/etc. paths not found.",
                current="none",
                recommended="Manage hardening via OS packages and this assistant",
            )
        )

    return findings
