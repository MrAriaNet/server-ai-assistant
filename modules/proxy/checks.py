"""HAProxy, Varnish, and Keepalived configuration signals."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import read_text, run_cmd, service_is_active, which


@register_module("proxy")
def check_proxy(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []
    found = False

    # HAProxy
    if which("haproxy") or Path("/etc/haproxy/haproxy.cfg").exists():
        found = True
        active = service_is_active("haproxy")
        cfg = Path("/etc/haproxy/haproxy.cfg")
        findings.append(
            Finding(
                id="proxy.haproxy.present",
                module="proxy",
                severity=Severity.INFO,
                title="HAProxy detected",
                detail=f"active={active}",
                current="active" if active else "installed",
                recommended="Run haproxy -c -f /etc/haproxy/haproxy.cfg after changes",
            )
        )
        if cfg.is_file():
            text = read_text(cfg)
            code, out, err = run_cmd(["haproxy", "-c", "-f", str(cfg)], timeout=20)
            if code != 0:
                findings.append(
                    Finding(
                        id="proxy.haproxy.config",
                        module="proxy",
                        severity=Severity.CRITICAL,
                        title="HAProxy configuration invalid",
                        detail=(err or out or "haproxy -c failed")[:400],
                        current="FAIL",
                        recommended="Fix haproxy.cfg before reload",
                    )
                )
            if not re.search(r"^\s*stats\s+", text, re.M | re.I):
                findings.append(
                    Finding(
                        id="proxy.haproxy.stats",
                        module="proxy",
                        severity=Severity.LOW,
                        title="HAProxy stats socket/page not obvious",
                        detail="No clear stats directive found (may be intentional).",
                        current="unset/not matched",
                        recommended="Expose stats on localhost only for ops visibility",
                    )
                )
            if re.search(r"mode\s+http", text) and not re.search(r"timeout\s+client", text):
                findings.append(
                    Finding(
                        id="proxy.haproxy.timeouts",
                        module="proxy",
                        severity=Severity.MEDIUM,
                        title="HAProxy client timeout may be unset",
                        detail="HTTP mode without obvious timeout client.",
                        current="missing timeout client",
                        recommended="Set timeout connect/client/server explicitly",
                    )
                )

    # Varnish
    if which("varnishd") or Path("/etc/varnish/default.vcl").exists():
        found = True
        active = service_is_active("varnish")
        findings.append(
            Finding(
                id="proxy.varnish.present",
                module="proxy",
                severity=Severity.INFO,
                title="Varnish detected",
                detail=f"active={active}",
                current="active" if active else "installed",
                recommended="Keep VCL under review; avoid caching authenticated responses",
            )
        )

    # Keepalived
    if which("keepalived") or Path("/etc/keepalived/keepalived.conf").exists():
        found = True
        active = service_is_active("keepalived")
        findings.append(
            Finding(
                id="proxy.keepalived.present",
                module="proxy",
                severity=Severity.INFO,
                title="Keepalived detected",
                detail=f"active={active}",
                current="active" if active else "installed",
                recommended="Monitor VRRP state and firewall multicast/unicast rules",
            )
        )
        if not active and Path("/etc/keepalived/keepalived.conf").exists():
            findings.append(
                Finding(
                    id="proxy.keepalived.inactive",
                    module="proxy",
                    severity=Severity.HIGH,
                    title="Keepalived installed but inactive",
                    detail="HA VIP may be unmanaged.",
                    current="inactive",
                    recommended="systemctl enable --now keepalived",
                )
            )

    if not found:
        findings.append(
            Finding(
                id="proxy.none",
                module="proxy",
                severity=Severity.INFO,
                title="No HAProxy/Varnish/Keepalived detected",
                detail="Common load-balancer stack not found.",
                current="none",
                recommended="n/a unless this host is an edge/LB node",
            )
        )

    return findings
