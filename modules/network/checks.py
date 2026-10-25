"""Listening ports, DNS, and NTP-related network checks."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import read_text, run_cmd


# Ports that are often unexpected on a hardened edge host
RISKY_PUBLIC = {
    21: "FTP",
    23: "Telnet",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    11211: "Memcached",
    9200: "Elasticsearch",
    5601: "Kibana",
}


@register_module("network")
def check_network(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []

    code, out, _ = run_cmd(["ss", "-tulpn"], timeout=30)
    if code != 0:
        code, out, _ = run_cmd(["netstat", "-tulpn"], timeout=30)

    if code == 0 and out.strip():
        findings.append(
            Finding(
                id="network.listeners",
                module="network",
                severity=Severity.INFO,
                title="Listening sockets snapshot",
                detail="Active TCP/UDP listeners (truncated).",
                current="\n".join(out.strip().splitlines()[:40]),
                recommended="Ensure only required services listen publicly",
            )
        )
        for port, name in RISKY_PUBLIC.items():
            if re.search(rf"(0\.0\.0\.0|\[::\]|\*):{port}\b", out):
                findings.append(
                    Finding(
                        id=f"network.public.{port}",
                        module="network",
                        severity=Severity.HIGH,
                        title=f"{name} port {port} is publicly listening",
                        detail="High-risk service appears bound on all interfaces.",
                        current=f"*:{port}",
                        recommended="Bind to localhost/private IP and firewall restrict",
                    )
                )
    else:
        findings.append(
            Finding(
                id="network.listeners",
                module="network",
                severity=Severity.LOW,
                title="Could not list listening sockets",
                detail="ss/netstat unavailable or failed.",
                current="n/a",
                recommended="Install iproute2 (ss)",
            )
        )

    # DNS resolvers
    resolv = read_text("/etc/resolv.conf")
    nameservers = [ln.split()[1] for ln in resolv.splitlines() if ln.strip().startswith("nameserver")]
    if not nameservers:
        findings.append(
            Finding(
                id="network.dns",
                module="network",
                severity=Severity.MEDIUM,
                title="No DNS nameservers configured",
                detail="/etc/resolv.conf has no nameserver entries.",
                current="none",
                recommended="Configure reliable resolvers (or systemd-resolved)",
            )
        )
    else:
        findings.append(
            Finding(
                id="network.dns",
                module="network",
                severity=Severity.INFO,
                title="DNS nameservers",
                detail="Configured resolvers from /etc/resolv.conf.",
                current=", ".join(nameservers),
                recommended="Prefer trusted resolvers; consider DNSSEC-aware setup",
            )
        )

    # IP forwarding (router accidental)
    try:
        fwd = Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="utf-8").strip()
        if fwd == "1":
            findings.append(
                Finding(
                    id="network.ip_forward",
                    module="network",
                    severity=Severity.LOW,
                    title="IPv4 forwarding is enabled",
                    detail="Expected on routers/NAT gateways; unusual on single app hosts.",
                    current="1",
                    recommended="Disable if this host is not a router/gateway",
                )
            )
    except OSError:
        pass

    return findings
