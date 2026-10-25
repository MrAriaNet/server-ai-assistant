"""Docker and Podman basic health and security signals."""

from __future__ import annotations

import json
from typing import List

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import run_cmd, service_is_active, which


@register_module("containers")
def check_containers(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []
    found = False

    if which("docker"):
        found = True
        active = service_is_active("docker")
        findings.append(
            Finding(
                id="containers.docker.present",
                module="containers",
                severity=Severity.INFO,
                title="Docker detected",
                detail=f"daemon active={active}",
                current="active" if active else "installed",
                recommended="Keep engine updated; avoid privileged containers",
            )
        )
        code, out, _ = run_cmd(["docker", "ps", "-aq"], timeout=30)
        running_code, running_out, _ = run_cmd(["docker", "ps", "-q"], timeout=30)
        total = len([x for x in (out or "").splitlines() if x.strip()]) if code == 0 else 0
        running = len([x for x in (running_out or "").splitlines() if x.strip()]) if running_code == 0 else 0
        findings.append(
            Finding(
                id="containers.docker.count",
                module="containers",
                severity=Severity.INFO,
                title="Docker container counts",
                detail="Running vs total containers.",
                current=f"{running} running / {total} total",
                recommended="Remove unused containers regularly",
            )
        )
        # dangling images
        dcode, dout, _ = run_cmd(["docker", "images", "-f", "dangling=true", "-q"], timeout=30)
        dangling = len([x for x in (dout or "").splitlines() if x.strip()]) if dcode == 0 else 0
        if dangling:
            findings.append(
                Finding(
                    id="containers.docker.dangling",
                    module="containers",
                    severity=Severity.LOW,
                    title="Dangling Docker images",
                    detail="Unused intermediate images consume disk.",
                    current=f"{dangling} dangling image(s)",
                    recommended="docker image prune",
                )
            )
        # privileged / host network
        icode, iout, _ = run_cmd(
            ["docker", "ps", "--format", "{{.ID}}"],
            timeout=30,
        )
        privileged = []
        host_net = []
        if icode == 0:
            for cid in [x.strip() for x in (iout or "").splitlines() if x.strip()][:50]:
                jcode, jout, _ = run_cmd(["docker", "inspect", cid], timeout=20)
                if jcode != 0:
                    continue
                try:
                    data = json.loads(jout)[0]
                except (json.JSONDecodeError, IndexError, KeyError):
                    continue
                name = data.get("Name", cid).lstrip("/")
                host_cfg = data.get("HostConfig") or {}
                if host_cfg.get("Privileged"):
                    privileged.append(name)
                if host_cfg.get("NetworkMode") == "host":
                    host_net.append(name)
        if privileged:
            findings.append(
                Finding(
                    id="containers.docker.privileged",
                    module="containers",
                    severity=Severity.HIGH,
                    title="Privileged containers running",
                    detail="Privileged mode weakens container isolation.",
                    current=", ".join(privileged[:20]),
                    recommended="Avoid --privileged; use fine-grained capabilities",
                )
            )
        if host_net:
            findings.append(
                Finding(
                    id="containers.docker.host_network",
                    module="containers",
                    severity=Severity.MEDIUM,
                    title="Containers using host network",
                    detail="Host networking shares the host network namespace.",
                    current=", ".join(host_net[:20]),
                    recommended="Use bridge/overlay networks unless host mode is required",
                )
            )

    if which("podman"):
        found = True
        findings.append(
            Finding(
                id="containers.podman.present",
                module="containers",
                severity=Severity.INFO,
                title="Podman detected",
                detail="Podman CLI is available.",
                current="installed",
                recommended="Prefer rootless Podman where practical",
            )
        )
        code, out, _ = run_cmd(["podman", "ps", "-q"], timeout=30)
        running = len([x for x in (out or "").splitlines() if x.strip()]) if code == 0 else 0
        findings.append(
            Finding(
                id="containers.podman.count",
                module="containers",
                severity=Severity.INFO,
                title="Podman running containers",
                detail="Count of running Podman containers.",
                current=str(running),
                recommended="Audit images and rebuild regularly",
            )
        )

    if not found:
        findings.append(
            Finding(
                id="containers.none",
                module="containers",
                severity=Severity.INFO,
                title="No container runtime detected",
                detail="Docker/Podman not found in PATH.",
                current="none",
                recommended="n/a",
            )
        )

    return findings
