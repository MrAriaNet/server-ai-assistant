"""Pending package updates and reboot-required checks."""

from __future__ import annotations

from pathlib import Path
from typing import List

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import read_text, run_cmd, run_script


@register_module("updates")
def check_updates(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []

    code, out, err = run_script("pkg_updates.sh", args=[os_info.pkg_manager], timeout=300)
    pending = 0
    security = 0
    detail_lines = []
    if code == 0 and out.strip():
        for line in out.strip().splitlines():
            if line.startswith("PENDING="):
                try:
                    pending = int(line.split("=", 1)[1])
                except ValueError:
                    pass
            elif line.startswith("SECURITY="):
                try:
                    security = int(line.split("=", 1)[1])
                except ValueError:
                    pass
            else:
                detail_lines.append(line)
    else:
        # Fallback inline
        if os_info.pkg_manager == "apt":
            run_cmd(["apt-get", "update", "-qq"], timeout=180)
            c2, o2, _ = run_cmd(
                ["bash", "-c", "apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || true"],
                timeout=180,
            )
            try:
                pending = int((o2 or "0").strip().splitlines()[-1])
            except ValueError:
                pending = 0
        elif os_info.pkg_manager in {"dnf", "yum"}:
            mgr = os_info.pkg_manager
            c2, o2, _ = run_cmd([mgr, "-q", "check-update"], timeout=180)
            # dnf returns 100 when updates available
            lines = [ln for ln in (o2 or "").splitlines() if ln.strip() and not ln.startswith("Last metadata")]
            pending = len(lines) if c2 in (0, 100) else 0

    if security > 0:
        findings.append(
            Finding(
                id="updates.security",
                module="updates",
                severity=Severity.CRITICAL,
                title="Security updates available",
                detail="Pending security-related package updates should be applied promptly.",
                current=f"{security} security update(s); {pending} total pending",
                recommended="Apply security updates in a maintenance window",
                remediation_id="apply_updates",
            )
        )
    elif pending > 0:
        findings.append(
            Finding(
                id="updates.pending",
                module="updates",
                severity=Severity.MEDIUM,
                title="Package updates available",
                detail="Non-zero pending package updates detected.",
                current=f"{pending} package(s) pending",
                recommended="Review and apply updates regularly",
                remediation_id="apply_updates",
            )
        )
    else:
        findings.append(
            Finding(
                id="updates.pending",
                module="updates",
                severity=Severity.INFO,
                title="System packages appear up to date",
                detail="No pending updates detected by the package manager probe.",
                current="0 pending",
                recommended="Keep automatic security updates enabled where appropriate",
            )
        )

    # Reboot required
    reboot = False
    reason = ""
    if Path("/var/run/reboot-required").exists():
        reboot = True
        reason = read_text("/var/run/reboot-required.pkgs", default="reboot-required flag present").strip()
    elif os_info.family == "rhel":
        c, o, _ = run_cmd(["needs-restarting", "-r"], timeout=60)
        # needs-restarting -r returns 1 if reboot needed
        if c == 1:
            reboot = True
            reason = (o or "needs-restarting indicates reboot").strip()

    if reboot:
        findings.append(
            Finding(
                id="updates.reboot_required",
                module="updates",
                severity=Severity.HIGH,
                title="Reboot required",
                detail="A reboot is required to finish applying kernel or core library updates.",
                current=reason[:300] or "reboot required",
                recommended="Schedule a controlled reboot",
            )
        )

    # Running vs installed kernel (simple)
    c_u, uname, _ = run_cmd(["uname", "-r"], timeout=10)
    if c_u == 0 and uname.strip():
        findings.append(
            Finding(
                id="updates.kernel_running",
                module="updates",
                severity=Severity.INFO,
                title="Running kernel",
                detail="Currently booted kernel release.",
                current=uname.strip(),
                recommended="After kernel updates, reboot into the new kernel",
            )
        )

    # Auto-update agents
    if os_info.family == "debian":
        auto = Path("/etc/apt/apt.conf.d/20auto-upgrades").exists() or Path(
            "/etc/apt/apt.conf.d/50unattended-upgrades"
        ).exists()
        findings.append(
            Finding(
                id="updates.unattended",
                module="updates",
                severity=Severity.LOW if not auto else Severity.INFO,
                title="Unattended upgrades configuration",
                detail="Debian/Ubuntu unattended-upgrades presence.",
                current="configured" if auto else "not detected",
                recommended="Install and enable unattended-upgrades for security patches",
            )
        )
    elif os_info.family == "rhel":
        c, o, _ = run_cmd(["systemctl", "is-enabled", "dnf-automatic.timer"], timeout=15)
        enabled = c == 0 and "enabled" in (o or "")
        findings.append(
            Finding(
                id="updates.dnf_automatic",
                module="updates",
                severity=Severity.LOW if not enabled else Severity.INFO,
                title="dnf-automatic status",
                detail="Automatic update timer on RHEL-like systems.",
                current="enabled" if enabled else "not enabled",
                recommended="Enable dnf-automatic.timer for security updates",
            )
        )

    if detail_lines:
        findings.append(
            Finding(
                id="updates.detail",
                module="updates",
                severity=Severity.INFO,
                title="Update probe details",
                detail="Additional output from package update helper.",
                current="\n".join(detail_lines)[:500],
                recommended="Review package list before applying",
            )
        )

    if err.strip() and code not in (0, 100):
        findings.append(
            Finding(
                id="updates.probe_error",
                module="updates",
                severity=Severity.LOW,
                title="Update probe warning",
                detail=err.strip()[:400],
                current=f"exit {code}",
                recommended="Ensure package indexes are reachable",
            )
        )

    return findings
