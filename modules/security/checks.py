"""SSH, firewall, fail2ban, sysctl, and filesystem security checks."""

from __future__ import annotations

from pathlib import Path
from typing import List

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import parse_sshd_config, read_text, run_cmd, service_is_active, which


def _sysctl_get(key: str) -> str:
    code, out, _ = run_cmd(["sysctl", "-n", key], timeout=10)
    return out.strip() if code == 0 else ""


@register_module("security")
def check_security(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []
    recs = (config.get("security_recommendations") or {})
    ssh_rec = recs.get("ssh") or {}
    sysctl_rec = recs.get("sysctl") or {}

    # SSH
    sshd = which("sshd") or which("ssh")
    if Path("/etc/ssh/sshd_config").exists() or sshd:
        cfg = parse_sshd_config()
        checks = [
            ("PermitRootLogin", ssh_rec.get("PermitRootLogin", "no"), Severity.HIGH),
            ("PasswordAuthentication", ssh_rec.get("PasswordAuthentication", "no"), Severity.HIGH),
            ("MaxAuthTries", ssh_rec.get("MaxAuthTries", "3"), Severity.MEDIUM),
            ("X11Forwarding", ssh_rec.get("X11Forwarding", "no"), Severity.LOW),
            ("ClientAliveInterval", ssh_rec.get("ClientAliveInterval", "300"), Severity.LOW),
        ]
        weak = []
        for key, recommended, sev in checks:
            current = cfg.get(key, "(default/unset)")
            cur_norm = str(current).split()[0].lower()
            rec_norm = str(recommended).lower()
            # PermitRootLogin prohibit-password / without-password is better than yes
            if key == "PermitRootLogin":
                bad = cur_norm in {"yes", "true"}
            elif key == "PasswordAuthentication":
                bad = cur_norm in {"yes", "true"}
            elif key == "X11Forwarding":
                bad = cur_norm in {"yes", "true"}
            elif key == "MaxAuthTries":
                try:
                    bad = int(cur_norm) > int(rec_norm)
                except ValueError:
                    bad = cur_norm == "(default/unset)"
            else:
                bad = cur_norm != rec_norm and cur_norm == "(default/unset)"
            if bad:
                weak.append(key)
                findings.append(
                    Finding(
                        id=f"security.ssh.{key}",
                        module="security",
                        severity=sev,
                        title=f"SSH {key} not hardened",
                        detail=f"Recommended hardening for {key}.",
                        current=str(current),
                        recommended=str(recommended),
                        remediation_id="ssh_harden",
                    )
                )
        if not weak:
            findings.append(
                Finding(
                    id="security.ssh.ok",
                    module="security",
                    severity=Severity.INFO,
                    title="SSH hardening looks reasonable",
                    detail="Key SSH settings match recommended baseline or safer values.",
                    current="ok",
                    recommended="Keep key-based auth and monitor auth logs",
                )
            )
    else:
        findings.append(
            Finding(
                id="security.ssh.missing",
                module="security",
                severity=Severity.INFO,
                title="sshd configuration not found",
                detail="No /etc/ssh/sshd_config detected on this host.",
                current="absent",
                recommended="n/a",
            )
        )

    # Firewall
    if os_info.firewall == "ufw" or which("ufw"):
        code, out, _ = run_cmd(["ufw", "status"], timeout=20)
        status_line = (out or "").strip().splitlines()[0].lower() if (out or "").strip() else ""
        active = code == 0 and status_line.startswith("status: active")
        findings.append(
            Finding(
                id="security.firewall.ufw",
                module="security",
                severity=Severity.HIGH if not active else Severity.INFO,
                title="UFW firewall status",
                detail="Ubuntu/Debian hosts should typically run UFW or equivalent.",
                current="active" if active else "inactive/unknown",
                recommended="Default deny incoming; allow 22/80/443 as needed",
                remediation_id=None if active else "ufw_baseline",
            )
        )
    elif os_info.firewall == "firewalld" or which("firewall-cmd"):
        code, out, _ = run_cmd(["firewall-cmd", "--state"], timeout=20)
        active = code == 0 and "running" in (out or "").lower()
        findings.append(
            Finding(
                id="security.firewall.firewalld",
                module="security",
                severity=Severity.HIGH if not active else Severity.INFO,
                title="firewalld status",
                detail="Alma/Rocky hosts should typically run firewalld.",
                current="running" if active else "not running",
                recommended="Enable firewalld; allow ssh http https",
                remediation_id=None if active else "firewalld_baseline",
            )
        )
    else:
        findings.append(
            Finding(
                id="security.firewall.none",
                module="security",
                severity=Severity.HIGH,
                title="No host firewall tool detected",
                detail="Neither ufw nor firewalld was found in PATH.",
                current="none",
                recommended="Install and enable ufw (Debian) or firewalld (RHEL-like)",
            )
        )

    # fail2ban
    if which("fail2ban-client") or Path("/etc/fail2ban").exists():
        active = service_is_active("fail2ban")
        findings.append(
            Finding(
                id="security.fail2ban",
                module="security",
                severity=Severity.MEDIUM if not active else Severity.INFO,
                title="fail2ban status",
                detail="Intrusion prevention via fail2ban.",
                current="active" if active else "installed but inactive",
                recommended="Enable fail2ban with sshd jail",
                remediation_id=None if active else "enable_fail2ban",
            )
        )
    else:
        findings.append(
            Finding(
                id="security.fail2ban",
                module="security",
                severity=Severity.LOW,
                title="fail2ban not installed",
                detail="fail2ban helps block brute-force attempts.",
                current="not installed",
                recommended="Install fail2ban and enable the sshd jail",
            )
        )

    # Sysctl hardening
    for key, recommended in sysctl_rec.items():
        current = _sysctl_get(key)
        if not current:
            continue
        if current.strip() != str(recommended).strip():
            findings.append(
                Finding(
                    id=f"security.sysctl.{key}",
                    module="security",
                    severity=Severity.MEDIUM,
                    title=f"sysctl {key} not hardened",
                    detail="Kernel network hardening parameter differs from baseline.",
                    current=current,
                    recommended=str(recommended),
                    remediation_id="sysctl_harden",
                )
            )

    # World-writable directories under sensitive roots (fast, limited)
    code, out, _ = run_cmd(
        [
            "bash",
            "-c",
            "find /etc /usr /var /home -xdev -type d -perm -0002 2>/dev/null | head -n 30",
        ],
        timeout=60,
    )
    if code == 0 and out.strip():
        findings.append(
            Finding(
                id="security.world_writable_dirs",
                module="security",
                severity=Severity.MEDIUM,
                title="World-writable directories found",
                detail="Directories writable by others can be a risk (sample limited to 30).",
                current=out.strip()[:500],
                recommended="Review and tighten permissions (chmod o-w) where inappropriate",
            )
        )

    # Empty password accounts (shadow)
    if Path("/etc/shadow").is_file():
        code, out, _ = run_cmd(
            ["bash", "-c", "awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null"],
            timeout=15,
        )
        users = [u for u in (out or "").splitlines() if u.strip()]
        if users:
            findings.append(
                Finding(
                    id="security.empty_passwords",
                    module="security",
                    severity=Severity.CRITICAL,
                    title="Accounts with empty passwords",
                    detail="Users with empty password fields in /etc/shadow.",
                    current=", ".join(users[:20]),
                    recommended="Lock accounts or set strong passwords immediately",
                )
            )

    # SELinux (RHEL-like)
    if which("getenforce") or Path("/etc/selinux/config").exists():
        code, out, _ = run_cmd(["getenforce"], timeout=10)
        mode = (out or "").strip() or "unknown"
        sev = Severity.INFO
        if mode.lower() == "disabled":
            sev = Severity.MEDIUM
        elif mode.lower() == "permissive":
            sev = Severity.LOW
        findings.append(
            Finding(
                id="security.selinux",
                module="security",
                severity=sev,
                title="SELinux mode",
                detail="Mandatory access control posture on RHEL-like systems.",
                current=mode,
                recommended="Enforcing in production when workloads support it",
            )
        )

    # AppArmor (Debian/Ubuntu)
    if which("aa-status") or Path("/sys/module/apparmor").exists():
        code, out, _ = run_cmd(["aa-status", "--enabled"], timeout=10)
        enabled = code == 0
        findings.append(
            Finding(
                id="security.apparmor",
                module="security",
                severity=Severity.INFO if enabled else Severity.LOW,
                title="AppArmor status",
                detail="MAC framework common on Ubuntu.",
                current="enabled" if enabled else "not enabled/unknown",
                recommended="Keep profiles enforcing for exposed services",
            )
        )

    # auditd
    if which("auditctl") or Path("/etc/audit").exists():
        active = service_is_active("auditd")
        findings.append(
            Finding(
                id="security.auditd",
                module="security",
                severity=Severity.MEDIUM if not active else Severity.INFO,
                title="auditd status",
                detail="Linux audit daemon for security event logging.",
                current="active" if active else "inactive/not running",
                recommended="Enable auditd on production and compliance hosts",
                remediation_id=None if active else "enable_auditd",
            )
        )

    return findings
