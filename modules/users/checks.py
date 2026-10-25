"""Local users, sudo, and authentication hygiene."""

from __future__ import annotations

from pathlib import Path
from typing import List

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import read_lines, run_cmd


@register_module("users")
def check_users(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []

    # Extra UID 0 accounts
    uid0 = []
    for line in read_lines("/etc/passwd"):
        parts = line.split(":")
        if len(parts) >= 3 and parts[2] == "0":
            uid0.append(parts[0])
    if len(uid0) > 1:
        findings.append(
            Finding(
                id="users.uid0",
                module="users",
                severity=Severity.HIGH,
                title="Multiple UID 0 accounts",
                detail="Only root should normally have UID 0.",
                current=", ".join(uid0),
                recommended="Remove or renumber unexpected UID 0 accounts",
            )
        )
    elif uid0:
        findings.append(
            Finding(
                id="users.uid0",
                module="users",
                severity=Severity.INFO,
                title="Root UID 0 account",
                detail="Single UID 0 account present.",
                current=", ".join(uid0),
                recommended="Use sudo for admin access; disable remote root SSH",
            )
        )

    # Login-capable users with shell
    shells_ok = {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish", "/usr/bin/bash", "/usr/bin/zsh"}
    interactive = []
    for line in read_lines("/etc/passwd"):
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, _, uid, _, _, _, shell = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
        try:
            uid_i = int(uid)
        except ValueError:
            continue
        if uid_i >= 1000 and shell in shells_ok and name not in {"nobody"}:
            interactive.append(name)
    findings.append(
        Finding(
            id="users.interactive",
            module="users",
            severity=Severity.INFO,
            title="Interactive local users (UID≥1000)",
            detail="Human login accounts discovered from /etc/passwd.",
            current=", ".join(interactive) if interactive else "none",
            recommended="Remove unused accounts; enforce key-based SSH",
        )
    )

    # Password aging via chage (sample first interactive users)
    weak_aging = []
    for user in interactive[:15]:
        code, out, _ = run_cmd(["chage", "-l", user], timeout=10)
        if code != 0:
            continue
        text = out.lower()
        if "password expires" in text and "never" in text:
            weak_aging.append(user)
    if weak_aging:
        findings.append(
            Finding(
                id="users.password_aging",
                module="users",
                severity=Severity.LOW,
                title="Accounts without password expiry",
                detail="Password aging never expires (policy choice — flag for review).",
                current=", ".join(weak_aging[:20]),
                recommended="Set PASS_MAX_DAYS in /etc/login.defs where policy requires it",
            )
        )

    # sudo group / wheel members
    sudoers = []
    for group_name in ("sudo", "wheel"):
        code, out, _ = run_cmd(["getent", "group", group_name], timeout=10)
        if code == 0 and ":" in out:
            members = out.strip().split(":")[-1]
            if members:
                sudoers.extend([m for m in members.split(",") if m])
    # Also NOPASSWD in sudoers (high signal)
    nopasswd_hits = []
    for path in [Path("/etc/sudoers")] + list(Path("/etc/sudoers.d").glob("*") if Path("/etc/sudoers.d").is_dir() else []):
        if not path.is_file():
            continue
        for line in read_lines(path):
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if "NOPASSWD" in stripped:
                nopasswd_hits.append(f"{path.name}: {stripped[:120]}")
    if sudoers:
        findings.append(
            Finding(
                id="users.sudo_members",
                module="users",
                severity=Severity.INFO,
                title="sudo/wheel group members",
                detail="Privileged group membership.",
                current=", ".join(sorted(set(sudoers))),
                recommended="Keep sudoers minimal and personally accountable",
            )
        )
    if nopasswd_hits:
        findings.append(
            Finding(
                id="users.sudo_nopasswd",
                module="users",
                severity=Severity.MEDIUM,
                title="NOPASSWD rules in sudoers",
                detail="Passwordless sudo increases impact of account compromise.",
                current="\n".join(nopasswd_hits[:15]),
                recommended="Prefer password or MFA-gated sudo except for break-glass automation",
            )
        )

    # Failed SSH / auth noise from lastb if available
    if Path("/var/log/btmp").exists() or Path("/var/log/auth.log").exists() or Path("/var/log/secure").exists():
        code, out, _ = run_cmd(
            ["bash", "-c", "lastb -n 20 2>/dev/null | head -n 15 || true"],
            timeout=15,
        )
        if code == 0 and out.strip() and "btmp begins" not in out.lower():
            lines = [ln for ln in out.splitlines() if ln.strip() and not ln.startswith("btmp")]
            if lines:
                findings.append(
                    Finding(
                        id="users.failed_logins",
                        module="users",
                        severity=Severity.MEDIUM,
                        title="Recent failed login attempts",
                        detail="Sample from lastb (bad password attempts).",
                        current="\n".join(lines[:12]),
                        recommended="Ensure fail2ban/firewall rate limits; review exposed SSH",
                    )
                )

    # Home dir .ssh permissions quick check
    bad_perm = []
    for user in interactive[:20]:
        # home from passwd
        code, out, _ = run_cmd(["getent", "passwd", user], timeout=5)
        if code != 0 or ":" not in out:
            continue
        home = out.strip().split(":")[5]
        ssh_dir = Path(home) / ".ssh"
        if ssh_dir.is_dir():
            mode = ssh_dir.stat().st_mode & 0o777
            if mode & 0o077:
                bad_perm.append(f"{ssh_dir} mode={oct(mode)}")
            auth = ssh_dir / "authorized_keys"
            if auth.is_file():
                amode = auth.stat().st_mode & 0o777
                if amode & 0o077:
                    bad_perm.append(f"{auth} mode={oct(amode)}")
    if bad_perm:
        findings.append(
            Finding(
                id="users.ssh_dir_perms",
                module="users",
                severity=Severity.HIGH,
                title="Insecure .ssh permissions",
                detail="Group/other-accessible SSH files weaken key auth.",
                current="\n".join(bad_perm[:20]),
                recommended="chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys",
            )
        )

    return findings
