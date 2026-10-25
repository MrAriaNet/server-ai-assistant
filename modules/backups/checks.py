"""Detect backup agents and stale backup destinations."""

from __future__ import annotations

import time
from pathlib import Path
from typing import List, Tuple

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import run_cmd, service_is_active, which


BACKUP_PATHS = [
    ("/var/lib/restic", "restic repo data"),
    ("/var/backup", "generic /var/backup"),
    ("/backup", "generic /backup"),
    ("/home/backup", "home backup"),
    ("/var/cpanel/backups", "cPanel backups"),
    ("/var/lib/psa/dumps", "Plesk dumps"),
    ("/usr/local/directadmin/backups", "DirectAdmin backups"),
]


@register_module("backups")
def check_backups(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []
    thr = config.get("thresholds") or {}
    max_age_hours = float(thr.get("backup_max_age_hours", 48))
    tools = []

    for binary, label in (
        ("restic", "restic"),
        ("borg", "borgbackup"),
        ("rclone", "rclone"),
        ("rsnapshot", "rsnapshot"),
        ("duplicity", "duplicity"),
    ):
        if which(binary):
            tools.append(label)

    # systemd backup-ish timers
    code, out, _ = run_cmd(
        ["bash", "-c", "systemctl list-timers --all --no-pager 2>/dev/null | grep -iE 'backup|restic|borg|rclone' || true"],
        timeout=20,
    )
    timer_lines = [ln for ln in (out or "").splitlines() if ln.strip()]

    if tools:
        findings.append(
            Finding(
                id="backups.tools",
                module="backups",
                severity=Severity.INFO,
                title="Backup tools installed",
                detail="CLI backup utilities detected on PATH.",
                current=", ".join(tools),
                recommended="Verify jobs succeed and offsite copies exist",
            )
        )
    else:
        findings.append(
            Finding(
                id="backups.tools",
                module="backups",
                severity=Severity.MEDIUM,
                title="No common backup CLI detected",
                detail="restic/borg/rclone/rsnapshot/duplicity not found.",
                current="none",
                recommended="Deploy tested backups with restore drills",
            )
        )

    if timer_lines:
        findings.append(
            Finding(
                id="backups.timers",
                module="backups",
                severity=Severity.INFO,
                title="Backup-related systemd timers",
                detail="Timers whose unit names mention backup tooling.",
                current="\n".join(timer_lines[:15]),
                recommended="Confirm last run success in journalctl -u <timer>",
            )
        )

    # Freshness of backup directories
    stale: List[Tuple[str, float]] = []
    present = []
    now = time.time()
    for path, label in BACKUP_PATHS:
        p = Path(path)
        if not p.exists():
            continue
        try:
            mtime = p.stat().st_mtime
            # For directories, also consider newest child (shallow)
            if p.is_dir():
                newest = mtime
                try:
                    for child in list(p.iterdir())[:200]:
                        try:
                            newest = max(newest, child.stat().st_mtime)
                        except OSError:
                            continue
                except OSError:
                    pass
                mtime = newest
            age_h = (now - mtime) / 3600.0
            present.append(f"{label}: {age_h:.1f}h old ({path})")
            if age_h > max_age_hours:
                stale.append((f"{label} ({path})", age_h))
        except OSError:
            continue

    if present:
        findings.append(
            Finding(
                id="backups.paths",
                module="backups",
                severity=Severity.INFO,
                title="Backup destination paths found",
                detail=f"Freshness threshold {max_age_hours:g} hours.",
                current="\n".join(present[:20]),
                recommended="Keep at least one offline/offsite copy",
            )
        )
    if stale:
        findings.append(
            Finding(
                id="backups.stale",
                module="backups",
                severity=Severity.HIGH,
                title="Backup data looks stale",
                detail="Destination path mtime older than configured threshold.",
                current="\n".join(f"{name}: {age:.1f}h" for name, age in stale[:15]),
                recommended="Investigate failed backup jobs immediately",
            )
        )

    # SAI's own backups dir
    sai_bak = Path("/var/backups/sai")
    if sai_bak.is_dir():
        findings.append(
            Finding(
                id="backups.sai",
                module="backups",
                severity=Severity.INFO,
                title="Server AI Assistant config backups present",
                detail="Local remediation backups under /var/backups/sai.",
                current=str(sai_bak),
                recommended="Use: sai restore --list",
            )
        )

    # cron.d mentions of backup
    cron_hits = []
    for base in (Path("/etc/cron.d"), Path("/etc/cron.daily"), Path("/var/spool/cron/crontabs")):
        if not base.exists():
            continue
        try:
            for f in base.rglob("*"):
                if not f.is_file():
                    continue
                try:
                    text = f.read_text(encoding="utf-8", errors="ignore").lower()
                except OSError:
                    continue
                if "backup" in text or "restic" in text or "borg" in text:
                    cron_hits.append(str(f))
        except OSError:
            continue
    if cron_hits:
        findings.append(
            Finding(
                id="backups.cron",
                module="backups",
                severity=Severity.INFO,
                title="Cron jobs referencing backups",
                detail="Files under cron paths mentioning backup tools.",
                current="\n".join(cron_hits[:20]),
                recommended="Validate exit codes and log output of these jobs",
            )
        )

    if service_is_active("bacula-fd") or service_is_active("bareos-fd"):
        findings.append(
            Finding(
                id="backups.bacula",
                module="backups",
                severity=Severity.INFO,
                title="Bacula/Bareos file daemon active",
                detail="Enterprise backup agent appears running.",
                current="active",
                recommended="Confirm director jobs and retention with backup admin",
            )
        )

    return findings
