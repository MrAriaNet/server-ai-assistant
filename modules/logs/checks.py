"""Journal errors, OOM events, and oversized log files."""

from __future__ import annotations

from pathlib import Path
from typing import List

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import bytes_human, run_cmd


@register_module("logs")
def check_logs(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []
    thr = config.get("thresholds") or {}
    large_mb = float(thr.get("log_file_warn_mb", 500))

    # Recent journal priority err+
    code, out, _ = run_cmd(
        ["journalctl", "-p", "err", "-n", "30", "--no-pager", "-q"],
        timeout=30,
    )
    if code == 0 and out.strip():
        lines = out.strip().splitlines()
        findings.append(
            Finding(
                id="logs.journal_errors",
                module="logs",
                severity=Severity.MEDIUM,
                title="Recent journal errors",
                detail=f"Last {min(len(lines), 30)} priority≥err messages.",
                current="\n".join(lines[:15]),
                recommended="Investigate recurring units with journalctl -u <unit>",
            )
        )
    else:
        findings.append(
            Finding(
                id="logs.journal_errors",
                module="logs",
                severity=Severity.INFO,
                title="No recent journal errors sampled",
                detail="journalctl -p err returned empty or unavailable.",
                current="none",
                recommended="Keep journald disk limits sane (SystemMaxUse)",
            )
        )

    # OOM killer
    code, out, _ = run_cmd(
        [
            "bash",
            "-c",
            "journalctl -k -n 200 --no-pager -q 2>/dev/null | grep -iE 'out of memory|oom-kill|Killed process' | tail -n 15 || true",
        ],
        timeout=30,
    )
    if out.strip():
        findings.append(
            Finding(
                id="logs.oom",
                module="logs",
                severity=Severity.HIGH,
                title="Out-of-memory killer activity detected",
                detail="Kernel/journal shows OOM events — services may have been killed.",
                current=out.strip()[:600],
                recommended="Add RAM, reduce memory limits, or tune service footprints",
            )
        )

    # Large files under /var/log
    large = []
    log_root = Path("/var/log")
    if log_root.is_dir():
        for path in log_root.rglob("*"):
            try:
                if not path.is_file():
                    continue
                size = path.stat().st_size
                if size >= large_mb * 1024 * 1024:
                    large.append((size, str(path)))
            except OSError:
                continue
    large.sort(reverse=True)
    if large:
        findings.append(
            Finding(
                id="logs.large_files",
                module="logs",
                severity=Severity.MEDIUM,
                title="Large log files",
                detail=f"Files under /var/log larger than {large_mb:.0f} MiB.",
                current="\n".join(f"{bytes_human(sz)}  {p}" for sz, p in large[:15]),
                recommended="Rotate/compress with logrotate; truncate abandoned logs",
                remediation_id="logrotate_force",
            )
        )

    # logrotate presence
    if not Path("/etc/logrotate.conf").exists():
        findings.append(
            Finding(
                id="logs.logrotate_missing",
                module="logs",
                severity=Severity.MEDIUM,
                title="logrotate configuration missing",
                detail="Without rotation, disks fill from application logs.",
                current="absent",
                recommended="Install and configure logrotate",
            )
        )
    else:
        findings.append(
            Finding(
                id="logs.logrotate",
                module="logs",
                severity=Severity.INFO,
                title="logrotate present",
                detail="/etc/logrotate.conf found.",
                current="configured",
                recommended="Verify app-specific rotate stanzas under /etc/logrotate.d",
            )
        )

    # Disk use specifically on /var/log if separate or via df
    code, out, _ = run_cmd(["df", "-P", "/var/log"], timeout=15)
    if code == 0:
        lines = out.strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 5:
                pct = parts[4].rstrip("%")
                try:
                    used = float(pct)
                except ValueError:
                    used = 0
                if used >= float(thr.get("disk_usage_percent", 85)):
                    findings.append(
                        Finding(
                            id="logs.var_log_disk",
                            module="logs",
                            severity=Severity.HIGH,
                            title="/var/log filesystem nearly full",
                            detail="Log volume pressure can break services and auditing.",
                            current=f"{used:.0f}% used",
                            recommended="Purge old journals: journalctl --vacuum-time=7d",
                            remediation_id="journal_vacuum",
                        )
                    )

    return findings
