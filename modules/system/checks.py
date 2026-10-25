"""System resource and health checks."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import bytes_human, run_cmd, run_script, service_is_active


def _cpu_count() -> int:
    return os.cpu_count() or 1


def _load_avg() -> tuple[float, float, float]:
    try:
        return os.getloadavg()
    except (AttributeError, OSError):
        return (0.0, 0.0, 0.0)


def _meminfo() -> dict[str, int]:
    info: dict[str, int] = {}
    path = Path("/proc/meminfo")
    if not path.is_file():
        return info
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        parts = rest.strip().split()
        if parts:
            try:
                info[key] = int(parts[0]) * 1024  # kB -> bytes
            except ValueError:
                continue
    return info


def _disk_usage() -> List[tuple[str, float, float, float]]:
    """Return list of (mount, used_pct, inode_pct, avail_bytes)."""
    results = []
    code, out, _ = run_cmd(["df", "-P", "-B1"], timeout=30)
    if code != 0:
        return results
    lines = out.strip().splitlines()[1:]
    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        fs, _blocks, used, avail, pct, mount = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        if fs.startswith("tmpfs") or fs.startswith("devtmpfs") or mount.startswith("/snap"):
            continue
        try:
            used_pct = float(pct.rstrip("%"))
            avail_b = float(avail)
        except ValueError:
            continue
        inode_pct = 0.0
        results.append((mount, used_pct, inode_pct, avail_b))

    # inode usage
    code_i, out_i, _ = run_cmd(["df", "-Pi"], timeout=30)
    inode_map: dict[str, float] = {}
    if code_i == 0:
        for line in out_i.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                pct = parts[4].rstrip("%")
                mount = parts[5]
                try:
                    inode_map[mount] = float(pct)
                except ValueError:
                    pass
    updated = []
    for mount, used_pct, _, avail_b in results:
        updated.append((mount, used_pct, inode_map.get(mount, 0.0), avail_b))
    return updated


@register_module("system")
def check_system(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []
    thr = config.get("thresholds") or {}
    disk_thr = float(thr.get("disk_usage_percent", 85))
    inode_thr = float(thr.get("inode_usage_percent", 85))
    mem_thr = float(thr.get("memory_usage_percent", 90))
    load_thr = float(thr.get("load_per_cpu", 2.0))
    swap_thr = float(thr.get("swap_usage_percent", 50))

    # Load average
    cpus = _cpu_count()
    load1, load5, load15 = _load_avg()
    per_cpu = load1 / max(cpus, 1)
    findings.append(
        Finding(
            id="system.load",
            module="system",
            severity=Severity.HIGH if per_cpu >= load_thr else Severity.INFO,
            title="CPU load average",
            detail=f"1/5/15 minute load averages relative to {cpus} CPU(s).",
            current=f"{load1:.2f} / {load5:.2f} / {load15:.2f} ({per_cpu:.2f} per CPU)",
            recommended=f"Keep 1-minute load under ~{load_thr}x CPU count ({load_thr * cpus:.1f})",
        )
    )

    # Memory
    mem = _meminfo()
    if mem:
        total = mem.get("MemTotal", 0)
        available = mem.get("MemAvailable", mem.get("MemFree", 0))
        used_pct = ((total - available) / total * 100) if total else 0
        severity = Severity.CRITICAL if used_pct >= 95 else (Severity.HIGH if used_pct >= mem_thr else Severity.INFO)
        findings.append(
            Finding(
                id="system.memory",
                module="system",
                severity=severity,
                title="Memory usage",
                detail="Physical memory pressure based on MemAvailable.",
                current=f"{used_pct:.1f}% used ({bytes_human(total - available)} / {bytes_human(total)})",
                recommended=f"Keep usage under {mem_thr}% or add RAM / tune services",
            )
        )
        swap_total = mem.get("SwapTotal", 0)
        swap_free = mem.get("SwapFree", 0)
        if swap_total > 0:
            swap_used_pct = (swap_total - swap_free) / swap_total * 100
            sev = Severity.MEDIUM if swap_used_pct >= swap_thr else Severity.INFO
            if swap_used_pct >= 80:
                sev = Severity.HIGH
            findings.append(
                Finding(
                    id="system.swap",
                    module="system",
                    severity=sev,
                    title="Swap usage",
                    detail="Elevated swap usage often indicates memory pressure.",
                    current=f"{swap_used_pct:.1f}% of {bytes_human(swap_total)}",
                    recommended=f"Investigate memory hogs if swap exceeds {swap_thr}%",
                )
            )
        else:
            findings.append(
                Finding(
                    id="system.swap_missing",
                    module="system",
                    severity=Severity.LOW,
                    title="No swap configured",
                    detail="System has no swap space. Useful as a safety cushion on small VMs.",
                    current="SwapTotal=0",
                    recommended="Add a swap file or partition (e.g. 1–2 GiB) for burst protection",
                )
            )

    # Disk / inodes
    for mount, used_pct, inode_pct, avail_b in _disk_usage():
        if used_pct >= disk_thr:
            sev = Severity.CRITICAL if used_pct >= 95 else Severity.HIGH
            findings.append(
                Finding(
                    id=f"system.disk.{mount.replace('/', '_') or 'root'}",
                    module="system",
                    severity=sev,
                    title=f"Disk space low on {mount}",
                    detail="Filesystem usage exceeds configured threshold.",
                    current=f"{used_pct:.0f}% used, {bytes_human(avail_b)} free",
                    recommended=f"Free space or expand volume; threshold {disk_thr}%",
                )
            )
        if inode_pct >= inode_thr:
            sev = Severity.CRITICAL if inode_pct >= 95 else Severity.HIGH
            findings.append(
                Finding(
                    id=f"system.inode.{mount.replace('/', '_') or 'root'}",
                    module="system",
                    severity=sev,
                    title=f"Inode usage high on {mount}",
                    detail="Inode exhaustion prevents creating new files even with free space.",
                    current=f"{inode_pct:.0f}% inodes used",
                    recommended="Remove many small files or enlarge filesystem",
                )
            )

    # Failed systemd units
    code, out, _ = run_cmd(["systemctl", "--failed", "--no-legend", "--no-pager"], timeout=30)
    if code == 0 and out.strip():
        failed = [ln.split()[0] for ln in out.strip().splitlines() if ln.strip()]
        findings.append(
            Finding(
                id="system.failed_units",
                module="system",
                severity=Severity.HIGH,
                title="Failed systemd units",
                detail="One or more units are in a failed state.",
                current=", ".join(failed[:20]),
                recommended="systemctl status <unit>; journalctl -u <unit> -xe",
            )
        )
    else:
        findings.append(
            Finding(
                id="system.failed_units",
                module="system",
                severity=Severity.INFO,
                title="No failed systemd units",
                detail="systemctl --failed reported none.",
                current="none",
                recommended="Keep monitoring after package upgrades",
            )
        )

    # Time sync
    time_ok = service_is_active("chronyd") or service_is_active("systemd-timesyncd") or service_is_active("ntpd")
    if not time_ok:
        # timedatectl
        code_t, out_t, _ = run_cmd(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], timeout=15)
        synced = code_t == 0 and out_t.strip().lower() == "yes"
        if not synced:
            findings.append(
                Finding(
                    id="system.time_sync",
                    module="system",
                    severity=Severity.MEDIUM,
                    title="Time synchronization not confirmed",
                    detail="chronyd/systemd-timesyncd/ntpd inactive or NTP not synchronized.",
                    current="not synchronized",
                    recommended="Enable chrony or systemd-timesyncd for accurate logs and TLS",
                )
            )
    else:
        findings.append(
            Finding(
                id="system.time_sync",
                module="system",
                severity=Severity.INFO,
                title="Time synchronization service active",
                detail="A known NTP/chrony service is running.",
                current="active",
                recommended="Ensure peers are reachable",
            )
        )

    # Optional facts script enrichment
    code_f, out_f, _ = run_script("collect_facts.sh", timeout=60)
    if code_f == 0 and out_f.strip():
        findings.append(
            Finding(
                id="system.facts",
                module="system",
                severity=Severity.INFO,
                title="Collected system facts",
                detail="Summary from collect_facts.sh helper.",
                current=out_f.strip()[:500],
                recommended="Review facts for capacity planning",
            )
        )

    # Zombie processes
    code_z, out_z, _ = run_cmd(
        ["bash", "-c", "ps -eo stat=,pid=,comm= 2>/dev/null | awk '$1 ~ /Z/ {print}' | head -n 20"],
        timeout=15,
    )
    zombies = [ln for ln in (out_z or "").splitlines() if ln.strip()]
    if zombies:
        findings.append(
            Finding(
                id="system.zombies",
                module="system",
                severity=Severity.MEDIUM,
                title="Zombie processes present",
                detail="Defunct child processes waiting for parent wait().",
                current="\n".join(zombies[:20]),
                recommended="Restart the parent process; investigate stuck supervisors",
            )
        )

    # Recent kernel disk/IO errors
    code_k, out_k, _ = run_cmd(
        [
            "bash",
            "-c",
            "dmesg -T 2>/dev/null | grep -iE 'I/O error|ext4|xfs|nvme|smart|blocked for more' | tail -n 15 || true",
        ],
        timeout=20,
    )
    if out_k.strip():
        findings.append(
            Finding(
                id="system.kernel_io",
                module="system",
                severity=Severity.HIGH,
                title="Kernel I/O or filesystem warnings",
                detail="Recent dmesg lines related to disk/filesystem issues.",
                current=out_k.strip()[:600],
                recommended="Check SMART, RAID, and filesystem health immediately",
            )
        )

    return findings
