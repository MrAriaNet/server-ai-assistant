"""Storage health: SMART, mdadm, mount options, /tmp sticky bit."""

from __future__ import annotations

from pathlib import Path
from typing import List

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import read_text, run_cmd, which


@register_module("storage")
def check_storage(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []

    # /tmp sticky bit
    tmp = Path("/tmp")
    if tmp.is_dir():
        mode = tmp.stat().st_mode
        sticky = bool(mode & 0o1000)
        if not sticky:
            findings.append(
                Finding(
                    id="storage.tmp_sticky",
                    module="storage",
                    severity=Severity.HIGH,
                    title="/tmp missing sticky bit",
                    detail="Without sticky bit, users can delete others' temp files.",
                    current=oct(mode & 0o7777),
                    recommended="chmod 1777 /tmp",
                    remediation_id="fix_tmp_sticky",
                )
            )
        else:
            findings.append(
                Finding(
                    id="storage.tmp_sticky",
                    module="storage",
                    severity=Severity.INFO,
                    title="/tmp sticky bit set",
                    detail="Expected mode includes the sticky bit (1777).",
                    current=oct(mode & 0o7777),
                    recommended="Keep 1777 on /tmp",
                )
            )

    # Read-only or problematic mounts
    code, out, _ = run_cmd(["findmnt", "-rno", "TARGET,OPTIONS,FSTYPE"], timeout=20)
    if code != 0:
        code, out, _ = run_cmd(["mount"], timeout=20)
    if out:
        for line in out.splitlines():
            if " ro," in f" {line} " or line.endswith(" ro") or ",ro," in line or " ro)" in line:
                # Ignore known read-only system mounts
                if any(x in line for x in ("/sys", "/proc", "/dev", "squashfs", "iso9660", "efivarfs")):
                    continue
                findings.append(
                    Finding(
                        id="storage.ro_mount",
                        module="storage",
                        severity=Severity.HIGH,
                        title="Unexpected read-only mount",
                        detail="A non-pseudo filesystem appears mounted read-only (possible disk errors).",
                        current=line[:200],
                        recommended="Check dmesg/SMART; remount rw after fixing underlying issue",
                    )
                )

    # mdadm RAID
    mdstat = read_text("/proc/mdstat")
    if mdstat and "md" in mdstat:
        if "_T" in mdstat or "recovering" in mdstat.lower() or "degraded" in mdstat.lower() or "[U_]" in mdstat or "[_U]" in mdstat:
            findings.append(
                Finding(
                    id="storage.mdadm.degraded",
                    module="storage",
                    severity=Severity.CRITICAL,
                    title="Software RAID array degraded or recovering",
                    detail="/proc/mdstat indicates unhealthy RAID state.",
                    current=mdstat[:500],
                    recommended="Replace failed disk; monitor mdadm --detail",
                )
            )
        else:
            findings.append(
                Finding(
                    id="storage.mdadm",
                    module="storage",
                    severity=Severity.INFO,
                    title="mdadm RAID present",
                    detail="Software RAID configuration detected.",
                    current=mdstat[:400],
                    recommended="Ensure mdadm email/monitoring is configured",
                )
            )

    # SMART sample (first few disks)
    if which("smartctl"):
        code, out, _ = run_cmd(
            ["bash", "-c", "lsblk -dn -o NAME,TYPE | awk '$2==\"disk\"{print $1}' | head -n 4"],
            timeout=15,
        )
        disks = [d.strip() for d in (out or "").splitlines() if d.strip()]
        for disk in disks:
            dev = f"/dev/{disk}"
            sc, sout, serr = run_cmd(["smartctl", "-H", dev], timeout=30)
            text = (sout or "") + (serr or "")
            if "SMART overall-health" in text or "SMART Health Status" in text:
                healthy = "PASSED" in text or "OK" in text
                findings.append(
                    Finding(
                        id=f"storage.smart.{disk}",
                        module="storage",
                        severity=Severity.INFO if healthy else Severity.CRITICAL,
                        title=f"SMART health {disk}",
                        detail=text.strip()[:300],
                        current="PASSED/OK" if healthy else "FAIL/unknown",
                        recommended="Replace disk on SMART failure; keep smartmontools scheduled",
                    )
                )
    else:
        findings.append(
            Finding(
                id="storage.smartctl_missing",
                module="storage",
                severity=Severity.LOW,
                title="smartctl not installed",
                detail="Disk SMART monitoring is unavailable.",
                current="missing",
                recommended="Install smartmontools on bare-metal hosts",
            )
        )

    # Disk space already covered in system — add inode-ish via lsblk summary
    code, out, _ = run_cmd(["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE"], timeout=15)
    if code == 0 and out.strip():
        findings.append(
            Finding(
                id="storage.lsblk",
                module="storage",
                severity=Severity.INFO,
                title="Block device inventory",
                detail="lsblk summary for capacity planning.",
                current=out.strip()[:800],
                recommended="Document disk layout and spare capacity",
            )
        )

    return findings
