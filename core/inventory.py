"""Host inventory / facts export for ops CMDB-style snapshots."""

from __future__ import annotations

import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from core.os_detect import detect_os, is_root
from core.util import bytes_human, run_cmd, which


def collect_inventory() -> Dict[str, Any]:
    os_info = detect_os()
    data: Dict[str, Any] = {
        "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": os_info.hostname,
        "os": os_info.to_dict(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "is_root": is_root(),
        "cpus": None,
        "memory": {},
        "disks": "",
        "listeners_sample": "",
        "packages_hint": os_info.pkg_manager,
        "virtualization": "",
        "tools": {},
    }
    try:
        import os

        data["cpus"] = os.cpu_count()
    except Exception:
        pass

    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        mem = {}
        for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("MemTotal:") or line.startswith("MemAvailable:") or line.startswith("SwapTotal:"):
                key = line.split(":")[0]
                kb = int(line.split()[1])
                mem[key] = bytes_human(kb * 1024)
        data["memory"] = mem

    code, out, _ = run_cmd(["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE"], timeout=15)
    if code == 0:
        data["disks"] = out.strip()

    code, out, _ = run_cmd(["ss", "-tulpn"], timeout=20)
    if code == 0:
        data["listeners_sample"] = "\n".join(out.strip().splitlines()[:40])

    code, out, _ = run_cmd(["systemd-detect-virt"], timeout=10)
    if code == 0:
        data["virtualization"] = out.strip()
    else:
        data["virtualization"] = "unknown"

    for tool in (
        "nginx",
        "apache2",
        "httpd",
        "mysql",
        "mariadb",
        "psql",
        "redis-server",
        "docker",
        "podman",
        "fail2ban-client",
        "ufw",
        "firewall-cmd",
        "certbot",
        "haproxy",
    ):
        data["tools"][tool] = bool(which(tool))

    # Uptime
    code, out, _ = run_cmd(["uptime", "-p"], timeout=5)
    data["uptime"] = out.strip() if code == 0 else ""

    return data
