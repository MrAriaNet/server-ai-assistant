"""Operating system detection for Ubuntu, AlmaLinux, and Rocky Linux."""

from __future__ import annotations

import os
import platform
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


SUPPORTED_IDS = {"ubuntu", "almalinux", "rocky", "centos", "rhel", "debian"}
DEBIAN_FAMILY = {"ubuntu", "debian"}
RHEL_FAMILY = {"almalinux", "rocky", "centos", "rhel", "fedora"}


@dataclass
class OSInfo:
    id: str
    name: str
    version: str
    version_id: str
    pretty_name: str
    family: str  # debian | rhel | unknown
    pkg_manager: str  # apt | dnf | yum | unknown
    firewall: str  # ufw | firewalld | iptables | unknown
    supported: bool
    hostname: str

    def to_dict(self) -> Dict[str, str | bool]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "version_id": self.version_id,
            "pretty_name": self.pretty_name,
            "family": self.family,
            "pkg_manager": self.pkg_manager,
            "firewall": self.firewall,
            "supported": self.supported,
            "hostname": self.hostname,
        }


def _parse_os_release(path: Path = Path("/etc/os-release")) -> Dict[str, str]:
    data: Dict[str, str] = {}
    if not path.is_file():
        return data
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"')
    return data


def _which(cmd: str) -> bool:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / cmd
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return True
    return False


def detect_os() -> OSInfo:
    release = _parse_os_release()
    os_id = (release.get("ID") or platform.system().lower() or "unknown").lower()
    # Normalize ID_LIKE hints
    id_like = (release.get("ID_LIKE") or "").lower().split()

    if os_id in DEBIAN_FAMILY or any(x in DEBIAN_FAMILY for x in id_like):
        family = "debian"
    elif os_id in RHEL_FAMILY or any(x in RHEL_FAMILY for x in id_like):
        family = "rhel"
    else:
        family = "unknown"

    if family == "debian":
        pkg = "apt" if _which("apt-get") or _which("apt") else "unknown"
        fw = "ufw" if _which("ufw") else ("iptables" if _which("iptables") else "unknown")
    elif family == "rhel":
        if _which("dnf"):
            pkg = "dnf"
        elif _which("yum"):
            pkg = "yum"
        else:
            pkg = "unknown"
        fw = "firewalld" if _which("firewall-cmd") else ("iptables" if _which("iptables") else "unknown")
    else:
        pkg = "unknown"
        fw = "unknown"

    # Primary supported distros per plan
    primary = os_id in {"ubuntu", "almalinux", "rocky"}
    # Also allow close relatives for package commands
    supported = primary or (
        family in {"debian", "rhel"} and os_id in SUPPORTED_IDS
    )

    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"

    return OSInfo(
        id=os_id,
        name=release.get("NAME", platform.system() or "Unknown"),
        version=release.get("VERSION", release.get("VERSION_ID", "")),
        version_id=release.get("VERSION_ID", ""),
        pretty_name=release.get("PRETTY_NAME", f"{platform.system()} {platform.release()}"),
        family=family,
        pkg_manager=pkg,
        firewall=fw,
        supported=supported,
        hostname=hostname,
    )


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows / non-POSIX
        return False


def command_exists(cmd: str) -> bool:
    return _which(cmd)
