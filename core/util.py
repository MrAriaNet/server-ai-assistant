"""Shared utilities: subprocess helpers, config loading, paths."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config" / "defaults.yaml"


def project_root() -> Path:
    return ROOT


def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    cfg_path = path or CONFIG_PATH
    if not cfg_path.is_file():
        return {}
    with cfg_path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def ensure_dir(path: Union[str, Path]) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def run_cmd(
    cmd: Sequence[str] | str,
    *,
    timeout: int = 120,
    check: bool = False,
    shell: bool = False,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[Union[str, Path]] = None,
) -> Tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
            env=env,
            cwd=str(cwd) if cwd else None,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return 124, out, err or f"Command timed out after {timeout}s"
    except OSError as exc:
        return 1, "", str(exc)


def run_script(script_name: str, args: Optional[List[str]] = None, timeout: int = 180) -> Tuple[int, str, str]:
    script = ROOT / "scripts" / script_name
    if not script.is_file():
        return 127, "", f"Script not found: {script}"
    # Prefer bash when available
    bash = shutil.which("bash") or "/bin/bash"
    cmd = [bash, str(script)] + (args or [])
    return run_cmd(cmd, timeout=timeout)


def read_text(path: Union[str, Path], default: str = "") -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default


def read_lines(path: Union[str, Path]) -> List[str]:
    text = read_text(path)
    return text.splitlines() if text else []


def file_exists(path: Union[str, Path]) -> bool:
    return Path(path).exists()


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def service_is_active(name: str) -> bool:
    code, out, _ = run_cmd(["systemctl", "is-active", name], timeout=15)
    return code == 0 and out.strip() == "active"


def service_is_enabled(name: str) -> bool:
    code, out, _ = run_cmd(["systemctl", "is-enabled", name], timeout=15)
    return code == 0 and out.strip() in {"enabled", "static", "indirect"}


def service_exists(name: str) -> bool:
    code, _, _ = run_cmd(["systemctl", "status", name, "--no-pager"], timeout=15)
    # 0 active, 3 inactive but unit exists, 4 not-found
    return code != 4


def parse_sshd_config(path: str = "/etc/ssh/sshd_config") -> Dict[str, str]:
    """Parse effective-looking sshd settings (last wins; ignore Match blocks simply)."""
    values: Dict[str, str] = {}
    dropin_dir = Path("/etc/ssh/sshd_config.d")
    files: List[Path] = []
    main = Path(path)
    if main.is_file():
        files.append(main)
    if dropin_dir.is_dir():
        files.extend(sorted(dropin_dir.glob("*.conf")))
    for fp in files:
        in_match = False
        for line in read_lines(fp):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lower = stripped.lower()
            if lower.startswith("match "):
                in_match = True
                continue
            if in_match:
                # Skip Match block content for simple global view
                continue
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                values[parts[0]] = parts[1]
    return values


def parse_key_value_config(
    path: Union[str, Path],
    *,
    separators: Sequence[str] = ("=", " "),
    comment: str = "#",
) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in read_lines(path):
        stripped = line.strip()
        if not stripped or stripped.startswith(comment):
            continue
        for sep in separators:
            if sep in stripped:
                key, value = stripped.split(sep, 1)
                result[key.strip()] = value.strip().strip("'\"")
                break
    return result


def write_json(path: Union[str, Path], data: Any) -> None:
    p = Path(path)
    ensure_dir(p.parent)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_json(path: Union[str, Path]) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def bytes_human(n: float) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(n)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} B"
