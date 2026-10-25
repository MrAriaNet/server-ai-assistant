"""Configuration backup helpers."""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence

from core.util import ensure_dir, load_config, run_cmd


def backup_root() -> Path:
    cfg = load_config()
    return Path(cfg.get("paths", {}).get("backup_dir", "/var/backups/sai"))


def new_backup_session(label: str = "session") -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)[:40]
    path = backup_root() / f"{stamp}_{safe}"
    ensure_dir(path)
    return path


def backup_files(files: Sequence[str], session: Optional[Path] = None) -> Path:
    """Copy existing files into a timestamped backup directory. Returns session path."""
    sess = session or new_backup_session("files")
    ensure_dir(sess)
    manifest: List[str] = []
    for src in files:
        src_path = Path(src)
        if not src_path.exists():
            continue
        # Preserve absolute path structure under session
        rel = str(src_path).lstrip("/")
        dest = sess / rel
        ensure_dir(dest.parent)
        if src_path.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(src_path, dest)
        else:
            shutil.copy2(src_path, dest)
        manifest.append(str(src_path))
    (sess / "MANIFEST.txt").write_text("\n".join(manifest) + "\n", encoding="utf-8")
    return sess


def log_action(message: str) -> None:
    cfg = load_config()
    log_dir = Path(cfg.get("paths", {}).get("log_dir", "/var/log/sai"))
    try:
        ensure_dir(log_dir)
        log_file = log_dir / "actions.log"
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with log_file.open("a", encoding="utf-8") as fh:
            fh.write(f"[{stamp}] {message}\n")
    except OSError:
        # Fall back to local project log when not root / no permission
        local = Path(__file__).resolve().parent.parent / "data" / "actions.log"
        ensure_dir(local.parent)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with local.open("a", encoding="utf-8") as fh:
            fh.write(f"[{stamp}] {message}\n")


def restart_service(name: str, dry_run: bool = False) -> tuple[int, str]:
    if dry_run:
        return 0, f"[dry-run] systemctl restart {name}"
    code, out, err = run_cmd(["systemctl", "restart", name], timeout=60)
    msg = (out + err).strip()
    log_action(f"restart {name}: rc={code} {msg}")
    return code, msg or ("ok" if code == 0 else "failed")


def list_sessions() -> List[Path]:
    root = backup_root()
    if not root.is_dir():
        return []
    sessions = [p for p in root.iterdir() if p.is_dir()]
    return sorted(sessions, key=lambda p: p.name, reverse=True)


def restore_session(session: Path, *, dry_run: bool = False) -> List[str]:
    """Restore files listed in session MANIFEST.txt back to absolute paths."""
    manifest = session / "MANIFEST.txt"
    if not manifest.is_file():
        raise FileNotFoundError(f"No MANIFEST.txt in {session}")
    restored: List[str] = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        original = line.strip()
        if not original:
            continue
        rel = original.lstrip("/")
        src = session / rel
        if not src.exists():
            continue
        if dry_run:
            restored.append(f"[dry-run] {src} -> {original}")
            continue
        dest = Path(original)
        ensure_dir(dest.parent)
        if src.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(src, dest)
        else:
            shutil.copy2(src, dest)
        restored.append(original)
        log_action(f"RESTORE {original} from {session}")
    return restored
