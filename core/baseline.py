"""Save and compare audit baselines (finding IDs)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from core.models import AuditResult
from core.util import ensure_dir, load_config


def baseline_path(name: str = "default") -> Path:
    cfg = load_config()
    preferred = Path(cfg.get("paths", {}).get("cache_dir", "/var/cache/sai"))
    try:
        ensure_dir(preferred)
        return preferred / f"baseline_{name}.json"
    except OSError:
        local = Path(__file__).resolve().parent.parent / "data"
        ensure_dir(local)
        return local / f"baseline_{name}.json"


def save_baseline(result: AuditResult, name: str = "default") -> Path:
    path = baseline_path(name)
    payload = {
        "name": name,
        "saved_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": result.hostname,
        "finding_ids": sorted({f.id for f in result.findings}),
        "summary": result.summary(),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def load_baseline(name: str = "default") -> Optional[Dict]:
    path = baseline_path(name)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def compare_baseline(result: AuditResult, name: str = "default") -> Tuple[List[str], List[str], List[str]]:
    """Return (new_ids, resolved_ids, unchanged_ids)."""
    base = load_baseline(name)
    if not base:
        raise FileNotFoundError(f"No baseline named '{name}'")
    old: Set[str] = set(base.get("finding_ids") or [])
    new: Set[str] = {f.id for f in result.findings}
    added = sorted(new - old)
    resolved = sorted(old - new)
    same = sorted(new & old)
    return added, resolved, same
