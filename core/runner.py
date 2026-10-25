"""Audit runner — discovers and executes check modules."""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Sequence

from core.models import AuditResult, Finding, Severity
from core.os_detect import OSInfo, detect_os
from core.util import load_config

CheckFn = Callable[[OSInfo, dict], List[Finding]]

_REGISTRY: Dict[str, CheckFn] = {}


def register_module(name: str):
    def decorator(fn: CheckFn) -> CheckFn:
        _REGISTRY[name] = fn
        return fn

    return decorator


def available_modules() -> List[str]:
    _ensure_modules_loaded()
    return sorted(_REGISTRY.keys())


def _ensure_modules_loaded() -> None:
    if _REGISTRY:
        return
    # Import side-effects register modules
    import modules.system.checks  # noqa: F401
    import modules.updates.checks  # noqa: F401
    import modules.security.checks  # noqa: F401
    import modules.users.checks  # noqa: F401
    import modules.ssl.checks  # noqa: F401
    import modules.web.checks  # noqa: F401
    import modules.database.checks  # noqa: F401
    import modules.mail.checks  # noqa: F401
    import modules.network.checks  # noqa: F401
    import modules.containers.checks  # noqa: F401
    import modules.hosting.checks  # noqa: F401
    import modules.logs.checks  # noqa: F401
    import modules.storage.checks  # noqa: F401
    import modules.services.checks  # noqa: F401
    import modules.backups.checks  # noqa: F401
    import modules.proxy.checks  # noqa: F401


def run_audit(
    modules: Optional[Sequence[str]] = None,
    *,
    os_info: Optional[OSInfo] = None,
    config: Optional[dict] = None,
) -> AuditResult:
    _ensure_modules_loaded()
    os_info = os_info or detect_os()
    config = config if config is not None else load_config()

    default_mods = config.get("modules") or list(_REGISTRY.keys())
    selected = list(modules) if modules else list(default_mods)

    result = AuditResult(
        hostname=os_info.hostname,
        os_name=os_info.pretty_name or os_info.name,
        os_version=os_info.version_id or os_info.version,
    )

    for name in selected:
        fn = _REGISTRY.get(name)
        if not fn:
            result.errors.append(f"Unknown module: {name}")
            continue
        result.modules_run.append(name)
        try:
            findings = fn(os_info, config) or []
            result.findings.extend(findings)
        except Exception as exc:  # noqa: BLE001 — isolate module failures
            result.errors.append(f"Module '{name}' failed: {exc}")

    return result


def exit_code_for(result: AuditResult, threshold: str = "high") -> int:
    """Return process exit code based on findings severity."""
    if result.errors and not result.findings:
        # Soft: errors alone don't force 2 if we got partial results
        pass
    try:
        sev = Severity(threshold.lower())
    except ValueError:
        sev = Severity.HIGH
    if any(f.severity.at_or_above(sev) for f in result.findings):
        return 1
    return 0
