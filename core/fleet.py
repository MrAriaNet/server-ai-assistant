"""Multi-host SSH fleet auditing."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from core.models import AuditResult, Finding
from core.util import ensure_dir, load_config, run_cmd, write_json


@dataclass
class FleetHost:
    name: str
    host: str
    user: str = "root"
    port: int = 22
    key: Optional[str] = None
    groups: List[str] = field(default_factory=list)
    vars: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "host": self.host,
            "user": self.user,
            "port": self.port,
            "groups": self.groups,
            "vars": self.vars,
        }
        if self.key:
            d["key"] = self.key
        return d


@dataclass
class FleetResult:
    host: FleetHost
    ok: bool
    error: str = ""
    audit: Optional[AuditResult] = None
    raw: str = ""

    def summary(self) -> Dict[str, Any]:
        if self.audit:
            return self.audit.summary()
        return {}


def default_fleet_path() -> Path:
    cfg = load_config()
    preferred = Path(cfg.get("paths", {}).get("fleet_file", "/etc/sai/fleet.yaml"))
    if preferred.is_file():
        return preferred
    local = Path(__file__).resolve().parent.parent / "config" / "fleet.example.yaml"
    return local


def load_fleet(path: Path) -> List[FleetHost]:
    if not path.is_file():
        raise FileNotFoundError(f"Fleet file not found: {path}")
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()

    use_yaml = suffix in {".yaml", ".yml"}
    if suffix in {".txt", ".list"}:
        use_yaml = False
    elif suffix not in {".yaml", ".yml"}:
        # Auto-detect: YAML if it declares a hosts: mapping
        stripped = text.lstrip()
        use_yaml = stripped.startswith("hosts:") or "\nhosts:" in text or stripped.startswith("---")

    if not use_yaml:
        return _parse_hosts_txt(text)

    data = yaml.safe_load(text) or {}
    hosts_raw = data.get("hosts") or []
    hosts: List[FleetHost] = []
    for item in hosts_raw:
        if isinstance(item, str):
            hosts.extend(_parse_hosts_txt(item))
            continue
        name = str(item.get("name") or item.get("host"))
        host = str(item.get("host") or item.get("ansible_host") or name)
        hosts.append(
            FleetHost(
                name=name,
                host=host,
                user=str(item.get("user") or item.get("ansible_user") or "root"),
                port=int(item.get("port") or item.get("ansible_port") or 22),
                key=item.get("key") or item.get("ansible_ssh_private_key_file"),
                groups=list(item.get("groups") or []),
                vars=dict(item.get("vars") or {}),
            )
        )
    return hosts


def _parse_hosts_txt(text: str) -> List[FleetHost]:
    hosts: List[FleetHost] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        user = "root"
        port = 22
        target = line
        if "@" in target:
            user, target = target.split("@", 1)
        if ":" in target and not target.count(":") > 1:  # skip IPv6 simple case
            # host:port
            host_part, port_s = target.rsplit(":", 1)
            if port_s.isdigit():
                target, port = host_part, int(port_s)
        name = target.replace(".", "-")
        hosts.append(FleetHost(name=name, host=target, user=user, port=port))
    return hosts


def _ssh_base(h: FleetHost, connect_timeout: int = 15) -> List[str]:
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-p",
        str(h.port),
    ]
    if h.key:
        cmd.extend(["-i", h.key])
    cmd.append(f"{h.user}@{h.host}")
    return cmd


def remote_audit(
    h: FleetHost,
    *,
    modules: Optional[List[str]] = None,
    profile: Optional[str] = None,
    sai_bin: str = "sai",
    timeout: int = 600,
) -> FleetResult:
    """Run `sai audit --json` on a remote host over SSH."""
    remote_cmd = f"{sai_bin} audit --json"
    if profile:
        remote_cmd += f" --profile {profile}"
    elif modules:
        remote_cmd += f" --modules {','.join(modules)}"

    cmd = _ssh_base(h) + [remote_cmd]
    code, out, err = run_cmd(cmd, timeout=timeout)

    def _json_blob(text: str) -> str:
        text = (text or "").strip()
        if text.startswith("{"):
            return text
        # Locate last JSON object if remote printed warnings first
        idx = text.rfind("\n{")
        if idx >= 0:
            return text[idx + 1 :].strip()
        idx = text.find("{")
        if idx >= 0:
            return text[idx:].strip()
        return ""

    blob = _json_blob(out)
    if not blob or code not in (0, 1):
        # Retry with sudo / full path hints
        for alt in (f"sudo -n {sai_bin} audit --json", "/usr/local/bin/sai audit --json"):
            extra = ""
            if profile:
                extra = f" --profile {profile}"
            elif modules:
                extra = f" --modules {','.join(modules)}"
            # rebuild from base command name
            if alt.startswith("sudo"):
                remote = f"sudo -n {sai_bin} audit --json{extra}"
            else:
                remote = f"/usr/local/bin/sai audit --json{extra}"
            cmd = _ssh_base(h) + [remote]
            code, out, err = run_cmd(cmd, timeout=timeout)
            blob = _json_blob(out)
            if blob and code in (0, 1):
                break

    if not blob:
        return FleetResult(
            host=h,
            ok=False,
            error=(err or out or f"ssh exit {code}")[:500],
            raw=(out or "")[:2000],
        )
    out = blob

    try:
        import json

        data = json.loads(out)
        findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        audit = AuditResult(
            hostname=data.get("hostname") or h.name,
            os_name=data.get("os_name", ""),
            os_version=data.get("os_version", ""),
            findings=findings,
            modules_run=data.get("modules_run", []),
            errors=data.get("errors", []),
        )
        return FleetResult(host=h, ok=True, audit=audit, raw=out)
    except Exception as exc:  # noqa: BLE001
        return FleetResult(host=h, ok=False, error=f"JSON parse error: {exc}", raw=out[:2000])


def run_fleet(
    hosts: List[FleetHost],
    *,
    modules: Optional[List[str]] = None,
    profile: Optional[str] = None,
    parallelism: int = 5,
    sai_bin: str = "sai",
) -> List[FleetResult]:
    results: List[FleetResult] = []
    workers = max(1, min(parallelism, len(hosts) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(remote_audit, h, modules=modules, profile=profile, sai_bin=sai_bin): h
            for h in hosts
        }
        for fut in as_completed(futs):
            results.append(fut.result())
    # Stable order by host name
    order = {h.name: i for i, h in enumerate(hosts)}
    results.sort(key=lambda r: order.get(r.host.name, 0))
    return results


def save_fleet_results(results: List[FleetResult], out_dir: Path) -> Path:
    ensure_dir(out_dir)
    index: Dict[str, Any] = {"hosts": []}
    for r in results:
        entry: Dict[str, Any] = {
            "name": r.host.name,
            "host": r.host.host,
            "ok": r.ok,
            "error": r.error,
            "summary": r.summary(),
        }
        index["hosts"].append(entry)
        if r.audit:
            write_json(out_dir / f"{r.host.name}.json", r.audit.to_dict())
    path = out_dir / "fleet_summary.json"
    write_json(path, index)
    return path
