"""CIS Benchmark mapping for SAI findings."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from rich.console import Console
from rich.table import Table

from core.models import AuditResult, Finding, Severity
from core.util import project_root

console = Console()

_MAPPING_CACHE: Optional[Dict[str, Any]] = None


def cis_mapping_path() -> Path:
    return project_root() / "config" / "cis_mapping.yaml"


def load_cis_mapping() -> Dict[str, Any]:
    global _MAPPING_CACHE
    if _MAPPING_CACHE is not None:
        return _MAPPING_CACHE
    path = cis_mapping_path()
    if not path.is_file():
        _MAPPING_CACHE = {"mappings": {}, "cis_profile_modules": []}
        return _MAPPING_CACHE
    with path.open(encoding="utf-8") as fh:
        _MAPPING_CACHE = yaml.safe_load(fh) or {}
    return _MAPPING_CACHE


def lookup_cis(finding_id: str) -> List[Dict[str, str]]:
    """Return CIS controls for a finding id (exact or longest prefix match)."""
    mappings: Dict[str, List[Dict[str, str]]] = (load_cis_mapping().get("mappings") or {})
    if finding_id in mappings:
        return list(mappings[finding_id])
    # Longest prefix match
    best = ""
    for key in mappings:
        if finding_id.startswith(key) and len(key) > len(best):
            best = key
    if best:
        return list(mappings[best])
    # Try module-level prefixes like "security.firewall.ufw" -> "security.firewall"
    parts = finding_id.split(".")
    for i in range(len(parts) - 1, 1, -1):
        prefix = ".".join(parts[:i])
        if prefix in mappings:
            return list(mappings[prefix])
    return []


def annotate_findings(findings: List[Finding]) -> List[Finding]:
    for f in findings:
        controls = lookup_cis(f.id)
        if controls:
            f.meta = dict(f.meta or {})
            f.meta["cis"] = controls
    return findings


def annotate_result(result: AuditResult) -> AuditResult:
    annotate_findings(result.findings)
    return result


def cis_coverage(result: AuditResult) -> Tuple[Dict[str, Dict[str, Any]], int, int]:
    """
    Build coverage map: control_id -> {title, findings[], worst_severity}.
    Returns (controls, mapped_findings, unmapped_findings).
    """
    controls: Dict[str, Dict[str, Any]] = {}
    mapped = 0
    unmapped = 0
    for f in result.findings:
        cis_list = (f.meta or {}).get("cis") or lookup_cis(f.id)
        if not cis_list:
            unmapped += 1
            continue
        mapped += 1
        for c in cis_list:
            cid = str(c.get("id", ""))
            title = str(c.get("title", ""))
            entry = controls.setdefault(
                cid,
                {"id": cid, "title": title, "findings": [], "worst": Severity.INFO},
            )
            entry["findings"].append(f)
            if Severity.rank(f.severity) > Severity.rank(entry["worst"]):
                entry["worst"] = f.severity
    return controls, mapped, unmapped


def print_cis_report(result: AuditResult) -> None:
    annotate_result(result)
    controls, mapped, unmapped = cis_coverage(result)
    console.print(
        f"[bold]CIS mapping[/bold] — mapped findings: {mapped}, "
        f"unmapped: {unmapped}, controls touched: {len(controls)}"
    )
    table = Table(title="CIS controls related to current findings", show_lines=True)
    table.add_column("CIS ID", width=10)
    table.add_column("Control")
    table.add_column("Worst", width=10)
    table.add_column("Findings", ratio=2)
    for cid in sorted(controls.keys(), key=lambda x: [int(p) if p.isdigit() else p for p in x.replace("-", ".").split(".")]):
        entry = controls[cid]
        ids = ", ".join(f.id for f in entry["findings"][:8])
        if len(entry["findings"]) > 8:
            ids += f" (+{len(entry['findings']) - 8})"
        worst = entry["worst"]
        worst_s = worst.value if isinstance(worst, Severity) else str(worst)
        table.add_row(cid, entry["title"], worst_s.upper(), ids)
    if controls:
        console.print(table)
    else:
        console.print("[yellow]No CIS-mapped findings in this result.[/yellow]")


def cis_modules() -> List[str]:
    data = load_cis_mapping()
    return list(data.get("cis_profile_modules") or ["security", "users", "updates", "network", "storage"])
