"""Report rendering: terminal, JSON, HTML, Markdown."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from core.models import SEVERITY_COLORS, AuditResult, Severity
from core.util import ensure_dir, load_config, write_json

console = Console()


def cache_path() -> Path:
    cfg = load_config()
    preferred = Path(cfg.get("paths", {}).get("cache_dir", "/var/cache/sai"))
    try:
        ensure_dir(preferred)
        test = preferred / ".write_test"
        test.write_text("ok", encoding="utf-8")
        try:
            test.unlink()
        except OSError:
            pass
        return preferred / "last_audit.json"
    except OSError:
        local = Path(__file__).resolve().parent.parent / "data"
        ensure_dir(local)
        return local / "last_audit.json"


def save_result(result: AuditResult) -> Path:
    path = cache_path()
    write_json(path, result.to_dict())
    return path


def load_last_result() -> Optional[AuditResult]:
    path = cache_path()
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    from core.models import Finding

    findings = [Finding.from_dict(f) for f in data.get("findings", [])]
    return AuditResult(
        hostname=data.get("hostname", ""),
        os_name=data.get("os_name", ""),
        os_version=data.get("os_version", ""),
        findings=findings,
        modules_run=data.get("modules_run", []),
        errors=data.get("errors", []),
    )


def print_terminal(result: AuditResult, *, minimum: Optional[Severity] = None) -> None:
    findings = result.findings
    if minimum:
        findings = [f for f in findings if f.severity.at_or_above(minimum)]

    header = (
        f"[bold]Server AI Assistant[/bold] — audit report\n"
        f"Host: [cyan]{result.hostname}[/cyan]  "
        f"OS: [cyan]{result.os_name} {result.os_version}[/cyan]\n"
        f"Modules: {', '.join(result.modules_run) or 'none'}"
    )
    console.print(Panel(header, border_style="blue"))

    summary = result.summary()
    sum_table = Table(title="Summary", show_header=True, header_style="bold")
    sum_table.add_column("Severity")
    sum_table.add_column("Count", justify="right")
    for sev in Severity:
        style = SEVERITY_COLORS[sev]
        sum_table.add_row(Text(sev.value.upper(), style=style), str(summary.get(sev.value, 0)))
    sum_table.add_row("TOTAL", str(summary.get("total", 0)))
    console.print(sum_table)

    if result.errors:
        console.print(Panel("\n".join(result.errors), title="Module errors", border_style="red"))

    if not findings:
        console.print("[green]No findings matched the current filters.[/green]")
        return

    table = Table(title="Findings", show_lines=True, expand=True)
    table.add_column("Sev", width=10)
    table.add_column("Module", width=12)
    table.add_column("Title", ratio=2)
    table.add_column("Current", ratio=1)
    table.add_column("Recommended", ratio=1)
    table.add_column("Fix", width=16)

    for f in sorted(findings, key=lambda x: Severity.rank(x.severity), reverse=True):
        style = SEVERITY_COLORS[f.severity]
        table.add_row(
            Text(f.severity.value.upper(), style=style),
            f.module,
            f"{f.title}\n[dim]{f.detail}[/dim]",
            f.current or "—",
            f.recommended or "—",
            f.remediation_id or "—",
        )
    console.print(table)


def export_json(result: AuditResult, path: Path) -> None:
    write_json(path, result.to_dict())


def export_markdown(result: AuditResult, path: Path) -> None:
    lines = [
        f"# Server AI Assistant Report",
        "",
        f"- **Host:** {result.hostname}",
        f"- **OS:** {result.os_name} {result.os_version}",
        f"- **Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"- **Modules:** {', '.join(result.modules_run)}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|------:|",
    ]
    summary = result.summary()
    for sev in Severity:
        lines.append(f"| {sev.value} | {summary.get(sev.value, 0)} |")
    lines.append(f"| total | {summary.get('total', 0)} |")
    lines.extend(["", "## Findings", ""])
    if not result.findings:
        lines.append("_No findings._")
    for f in sorted(result.findings, key=lambda x: Severity.rank(x.severity), reverse=True):
        lines.extend([
            f"### [{f.severity.value.upper()}] {f.title}",
            "",
            f"- **ID:** `{f.id}`",
            f"- **Module:** {f.module}",
            f"- **Detail:** {f.detail}",
            f"- **Current:** {f.current or 'n/a'}",
            f"- **Recommended:** {f.recommended or 'n/a'}",
            f"- **Remediation:** {f.remediation_id or 'none'}",
            "",
        ])
    if result.errors:
        lines.extend(["## Errors", ""])
        for err in result.errors:
            lines.append(f"- {err}")
    ensure_dir(path.parent)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def export_html(result: AuditResult, path: Path) -> None:
    summary = result.summary()
    rows = []
    for f in sorted(result.findings, key=lambda x: Severity.rank(x.severity), reverse=True):
        rows.append(
            "<tr>"
            f"<td class='sev-{html.escape(f.severity.value)}'>{html.escape(f.severity.value.upper())}</td>"
            f"<td>{html.escape(f.module)}</td>"
            f"<td><strong>{html.escape(f.title)}</strong><br><span class='dim'>{html.escape(f.detail)}</span></td>"
            f"<td>{html.escape(f.current or '—')}</td>"
            f"<td>{html.escape(f.recommended or '—')}</td>"
            f"<td>{html.escape(f.remediation_id or '—')}</td>"
            "</tr>"
        )
    summary_cells = "".join(
        f"<li><strong>{sev.value}</strong>: {summary.get(sev.value, 0)}</li>" for sev in Severity
    )
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Server AI Assistant Report — {html.escape(result.hostname)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0f1419; color: #e7ecf1; }}
h1 {{ color: #7dd3fc; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
th, td {{ border: 1px solid #334155; padding: 0.5rem 0.75rem; vertical-align: top; }}
th {{ background: #1e293b; text-align: left; }}
.dim {{ color: #94a3b8; font-size: 0.9em; }}
.sev-critical {{ color: #f87171; font-weight: bold; }}
.sev-high {{ color: #fb7185; }}
.sev-medium {{ color: #fbbf24; }}
.sev-low {{ color: #22d3ee; }}
.sev-info {{ color: #60a5fa; }}
ul.summary {{ list-style: none; padding: 0; display: flex; gap: 1.5rem; flex-wrap: wrap; }}
</style>
</head>
<body>
<h1>Server AI Assistant Report</h1>
<p>Host: <strong>{html.escape(result.hostname)}</strong> —
OS: <strong>{html.escape(result.os_name + ' ' + result.os_version)}</strong><br/>
Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}<br/>
Modules: {html.escape(', '.join(result.modules_run))}</p>
<ul class="summary">{summary_cells}<li><strong>total</strong>: {summary.get('total', 0)}</li></ul>
<table>
<thead><tr><th>Severity</th><th>Module</th><th>Finding</th><th>Current</th><th>Recommended</th><th>Fix</th></tr></thead>
<tbody>
{''.join(rows) if rows else '<tr><td colspan="6">No findings.</td></tr>'}
</tbody>
</table>
</body>
</html>
"""
    ensure_dir(path.parent)
    path.write_text(doc, encoding="utf-8")


def emit_exports(
    result: AuditResult,
    *,
    json_path: Optional[Path] = None,
    html_path: Optional[Path] = None,
    md_path: Optional[Path] = None,
    as_json_stdout: bool = False,
) -> None:
    save_result(result)
    if as_json_stdout:
        console.print_json(data=result.to_dict())
    if json_path:
        export_json(result, json_path)
        console.print(f"[green]JSON written:[/green] {json_path}")
    if html_path:
        export_html(result, html_path)
        console.print(f"[green]HTML written:[/green] {html_path}")
    if md_path:
        export_markdown(result, md_path)
        console.print(f"[green]Markdown written:[/green] {md_path}")
