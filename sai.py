#!/usr/bin/env python3
"""Server AI Assistant — rule-based CLI auditor for Linux servers."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Ensure project root is on sys.path when executed as a script
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import __version__
from core.alerts import notify_from_config, send_slack, send_webhook
from core.ansible_export import (
    inventory_from_fleet_hosts,
    inventory_from_local,
    write_inventory,
)
from core.backup import list_sessions, log_action, restore_session
from core.baseline import compare_baseline, load_baseline, save_baseline
from core.cis import annotate_result, cis_modules, print_cis_report
from core.confirm import apply_findings, ask_confirm, bootstrap_remediation_registry, get_remediation
from core.fleet import load_fleet, run_fleet, save_fleet_results
from core.inventory import collect_inventory
from core.models import Severity
from core.os_detect import command_exists, detect_os, is_root
from core.report import emit_exports, load_last_result, print_terminal
from core.runner import available_modules, exit_code_for, run_audit
from core.util import ensure_dir, load_config, write_json

console = Console()


def _parse_modules(modules: Optional[str]) -> Optional[list[str]]:
    if not modules:
        return None
    return [m.strip() for m in modules.split(",") if m.strip()]


def _resolve_modules(modules_opt: Optional[str], profile: Optional[str]) -> Optional[list[str]]:
    if modules_opt:
        return _parse_modules(modules_opt)
    if profile:
        cfg = load_config()
        profiles = cfg.get("profiles") or {}
        if profile not in profiles:
            console.print(
                f"[red]Unknown profile '{profile}'.[/red] "
                f"Available: {', '.join(sorted(profiles)) or 'none'}"
            )
            sys.exit(2)
        return list(profiles[profile])
    return None


def _parse_severity(value: Optional[str]) -> Optional[Severity]:
    if not value:
        return None
    return Severity(value.lower())


def _export_opts(
    as_json: bool,
    html: Optional[str],
    md: Optional[str],
    json_file: Optional[str],
) -> dict:
    return {
        "as_json_stdout": as_json,
        "html_path": Path(html) if html else None,
        "md_path": Path(md) if md else None,
        "json_path": Path(json_file) if json_file else None,
    }


@click.group()
@click.version_option(__version__, prog_name="Server AI Assistant")
def cli() -> None:
    """Server AI Assistant — audit, harden, and remediate Linux servers (rule-based)."""
    bootstrap_remediation_registry()


@cli.command("doctor")
def doctor_cmd() -> None:
    """Self-check: OS support, privileges, and dependencies."""
    os_info = detect_os()
    table = Table(title="Server AI Assistant Doctor", show_header=True)
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")

    table.add_row(
        "Operating system",
        "[green]OK[/green]" if os_info.supported else "[red]UNSUPPORTED[/red]",
        f"{os_info.pretty_name} (id={os_info.id}, family={os_info.family})",
    )
    table.add_row(
        "Hostname",
        "[green]OK[/green]",
        os_info.hostname,
    )
    table.add_row(
        "Package manager",
        "[green]OK[/green]" if os_info.pkg_manager != "unknown" else "[yellow]WARN[/yellow]",
        os_info.pkg_manager,
    )
    table.add_row(
        "Firewall tooling",
        "[green]OK[/green]" if os_info.firewall != "unknown" else "[yellow]WARN[/yellow]",
        os_info.firewall,
    )
    table.add_row(
        "Root privileges",
        "[green]YES[/green]" if is_root() else "[yellow]NO[/yellow]",
        "Full audits/remediations require root" if not is_root() else "Running as root",
    )
    for dep in ("systemctl", "ss", "bash"):
        table.add_row(
            f"Dependency: {dep}",
            "[green]OK[/green]" if command_exists(dep) else "[red]MISSING[/red]",
            "found" if command_exists(dep) else "not in PATH",
        )
    table.add_row("Modules", "[green]OK[/green]", ", ".join(available_modules()))
    console.print(table)
    if not os_info.supported:
        console.print(
            "[red]This OS is outside the supported set "
            "(Ubuntu, AlmaLinux, Rocky Linux and close relatives).[/red]"
        )
        sys.exit(2)
    sys.exit(0)


@cli.command("status")
def status_cmd() -> None:
    """Quick health snapshot (system module only)."""
    result = run_audit(modules=["system"])
    print_terminal(result)
    emit_exports(result)
    cfg = load_config()
    sys.exit(exit_code_for(result, cfg.get("severity_exit_threshold", "high")))


@cli.command("audit")
@click.option("--modules", "-m", "modules_opt", default=None, help="Comma-separated module list")
@click.option("--profile", "-p", default=None, help="Named profile from config (quick, security, webstack, hosting)")
@click.option("--severity", default=None, type=click.Choice([s.value for s in Severity]), help="Minimum severity to display")
@click.option("--json", "as_json", is_flag=True, help="Print JSON to stdout")
@click.option("--json-file", default=None, type=click.Path(), help="Write JSON report to path")
@click.option("--html", default=None, type=click.Path(), help="Write HTML report to path")
@click.option("--md", default=None, type=click.Path(), help="Write Markdown report to path")
@click.option("--cis", "with_cis", is_flag=True, help="Annotate findings with CIS control mappings")
@click.option("--notify", is_flag=True, help="Send alerts using config alerts.* settings")
@click.option("--slack-webhook", default=None, help="Slack incoming webhook URL for this run")
@click.option("--webhook", default=None, help="Generic JSON webhook URL for this run")
def audit_cmd(
    modules_opt: Optional[str],
    profile: Optional[str],
    severity: Optional[str],
    as_json: bool,
    json_file: Optional[str],
    html: Optional[str],
    md: Optional[str],
    with_cis: bool,
    notify: bool,
    slack_webhook: Optional[str],
    webhook: Optional[str],
) -> None:
    """Run a full or module-scoped server audit."""
    os_info = detect_os()
    if not os_info.supported:
        if as_json:
            console.print_json(data={"error": "unsupported_os", "os": os_info.pretty_name})
        else:
            console.print(f"[red]Unsupported OS:[/red] {os_info.pretty_name}")
        sys.exit(2)
    if not is_root() and not as_json:
        console.print("[yellow]Warning:[/yellow] not running as root; some checks will be limited.")

    result = run_audit(modules=_resolve_modules(modules_opt, profile))
    if with_cis:
        annotate_result(result)
    min_sev = _parse_severity(severity)
    if not as_json:
        print_terminal(result, minimum=min_sev)
        if with_cis:
            print_cis_report(result)
    emit_exports(result, **_export_opts(as_json, html, md, json_file))

    cfg = load_config()
    if notify:
        for msg in notify_from_config(result, cfg):
            if not as_json:
                console.print(f"[cyan]notify:[/cyan] {msg}")
    if slack_webhook:
        ok, msg = send_slack(slack_webhook, result)
        if not as_json:
            console.print(f"[cyan]slack:[/cyan] {'OK' if ok else 'FAIL'} — {msg}")
    if webhook:
        ok, msg = send_webhook(webhook, result)
        if not as_json:
            console.print(f"[cyan]webhook:[/cyan] {'OK' if ok else 'FAIL'} — {msg}")

    sys.exit(exit_code_for(result, cfg.get("severity_exit_threshold", "high")))


@cli.command("check")
@click.argument("module")
@click.option("--json", "as_json", is_flag=True)
@click.option("--html", default=None, type=click.Path())
@click.option("--md", default=None, type=click.Path())
@click.option("--json-file", default=None, type=click.Path())
def check_cmd(
    module: str,
    as_json: bool,
    html: Optional[str],
    md: Optional[str],
    json_file: Optional[str],
) -> None:
    """Run a single audit module."""
    mods = available_modules()
    if module not in mods:
        console.print(f"[red]Unknown module '{module}'.[/red] Available: {', '.join(mods)}")
        sys.exit(2)
    result = run_audit(modules=[module])
    if not as_json:
        print_terminal(result)
    emit_exports(result, **_export_opts(as_json, html, md, json_file))
    cfg = load_config()
    sys.exit(exit_code_for(result, cfg.get("severity_exit_threshold", "high")))


@cli.command("report")
@click.option("--json", "as_json", is_flag=True)
@click.option("--html", default=None, type=click.Path())
@click.option("--md", default=None, type=click.Path())
@click.option("--json-file", default=None, type=click.Path())
@click.option("--severity", default=None, type=click.Choice([s.value for s in Severity]))
def report_cmd(
    as_json: bool,
    html: Optional[str],
    md: Optional[str],
    json_file: Optional[str],
    severity: Optional[str],
) -> None:
    """Re-render the last cached audit result."""
    result = load_last_result()
    if not result:
        console.print("[yellow]No cached audit found. Run 'sai audit' first.[/yellow]")
        sys.exit(2)
    if not as_json:
        print_terminal(result, minimum=_parse_severity(severity))
    emit_exports(result, **_export_opts(as_json, html, md, json_file))
    sys.exit(0)


@cli.command("fix")
@click.option("--dry-run", is_flag=True, help="Show actions without applying")
@click.option("--yes", "assume_yes", is_flag=True, help="Auto-confirm (dangerous; for automation)")
@click.option("--modules", "-m", "modules_opt", default=None, help="Limit to modules before fixing")
@click.option("--severity", default="medium", type=click.Choice([s.value for s in Severity]))
def fix_cmd(
    dry_run: bool,
    assume_yes: bool,
    modules_opt: Optional[str],
    severity: str,
) -> None:
    """Interactively apply remediations for findings that support them."""
    if not is_root() and not dry_run:
        console.print("[red]Remediations require root (or use --dry-run).[/red]")
        sys.exit(2)
    result = run_audit(modules=_parse_modules(modules_opt))
    print_terminal(result, minimum=Severity(severity))
    emit_exports(result)
    actionable = [
        f
        for f in result.findings
        if f.remediation_id and f.severity.at_or_above(severity)
    ]
    if not actionable:
        console.print("[yellow]No remediations available at this severity filter.[/yellow]")
        sys.exit(0)
    applied = apply_findings(actionable, dry_run=dry_run, assume_yes=assume_yes)
    console.print(f"[bold]Applied:[/bold] {applied}/{len(actionable)}")
    log_action(f"fix command finished applied={applied}")
    sys.exit(0)


@cli.command("harden")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "assume_yes", is_flag=True)
def harden_cmd(dry_run: bool, assume_yes: bool) -> None:
    """Propose and optionally apply the security baseline."""
    if not is_root() and not dry_run:
        console.print("[red]Hardening requires root (or use --dry-run).[/red]")
        sys.exit(2)
    result = run_audit(modules=["security"])
    print_terminal(result)
    emit_exports(result)
    console.print(Panel(
        "This will walk security findings that have remediations "
        "(SSH, firewall, sysctl, fail2ban).",
        title="Security harden",
        border_style="magenta",
    ))
    actionable = [f for f in result.findings if f.remediation_id]
    applied = apply_findings(actionable, dry_run=dry_run, assume_yes=assume_yes)
    console.print(f"[bold]Applied:[/bold] {applied}/{len(actionable)}")
    sys.exit(0)


@cli.command("updates")
@click.option("--apply", "do_apply", is_flag=True, help="Offer to apply pending updates")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "assume_yes", is_flag=True)
def updates_cmd(do_apply: bool, dry_run: bool, assume_yes: bool) -> None:
    """Check package updates; optionally apply with confirmation."""
    result = run_audit(modules=["updates"])
    print_terminal(result)
    emit_exports(result)
    if do_apply:
        if not is_root() and not dry_run:
            console.print("[red]Applying updates requires root.[/red]")
            sys.exit(2)
        actionable = [f for f in result.findings if f.remediation_id == "apply_updates"]
        apply_findings(actionable, dry_run=dry_run, assume_yes=assume_yes)
    sys.exit(exit_code_for(result, "high"))


@cli.command("modules")
def modules_cmd() -> None:
    """List available audit modules and profiles."""
    console.print("[bold]Modules[/bold]")
    for name in available_modules():
        console.print(f" - {name}")
    profiles = (load_config().get("profiles") or {})
    if profiles:
        console.print("\n[bold]Profiles[/bold]")
        for pname, mods in sorted(profiles.items()):
            console.print(f" - {pname}: {', '.join(mods)}")


@cli.command("inventory")
@click.option("--json-file", default=None, type=click.Path(), help="Write inventory JSON to path")
@click.option("--json", "as_json", is_flag=True, help="Print JSON to stdout")
def inventory_cmd(json_file: Optional[str], as_json: bool) -> None:
    """Collect host inventory facts (CMDB-style snapshot)."""
    data = collect_inventory()
    if as_json or json_file:
        if as_json:
            console.print_json(data=data)
        if json_file:
            write_json(json_file, data)
            console.print(f"[green]Inventory written:[/green] {json_file}")
    else:
        table = Table(title="Host inventory", show_header=True)
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("Hostname", str(data.get("hostname")))
        table.add_row("OS", str((data.get("os") or {}).get("pretty_name")))
        table.add_row("Kernel", str(data.get("kernel")))
        table.add_row("CPUs", str(data.get("cpus")))
        table.add_row("Memory", str(data.get("memory")))
        table.add_row("Virt", str(data.get("virtualization")))
        table.add_row("Uptime", str(data.get("uptime")))
        tools = data.get("tools") or {}
        present = [k for k, v in tools.items() if v]
        table.add_row("Tools", ", ".join(present) or "none")
        console.print(table)
        if data.get("disks"):
            console.print(Panel(str(data["disks"]), title="Disks", border_style="blue"))
    sys.exit(0)


@cli.command("restore")
@click.option("--list", "list_only", is_flag=True, help="List SAI config backup sessions")
@click.option("--session", default=None, help="Session directory name under backup dir")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "assume_yes", is_flag=True)
def restore_cmd(list_only: bool, session: Optional[str], dry_run: bool, assume_yes: bool) -> None:
    """List or restore configuration backups created by SAI remediations."""
    sessions = list_sessions()
    if list_only or not session:
        if not sessions:
            console.print("[yellow]No backup sessions found.[/yellow]")
            sys.exit(0)
        table = Table(title="SAI backup sessions")
        table.add_column("Session")
        table.add_column("Files")
        for s in sessions[:50]:
            manifest = s / "MANIFEST.txt"
            count = "0"
            if manifest.is_file():
                count = str(len([ln for ln in manifest.read_text(encoding="utf-8").splitlines() if ln.strip()]))
            table.add_row(s.name, count)
        console.print(table)
        if not session:
            console.print("Restore with: [cyan]sai restore --session <name>[/cyan]")
            sys.exit(0)

    from core.backup import backup_root

    target = backup_root() / session
    if not target.is_dir():
        console.print(f"[red]Session not found:[/red] {target}")
        sys.exit(2)
    if not is_root() and not dry_run:
        console.print("[red]Restore requires root (or --dry-run).[/red]")
        sys.exit(2)
    if not ask_confirm(
        f"Restore files from backup session '{session}'?",
        require_apply=True,
        assume_yes=assume_yes,
    ):
        console.print("[yellow]Skipped.[/yellow]")
        sys.exit(0)
    restored = restore_session(target, dry_run=dry_run)
    for item in restored:
        console.print(f"  {item}")
    console.print(f"[green]Restored {len(restored)} path(s).[/green]")
    sys.exit(0)


@cli.command("baseline")
@click.argument("action", type=click.Choice(["save", "diff", "show"]))
@click.option("--name", default="default", help="Baseline name")
@click.option("--profile", "-p", default=None)
@click.option("--modules", "-m", "modules_opt", default=None)
def baseline_cmd(
    action: str,
    name: str,
    profile: Optional[str],
    modules_opt: Optional[str],
) -> None:
    """Save or compare an audit baseline (finding ID set)."""
    if action == "show":
        data = load_baseline(name)
        if not data:
            console.print(f"[yellow]No baseline '{name}'.[/yellow]")
            sys.exit(2)
        console.print_json(data=data)
        sys.exit(0)

    result = run_audit(modules=_resolve_modules(modules_opt, profile))
    emit_exports(result)
    if action == "save":
        path = save_baseline(result, name=name)
        console.print(f"[green]Baseline saved:[/green] {path} ({len(result.findings)} findings)")
        sys.exit(0)

    # diff
    try:
        added, resolved, same = compare_baseline(result, name=name)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(2)
    console.print(Panel(
        f"[green]Resolved:[/green] {len(resolved)}\n"
        f"[red]New:[/red] {len(added)}\n"
        f"[dim]Unchanged:[/dim] {len(same)}",
        title=f"Baseline diff ({name})",
    ))
    if added:
        console.print("[bold red]New findings[/bold red]")
        for i in added:
            console.print(f" + {i}")
    if resolved:
        console.print("[bold green]Resolved findings[/bold green]")
        for i in resolved:
            console.print(f" - {i}")
    sys.exit(1 if added else 0)


@cli.command("schedule")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "assume_yes", is_flag=True)
def schedule_cmd(dry_run: bool, assume_yes: bool) -> None:
    """Install a daily systemd timer for SAI audits (requires confirmation)."""
    if not is_root() and not dry_run:
        console.print("[red]schedule requires root (or --dry-run).[/red]")
        sys.exit(2)
    rem = get_remediation("install_sai_timer")
    if not rem:
        console.print("[red]Remediation install_sai_timer missing.[/red]")
        sys.exit(2)
    from core.models import Finding

    fake = Finding(
        id="ops.schedule",
        module="services",
        severity=Severity.INFO,
        title="Install daily SAI audit timer",
        detail="Creates sai-audit.service and sai-audit.timer for daily audits.",
        recommended="Enable persistent daily audits with HTML/JSON under /var/cache/sai",
        remediation_id="install_sai_timer",
    )
    ok = apply_findings([fake], dry_run=dry_run, assume_yes=assume_yes)
    sys.exit(0 if ok else 1)


@cli.command("critical")
@click.option("--json", "as_json", is_flag=True)
@click.option("--html", default=None, type=click.Path())
@click.option("--md", default=None, type=click.Path())
@click.option("--json-file", default=None, type=click.Path())
@click.option("--notify", is_flag=True)
@click.option("--slack-webhook", default=None)
@click.option("--webhook", default=None)
def critical_cmd(
    as_json: bool,
    html: Optional[str],
    md: Optional[str],
    json_file: Optional[str],
    notify: bool,
    slack_webhook: Optional[str],
    webhook: Optional[str],
) -> None:
    """Fast pass: full audit but only display critical/high findings."""
    result = run_audit()
    if not as_json:
        print_terminal(result, minimum=Severity.HIGH)
    emit_exports(result, **_export_opts(as_json, html, md, json_file))
    if notify:
        for msg in notify_from_config(result):
            if not as_json:
                console.print(f"[cyan]notify:[/cyan] {msg}")
    if slack_webhook:
        ok, msg = send_slack(slack_webhook, result)
        if not as_json:
            console.print(f"[cyan]slack:[/cyan] {'OK' if ok else 'FAIL'} — {msg}")
    if webhook:
        ok, msg = send_webhook(webhook, result)
        if not as_json:
            console.print(f"[cyan]webhook:[/cyan] {'OK' if ok else 'FAIL'} — {msg}")
    sys.exit(exit_code_for(result, "high"))


@cli.command("cis")
@click.option("--modules", "-m", "modules_opt", default=None)
@click.option("--json", "as_json", is_flag=True)
@click.option("--json-file", default=None, type=click.Path())
@click.option("--html", default=None, type=click.Path())
@click.option("--md", default=None, type=click.Path())
@click.option("--from-cache", is_flag=True, help="Map CIS controls onto the last cached audit")
def cis_cmd(
    modules_opt: Optional[str],
    as_json: bool,
    json_file: Optional[str],
    html: Optional[str],
    md: Optional[str],
    from_cache: bool,
) -> None:
    """Run a CIS-oriented audit and show control mappings."""
    if from_cache:
        result = load_last_result()
        if not result:
            console.print("[yellow]No cached audit. Run 'sai audit' first.[/yellow]")
            sys.exit(2)
    else:
        mods = _parse_modules(modules_opt) or cis_modules()
        result = run_audit(modules=mods)
    annotate_result(result)
    if not as_json:
        print_terminal(result, minimum=Severity.LOW)
        print_cis_report(result)
    emit_exports(result, **_export_opts(as_json, html, md, json_file))
    sys.exit(exit_code_for(result, "high"))


@cli.command("ansible")
@click.option("--output", "-o", "output", default="-", help="Output path or '-' for stdout")
@click.option("--format", "fmt", type=click.Choice(["yaml", "ini"]), default="yaml")
@click.option("--fleet", "-f", "fleet_file", default=None, type=click.Path(), help="Fleet YAML/hosts file")
@click.option("--ansible-host", default=None, help="Override ansible_host for local export")
@click.option("--ansible-user", default=None, help="Override ansible_user for local export")
@click.option("--group", multiple=True, help="Extra Ansible group for local host (repeatable)")
def ansible_cmd(
    output: str,
    fmt: str,
    fleet_file: Optional[str],
    ansible_host: Optional[str],
    ansible_user: Optional[str],
    group: tuple,
) -> None:
    """Export an Ansible inventory (local host or fleet file)."""
    if fleet_file:
        hosts = [h.to_dict() for h in load_fleet(Path(fleet_file))]
        inventory = inventory_from_fleet_hosts(hosts)
    else:
        inventory = inventory_from_local(
            ansible_host=ansible_host,
            ansible_user=ansible_user,
            groups=list(group) or None,
        )
    if output == "-":
        from core.ansible_export import to_ini, to_yaml

        console.print(to_ini(inventory) if fmt == "ini" else to_yaml(inventory), end="")
    else:
        path = write_inventory(inventory, Path(output), fmt=fmt)
        console.print(f"[green]Ansible inventory written:[/green] {path}")
    sys.exit(0)


@cli.group("fleet")
def fleet_group() -> None:
    """Multi-host SSH fleet operations (requires key-based SSH)."""


@fleet_group.command("audit")
@click.option("--fleet", "-f", "fleet_file", required=True, type=click.Path(exists=True), help="Fleet YAML or hosts.txt")
@click.option("--modules", "-m", "modules_opt", default=None)
@click.option("--profile", "-p", default=None)
@click.option("--parallel", default=5, show_default=True, help="Max concurrent SSH sessions")
@click.option("--sai-bin", default="sai", show_default=True, help="Remote sai binary name/path")
@click.option("--out-dir", default=None, type=click.Path(), help="Directory for per-host JSON + summary")
@click.option("--ansible-out", default=None, type=click.Path(), help="Also write Ansible inventory from results")
@click.option("--notify", is_flag=True, help="Notify using config alerts for each host with issues")
@click.option("--slack-webhook", default=None)
@click.option("--webhook", default=None)
def fleet_audit_cmd(
    fleet_file: str,
    modules_opt: Optional[str],
    profile: Optional[str],
    parallel: int,
    sai_bin: str,
    out_dir: Optional[str],
    ansible_out: Optional[str],
    notify: bool,
    slack_webhook: Optional[str],
    webhook: Optional[str],
) -> None:
    """Audit many hosts over SSH (`sai` must be installed remotely)."""
    if not command_exists("ssh"):
        console.print("[red]ssh client not found in PATH.[/red]")
        sys.exit(2)
    hosts = load_fleet(Path(fleet_file))
    if not hosts:
        console.print("[yellow]No hosts in fleet file.[/yellow]")
        sys.exit(2)
    console.print(f"[bold]Fleet audit[/bold] — {len(hosts)} host(s), parallel={parallel}")
    results = run_fleet(
        hosts,
        modules=_parse_modules(modules_opt),
        profile=profile,
        parallelism=parallel,
        sai_bin=sai_bin,
    )

    table = Table(title="Fleet results", show_lines=True)
    table.add_column("Host")
    table.add_column("Status", width=12)
    table.add_column("Crit", justify="right")
    table.add_column("High", justify="right")
    table.add_column("Total", justify="right")
    table.add_column("Detail")
    worst_exit = 0
    for r in results:
        if not r.ok:
            table.add_row(r.host.name, "[red]FAIL[/red]", "—", "—", "—", r.error[:80])
            worst_exit = max(worst_exit, 2)
            continue
        summary = r.summary()
        crit = summary.get("critical", 0)
        high = summary.get("high", 0)
        total = summary.get("total", 0)
        status = "[green]OK[/green]" if crit + high == 0 else "[yellow]ISSUES[/yellow]"
        table.add_row(r.host.name, status, str(crit), str(high), str(total), r.audit.os_name if r.audit else "")
        if crit + high > 0:
            worst_exit = max(worst_exit, 1)
        if r.audit and (notify or slack_webhook or webhook):
            if notify:
                for msg in notify_from_config(r.audit):
                    console.print(f"[dim]{r.host.name} notify:[/dim] {msg}")
            if slack_webhook:
                send_slack(slack_webhook, r.audit)
            if webhook:
                send_webhook(webhook, r.audit)
    console.print(table)

    dest = Path(out_dir) if out_dir else Path("data") / "fleet"
    ensure_dir(dest)
    summary_path = save_fleet_results(results, dest)
    console.print(f"[green]Fleet summary:[/green] {summary_path}")

    if ansible_out:
        result_map = {
            r.host.name: {"summary": r.summary(), "error": r.error, "ok": r.ok}
            for r in results
        }
        inv = inventory_from_fleet_hosts([h.to_dict() for h in hosts], results=result_map)
        path = write_inventory(inv, Path(ansible_out), fmt="yaml")
        console.print(f"[green]Ansible inventory:[/green] {path}")

    log_action(f"fleet audit hosts={len(hosts)} exit={worst_exit}")
    sys.exit(worst_exit)


@cli.command("alert")
@click.option("--from-cache", is_flag=True, help="Alert from last cached audit (default)")
@click.option("--profile", "-p", default=None)
@click.option("--modules", "-m", "modules_opt", default=None)
@click.option("--slack-webhook", default=None, help="Override Slack webhook URL")
@click.option("--webhook", default=None, help="Override generic webhook URL")
@click.option("--severity", default=None, type=click.Choice([s.value for s in Severity]))
def alert_cmd(
    from_cache: bool,
    profile: Optional[str],
    modules_opt: Optional[str],
    slack_webhook: Optional[str],
    webhook: Optional[str],
    severity: Optional[str],
) -> None:
    """Send Slack / webhook alerts for findings at or above threshold."""
    if modules_opt or profile:
        result = run_audit(modules=_resolve_modules(modules_opt, profile))
        emit_exports(result)
    else:
        result = load_last_result()
        if not result:
            console.print("[yellow]No cached audit. Running a quick audit…[/yellow]")
            result = run_audit(modules=["security", "updates", "ssl", "services"])
            emit_exports(result)

    min_sev = _parse_severity(severity)
    cfg = load_config()
    messages = []
    if slack_webhook or webhook:
        if slack_webhook:
            ok, msg = send_slack(slack_webhook, result, minimum=min_sev)
            messages.append(f"slack: {'OK' if ok else 'FAIL'} — {msg}")
        if webhook:
            ok, msg = send_webhook(webhook, result, minimum=min_sev)
            messages.append(f"webhook: {'OK' if ok else 'FAIL'} — {msg}")
    else:
        # Temporarily honor severity override via config copy
        if min_sev:
            cfg = dict(cfg)
            alerts = dict(cfg.get("alerts") or {})
            alerts["min_severity"] = min_sev.value
            alerts["enabled"] = True
            cfg["alerts"] = alerts
        messages = notify_from_config(result, cfg)

    for msg in messages:
        console.print(msg)
    # Exit 1 if there were alertable findings
    from core.alerts import filter_alert_findings

    findings = filter_alert_findings(result, min_sev)
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
