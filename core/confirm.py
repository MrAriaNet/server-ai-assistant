"""Interactive confirmation and remediation application."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence

from rich.console import Console
from rich.panel import Panel

from core.backup import backup_files, log_action, restart_service
from core.models import Finding, Remediation
from core.util import project_root, run_cmd

console = Console()

# Registry of built-in remediations
REMEDIATIONS: dict[str, Remediation] = {}


def register_remediation(rem: Remediation) -> None:
    REMEDIATIONS[rem.id] = rem


def get_remediation(remediation_id: str) -> Optional[Remediation]:
    if remediation_id in REMEDIATIONS:
        return REMEDIATIONS[remediation_id]
    # Auto-discover script under remediations/
    script = project_root() / "remediations" / f"{remediation_id}.sh"
    if script.is_file():
        rem = Remediation(
            id=remediation_id,
            title=remediation_id.replace("_", " ").title(),
            description=f"Run remediation script {script.name}",
            script=str(script),
        )
        REMEDIATIONS[remediation_id] = rem
        return rem
    return None


def ask_confirm(prompt: str, *, require_apply: bool = False, assume_yes: bool = False) -> bool:
    if assume_yes:
        console.print(f"[yellow]Auto-confirmed (--yes):[/yellow] {prompt}")
        return True
    if require_apply:
        console.print(Panel(prompt, title="Confirmation required", border_style="yellow"))
        answer = console.input("Type [bold]APPLY[/bold] to proceed (or anything else to skip): ").strip()
        return answer == "APPLY"
    answer = console.input(f"{prompt} [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def apply_remediation(
    finding: Finding,
    *,
    dry_run: bool = False,
    assume_yes: bool = False,
    skip_restart_confirm: bool = False,
) -> bool:
    """Apply remediation for a finding. Returns True if applied successfully."""
    if not finding.remediation_id:
        console.print(f"[dim]No remediation for {finding.id}[/dim]")
        return False

    rem = get_remediation(finding.remediation_id)
    if not rem:
        console.print(f"[red]Unknown remediation:[/red] {finding.remediation_id}")
        return False

    console.print()
    console.print(Panel.fit(
        f"[bold]{finding.title}[/bold]\n\n"
        f"{finding.detail}\n\n"
        f"[cyan]Current:[/cyan] {finding.current or 'n/a'}\n"
        f"[green]Recommended:[/green] {finding.recommended or rem.description}\n"
        f"[magenta]Script:[/magenta] {rem.script}",
        title=f"Remediation: {rem.id}",
        border_style="magenta",
    ))

    if not ask_confirm(
        f"Apply remediation '{rem.id}'?",
        require_apply=True,
        assume_yes=assume_yes,
    ):
        console.print("[yellow]Skipped.[/yellow]")
        log_action(f"SKIP remediation={rem.id} finding={finding.id}")
        return False

    files = list(rem.files_touched)
    if dry_run:
        console.print(f"[cyan][dry-run] Would backup:[/cyan] {files or '(none listed)'}")
        console.print(f"[cyan][dry-run] Would run:[/cyan] {rem.script}")
        log_action(f"DRY-RUN remediation={rem.id} finding={finding.id}")
        return True

    session = None
    if files:
        session = backup_files(files, session=None)
        console.print(f"[green]Backup created:[/green] {session}")

    script_path = Path(rem.script)
    if not script_path.is_file():
        # Resolve relative to project remediations/
        alt = project_root() / "remediations" / Path(rem.script).name
        if alt.is_file():
            script_path = alt
        else:
            console.print(f"[red]Script missing:[/red] {rem.script}")
            return False

    code, out, err = run_cmd(["bash", str(script_path)], timeout=300)
    log_action(
        f"APPLY remediation={rem.id} finding={finding.id} rc={code} "
        f"backup={session or 'none'}"
    )
    if out.strip():
        console.print(out.strip())
    if err.strip():
        console.print(f"[yellow]{err.strip()}[/yellow]")

    if code != 0:
        console.print(f"[red]Remediation failed (exit {code}).[/red]")
        return False

    console.print("[green]Remediation applied successfully.[/green]")

    if rem.restart_service:
        svc = rem.restart_service
        # Ubuntu uses ssh.service; RHEL-like uses sshd.service
        if svc == "sshd":
            from core.util import service_exists

            if not service_exists("sshd") and service_exists("ssh"):
                svc = "ssh"
        if svc == "redis":
            from core.util import service_exists

            if not service_exists("redis") and service_exists("redis-server"):
                svc = "redis-server"
        do_restart = skip_restart_confirm or assume_yes or ask_confirm(
            f"Restart service '{svc}' now?",
            require_apply=False,
            assume_yes=assume_yes,
        )
        if do_restart:
            rc, msg = restart_service(svc, dry_run=False)
            if rc == 0:
                console.print(f"[green]Service restarted:[/green] {svc}")
            else:
                console.print(f"[red]Restart failed:[/red] {msg}")
        else:
            console.print(
                f"[yellow]Remember to restart:[/yellow] systemctl restart {svc}"
            )

    return True


def apply_findings(
    findings: Sequence[Finding],
    *,
    dry_run: bool = False,
    assume_yes: bool = False,
) -> int:
    """Apply remediations for findings that have them. Returns count applied."""
    actionable = [f for f in findings if f.remediation_id]
    if not actionable:
        console.print("[yellow]No actionable remediations in the current findings.[/yellow]")
        return 0
    applied = 0
    for finding in actionable:
        if apply_remediation(finding, dry_run=dry_run, assume_yes=assume_yes):
            applied += 1
    return applied


def bootstrap_remediation_registry() -> None:
    """Register known remediations with metadata."""
    root = project_root() / "remediations"
    specs = [
        Remediation(
            id="ssh_harden",
            title="Harden SSH daemon",
            description="Write SSH hardening drop-in (disable password auth, restrict root login, etc.)",
            script=str(root / "ssh_harden.sh"),
            files_touched=["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/99-sai.conf"],
            restart_service="sshd",
        ),
        Remediation(
            id="ufw_baseline",
            title="Enable UFW baseline",
            description="Enable UFW with default deny incoming, allow SSH/HTTP/HTTPS",
            script=str(root / "ufw_baseline.sh"),
            files_touched=["/etc/ufw/ufw.conf"],
            restart_service=None,
        ),
        Remediation(
            id="firewalld_baseline",
            title="Enable firewalld baseline",
            description="Enable firewalld and allow ssh/http/https services",
            script=str(root / "firewalld_baseline.sh"),
            files_touched=["/etc/firewalld"],
            restart_service="firewalld",
        ),
        Remediation(
            id="sysctl_harden",
            title="Apply sysctl hardening",
            description="Write network hardening sysctl drop-in and reload",
            script=str(root / "sysctl_harden.sh"),
            files_touched=["/etc/sysctl.d/99-sai.conf"],
            restart_service=None,
        ),
        Remediation(
            id="enable_fail2ban",
            title="Enable fail2ban",
            description="Enable and start fail2ban service if installed",
            script=str(root / "enable_fail2ban.sh"),
            files_touched=[],
            restart_service="fail2ban",
        ),
        Remediation(
            id="nginx_security_headers",
            title="Nginx security tokens",
            description="Disable nginx server tokens via drop-in snippet",
            script=str(root / "nginx_security_headers.sh"),
            files_touched=["/etc/nginx/conf.d/00-sai-security.conf"],
            restart_service="nginx",
        ),
        Remediation(
            id="apache_security_tokens",
            title="Apache ServerTokens Prod",
            description="Set ServerTokens Prod and ServerSignature Off",
            script=str(root / "apache_security_tokens.sh"),
            files_touched=["/etc/apache2/conf-available/sai-security.conf", "/etc/httpd/conf.d/sai-security.conf"],
            restart_service=None,
        ),
        Remediation(
            id="apply_updates",
            title="Apply package updates",
            description="Install pending package updates via apt or dnf",
            script=str(root / "apply_updates.sh"),
            files_touched=[],
            restart_service=None,
        ),
        Remediation(
            id="redis_bind_localhost",
            title="Bind Redis to localhost",
            description="Ensure Redis listens on 127.0.0.1 only",
            script=str(root / "redis_bind_localhost.sh"),
            files_touched=["/etc/redis/redis.conf", "/etc/redis.conf"],
            restart_service="redis",
        ),
        Remediation(
            id="fix_tmp_sticky",
            title="Set /tmp sticky bit",
            description="chmod 1777 /tmp",
            script=str(root / "fix_tmp_sticky.sh"),
            files_touched=[],
            restart_service=None,
        ),
        Remediation(
            id="enable_auditd",
            title="Enable auditd",
            description="Enable and start the Linux audit daemon",
            script=str(root / "enable_auditd.sh"),
            files_touched=[],
            restart_service="auditd",
        ),
        Remediation(
            id="journal_vacuum",
            title="Vacuum journal logs",
            description="journalctl --vacuum-time=7d",
            script=str(root / "journal_vacuum.sh"),
            files_touched=[],
            restart_service=None,
        ),
        Remediation(
            id="logrotate_force",
            title="Force logrotate",
            description="Run logrotate -f against system config",
            script=str(root / "logrotate_force.sh"),
            files_touched=[],
            restart_service=None,
        ),
        Remediation(
            id="install_sai_timer",
            title="Install daily SAI audit timer",
            description="Install systemd timer for daily sai audit",
            script=str(root / "install_sai_timer.sh"),
            files_touched=[
                "/etc/systemd/system/sai-audit.service",
                "/etc/systemd/system/sai-audit.timer",
            ],
            restart_service=None,
        ),
    ]
    for rem in specs:
        register_remediation(rem)
