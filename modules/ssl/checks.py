"""TLS certificate expiry and chain sanity checks."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set, Tuple

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import run_cmd, which


CERT_GLOBS = [
    "/etc/ssl/certs/*.pem",
    "/etc/letsencrypt/live/*/fullchain.pem",
    "/etc/nginx/ssl/*.crt",
    "/etc/nginx/ssl/*.pem",
    "/etc/httpd/conf/*.crt",
    "/etc/pki/tls/certs/*.crt",
    "/etc/apache2/ssl/*.crt",
]


def _cert_not_after(path: Path) -> Optional[datetime]:
    if not which("openssl"):
        return None
    code, out, _ = run_cmd(
        ["openssl", "x509", "-in", str(path), "-noout", "-enddate"],
        timeout=15,
    )
    if code != 0 or "notAfter=" not in out:
        return None
    raw = out.strip().split("=", 1)[1].strip()
    # e.g. Oct 25 12:00:00 2027 GMT
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _discover_certs() -> List[Path]:
    found: List[Path] = []
    seen: Set[str] = set()
    for pattern in CERT_GLOBS:
        parent = Path(pattern).parent
        name = Path(pattern).name
        if "*" in str(parent):
            # /etc/letsencrypt/live/*/fullchain.pem
            base = Path("/etc/letsencrypt/live")
            if base.is_dir():
                for child in base.iterdir():
                    cand = child / "fullchain.pem"
                    if cand.is_file():
                        key = str(cand.resolve()) if cand.exists() else str(cand)
                        if key not in seen:
                            seen.add(key)
                            found.append(cand)
            continue
        if parent.is_dir():
            for cand in parent.glob(name):
                if cand.is_file() and cand.stat().st_size > 0:
                    try:
                        key = str(cand.resolve())
                    except OSError:
                        key = str(cand)
                    if key in seen:
                        continue
                    # Skip huge CA bundles partially — still check but skip known system store bulk
                    if "ca-certificates" in key or key.endswith("/ca-bundle.crt"):
                        continue
                    seen.add(key)
                    found.append(cand)
    return found[:80]


def _probe_local_https(port: int = 443) -> Optional[Tuple[int, str]]:
    if not which("openssl"):
        return None
    code, out, err = run_cmd(
        [
            "bash",
            "-c",
            f"echo | openssl s_client -servername localhost -connect 127.0.0.1:{port} 2>/dev/null "
            f"| openssl x509 -noout -enddate 2>/dev/null",
        ],
        timeout=20,
    )
    text = (out or "") + (err or "")
    if "notAfter=" not in text:
        return None
    raw = text.strip().split("=", 1)[-1].strip().splitlines()[0]
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            exp = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            return days, raw
        except ValueError:
            continue
    return None


@register_module("ssl")
def check_ssl(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []
    thr = config.get("thresholds") or {}
    warn_days = int(thr.get("ssl_expiry_warn_days", 30))
    crit_days = int(thr.get("ssl_expiry_crit_days", 7))
    now = datetime.now(timezone.utc)

    if not which("openssl"):
        findings.append(
            Finding(
                id="ssl.openssl_missing",
                module="ssl",
                severity=Severity.LOW,
                title="openssl not available",
                detail="Certificate checks require the openssl CLI.",
                current="missing",
                recommended="Install openssl package",
            )
        )
        return findings

    certs = _discover_certs()
    expired = []
    soon = []
    ok_count = 0
    for cert in certs:
        exp = _cert_not_after(cert)
        if not exp:
            continue
        days = (exp - now).days
        if days < 0:
            expired.append((cert, days))
            findings.append(
                Finding(
                    id=f"ssl.expired.{cert.name}",
                    module="ssl",
                    severity=Severity.CRITICAL,
                    title=f"Certificate expired: {cert}",
                    detail="TLS certificate is past its notAfter date.",
                    current=f"expired {abs(days)} day(s) ago",
                    recommended="Renew immediately (certbot renew / replace cert)",
                )
            )
        elif days <= crit_days:
            soon.append((cert, days))
            findings.append(
                Finding(
                    id=f"ssl.expiring_crit.{cert.name}",
                    module="ssl",
                    severity=Severity.CRITICAL,
                    title=f"Certificate expires in {days} day(s)",
                    detail=str(cert),
                    current=f"{days} day(s) remaining",
                    recommended="Renew before expiry; verify auto-renew timers",
                )
            )
        elif days <= warn_days:
            soon.append((cert, days))
            findings.append(
                Finding(
                    id=f"ssl.expiring.{cert.name}",
                    module="ssl",
                    severity=Severity.HIGH,
                    title=f"Certificate expires in {days} day(s)",
                    detail=str(cert),
                    current=f"{days} day(s) remaining",
                    recommended=f"Renew within {warn_days} days of expiry",
                )
            )
        else:
            ok_count += 1

    # Let's Encrypt renew timer
    code, out, _ = run_cmd(["systemctl", "is-active", "certbot.timer"], timeout=10)
    code2, out2, _ = run_cmd(["systemctl", "is-active", "certbot-renew.timer"], timeout=10)
    le_live = Path("/etc/letsencrypt/live").is_dir()
    if le_live:
        timer_ok = (code == 0 and out.strip() == "active") or (code2 == 0 and out2.strip() == "active")
        # also cron.d/certbot
        cron_le = Path("/etc/cron.d/certbot").exists()
        if not timer_ok and not cron_le:
            findings.append(
                Finding(
                    id="ssl.letsencrypt.renew",
                    module="ssl",
                    severity=Severity.HIGH,
                    title="Let's Encrypt auto-renew not detected",
                    detail="/etc/letsencrypt/live exists but certbot timer/cron not active.",
                    current="no timer/cron",
                    recommended="Enable certbot.timer or install certbot renew cron",
                )
            )
        else:
            findings.append(
                Finding(
                    id="ssl.letsencrypt.renew",
                    module="ssl",
                    severity=Severity.INFO,
                    title="Let's Encrypt renewal mechanism present",
                    detail="certbot timer or cron.d entry detected.",
                    current="configured",
                    recommended="Test with: certbot renew --dry-run",
                )
            )

    probe = _probe_local_https(443)
    if probe:
        days, raw = probe
        sev = Severity.INFO
        if days < 0:
            sev = Severity.CRITICAL
        elif days <= crit_days:
            sev = Severity.CRITICAL
        elif days <= warn_days:
            sev = Severity.HIGH
        findings.append(
            Finding(
                id="ssl.localhost_443",
                module="ssl",
                severity=sev,
                title="Local HTTPS :443 certificate",
                detail="Probed certificate presented on 127.0.0.1:443.",
                current=f"{days} day(s) until {raw}",
                recommended="Align vhost certs with renewal automation",
            )
        )

    if not certs and not probe and not le_live:
        findings.append(
            Finding(
                id="ssl.none",
                module="ssl",
                severity=Severity.INFO,
                title="No site certificates discovered",
                detail="No Let's Encrypt/nginx/apache cert paths found.",
                current="none",
                recommended="n/a if this host does not terminate TLS",
            )
        )
    elif ok_count and not expired and not soon:
        findings.append(
            Finding(
                id="ssl.ok",
                module="ssl",
                severity=Severity.INFO,
                title="Checked certificates look healthy",
                detail=f"Scanned {len(certs)} candidate file(s); {ok_count} within policy.",
                current=f"warn<{warn_days}d crit<{crit_days}d",
                recommended="Keep auto-renew enabled and monitored",
            )
        )

    return findings
