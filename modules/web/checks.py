"""Nginx, Apache/httpd, and PHP-FPM configuration checks."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import read_text, run_cmd, service_is_active, which


def _nginx_conf_paths() -> List[Path]:
    candidates = [
        Path("/etc/nginx/nginx.conf"),
        Path("/usr/local/nginx/conf/nginx.conf"),
    ]
    return [p for p in candidates if p.is_file()]


def _apache_conf_paths() -> List[Path]:
    candidates = [
        Path("/etc/apache2/apache2.conf"),
        Path("/etc/httpd/conf/httpd.conf"),
        Path("/etc/httpd/httpd.conf"),
    ]
    return [p for p in candidates if p.is_file()]


def _conf_contains(paths: List[Path], pattern: str) -> bool:
    rx = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    for p in paths:
        text = read_text(p)
        if rx.search(text):
            return True
        # Also scan conf.d includes shallowly
        for child in list(p.parent.glob("conf.d/*.conf")) + list(p.parent.glob("sites-enabled/*")):
            if child.is_file() and rx.search(read_text(child)):
                return True
    return False


def _read_directive(paths: List[Path], name: str) -> Optional[str]:
    rx = re.compile(rf"^\s*{re.escape(name)}\s+(.+?);?\s*$", re.IGNORECASE | re.MULTILINE)
    for p in paths:
        for target in [p] + list(p.parent.glob("conf.d/*.conf")) + list(p.parent.glob("conf-enabled/*")):
            if not target.is_file():
                continue
            m = rx.search(read_text(target))
            if m:
                return m.group(1).strip().strip("\"'")
    return None


@register_module("web")
def check_web(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []

    # --- nginx ---
    if which("nginx") or _nginx_conf_paths():
        active = service_is_active("nginx")
        findings.append(
            Finding(
                id="web.nginx.present",
                module="web",
                severity=Severity.INFO,
                title="Nginx detected",
                detail=f"Service active={active}",
                current="active" if active else "installed/inactive",
                recommended="Keep configs under version control; test with nginx -t",
            )
        )
        paths = _nginx_conf_paths()
        tokens = _read_directive(paths, "server_tokens")
        if tokens is None or tokens.lower() not in {"off", "0"}:
            findings.append(
                Finding(
                    id="web.nginx.server_tokens",
                    module="web",
                    severity=Severity.LOW,
                    title="Nginx server_tokens not disabled",
                    detail="Hiding version strings reduces information disclosure.",
                    current=tokens or "on (default)",
                    recommended="server_tokens off;",
                    remediation_id="nginx_security_headers",
                )
            )
        # Weak SSL protocols
        if _conf_contains(paths, r"ssl_protocols\s+[^;]*SSLv3|ssl_protocols\s+[^;]*TLSv1[^.]"):
            # Check more carefully
            for p in paths:
                for conf in [p] + list(p.parent.glob("**/*.conf")):
                    if not conf.is_file():
                        continue
                    text = read_text(conf)
                    m = re.search(r"ssl_protocols\s+([^;]+);", text, re.I)
                    if m:
                        protos = m.group(1)
                        if re.search(r"SSLv3|TLSv1(\s|;|$)|TLSv1\.0|TLSv1\.1", protos, re.I):
                            findings.append(
                                Finding(
                                    id="web.nginx.ssl_protocols",
                                    module="web",
                                    severity=Severity.HIGH,
                                    title="Nginx allows weak TLS protocols",
                                    detail=f"Found in {conf}",
                                    current=protos.strip(),
                                    recommended="ssl_protocols TLSv1.2 TLSv1.3;",
                                )
                            )
                            break
        # client_max_body_size
        body = _read_directive(paths, "client_max_body_size")
        if body is None:
            findings.append(
                Finding(
                    id="web.nginx.client_max_body_size",
                    module="web",
                    severity=Severity.INFO,
                    title="client_max_body_size not explicitly set",
                    detail="Default is 1m; uploads may fail unexpectedly for apps.",
                    current="default (1m)",
                    recommended="Set explicitly per application (e.g. 20m)",
                )
            )
        # Config test
        code, out, err = run_cmd(["nginx", "-t"], timeout=20)
        if code != 0:
            findings.append(
                Finding(
                    id="web.nginx.config_test",
                    module="web",
                    severity=Severity.CRITICAL,
                    title="Nginx configuration test failed",
                    detail=(err or out or "nginx -t failed")[:400],
                    current="FAIL",
                    recommended="Fix syntax errors before reload",
                )
            )
        # worker_connections hint
        wc = _read_directive(paths, "worker_connections")
        findings.append(
            Finding(
                id="web.nginx.worker_connections",
                module="web",
                severity=Severity.INFO,
                title="Nginx worker_connections",
                detail="Tune based on expected concurrent connections.",
                current=wc or "unset/default",
                recommended="1024–4096 typical; raise with worker_rlimit_nofile if needed",
            )
        )

    # --- Apache ---
    apache_bin = which("apache2ctl") or which("httpd") or which("apache2")
    if apache_bin or _apache_conf_paths():
        active = service_is_active("apache2") or service_is_active("httpd")
        findings.append(
            Finding(
                id="web.apache.present",
                module="web",
                severity=Severity.INFO,
                title="Apache HTTP Server detected",
                detail=f"Service active={active}",
                current="active" if active else "installed/inactive",
                recommended="Prefer mpm_event with php-fpm on busy hosts",
            )
        )
        paths = _apache_conf_paths()
        # Also scan conf.d / mods
        scan_files = list(paths)
        for extra in (
            Path("/etc/apache2/conf-enabled"),
            Path("/etc/apache2/conf-available"),
            Path("/etc/httpd/conf.d"),
        ):
            if extra.is_dir():
                scan_files.extend(extra.glob("*.conf"))
        tokens = None
        signature = None
        for conf in scan_files:
            text = read_text(conf)
            m = re.search(r"^\s*ServerTokens\s+(\S+)", text, re.I | re.M)
            if m:
                tokens = m.group(1)
            m2 = re.search(r"^\s*ServerSignature\s+(\S+)", text, re.I | re.M)
            if m2:
                signature = m2.group(1)
        if (tokens or "Full").lower() not in {"prod", "productonly"}:
            findings.append(
                Finding(
                    id="web.apache.servertokens",
                    module="web",
                    severity=Severity.LOW,
                    title="Apache ServerTokens not set to Prod",
                    detail="Version disclosure via Server header.",
                    current=tokens or "Full (default)",
                    recommended="ServerTokens Prod",
                    remediation_id="apache_security_tokens",
                )
            )
        if (signature or "On").lower() not in {"off"}:
            findings.append(
                Finding(
                    id="web.apache.serversignature",
                    module="web",
                    severity=Severity.LOW,
                    title="Apache ServerSignature not Off",
                    detail="Error pages may reveal server version.",
                    current=signature or "On (default)",
                    recommended="ServerSignature Off",
                    remediation_id="apache_security_tokens",
                )
            )
        # Config test
        if which("apache2ctl"):
            code, out, err = run_cmd(["apache2ctl", "configtest"], timeout=20)
        elif which("httpd"):
            code, out, err = run_cmd(["httpd", "-t"], timeout=20)
        else:
            code, out, err = 0, "", ""
        if code != 0:
            findings.append(
                Finding(
                    id="web.apache.config_test",
                    module="web",
                    severity=Severity.CRITICAL,
                    title="Apache configuration test failed",
                    detail=(err or out)[:400],
                    current="FAIL",
                    recommended="Fix configuration before reload",
                )
            )

    # --- PHP-FPM ---
    if which("php-fpm") or which("php-fpm8.3") or which("php-fpm8.2") or Path("/etc/php").exists():
        active = any(
            service_is_active(name)
            for name in ("php-fpm", "php8.3-fpm", "php8.2-fpm", "php8.1-fpm", "php7.4-fpm")
        )
        findings.append(
            Finding(
                id="web.phpfpm.present",
                module="web",
                severity=Severity.INFO,
                title="PHP-FPM detected",
                detail=f"Service active={active}",
                current="active" if active else "installed/inactive",
                recommended="Tune pm.max_children from available RAM; disable expose_php",
            )
        )
        # expose_php
        for ini in Path("/etc").glob("php/**/php.ini"):
            text = read_text(ini)
            m = re.search(r"^\s*expose_php\s*=\s*(\w+)", text, re.I | re.M)
            if m and m.group(1).lower() in {"on", "1", "true"}:
                findings.append(
                    Finding(
                        id="web.php.expose_php",
                        module="web",
                        severity=Severity.LOW,
                        title="PHP expose_php is enabled",
                        detail=f"Found in {ini}",
                        current="On",
                        recommended="expose_php = Off",
                    )
                )
                break

    if not findings:
        findings.append(
            Finding(
                id="web.none",
                module="web",
                severity=Severity.INFO,
                title="No common web server detected",
                detail="nginx/apache/php-fpm not found.",
                current="none",
                recommended="n/a for this host role",
            )
        )

    return findings
