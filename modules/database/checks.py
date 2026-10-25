"""MySQL/MariaDB, PostgreSQL, Redis, and MongoDB checks."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from core.models import Finding, Severity
from core.os_detect import OSInfo
from core.runner import register_module
from core.util import bytes_human, read_text, run_cmd, service_is_active, which


def _first_existing(paths: List[str]) -> Optional[Path]:
    for p in paths:
        path = Path(p)
        if path.is_file():
            return path
    return None


def _listen_ports() -> str:
    code, out, _ = run_cmd(["ss", "-tulpn"], timeout=20)
    return out if code == 0 else ""


@register_module("database")
def check_database(os_info: OSInfo, config: dict) -> List[Finding]:
    findings: List[Finding] = []
    public_ports = set(int(p) for p in (config.get("database_public_ports") or [3306, 5432, 6379, 27017]))
    listeners = _listen_ports()
    mem_total = 0
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                mem_total = int(line.split()[1]) * 1024
                break
    except OSError:
        pass

    # MySQL / MariaDB
    mysql_svc = service_is_active("mariadb") or service_is_active("mysql") or service_is_active("mysqld")
    mysql_conf = _first_existing([
        "/etc/mysql/my.cnf",
        "/etc/my.cnf",
        "/etc/mysql/mysql.conf.d/mysqld.cnf",
        "/etc/mysql/mariadb.conf.d/50-server.cnf",
        "/etc/my.cnf.d/server.cnf",
    ])
    if which("mysql") or which("mysqld") or mysql_conf or mysql_svc:
        findings.append(
            Finding(
                id="database.mysql.present",
                module="database",
                severity=Severity.INFO,
                title="MySQL/MariaDB detected",
                detail=f"active={mysql_svc}",
                current="active" if mysql_svc else "installed",
                recommended="Bind to localhost or private network; require strong auth",
            )
        )
        bind = None
        if mysql_conf:
            text = read_text(mysql_conf)
            # also scan sibling conf.d
            texts = [text]
            for sibling in mysql_conf.parent.glob("**/*.cnf"):
                texts.append(read_text(sibling))
            combined = "\n".join(texts)
            m = re.search(r"^\s*bind-address\s*=\s*(\S+)", combined, re.I | re.M)
            if m:
                bind = m.group(1)
            slow = re.search(r"^\s*slow_query_log\s*=\s*(\S+)", combined, re.I | re.M)
            if not slow or slow.group(1) in {"0", "OFF", "off"}:
                findings.append(
                    Finding(
                        id="database.mysql.slow_query",
                        module="database",
                        severity=Severity.INFO,
                        title="MySQL slow query log not enabled",
                        detail="Useful for performance diagnostics on production DB hosts.",
                        current="off/unset",
                        recommended="slow_query_log=ON; long_query_time=1 or 2",
                    )
                )
            if mem_total:
                # innodb buffer pool recommendation ~50-70% RAM for dedicated DB
                rec = int(mem_total * 0.5)
                findings.append(
                    Finding(
                        id="database.mysql.buffer_pool_hint",
                        module="database",
                        severity=Severity.INFO,
                        title="InnoDB buffer pool sizing hint",
                        detail="For a dedicated DB server, ~50–70% of RAM is typical.",
                        current=f"system RAM {bytes_human(mem_total)}",
                        recommended=f"innodb_buffer_pool_size ≈ {bytes_human(rec)} (tune to workload)",
                    )
                )
        if bind in {None, "0.0.0.0", "*"} or (listeners and re.search(r":3306\b", listeners) and "127.0.0.1:3306" not in listeners):
            # Public bind risk
            exposed = bool(re.search(r"(0\.0\.0\.0|\[::\]|\*):3306\b", listeners or ""))
            if bind in {"0.0.0.0", "*"} or exposed:
                findings.append(
                    Finding(
                        id="database.mysql.bind",
                        module="database",
                        severity=Severity.CRITICAL,
                        title="MySQL/MariaDB may be listening publicly",
                        detail="Database ports exposed on all interfaces are high risk.",
                        current=f"bind-address={bind or 'unknown'}; check ss output",
                        recommended="bind-address=127.0.0.1 (or private IP) + firewall allowlist",
                    )
                )
        elif bind:
            findings.append(
                Finding(
                    id="database.mysql.bind",
                    module="database",
                    severity=Severity.INFO,
                    title="MySQL/MariaDB bind-address",
                    detail="Configured bind address.",
                    current=bind,
                    recommended="Prefer 127.0.0.1 unless remote app tier requires otherwise",
                )
            )

    # PostgreSQL
    pg_conf = _first_existing([
        "/var/lib/pgsql/data/postgresql.conf",
        "/var/lib/postgresql/*/main/postgresql.conf",
    ])
    # glob manually
    if not pg_conf:
        for p in Path("/etc/postgresql").glob("*/main/postgresql.conf"):
            pg_conf = p
            break
        if not pg_conf:
            for p in Path("/var/lib/pgsql").glob("*/data/postgresql.conf"):
                pg_conf = p
                break
    pg_active = service_is_active("postgresql") or service_is_active("postgresql-14") or service_is_active("postgresql-15")
    if which("psql") or pg_conf or pg_active:
        findings.append(
            Finding(
                id="database.postgres.present",
                module="database",
                severity=Severity.INFO,
                title="PostgreSQL detected",
                detail=f"active={pg_active}",
                current="active" if pg_active else "installed",
                recommended="Review listen_addresses and pg_hba.conf",
            )
        )
        if pg_conf:
            text = read_text(pg_conf)
            m = re.search(r"^\s*listen_addresses\s*=\s*'?([^'\n]+)'?", text, re.I | re.M)
            listen = m.group(1).strip() if m else "localhost (default)"
            if listen in {"*", "0.0.0.0"} or (listeners and re.search(r"(0\.0\.0\.0|\[::\]|\*):5432\b", listeners)):
                findings.append(
                    Finding(
                        id="database.postgres.listen",
                        module="database",
                        severity=Severity.CRITICAL,
                        title="PostgreSQL listening broadly",
                        detail="listen_addresses should be restricted on internet-facing hosts.",
                        current=listen,
                        recommended="listen_addresses = 'localhost' or private IP",
                    )
                )
            else:
                findings.append(
                    Finding(
                        id="database.postgres.listen",
                        module="database",
                        severity=Severity.INFO,
                        title="PostgreSQL listen_addresses",
                        detail="Configured listen addresses.",
                        current=listen,
                        recommended="Keep restricted; use SSL for remote clients",
                    )
                )

    # Redis
    redis_conf = _first_existing(["/etc/redis/redis.conf", "/etc/redis.conf"])
    redis_active = service_is_active("redis") or service_is_active("redis-server")
    if which("redis-server") or redis_conf or redis_active:
        findings.append(
            Finding(
                id="database.redis.present",
                module="database",
                severity=Severity.INFO,
                title="Redis detected",
                detail=f"active={redis_active}",
                current="active" if redis_active else "installed",
                recommended="Bind localhost; enable requirepass or ACL; disable dangerous commands",
            )
        )
        bind = "127.0.0.1"
        protected = None
        requirepass = False
        if redis_conf:
            text = read_text(redis_conf)
            m = re.search(r"^\s*bind\s+(.+)$", text, re.I | re.M)
            if m:
                bind = m.group(1).strip()
            m2 = re.search(r"^\s*protected-mode\s+(\w+)", text, re.I | re.M)
            if m2:
                protected = m2.group(1)
            if re.search(r"^\s*requirepass\s+\S+", text, re.I | re.M):
                requirepass = True
        exposed = bool(re.search(r"(0\.0\.0\.0|\[::\]|\*):6379\b", listeners or ""))
        if "0.0.0.0" in bind or exposed:
            findings.append(
                Finding(
                    id="database.redis.bind",
                    module="database",
                    severity=Severity.CRITICAL,
                    title="Redis may be publicly reachable",
                    detail="Unauthenticated public Redis is frequently compromised.",
                    current=f"bind={bind}; protected-mode={protected}",
                    recommended="bind 127.0.0.1 -::1",
                    remediation_id="redis_bind_localhost",
                )
            )
        if not requirepass and ("0.0.0.0" in bind or exposed or protected == "no"):
            findings.append(
                Finding(
                    id="database.redis.auth",
                    module="database",
                    severity=Severity.HIGH,
                    title="Redis authentication not detected",
                    detail="No requirepass found while Redis may be network-exposed.",
                    current="requirepass unset",
                    recommended="Set requirepass or Redis ACL users",
                )
            )

    # MongoDB
    mongo_conf = _first_existing(["/etc/mongod.conf", "/etc/mongodb.conf"])
    mongo_active = service_is_active("mongod") or service_is_active("mongodb")
    if which("mongod") or mongo_conf or mongo_active:
        findings.append(
            Finding(
                id="database.mongo.present",
                module="database",
                severity=Severity.INFO,
                title="MongoDB detected",
                detail=f"active={mongo_active}",
                current="active" if mongo_active else "installed",
                recommended="Enable authorization; bind to private interfaces",
            )
        )
        if mongo_conf:
            text = read_text(mongo_conf)
            if not re.search(r"authorization:\s*enabled", text, re.I):
                findings.append(
                    Finding(
                        id="database.mongo.auth",
                        module="database",
                        severity=Severity.HIGH,
                        title="MongoDB authorization may be disabled",
                        detail="security.authorization: enabled is recommended.",
                        current="not clearly enabled in mongod.conf",
                        recommended="security:\n  authorization: enabled",
                    )
                )
            if re.search(r"bindIp:\s*.*0\.0\.0\.0", text, re.I) or re.search(
                r"(0\.0\.0\.0|\[::\]|\*):27017\b", listeners or ""
            ):
                findings.append(
                    Finding(
                        id="database.mongo.bind",
                        module="database",
                        severity=Severity.CRITICAL,
                        title="MongoDB may listen on all interfaces",
                        detail="Public MongoDB instances are a common compromise vector.",
                        current="bindIp includes 0.0.0.0 or port 27017 public",
                        recommended="bindIp: 127.0.0.1 (or private IPs) + firewall",
                    )
                )

    # Generic: public DB ports from ss
    for port in public_ports:
        if re.search(rf"(0\.0\.0\.0|\[::\]|\*):{port}\b", listeners or ""):
            # Avoid duplicate if already flagged heavily — still useful as network signal
            findings.append(
                Finding(
                    id=f"database.port_public.{port}",
                    module="database",
                    severity=Severity.HIGH,
                    title=f"Database port {port} listening publicly",
                    detail="A common database port is bound on a non-loopback address.",
                    current=f"*:{port}",
                    recommended="Bind to localhost/private IP and restrict with firewall",
                )
            )

    if not any(f.id.endswith(".present") for f in findings) and not any(
        f.id.startswith("database.port_public") for f in findings
    ):
        findings.append(
            Finding(
                id="database.none",
                module="database",
                severity=Severity.INFO,
                title="No common database server detected",
                detail="MySQL/MariaDB, PostgreSQL, Redis, MongoDB not found.",
                current="none",
                recommended="n/a for this host role",
            )
        )

    return findings
