<p align="center">
  <img src="https://img.shields.io/badge/Server%20AI%20Assistant-v1.2.0-0ea5e9?style=for-the-badge&labelColor=0f172a" alt="Server AI Assistant" />
</p>

<h1 align="center">Server AI Assistant</h1>

<p align="center">
  <strong>Rule-based CLI auditor & hardener for production Linux servers</strong><br/>
  Find misconfigurations. Get clear recommendations. Fix only what you approve.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square" alt="Python" />
  <img src="https://img.shields.io/badge/ubuntu-supported-E95420?style=flat-square&logo=ubuntu&logoColor=white" alt="Ubuntu" />
  <img src="https://img.shields.io/badge/almalinux-supported-0F7B3A?style=flat-square" alt="AlmaLinux" />
  <img src="https://img.shields.io/badge/rocky-supported-10B981?style=flat-square" alt="Rocky Linux" />
  <img src="https://img.shields.io/badge/LLM-not%20required-64748b?style=flat-square" alt="No LLM" />
  <img src="https://img.shields.io/badge/license-MIT-22c55e?style=flat-square" alt="License" />
</p>

<p align="center">
  <a href="#-why-sai"><strong>Why SAI</strong></a> ·
  <a href="#-features"><strong>Features</strong></a> ·
  <a href="#-quick-start"><strong>Quick Start</strong></a> ·
  <a href="#-commands"><strong>Commands</strong></a> ·
  <a href="#-modules"><strong>Modules</strong></a> ·
  <a href="#-safety-model"><strong>Safety</strong></a>
</p>

---

## What is this?

**Server AI Assistant (`sai`)** is a production-grade, **fully offline**, rule-based toolkit written in **Python + Bash**.  
It audits real server posture — security, packages, TLS, web stacks, databases, storage, backups — then proposes concrete config changes and applies them **only after you type `APPLY`**.

No OpenAI key. No telemetry. No silent changes. Built for **sysadmins, hosting teams, and ops engineers**.

```text
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Discover OS │ →  │ Run modules  │ →  │ Rank findings│ →  │ Confirm fix  │
│  + services  │    │ rule engines │    │ + reports    │    │ + backup     │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

---

## Why SAI?

| Pain | What SAI does |
|------|----------------|
| “Is this VPS actually hardened?” | Audits SSH, firewall, fail2ban, sysctl, SELinux/AppArmor, auditd |
| “Will TLS blow up next week?” | Checks cert expiry + Let’s Encrypt renew timers |
| “Did someone leave Redis on `0.0.0.0`?” | Flags public DB/cache listeners and bad binds |
| “What changed since Monday?” | `baseline save` / `baseline diff` drift tracking |
| “Don’t touch prod without approval” | Interactive remediations, backups, restore, dry-run |
| “How do I cover a whole fleet?” | `sai fleet audit` over SSH + Ansible inventory export |
| “Map this to CIS?” | `sai cis` control mapping for findings |
| “Page me on critical?” | Slack / webhook alerts |

---

## Features

- **16 audit modules** — system, updates, security, users, SSL, web, database, mail, network, containers, hosting panels, logs, storage, services, backups, proxy
- **Profiles** — `quick`, `security`, `webstack`, `hosting`, `cis` for focused runs
- **CIS mapping** — map findings to CIS-style control IDs (`sai cis`)
- **Fleet mode** — multi-host SSH audits with aggregated results
- **Ansible export** — YAML/INI inventory from local host or fleet (+ issue groups)
- **Alerts** — Slack incoming webhooks + generic JSON webhooks
- **Actionable findings** — severity · current value · recommended config · optional remediation id
- **Safe remediations** — type `APPLY` · auto backup under `/var/backups/sai/` · optional service restart confirm · full action log
- **Restore** — roll back SAI-touched configs with `sai restore`
- **Inventory** — CMDB-style host facts dump
- **Schedule** — install a daily `systemd` timer for unattended audits
- **Reports** — Rich terminal UI · JSON · HTML · Markdown
- **Offline-first** — audits run locally; alerts are optional

---

## Quick Start

### One-liner install

```bash
sudo bash install.sh
```

### First run

```bash
sai doctor                 # OS + deps self-check
sudo sai audit             # full audit
sudo sai audit -p hosting  # hosting-focused profile
sudo sai critical          # show only critical/high
```

### Manual install

```bash
git clone https://github.com/YOUR_USER/server-ai-assistant.git
cd server-ai-assistant
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
chmod +x sai scripts/*.sh remediations/*.sh
sudo ./sai audit
```

> **Tip:** run as **root** for complete results and remediations. Non-root still works for many read-only checks.

---

## Demo

```bash
$ sudo sai audit --profile security

┌──────────────────────────────────────────────────────────┐
│ Server AI Assistant — audit report                       │
│ Host: web-01   OS: Ubuntu 22.04.5 LTS                    │
│ Modules: security, users, ssl, network                   │
└──────────────────────────────────────────────────────────┘

  Severity   Count
  CRITICAL       1
  HIGH           3
  MEDIUM         2
  LOW            1
  INFO           8

  Sev       Module     Title                          Fix
  HIGH      security   SSH PasswordAuthentication     ssh_harden
  HIGH      security   UFW firewall inactive          ufw_baseline
  CRITICAL  ssl        Certificate expires in 4 days  —
  ...
```

```bash
$ sudo sai harden --dry-run
# Preview remediations without changing anything

$ sudo sai fix --severity high
# Walk each fix — type APPLY to proceed
```

---

## Commands

| Command | Purpose |
|---------|---------|
| `sai doctor` | Self-check: OS support, root, dependencies |
| `sai status` | Fast system health snapshot |
| `sai audit` | Full audit (all modules) |
| `sai audit -p <profile>` | Profile-scoped audit |
| `sai critical` | Full audit; print critical/high only |
| `sai check <module>` | Single module |
| `sai report` | Re-render last cached result |
| `sai fix` | Interactive remediations |
| `sai harden` | Security baseline + confirm |
| `sai updates [--apply]` | Package update status / apply |
| `sai inventory` | Host facts snapshot |
| `sai ansible` | Export Ansible inventory (local or fleet) |
| `sai cis` | CIS-oriented audit + control mapping |
| `sai fleet audit -f <file>` | Multi-host SSH fleet audit |
| `sai alert` | Slack / webhook notify from cache or fresh audit |
| `sai baseline save\|diff\|show` | Drift tracking |
| `sai restore [--list]` | List / restore config backups |
| `sai schedule` | Install daily audit timer |
| `sai modules` | List modules + profiles |

### Useful flags

```bash
sudo sai audit -m security,web,database,ssl
sudo sai audit -p webstack --html /tmp/sai.html --md /tmp/sai.md
sudo sai audit --json-file /tmp/sai.json --severity high
sudo sai audit --cis --notify
sudo sai audit --slack-webhook https://hooks.slack.com/services/...
sudo sai harden --dry-run
sudo sai fix --severity high
sudo sai inventory --json-file /tmp/inventory.json
sudo sai baseline save --name monday
sudo sai baseline diff --name monday
```

---

## Ansible inventory export

```bash
# Local host → YAML inventory (stdout)
sai ansible

# Write INI for Ansible
sai ansible -o /etc/ansible/hosts-sai.ini --format ini

# From a fleet file (groups preserved)
sai ansible -f config/fleet.example.yaml -o inventory.yml
```

Fleet audits can also emit inventory with dynamic groups `sai_ok`, `sai_issues`, `sai_unreachable`:

```bash
sai fleet audit -f /etc/sai/fleet.yaml --ansible-out /tmp/sai-fleet-inventory.yml
```

---

## CIS mapping

Findings are mapped to illustrative CIS-style control IDs via [`config/cis_mapping.yaml`](config/cis_mapping.yaml).

```bash
sudo sai cis
sudo sai audit --cis -p security
sudo sai cis --from-cache
```

---

## Fleet mode (SSH)

Requires **key-based SSH** (`BatchMode`) and **`sai` installed on each remote host**.

```bash
# Edit example → real hosts
cp config/fleet.example.yaml /etc/sai/fleet.yaml

sai fleet audit -f /etc/sai/fleet.yaml \
  --profile security \
  --parallel 8 \
  --out-dir /var/cache/sai/fleet \
  --ansible-out /tmp/fleet-inventory.yml \
  --notify
```

Simple `hosts.txt` also works:

```text
root@10.0.0.11
root@10.0.0.21:22
```

---

## Alerts (Slack / webhook)

Configure in [`config/defaults.yaml`](config/defaults.yaml):

```yaml
alerts:
  enabled: true
  min_severity: high
  slack_webhook_url: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
  webhook_url: "https://example.com/hooks/sai"
```

Or one-shot:

```bash
sudo sai critical --slack-webhook "$SLACK_WEBHOOK"
sudo sai alert --webhook https://example.com/hooks/sai --severity critical
```

---

## Modules

| Module | Checks |
|--------|--------|
| `system` | Load, RAM, disk/inodes, swap, failed units, time sync, zombies, kernel I/O |
| `updates` | Pending / security updates, reboot-required, auto-update agents |
| `security` | SSH, firewall, fail2ban, sysctl, SELinux / AppArmor, auditd |
| `users` | Extra UID 0, sudo/wheel, NOPASSWD, failed logins, `.ssh` perms |
| `ssl` | Cert expiry, Let’s Encrypt renew, local `:443` probe |
| `web` | Nginx / Apache / PHP-FPM tokens, weak TLS, `nginx -t` / `apachectl` |
| `database` | MySQL/MariaDB, PostgreSQL, Redis, MongoDB bind & auth signals |
| `mail` | Postfix / Dovecot exposure |
| `network` | Public risky ports, DNS, IP forwarding |
| `containers` | Docker / Podman, privileged & host-network containers |
| `hosting` | cPanel, Plesk, DirectAdmin, Hestia, aaPanel, … |
| `logs` | Journal errors, OOM, huge logs, logrotate |
| `storage` | `/tmp` sticky bit, mdadm RAID, SMART, RO mounts |
| `services` | Failed units, enabled-but-down, cron, timers |
| `backups` | Backup tools / path freshness / cron & timers |
| `proxy` | HAProxy, Varnish, Keepalived |

### Profiles

| Profile | Modules |
|---------|---------|
| `quick` | system · updates · security · services |
| `security` | security · users · ssl · network |
| `webstack` | web · ssl · database · proxy · logs |
| `hosting` | hosting · web · database · ssl · backups · users · security |
| `cis` | security · users · updates · network · storage · ssl · services |

---

## Safety model

SAI will **never** silently rewrite production configs.

1. Show finding + recommended change + script name  
2. You type **`APPLY`** (or pass `--yes` intentionally)  
3. Files are copied to `/var/backups/sai/<timestamp>/`  
4. Small drop-in remediation runs (not blind full-file overwrites)  
5. Service restart asks for a **second** confirmation  
6. Every action is appended to `/var/log/sai/actions.log`  
7. Roll back with:

```bash
sudo sai restore --list
sudo sai restore --session 20261025T183012Z_files
```

`--dry-run` prints the plan without touching the system.

---

## Supported platforms

| Distro | Status |
|--------|--------|
| Ubuntu | First-class |
| AlmaLinux | First-class |
| Rocky Linux | First-class |
| Other Debian / RHEL-like | Best-effort |

**Needs:** Python 3.8+, `bash`, `systemctl`, root for full power.

---

## Project layout

```text
sai.py / sai              CLI entrypoint
core/                     runner, report, confirm, backup, inventory, baseline,
                          ansible_export, cis, fleet, alerts
modules/                  One package per audit domain
scripts/                  Bash fact collectors
remediations/             Idempotent apply scripts (confirm required)
config/defaults.yaml      Thresholds, modules, profiles, alerts
config/cis_mapping.yaml   CIS control mappings
config/fleet.example.yaml Example multi-host fleet
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean / below severity threshold |
| `1` | Findings at or above threshold (default: `high`) |
| `2` | Tool error / unsupported OS / fleet unreachable |

Perfect for CI / cron / monitoring wrappers.

PRs and real-world check ideas are welcome.

---

## Contributing

1. Fork & clone  
2. Keep findings **English**, severities honest, remediations **idempotent**  
3. Prefer drop-in configs under `/etc/*/…d/` over rewriting vendor files  
4. Test on Ubuntu **and** Alma/Rocky paths when touching package/firewall logic  

---

## Disclaimer

This tool helps operators. **You** are responsible for changes on production hosts.  
Always review remediations, maintain backups, and test in staging when possible.

---

## License

Released under the [MIT License](LICENSE).

---

<p align="center">
  <sub>Built for people who keep servers alive at 3 AM.</sub>
</p>
