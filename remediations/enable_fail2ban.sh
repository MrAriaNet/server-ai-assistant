#!/usr/bin/env bash
# Enable and start fail2ban if installed
set -euo pipefail

if ! command -v fail2ban-client >/dev/null 2>&1 && [[ ! -d /etc/fail2ban ]]; then
  echo "fail2ban is not installed. Install it first (apt/dnf)." >&2
  exit 1
fi

systemctl enable fail2ban
systemctl start fail2ban
systemctl is-active fail2ban
echo "OK: fail2ban enabled and started"
