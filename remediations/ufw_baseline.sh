#!/usr/bin/env bash
# Enable UFW with a conservative baseline (SSH/HTTP/HTTPS).
set -euo pipefail

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not installed" >&2
  exit 1
fi

ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH 2>/dev/null || ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
# Non-interactive enable
ufw --force enable
ufw status verbose
echo "OK: UFW baseline applied"
