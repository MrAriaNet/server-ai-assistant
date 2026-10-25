#!/usr/bin/env bash
# Enable firewalld and allow common services.
set -euo pipefail

if ! command -v firewall-cmd >/dev/null 2>&1; then
  echo "firewalld not installed" >&2
  exit 1
fi

systemctl enable --now firewalld
firewall-cmd --permanent --add-service=ssh || true
firewall-cmd --permanent --add-service=http || true
firewall-cmd --permanent --add-service=https || true
firewall-cmd --reload
firewall-cmd --list-all
echo "OK: firewalld baseline applied"
