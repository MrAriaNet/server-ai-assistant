#!/usr/bin/env bash
# Print systemd status for a list of service names
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <service> [service...]" >&2
  exit 2
fi

for svc in "$@"; do
  if systemctl status "$svc" --no-pager >/dev/null 2>&1; then
    state=$(systemctl is-active "$svc" 2>/dev/null || echo unknown)
    enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo unknown)
    echo "${svc}: active=${state} enabled=${enabled}"
  else
    echo "${svc}: not-found"
  fi
done
