#!/usr/bin/env bash
set -euo pipefail
if ! command -v logrotate >/dev/null 2>&1; then
  echo "logrotate not installed" >&2
  exit 1
fi
logrotate -f /etc/logrotate.conf
echo "OK: logrotate -f completed"
