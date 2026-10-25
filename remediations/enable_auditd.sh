#!/usr/bin/env bash
set -euo pipefail
if ! command -v auditctl >/dev/null 2>&1 && [[ ! -d /etc/audit ]]; then
  echo "auditd not installed" >&2
  exit 1
fi
systemctl enable auditd
systemctl start auditd
systemctl is-active auditd
echo "OK: auditd enabled"
