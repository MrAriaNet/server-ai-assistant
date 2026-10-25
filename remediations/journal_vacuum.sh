#!/usr/bin/env bash
set -euo pipefail
journalctl --vacuum-time=7d
journalctl --disk-usage
echo "OK: journal vacuumed to 7 days"
