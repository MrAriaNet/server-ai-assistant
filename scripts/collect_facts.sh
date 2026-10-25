#!/usr/bin/env bash
# Collect concise system facts for Server AI Assistant
set -euo pipefail

echo "HOSTNAME=$(hostname 2>/dev/null || echo unknown)"
echo "UPTIME=$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo unknown)"
echo "KERNEL=$(uname -r 2>/dev/null || echo unknown)"
if [[ -r /proc/meminfo ]]; then
  awk '/MemTotal|MemAvailable|SwapTotal/{printf "%s ", $0}' /proc/meminfo
  echo
fi
if command -v nproc >/dev/null 2>&1; then
  echo "CPUS=$(nproc)"
fi
df -h -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | head -n 8 || true
