#!/usr/bin/env bash
set -euo pipefail
chmod 1777 /tmp
ls -ld /tmp
echo "OK: /tmp sticky bit set (1777)"
