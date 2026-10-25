#!/usr/bin/env bash
# Apply pending package updates (apt or dnf/yum)
set -euo pipefail

if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
fi

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get upgrade -y
  echo "OK: apt upgrade completed"
  exit 0
fi

if command -v dnf >/dev/null 2>&1; then
  dnf -y upgrade
  echo "OK: dnf upgrade completed"
  exit 0
fi

if command -v yum >/dev/null 2>&1; then
  yum -y update
  echo "OK: yum update completed"
  exit 0
fi

echo "No supported package manager found" >&2
exit 1
