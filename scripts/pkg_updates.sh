#!/usr/bin/env bash
# Probe pending package updates. Arg1: apt|dnf|yum|unknown
set -euo pipefail

PM="${1:-unknown}"
PENDING=0
SECURITY=0

case "$PM" in
  apt)
    # Refresh quietly; ignore failures (offline mirrors)
    apt-get update -qq >/dev/null 2>&1 || true
    # Simulate upgrade
    sim=$(apt-get -s upgrade 2>/dev/null || true)
    PENDING=$(printf '%s\n' "$sim" | grep -c '^Inst ' || true)
    SECURITY=$(printf '%s\n' "$sim" | grep -ci 'security' || true)
    printf '%s\n' "$sim" | grep '^Inst ' | head -n 25 || true
    ;;
  dnf)
    # check-update returns 100 when updates exist
    set +e
    out=$(dnf -q check-update 2>/dev/null)
    rc=$?
    set -e
    if [[ $rc -eq 100 || $rc -eq 0 ]]; then
      PENDING=$(printf '%s\n' "$out" | awk 'NF && $1 !~ /^Last/ && $1 !~ /^$/ {c++} END{print c+0}')
      SECURITY=$(printf '%s\n' "$out" | grep -ci 'security' || true)
      printf '%s\n' "$out" | awk 'NF && $1 !~ /^Last/' | head -n 25 || true
    fi
    # Security plugin if available
    if command -v dnf >/dev/null 2>&1; then
      set +e
      sec_out=$(dnf -q updateinfo list security 2>/dev/null)
      set -e
      if [[ -n "${sec_out:-}" ]]; then
        sec_count=$(printf '%s\n' "$sec_out" | awk 'NF && $1 !~ /^Last/ {c++} END{print c+0}')
        if [[ "${sec_count:-0}" -gt 0 ]]; then
          SECURITY=$sec_count
        fi
      fi
    fi
    ;;
  yum)
    set +e
    out=$(yum -q check-update 2>/dev/null)
    rc=$?
    set -e
    if [[ $rc -eq 100 || $rc -eq 0 ]]; then
      PENDING=$(printf '%s\n' "$out" | awk 'NF && $1 !~ /^Loaded/ && $1 !~ /^$/ {c++} END{print c+0}')
      printf '%s\n' "$out" | head -n 25 || true
    fi
    ;;
  *)
    echo "Unsupported or unknown package manager: $PM" >&2
    echo "PENDING=0"
    echo "SECURITY=0"
    exit 0
    ;;
esac

echo "PENDING=${PENDING:-0}"
echo "SECURITY=${SECURITY:-0}"
