#!/usr/bin/env bash
# Install a daily systemd timer that runs: sai audit --severity high --json-file ...
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

SAI_BIN="$(command -v sai || true)"
if [[ -z "$SAI_BIN" ]]; then
  SAI_BIN="/usr/local/bin/sai"
fi
if [[ ! -x "$SAI_BIN" ]]; then
  echo "sai not found in PATH" >&2
  exit 1
fi

mkdir -p /var/log/sai /var/cache/sai

cat > /etc/systemd/system/sai-audit.service <<EOF
[Unit]
Description=Server AI Assistant daily audit
After=network-online.target

[Service]
Type=oneshot
ExecStart=${SAI_BIN} audit --severity high --json-file /var/cache/sai/daily.json --md /var/cache/sai/daily.md
Nice=10
EOF

cat > /etc/systemd/system/sai-audit.timer <<'EOF'
[Unit]
Description=Daily Server AI Assistant audit timer

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=30m

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now sai-audit.timer
systemctl list-timers sai-audit.timer --no-pager
echo "OK: sai-audit.timer installed"
