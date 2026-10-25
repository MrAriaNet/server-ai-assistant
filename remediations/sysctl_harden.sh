#!/usr/bin/env bash
# Network hardening sysctl drop-in
set -euo pipefail

DROPIN="/etc/sysctl.d/99-sai.conf"
mkdir -p /etc/sysctl.d

cat > "$DROPIN" <<'EOF'
# Managed by Server AI Assistant
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF

sysctl --system >/dev/null 2>&1 || sysctl -p "$DROPIN"
echo "OK: wrote and applied $DROPIN"
