#!/usr/bin/env bash
# Write SSH hardening drop-in. Idempotent.
set -euo pipefail

DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN="${DROPIN_DIR}/99-sai.conf"

if [[ ! -d "$DROPIN_DIR" ]]; then
  mkdir -p "$DROPIN_DIR"
fi

cat > "$DROPIN" <<'EOF'
# Managed by Server AI Assistant — do not edit casually
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
EOF

chmod 644 "$DROPIN"

# Validate config if possible
if command -v sshd >/dev/null 2>&1; then
  sshd -t
fi

# Prefer correct unit name
if systemctl list-unit-files | grep -q '^sshd\.service'; then
  echo "OK: wrote $DROPIN (restart sshd when ready)"
elif systemctl list-unit-files | grep -q '^ssh\.service'; then
  echo "OK: wrote $DROPIN (restart ssh when ready)"
else
  echo "OK: wrote $DROPIN"
fi
