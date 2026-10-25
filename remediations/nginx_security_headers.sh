#!/usr/bin/env bash
# Disable nginx server_tokens via conf.d drop-in
set -euo pipefail

if [[ ! -d /etc/nginx ]]; then
  echo "nginx not installed" >&2
  exit 1
fi

mkdir -p /etc/nginx/conf.d
DROPIN="/etc/nginx/conf.d/00-sai-security.conf"
cat > "$DROPIN" <<'EOF'
# Managed by Server AI Assistant
server_tokens off;
EOF

nginx -t
echo "OK: wrote $DROPIN (reload/restart nginx when ready)"
