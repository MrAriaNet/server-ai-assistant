#!/usr/bin/env bash
# Set ServerTokens Prod / ServerSignature Off for Apache
set -euo pipefail

applied=0

if [[ -d /etc/apache2 ]]; then
  mkdir -p /etc/apache2/conf-available
  CONF="/etc/apache2/conf-available/sai-security.conf"
  cat > "$CONF" <<'EOF'
# Managed by Server AI Assistant
ServerTokens Prod
ServerSignature Off
EOF
  if command -v a2enconf >/dev/null 2>&1; then
    a2enconf sai-security >/dev/null
  fi
  if command -v apache2ctl >/dev/null 2>&1; then
    apache2ctl configtest
  fi
  echo "OK: Debian/Ubuntu Apache drop-in $CONF"
  applied=1
fi

if [[ -d /etc/httpd ]]; then
  mkdir -p /etc/httpd/conf.d
  CONF="/etc/httpd/conf.d/sai-security.conf"
  cat > "$CONF" <<'EOF'
# Managed by Server AI Assistant
ServerTokens Prod
ServerSignature Off
EOF
  if command -v httpd >/dev/null 2>&1; then
    httpd -t
  fi
  echo "OK: RHEL-like Apache drop-in $CONF"
  applied=1
fi

if [[ "$applied" -eq 0 ]]; then
  echo "Apache configuration directories not found" >&2
  exit 1
fi

echo "Restart apache2 or httpd when ready"
