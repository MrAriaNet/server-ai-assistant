#!/usr/bin/env bash
# Ensure Redis bind directive prefers localhost
set -euo pipefail

CONF=""
for candidate in /etc/redis/redis.conf /etc/redis.conf; do
  if [[ -f "$candidate" ]]; then
    CONF="$candidate"
    break
  fi
done

if [[ -z "$CONF" ]]; then
  echo "redis.conf not found" >&2
  exit 1
fi

# Comment existing bind lines and append secure bind
sed -i.bak-sai -E 's/^\s*bind\s+/# bind /' "$CONF"
if ! grep -qE '^\s*bind\s+127\.0\.0\.1' "$CONF"; then
  printf '\n# Managed by Server AI Assistant\nbind 127.0.0.1 -::1\n' >> "$CONF"
fi
# Ensure protected-mode on
if grep -qE '^\s*protected-mode\s+' "$CONF"; then
  sed -i -E 's/^\s*protected-mode\s+.*/protected-mode yes/' "$CONF"
else
  printf 'protected-mode yes\n' >> "$CONF"
fi

echo "OK: updated $CONF (restart redis/redis-server when ready)"
