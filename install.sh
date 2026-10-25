#!/usr/bin/env bash
# Install Server AI Assistant system-wide
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash install.sh" >&2
  exit 1
fi

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="/opt/server-ai-assistant"

echo "==> Installing Server AI Assistant to ${DEST}"
mkdir -p "$DEST"
rsync -a --delete \
  --exclude '.venv' \
  --exclude '__pycache__' \
  --exclude 'data/*.json' \
  --exclude '.git' \
  "$SRC"/ "$DEST"/

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

python3 -m venv "$DEST/.venv"
# shellcheck disable=SC1091
source "$DEST/.venv/bin/activate"
pip install --upgrade pip
pip install -r "$DEST/requirements.txt"

chmod +x "$DEST/sai" "$DEST/sai.py"
find "$DEST/scripts" "$DEST/remediations" -type f -name '*.sh' -exec chmod +x {} \;

ln -sfn "$DEST/sai" /usr/local/bin/sai

mkdir -p /var/backups/sai /var/log/sai /var/cache/sai

echo
echo "Installed successfully."
echo "Try:  sai doctor"
echo "      sai audit"
echo "      sai harden --dry-run"
