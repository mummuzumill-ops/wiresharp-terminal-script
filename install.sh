#!/usr/bin/env bash
# Vite Shop Terminal Script — one-line installer for the NetScope capture agent.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/mummuzumill-ops/wiresharp-terminal-script/main/install.sh | sudo bash -s -- --room NET-XXXXX-XXXXX
#
# Clones the agent, then runs it. Everything the agent needs is in the repo.
set -euo pipefail

REPO_URL="${NETSCOPE_REPO_URL:-https://github.com/mummuzumill-ops/wiresharp-terminal-script.git}"
WORK_DIR="${NETSCOPE_DIR:-$HOME/.wiresharp-terminal-script}"

if [ "$(id -u)" -ne 0 ]; then
  echo "This script needs root to capture packets. Re-run with: sudo bash $0 $*" >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git is required. Install it first (apt install git / yum install git / brew install git)." >&2
  exit 1
fi

PY_BIN="python3"
command -v "$PY_BIN" >/dev/null 2>&1 || PY_BIN="python"
command -v "$PY_BIN" >/dev/null 2>&1 || { echo "python3 is required but was not found." >&2; exit 1; }

echo "==> Fetching the capture agent into $WORK_DIR"
if [ -d "$WORK_DIR/.git" ]; then
  git -C "$WORK_DIR" pull --ff-only --quiet || true
else
  mkdir -p "$(dirname "$WORK_DIR")"
  git clone --depth 1 --quiet "$REPO_URL" "$WORK_DIR"
fi

cd "$WORK_DIR"
chmod +x capture_agent.py 2>/dev/null || true

echo "==> Starting capture_agent.py $*"
exec "$PY_BIN" capture_agent.py "$@"
