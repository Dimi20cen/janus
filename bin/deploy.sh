#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/srv/stacks/janus"
LOCK_DIR="/tmp/janus-deploy.lock"

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "Deploy already running. Exiting."
  exit 0
fi
trap 'rmdir "$LOCK_DIR"' EXIT

cd "$REPO_DIR"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting Janus deploy..."
/usr/bin/git pull --ff-only
/usr/bin/docker compose up -d --build
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Janus deploy complete."
