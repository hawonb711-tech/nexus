#!/usr/bin/env bash
# Nexus Auto-Sync Hook — runs when session ends
# Syncs all new sessions to Obsidian automatically
set -euo pipefail

if [[ -z "${NEXUS_VAULT_PATH:-}" ]]; then
  echo "NEXUS_VAULT_PATH must name the Obsidian vault for auto-sync." >&2
  exit 2
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
NODE_BIN="${NODE_BIN:-node}"
LOG_PATH="${NEXUS_AUTO_SYNC_LOG:-${TMPDIR:-/tmp}/nexus-auto-sync.log}"

"$NODE_BIN" "$REPO_ROOT/dist/cli/index.js" sync \
  --vault "$NEXUS_VAULT_PATH" >"$LOG_PATH" 2>&1 &
