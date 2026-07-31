#!/usr/bin/env bash
# Compatibility wrapper for older manual hook configurations.
# Prefer `nexus guard install`, which writes the tested absolute hook command.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
NODE_BIN="${NODE_BIN:-node}"

exec "$NODE_BIN" "$REPO_ROOT/dist/cli/index.js" guard check
