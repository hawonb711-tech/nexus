#!/usr/bin/env bash
# Screenshot 4: Session Intelligence + Sync
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
NODE_BIN="${NODE_BIN:-node}"
NEXUS=("$NODE_BIN" "$REPO_ROOT/dist/cli/index.js")

clear 2>/dev/null || true
echo ""
echo -e "\033[1m━━━ nexus — AI Session Intelligence ━━━\033[0m"
echo ""
echo -e "\033[36m$ nexus sessions\033[0m"
"${NEXUS[@]}" sessions 2>&1 | head -15
echo ""
echo -e "\033[36m$ nexus skills\033[0m"
"${NEXUS[@]}" skills 2>&1 | head -15
echo ""
echo -e "\033[36m$ nexus status\033[0m"
"${NEXUS[@]}" status
echo ""
