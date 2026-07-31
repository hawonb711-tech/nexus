#!/usr/bin/env bash
# Screenshot 3: Codebase Mapping + Architecture
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
NODE_BIN="${NODE_BIN:-node}"
NEXUS=("$NODE_BIN" "$REPO_ROOT/dist/cli/index.js")

clear 2>/dev/null || true
echo ""
echo -e "\033[1m━━━ nexus — Codebase Architecture ━━━\033[0m"
echo ""
echo -e "\033[36m$ nexus map .\033[0m"
"${NEXUS[@]}" map "$REPO_ROOT"
echo ""
echo -e "\033[36m$ nexus test-health .\033[0m"
"${NEXUS[@]}" test-health "$REPO_ROOT"
echo ""
echo -e "\033[36m$ nexus config .\033[0m"
"${NEXUS[@]}" config "$REPO_ROOT"
echo ""
