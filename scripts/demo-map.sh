#!/bin/bash
# Screenshot 3: Codebase Mapping + Architecture
export PATH="/home/hawon/.local/share/fnm:$PATH"
eval "$(fnm env)" && fnm use lts-latest 2>/dev/null
NEXUS="node /home/hawon/claude-vault/dist/cli/index.js"

clear
echo ""
echo -e "\033[1m━━━ nexus — Codebase Architecture ━━━\033[0m"
echo ""
echo -e "\033[36m$ nexus map .\033[0m"
$NEXUS map .
echo ""
echo -e "\033[36m$ nexus test-health .\033[0m"
$NEXUS test-health .
echo ""
echo -e "\033[36m$ nexus config .\033[0m"
$NEXUS config .
echo ""
