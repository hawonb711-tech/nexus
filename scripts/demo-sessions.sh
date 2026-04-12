#!/bin/bash
# Screenshot 4: Session Intelligence + Sync
export PATH="/home/hawon/.local/share/fnm:$PATH"
eval "$(fnm env)" && fnm use lts-latest 2>/dev/null
NEXUS="node /home/hawon/claude-vault/dist/cli/index.js"

clear
echo ""
echo -e "\033[1m━━━ nexus — AI Session Intelligence ━━━\033[0m"
echo ""
echo -e "\033[36m$ nexus sessions\033[0m"
$NEXUS sessions 2>&1 | head -15
echo ""
echo -e "\033[36m$ nexus skills\033[0m"
$NEXUS skills 2>&1 | head -15
echo ""
echo -e "\033[36m$ nexus status --vault \"/mnt/c/Obsidian Vault\"\033[0m"
$NEXUS status --vault "/mnt/c/Obsidian Vault"
echo ""
