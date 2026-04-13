#!/bin/bash
# Nexus Auto-Sync Hook — runs when session ends
# Syncs all new sessions to Obsidian automatically

export PATH="/home/hawon/.local/share/fnm:$PATH"
eval "$(fnm env)" 2>/dev/null
fnm use lts-latest 2>/dev/null

node /home/hawon/claude-vault/dist/cli/index.js sync --vault "/mnt/c/Obsidian Vault" > /tmp/nexus-auto-sync.log 2>&1 &

exit 0
