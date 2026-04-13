#!/bin/bash
# Auto-Skill Generator — extracts skills from latest session using Claude CLI
# Runs as SessionEnd hook. Uses claude -p (headless) with only recent messages.

export PATH="/home/hawon/.local/share/fnm:$PATH"
eval "$(fnm env)" 2>/dev/null
fnm use lts-latest 2>/dev/null

SKILL_DIR="/mnt/c/Users/hawon/OneDrive/문서/Obsidian Vault/Knowledge/Skills"
CLAUDE_DIR="$HOME/.claude/projects"

# Find the most recently modified session JSONL
LATEST_SESSION=$(find "$CLAUDE_DIR" -name "*.jsonl" -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2)

if [ -z "$LATEST_SESSION" ]; then
  exit 0
fi

# Extract last 30 user+assistant messages (skip system/attachment noise)
RECENT=$(node -e "
const fs = require('fs');
const lines = fs.readFileSync('$LATEST_SESSION', 'utf-8').split('\n').filter(Boolean);
const msgs = [];
for (const line of lines) {
  try {
    const obj = JSON.parse(line);
    if (obj.type === 'user' && obj.message?.content) {
      const text = typeof obj.message.content === 'string' ? obj.message.content : '';
      if (text.length > 10 && !text.startsWith('<')) msgs.push('User: ' + text.slice(0, 200));
    }
    if (obj.type === 'assistant' && obj.message?.content) {
      const blocks = Array.isArray(obj.message.content) ? obj.message.content : [];
      const text = blocks.filter(b => b.type === 'text').map(b => b.text).join(' ');
      if (text.length > 20) msgs.push('Claude: ' + text.slice(0, 200));
    }
  } catch {}
}
// Take last 30 messages
const recent = msgs.slice(-30);
if (recent.length < 4) process.exit(0);
console.log(recent.join('\n'));
" 2>/dev/null)

if [ -z "$RECENT" ]; then
  exit 0
fi

# Use claude CLI to generate skill from recent context
echo "$RECENT" | claude -p "Based on this recent conversation summary, if there's a genuinely reusable technical pattern (not a one-off task), create a SKILL.md file in $SKILL_DIR/ with: frontmatter (name, description, tags), When to Use, Procedure with concrete commands, Pitfalls, Verification. If nothing reusable, just say 'No skill to extract.' and do nothing." --max-turns 1 2>/dev/null

# Also sync session to Obsidian
bash /home/hawon/claude-vault/scripts/auto-sync.sh 2>/dev/null &

exit 0
