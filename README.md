# claude-vault

Never lose what you learned with Claude. Auto-export all Claude Code sessions to Obsidian with skill extraction.

## What it does

1. **Discovers** all your Claude Code sessions from `~/.claude/`
2. **Parses** conversations, tool calls, file modifications, and topics
3. **Exports** to Obsidian as structured markdown with frontmatter and backlinks
4. **Extracts skills** — reusable patterns from successful interactions
5. **Updates** Map of Content (MOC) and Daily Notes automatically

## Install

```bash
npm install -g @hawon/claude-vault
```

## Quick Start

```bash
# Sync all sessions to Obsidian
claude-vault sync

# Sync to a specific vault
claude-vault sync --vault ~/MyVault

# List all sessions
claude-vault sessions

# Export a single session
claude-vault export abc-123-def

# View extracted skills
claude-vault skills

# Search skills
claude-vault skills search "fix lint"

# Check vault status
claude-vault status
```

## What gets created in Obsidian

### Session Notes

Each Claude Code session becomes a markdown file:

```markdown
---
session_id: "32fbf3ed-829b-4540"
date: "2026-04-12"
project: "/home/user/myproject"
branch: "main"
tools_used: ["Edit", "Bash", "Read"]
files_modified: ["src/app.ts"]
topics: ["security", "refactoring"]
tags: [claude/session]
---

# Session: Fix authentication vulnerability

> **Project**: `myproject` | **Branch**: `main`
> **Duration**: 45 min | **Messages**: 24 | **Tools**: 8

## Conversation

### User
Can you review the auth middleware for security issues?

### Claude
I found a SQL injection vulnerability in...

#### Tool: Edit `src/auth.ts`
...
```

### Skill Notes

Reusable patterns extracted from sessions:

```markdown
---
type: skill
name: "fix lint errors"
tools: ["Bash", "Edit"]
confidence: 0.85
tags: [claude/skill]
---

# Skill: Fix Lint Errors

## Steps
1. Run `npx eslint . --fix`
2. Fix remaining manual issues
3. Verify with `npx eslint .`
```

### Map of Content (MOC)

Auto-generated index organized by date, project, and topic with Obsidian wikilinks.

### Daily Notes

Each day's Claude sessions appended to your daily note.

## Folder Structure Options

```bash
# By date (default)
Claude Sessions/2026/04/2026-04-12 Session Title.md

# By project
Claude Sessions/myproject/2026-04-12 Session Title.md

# Flat
Claude Sessions/2026-04-12 Session Title.md
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAUDE_VAULT_PATH` | `~/ObsidianVault/Claude` | Obsidian vault path |
| `CLAUDE_DIR` | `~/.claude` | Claude Code data directory |

## How skill extraction works

1. Finds task-completion sequences in conversations (user request → Claude tool usage → completion)
2. Extracts action name, steps, tools used, and files involved
3. Generalizes file paths to glob patterns
4. Deduplicates similar skills (Jaccard similarity > 0.8)
5. Scores confidence based on tool count, variety, and file involvement
6. Exports as Obsidian-compatible markdown with frontmatter

## License

MIT
