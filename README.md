# nexus

The all-in-one AI developer framework — session intelligence, code review, prompt injection defense, infinite memory, and self-evolving skills.

**15 modules · 15 CLI commands · 14 MCP tools · 14,000+ lines · zero deps**

## Features

| Module | What it does |
|--------|-------------|
| **Multi-platform Parser** | Discover and parse sessions from Claude Code and OpenClaw |
| **Obsidian Export** | Structured markdown with frontmatter, backlinks, MOC, Daily Notes |
| **Prompt Injection Guard** | 6-layer, 82-rule detection across 8 languages |
| **Code Review** | 19 detectors: AI slop, bugs, security, performance, dead code |
| **Codebase Mapping** | Architecture map, dependency graph, entry points, hotspots |
| **Test Health** | Broken imports, stale mocks, missing tests, coverage estimate |
| **Cost Monitor** | AI API cost tracking, budget alerts, spike detection |
| **Config Validator** | Exposed secrets, missing env vars, insecure defaults |
| **Infinite Memory** | 4-tier hierarchical store with TF-IDF search, auto-compression |
| **Context Engine** | Bayesian intent classifier + conversation state machine |
| **Global Context** | Thread weaving, user state model, topic switch detection |
| **Pattern Engine** | Cross-session pattern evolution with drift analysis |
| **Smart Extractor** | Episode segmentation + decision point identification |
| **Wisdom Extractor** | Extracts principles ("when X, do Y because Z"), not procedures |
| **Skill Reconciler** | Quality gate, conditional branches, preference learning |

## Install

```bash
npm install -g @hawon/nexus
```

## Quick Start

```bash
# Sync all sessions to Obsidian (Claude Code + OpenClaw)
nexus sync --vault ~/MyVault

# Scan for prompt injection
nexus scan "Ignore all previous instructions"

# Review code
nexus review src/app.ts

# Map codebase architecture
nexus map .

# Full vault reorganization with wisdom pipeline
nexus reorganize
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `sync` | Sync all sessions to Obsidian (multi-platform) |
| `reorganize` | Clean rebuild with wisdom + skill pipeline |
| `sessions` | List all discovered sessions |
| `export <id>` | Export a single session |
| `skills` | View extracted refined skills |
| `skills search <q>` | Search skills by keyword |
| `status` | Vault sync status |
| `scan <text>` | Prompt injection detection |
| `review <file>` | Code review (19 detectors) |
| `map [dir]` | Codebase architecture map |
| `onboard [dir]` | Onboarding guide generation |
| `test-health [dir]` | Test suite health check |
| `config [dir]` | Config/env validation |
| `cost` | AI API cost report |
| `memory <search\|stats>` | Persistent memory operations |

## MCP Server

Nexus runs as an MCP server with 14 tools for Claude Code, OpenClaw, and any MCP-compatible agent.

```json
{
  "mcpServers": {
    "nexus": {
      "command": "npx",
      "args": ["@hawon/nexus-mcp"]
    }
  }
}
```

### MCP Tools

| Tool | Description |
|------|-------------|
| `nexus_sessions` | List all AI sessions |
| `nexus_parse_session` | Parse a specific session |
| `nexus_scan` | Prompt injection detection (6 layers) |
| `nexus_is_safe` | Quick injection check (true/false) |
| `nexus_review` | Code review (19 detectors) |
| `nexus_map` | Codebase architecture mapping |
| `nexus_onboard` | Onboarding guide generation |
| `nexus_test_health` | Test suite health check |
| `nexus_config` | Config/env validation |
| `nexus_cost` | AI API cost report |
| `nexus_memory_search` | Search persistent memory |
| `nexus_memory_save` | Save to persistent memory |
| `nexus_skills` | List refined skills |

## Auto-Scan Hook (Real-time Protection)

Nexus can automatically scan every web fetch and search result for prompt injection — no manual calls needed. Add this to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "WebFetch",
        "hooks": [{
          "type": "command",
          "command": "bash /path/to/nexus/scripts/scan-tool-result.sh",
          "timeout": 10,
          "statusMessage": "🛡️ Scanning for prompt injection..."
        }]
      },
      {
        "matcher": "WebSearch",
        "hooks": [{
          "type": "command",
          "command": "bash /path/to/nexus/scripts/scan-tool-result.sh",
          "timeout": 10,
          "statusMessage": "🛡️ Scanning for prompt injection..."
        }]
      }
    ]
  }
}
```

When Claude fetches a web page or searches, the hook automatically scans the result. If a critical/high prompt injection is detected, the result is **blocked before Claude sees it**.

## Skill Extraction Pipeline

6-layer pipeline that turns raw AI conversations into refined, reusable knowledge:

```
Session JSONL → Smart Extractor (episode segmentation)
                → Context Engine (Bayesian intent + state machine)
                → Global Context (thread weaving + user state)
                → Pattern Engine (cross-session evolution)
                → Wisdom Extractor (principles, not procedures)
                → Skill Reconciler (quality gate + preferences)
                → Refined Skills → Obsidian
```

**"이럴 때는 이렇게"** — not "Edit src/file.ts at line 42"

## Architecture

```
nexus
├── parser/          Multi-platform (Claude Code + OpenClaw)
├── obsidian/        Markdown + MOC + Daily Notes
├── skills/          6-layer extraction pipeline
│   ├── context-engine     Bayesian intent + state machine
│   ├── global-context     Thread weaving + user state
│   ├── pattern-engine     Cross-session evolution
│   ├── smart-extractor    Episode segmentation
│   ├── wisdom-extractor   Principles, not procedures
│   └── skill-reconciler   Quality gate + preferences
├── promptguard/     Prompt injection (82 rules, 8 languages)
├── review/          Code review (19 detectors)
├── codebase/        Architecture mapping + onboarding
├── testing/         Test health + fix suggestions
├── cost/            API cost tracking + budget alerts
├── config/          Config/env validation
├── memory-engine/   Infinite hierarchical memory
├── mcp/             MCP server (14 tools)
└── cli/             Unified CLI (15 commands)
```

## License

MIT
