# nexus

### If you find this useful, please give it a star! It helps a lot.

[![GitHub stars](https://img.shields.io/github/stars/hawonb711-tech/nexus?style=social)](https://github.com/hawonb711-tech/nexus/stargazers)
[![npm](https://img.shields.io/npm/v/@hawon/nexus)](https://www.npmjs.com/package/@hawon/nexus)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

The all-in-one AI developer framework — session intelligence, code review, prompt injection defense, infinite memory, and self-evolving skills.

**14 modules · 14 CLI commands · 13 MCP tools · 15,000+ lines · zero deps**

> *"Claude Code를 더 안전하고, 더 똑똑하게"*

## Features

| Module | What it does |
|--------|-------------|
| **Multi-platform Parser** | Discover and parse sessions from Claude Code and OpenClaw |
| **Obsidian Export** | Structured markdown with frontmatter, backlinks, MOC, Daily Notes |
| **Prompt Injection Guard** | 6-layer, 82-rule detection across 10 languages |
| **Code Review** | 19 detectors: AI slop, bugs, security, performance, dead code |
| **Codebase Mapping** | Architecture map, dependency graph, entry points, hotspots |
| **Test Health** | Broken imports, stale mocks, missing tests, coverage estimate |
| **Config Validator** | Exposed secrets, missing env vars, insecure defaults |
| **Infinite Memory** | BM25 + semantic search, knowledge graph, progressive retrieval |
| **Skill Auto-Generation** | LLM auto-generates SKILL.md after each session (Hermes-style) |
| **3-Tier Knowledge** | Skills (complex), Tips (quick), Facts (reference) → Obsidian |
| **Context Engine** | Bayesian intent classifier + conversation state machine |
| **Global Context** | Thread weaving, user state model, topic switch detection |
| **Semantic Engine** | 75 synonym groups (EN↔KO), PMI co-occurrence, query expansion |
| **Auto-Scan Hook** | Real-time prompt injection defense via PostToolUse hook |

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

# Full vault reorganization with knowledge pipeline
nexus reorganize
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `sync` | Sync all sessions to Obsidian (multi-platform) |
| `reorganize` | Clean rebuild with knowledge pipeline |
| `sessions` | List all discovered sessions |
| `export <id>` | Export a single session |
| `skills` | View extracted knowledge (skills/tips/facts) |
| `skills search <q>` | Search skills by keyword |
| `status` | Vault sync status |
| `scan <text>` | Prompt injection detection |
| `review <file>` | Code review (19 detectors) |
| `map [dir]` | Codebase architecture map |
| `onboard [dir]` | Onboarding guide generation |
| `test-health [dir]` | Test suite health check |
| `config [dir]` | Config/env validation |
| `memory <search\|stats>` | Persistent memory operations |

## MCP Server

Nexus runs as an MCP server with 13 tools for Claude Code, OpenClaw, and any MCP-compatible agent.

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
| `nexus_memory_search` | Search persistent memory |
| `nexus_memory_save` | Save to persistent memory |
| `nexus_skills` | List knowledge (skills/tips/facts) |

## Auto-Hooks

### Prompt Injection Defense (PostToolUse)

Auto-scans every WebFetch/WebSearch result before Claude sees it:

```json
{
  "hooks": {
    "PostToolUse": [{
      "matcher": "WebFetch",
      "hooks": [{
        "type": "command",
        "command": "bash /path/to/nexus/scripts/scan-tool-result.sh",
        "timeout": 10
      }]
    }]
  }
}
```

### Auto-Skill Generation (SessionEnd)

Claude auto-generates SKILL.md after each session (Hermes Agent style):

```json
{
  "hooks": {
    "SessionEnd": [{
      "hooks": [{
        "type": "command",
        "command": "bash /path/to/nexus/scripts/auto-skill.sh",
        "timeout": 60,
        "async": true
      }]
    }]
  }
}
```

## Architecture

```
nexus
├── parser/          Multi-platform (Claude Code + OpenClaw)
├── obsidian/        Markdown + MOC + Daily Notes
├── skills/          Knowledge extraction + auto-generation
├── promptguard/     Prompt injection (82 rules, 10 languages)
├── review/          Code review (19 detectors)
├── codebase/        Architecture mapping + onboarding
├── testing/         Test health + fix suggestions
├── config/          Config/env validation
├── memory-engine/   BM25 + semantic search + knowledge graph
├── mcp/             MCP server (13 tools)
└── cli/             Unified CLI (14 commands)
```

## License

MIT
