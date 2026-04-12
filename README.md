# nexus

The all-in-one AI developer framework — session intelligence, code review, prompt injection defense, infinite memory, and self-evolving skills. Connects Claude Code + OpenClaw to Obsidian.

## Features

| Module | What it does |
|--------|-------------|
| **Multi-platform Parser** | Discover and parse sessions from Claude Code and OpenClaw |
| **Obsidian Export** | Structured markdown with frontmatter, backlinks, MOC, and Daily Notes |
| **Wisdom Extractor** | Extract principles (not procedures) from successful interactions |
| **Skill Reconciler** | Quality gate with conditional branches, preferences, and dedup |
| **Context Engine** | Bayesian intent detection + state machine for conversation flow |
| **Global Context** | Thread weaving + persistent user state across sessions |
| **Pattern Engine** | Cross-session pattern evolution tracking |
| **Smart Extractor** | Episode segmentation + decision point identification |
| **Code Review** | 19 detectors including AI slop detection |
| **Codebase Mapping** | Architecture mapping + onboarding guide generation |
| **Test Health** | Test suite health checks + fix suggestions |
| **Cost Monitor** | AI API cost tracking + budget alerts |
| **Config Validator** | Config and environment validation |
| **Infinite Memory** | Hierarchical memory store with sliding context window |
| **Prompt Injection Guard** | 6-layer, 82-rule prompt injection detection (8 languages) |

## Install

```bash
npm install -g @hawon/nexus
```

## Quick Start

```bash
# Sync all sessions to Obsidian
nexus sync

# Reorganize vault with skill extraction pipeline
nexus reorganize
```

## Multi-platform Support

nexus discovers sessions from both **Claude Code** (`~/.claude/`) and **OpenClaw** data directories. Use `discoverAllSessions()` or `parseAnySession()` for unified access across platforms.

## CLI Commands

| Command | Description |
|---------|-------------|
| `sync` | Sync all sessions to Obsidian vault |
| `reorganize` | Re-export with updated skill pipeline |
| `sessions` | List all discovered sessions |
| `export <id>` | Export a single session |
| `skills` | View or search extracted skills |
| `status` | Check vault sync status |
| `review <path>` | Run code review (19 detectors) |
| `map <path>` | Generate codebase architecture map |
| `onboard <path>` | Generate onboarding guide for a codebase |
| `test-health` | Analyze test suite health |
| `config` | Validate config and environment |
| `cost` | View AI API cost tracking and budgets |
| `memory` | Manage hierarchical memory store |

## Skill Extraction Pipeline

The 6-layer pipeline turns raw conversations into refined, reusable knowledge:

1. **Smart Extractor** -- Segments conversations into episodes and identifies decision points
2. **Context Engine** -- Bayesian intent detection with state machine tracking
3. **Global Context** -- Weaves threads across sessions, maintains user state
4. **Pattern Engine** -- Tracks how patterns evolve across sessions over time
5. **Wisdom Extractor** -- Distills principles from patterns (not step-by-step procedures)
6. **Skill Reconciler** -- Quality gate that deduplicates, scores, and exports refined skills

## Architecture

```
nexus
├── parser/          Multi-platform session parser (Claude Code + OpenClaw)
├── obsidian/        Markdown export + MOC + Daily Notes
├── skills/          6-layer skill extraction pipeline
│   ├── context-engine    Bayesian intent + state machine
│   ├── global-context    Thread weaving + user state
│   ├── pattern-engine    Cross-session pattern evolution
│   ├── smart-extractor   Episode segmentation + decision points
│   ├── wisdom-extractor  Principles, not procedures
│   └── skill-reconciler  Quality gate + conditional branches + preferences
├── review/          Code review (19 detectors, AI slop)
├── codebase/        Architecture mapping + onboarding
├── testing/         Test health + fix suggestions
├── cost/            AI API cost tracking + budget alerts
├── config/          Config/env validation
├── memory-engine/   Infinite hierarchical memory
├── promptguard/     6-layer prompt injection detection (82 rules, 8 languages)
└── cli/             CLI + MCP server
```

## License

MIT
