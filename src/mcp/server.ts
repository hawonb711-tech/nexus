#!/usr/bin/env node

/**
 * Nexus MCP Server
 *
 * Exposes all 15 modules as MCP tools for Claude Code, OpenClaw,
 * and any MCP-compatible AI agent.
 *
 * Config:
 *   {
 *     "mcpServers": {
 *       "nexus": { "command": "npx", "args": ["@hawon/nexus-mcp"] }
 *     }
 *   }
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Session intelligence
import { discoverAllSessions } from "../parser/unified.js";
import { parseAnySession } from "../parser/unified.js";

// Code review
import { reviewCode } from "../review/analyzer.js";

// Codebase
import { mapCodebase } from "../codebase/mapper.js";
import { generateOnboardingGuide } from "../codebase/onboard.js";

// Testing
import { checkTestHealth } from "../testing/health-check.js";
import { suggestFixes } from "../testing/test-fixer.js";

// Config
import { validateConfig } from "../config/validator.js";

// Cost
import { createCostTracker } from "../cost/tracker.js";

// Memory
import { createMemoryStore } from "../memory-engine/store.js";

// Prompt injection
import { scan, isInjected } from "../promptguard/scanner.js";
import type { InjectionContext, Severity } from "../promptguard/types.js";

// Skills
import { loadRefinedLibrary } from "../skills/skill-reconciler.js";

const server = new McpServer({ name: "nexus", version: "0.1.0" });
const dataDir = resolve(process.env.NEXUS_DATA ?? ".nexus");

// ─── Session Intelligence ────────────────────────────────────────

server.tool(
  "nexus_sessions",
  "List all AI sessions from Claude Code and OpenClaw.",
  {},
  async () => {
    const discovery = discoverAllSessions();
    const sessions = [];
    for (const platform of discovery.platforms) {
      for (const s of platform.sessions) {
        sessions.push({ path: s.path, project: s.projectId, platform: platform.platform });
      }
    }
    return { content: [{ type: "text" as const, text: JSON.stringify({ total: discovery.totalSessions, sessions: sessions.slice(0, 50) }, null, 2) }] };
  },
);

server.tool(
  "nexus_parse_session",
  "Parse a specific AI session and return its messages, tools, and topics.",
  {
    path: z.string().describe("Path to the session JSONL file"),
    platform: z.enum(["claude-code", "openclaw"]).optional().describe("Platform (auto-detected if omitted)"),
  },
  async ({ path, platform }) => {
    const session = parseAnySession(path, platform ?? "claude-code");
    return { content: [{ type: "text" as const, text: JSON.stringify({
      sessionId: session.sessionId,
      platform: session.platform,
      messages: session.messages.length,
      toolsUsed: session.toolsUsed,
      topics: session.topics,
      summary: session.summary,
    }, null, 2) }] };
  },
);

// ─── Prompt Injection Guard ──────────────────────────────────────

server.tool(
  "nexus_scan",
  "Scan text for prompt injection attacks. 6 detection layers, 82 rules, 8 languages.",
  {
    text: z.string().describe("Text to scan"),
    context: z.enum(["user_input", "tool_result", "mcp_response", "document", "unknown"]).optional(),
  },
  async ({ text, context }) => {
    const result = scan(text, { context: (context as InjectionContext) ?? "unknown" });
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  },
);

server.tool(
  "nexus_is_safe",
  "Quick check: is this text safe from prompt injection? Returns true/false.",
  {
    text: z.string().describe("Text to check"),
  },
  async ({ text }) => {
    const injected = isInjected(text);
    return { content: [{ type: "text" as const, text: JSON.stringify({ safe: !injected }) }] };
  },
);

// ─── Code Review ─────────────────────────────────────────────────

server.tool(
  "nexus_review",
  "Review a source file for bugs, security issues, AI slop, performance problems, and dead code. 19 detectors.",
  {
    file_path: z.string().describe("Path to the file to review"),
  },
  async ({ file_path }) => {
    const code = readFileSync(resolve(file_path), "utf-8");
    const result = reviewCode(code, file_path);
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  },
);

// ─── Codebase Mapping ────────────────────────────────────────────

server.tool(
  "nexus_map",
  "Map the architecture of a codebase — files, imports, dependencies, entry points, hotspots.",
  {
    directory: z.string().optional().describe("Root directory (default: current dir)"),
  },
  async ({ directory }) => {
    const map = await mapCodebase({ root: resolve(directory ?? ".") });
    return { content: [{ type: "text" as const, text: JSON.stringify({
      totalFiles: map.totalFiles,
      totalLines: map.totalLines,
      languages: map.languages,
      entryPoints: map.entryPoints.slice(0, 10),
      hotspots: map.hotspots.slice(0, 10),
    }, null, 2) }] };
  },
);

server.tool(
  "nexus_onboard",
  "Generate a human-readable onboarding guide for a codebase.",
  {
    directory: z.string().optional().describe("Root directory (default: current dir)"),
  },
  async ({ directory }) => {
    const map = await mapCodebase({ root: resolve(directory ?? ".") });
    const guide = generateOnboardingGuide(map);
    return { content: [{ type: "text" as const, text: guide }] };
  },
);

// ─── Test Health ─────────────────────────────────────────────────

server.tool(
  "nexus_test_health",
  "Check test suite health — broken imports, stale mocks, missing tests, coverage estimate.",
  {
    directory: z.string().optional(),
  },
  async ({ directory }) => {
    const report = await checkTestHealth(resolve(directory ?? "."));
    const fixes = suggestFixes(report.issues);
    return { content: [{ type: "text" as const, text: JSON.stringify({ ...report, suggestedFixes: fixes }, null, 2) }] };
  },
);

// ─── Config Validation ───────────────────────────────────────────

server.tool(
  "nexus_config",
  "Validate environment variables and config files — exposed secrets, missing keys, insecure defaults.",
  {
    directory: z.string().optional(),
  },
  async ({ directory }) => {
    const report = await validateConfig(resolve(directory ?? "."));
    return { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] };
  },
);

// ─── Cost Monitor ────────────────────────────────────────────────

server.tool(
  "nexus_cost",
  "Show AI API cost report — total cost, by provider, by model, budget alerts.",
  {
    days: z.number().optional().describe("Days to report (default: 30)"),
  },
  async ({ days }) => {
    const tracker = createCostTracker(dataDir);
    const report = tracker.getReport(days ?? 30);
    return { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] };
  },
);

// ─── Memory ──────────────────────────────────────────────────────

server.tool(
  "nexus_memory_search",
  "Search persistent memory for relevant past interactions and context.",
  {
    query: z.string().describe("Search query"),
    limit: z.number().optional().describe("Max results (default: 10)"),
  },
  async ({ query, limit }) => {
    const store = createMemoryStore(dataDir);
    const results = store.search({ query, limit: limit ?? 10 });
    return { content: [{ type: "text" as const, text: JSON.stringify(results, null, 2) }] };
  },
);

server.tool(
  "nexus_memory_save",
  "Save information to persistent memory for future reference.",
  {
    content: z.string().describe("Content to remember"),
    tags: z.array(z.string()).optional().describe("Tags for categorization"),
  },
  async ({ content, tags }) => {
    const store = createMemoryStore(dataDir);
    const entry = store.add({ content, tags: tags ?? [], tier: "working" });
    return { content: [{ type: "text" as const, text: JSON.stringify({ saved: true, id: entry.id }) }] };
  },
);

// ─── Skills ──────────────────────────────────────────────────────

server.tool(
  "nexus_skills",
  "List all refined skills extracted from past sessions.",
  {},
  async () => {
    const library = loadRefinedLibrary(dataDir);
    return { content: [{ type: "text" as const, text: JSON.stringify(library.skills, null, 2) }] };
  },
);

// ─── Start ───────────────────────────────────────────────────────

async function main(): Promise<void> {
  const transport = new StdioServerTransport();

  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    process.stdin.off("end", shutdown);
    process.stdin.off("close", shutdown);
    process.off("SIGINT", shutdown);
    process.off("SIGTERM", shutdown);
    void server.close();
  };

  process.stdin.once("end", shutdown);
  process.stdin.once("close", shutdown);
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);

  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`nexus-mcp: ${String(err)}\n`);
  process.exit(1);
});
