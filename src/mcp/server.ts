#!/usr/bin/env node

/**
 * Nexus MCP Server
 *
 * Exposes 17 tools for Claude Code, OpenClaw,
 * and any MCP-compatible AI agent.
 *
 * Config:
 *   {
 *     "mcpServers": {
 *       "nexus": { "command": "nexus-mcp" }
 *     }
 *   }
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { resolve, join } from "node:path";
import { createPathValidator } from "./path-policy.js";
import { VERSION } from "../version.js";

/** Limit input size to prevent DoS. */
function limitInput(text: string, maxLen = 500_000): string {
  return text.length > maxLen ? text.slice(0, maxLen) : text;
}

// Session intelligence
import { discoverAllSessions } from "../parser/unified.js";
import { parseAnySession } from "../parser/unified.js";

// Code review
import { reviewCode } from "../review/analyzer.js";

// Secret scanner
import { redactSecretsInText, scanForSecrets } from "../secrets/scanner.js";

// Agent firewall
import { inspectContent, spotlightUntrusted } from "../guard/guard.js";
import { inspectCommand } from "../guard/command.js";
import { sanitizeExternalContent } from "../guard/sanitize.js";

// Codebase
import { mapCodebase } from "../codebase/mapper.js";
import { generateOnboardingGuide } from "../codebase/onboard.js";

// Testing
import { checkTestHealth } from "../testing/health-check.js";
import { suggestFixes } from "../testing/test-fixer.js";

// Config
import { validateConfig } from "../config/validator.js";


// Memory
import { createNexusMemory } from "../memory-engine/nexus-memory.js";

// Prompt injection
import { scan, isInjected } from "../promptguard/scanner.js";
import type { InjectionContext, Severity } from "../promptguard/types.js";

// Knowledge — uses cached data from last `nexus reorganize`

function safeExternalResponse(value: unknown) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  const sanitized = sanitizeExternalContent(text);
  return { content: [{ type: "text" as const, text: sanitized.displayText }] };
}

const server = new McpServer({ name: "nexus", version: VERSION });
const dataDir = resolve(process.env.NEXUS_DATA ?? join(homedir(), ".nexus"));
const validateFilePath = createPathValidator();
const validateSessionPath = createPathValidator({ includeCwd: false, includeSessionRoots: true });

// Singleton memory store (avoid re-reading from disk on every MCP call)
let _memoryStore: ReturnType<typeof createNexusMemory> | null = null;
function getMemoryStore() {
  if (!_memoryStore) _memoryStore = createNexusMemory(dataDir);
  return _memoryStore;
}

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
    return safeExternalResponse({ total: discovery.totalSessions, sessions: sessions.slice(0, 50) });
  },
);

server.tool(
  "nexus_parse_session",
  "Parse a specific AI session and return its messages, tools, and topics.",
  {
    path: z.string().max(32_768).describe("Path to the session JSONL file"),
    platform: z.enum(["claude-code", "openclaw"]).optional().describe("Platform (auto-detected if omitted)"),
  },
  async ({ path, platform }) => {
    const safePath = validateSessionPath(path);
    const session = parseAnySession(safePath, platform ?? "claude-code");
    const summary = sanitizeExternalContent(JSON.stringify({
      sessionId: session.sessionId,
      platform: session.platform,
      messages: session.messages.length,
      toolsUsed: session.toolsUsed,
      topics: session.topics,
      summary: session.summary,
    }, null, 2));
    return { content: [{ type: "text" as const, text: summary.displayText }] };
  },
);

// ─── Prompt Injection Guard ──────────────────────────────────────

server.tool(
  "nexus_scan",
  "Scan text for prompt injection attacks. 6 detection layers, 82 rules, 8 languages.",
  {
    text: z.string().max(500_000).describe("Text to scan"),
    context: z.enum(["user_input", "tool_result", "mcp_response", "document", "unknown"]).optional(),
  },
  async ({ text, context }) => {
    const result = scan(limitInput(text), { context: (context as InjectionContext) ?? "unknown" });
    const serialized = redactSecretsInText(JSON.stringify(result, null, 2)).text;
    return {
      content: [{
        type: "text" as const,
        text: result.injected ? spotlightUntrusted(serialized) : serialized,
      }],
    };
  },
);

server.tool(
  "nexus_is_safe",
  "Quick check: is this text safe from prompt injection? Returns true/false.",
  {
    text: z.string().max(500_000).describe("Text to check"),
  },
  async ({ text }) => {
    const injected = isInjected(limitInput(text));
    return { content: [{ type: "text" as const, text: JSON.stringify({ safe: !injected }) }] };
  },
);

// ─── Code Review ─────────────────────────────────────────────────

server.tool(
  "nexus_review",
  "Review a source file for bugs, security issues, AI slop, performance problems, and dead code. 19 detectors.",
  {
    file_path: z.string().max(32_768).describe("Path to the file to review"),
  },
  async ({ file_path }) => {
    const safePath = validateFilePath(file_path);
    const code = readFileSync(safePath, "utf-8");
    const result = reviewCode(code, file_path);
    return safeExternalResponse(result);
  },
);

// ─── Agent Firewall ──────────────────────────────────────────────
// Works with ANY MCP-capable agent (not just Claude Code's hooks): call this to
// vet untrusted content or a command before acting on it.

server.tool(
  "nexus_guard",
  "Agent firewall: vet untrusted content for prompt injection, and/or screen a shell command for danger, BEFORE acting on it. Pass `content` (e.g. a fetched page, an issue body, a tool result) and/or `command` (a shell command you're about to run). Returns a verdict — for content: block/warn/allow; for commands: deny/ask/allow — with a reason. Local, with no model API required.",
  {
    content: z.string().max(500_000).optional().describe("Untrusted text to inspect for prompt injection"),
    command: z.string().max(100_000).optional().describe("A shell command to screen before running"),
  },
  async ({ content, command }) => {
    const out: Record<string, unknown> = {};
    if (content != null) {
      const r = inspectContent(limitInput(content));
      out.content = { verdict: r.verdict, maxSeverity: r.maxSeverity, reason: r.reason, findings: r.findings };
    }
    if (command != null) {
      const r = inspectCommand(command);
      out.command = { decision: r.decision, reason: r.reason, rule: r.rule };
    }
    if (content == null && command == null) out.error = "Provide `content` and/or `command` to inspect.";
    return { content: [{ type: "text" as const, text: JSON.stringify(out, null, 2) }] };
  },
);

// ─── Secret Scanning ─────────────────────────────────────────────

server.tool(
  "nexus_secrets",
  "Scan a directory for leaked credentials — API keys, tokens, private keys — in the working tree and, optionally, across git history (secrets committed then removed remain exposed in history). Returns redacted findings; raw secret values are never included.",
  {
    directory: z.string().max(32_768).optional().describe("Root directory to scan (default: current dir)"),
    include_history: z.boolean().optional().describe("Also scan git history via `git log -p` (default: false)"),
    entropy: z.boolean().optional().describe("Enable entropy-based detection of unrecognized high-randomness strings (higher false-positive rate; default: false)"),
    max_commits: z.number().int().min(1).max(10_000).optional().describe("Cap on commits scanned in history mode (default: 1000, maximum: 10000)"),
  },
  async ({ directory, include_history, entropy, max_commits }) => {
    const result = await scanForSecrets(validateFilePath(directory ?? "."), {
      includeHistory: include_history ?? false,
      entropy: entropy ?? false,
      maxCommits: max_commits,
    });
    return safeExternalResponse(result);
  },
);

// ─── Codebase Mapping ────────────────────────────────────────────

server.tool(
  "nexus_map",
  "Map the architecture of a codebase — files, imports, dependencies, entry points, hotspots.",
  {
    directory: z.string().max(32_768).optional().describe("Root directory (default: current dir)"),
  },
  async ({ directory }) => {
    const map = await mapCodebase({ root: validateFilePath(directory ?? ".") });
    return safeExternalResponse({
      totalFiles: map.totalFiles,
      totalLines: map.totalLines,
      languages: map.languages,
      entryPoints: map.entryPoints.slice(0, 10),
      hotspots: map.hotspots.slice(0, 10),
    });
  },
);

server.tool(
  "nexus_onboard",
  "Generate a human-readable onboarding guide for a codebase.",
  {
    directory: z.string().max(32_768).optional().describe("Root directory (default: current dir)"),
  },
  async ({ directory }) => {
    const map = await mapCodebase({ root: validateFilePath(directory ?? ".") });
    const guide = generateOnboardingGuide(map);
    return safeExternalResponse(guide);
  },
);

// ─── Test Health ─────────────────────────────────────────────────

server.tool(
  "nexus_test_health",
  "Check test suite health — broken imports, stale mocks, missing tests, coverage estimate.",
  {
    directory: z.string().max(32_768).optional(),
  },
  async ({ directory }) => {
    const report = await checkTestHealth(validateFilePath(directory ?? "."));
    const fixes = suggestFixes(report.issues);
    return safeExternalResponse({ ...report, suggestedFixes: fixes });
  },
);

// ─── Config Validation ───────────────────────────────────────────

server.tool(
  "nexus_config",
  "Validate environment variables and config files — exposed secrets, missing keys, insecure defaults.",
  {
    directory: z.string().max(32_768).optional(),
  },
  async ({ directory }) => {
    const report = await validateConfig(validateFilePath(directory ?? "."));
    return safeExternalResponse(report);
  },
);

// ─── Memory ──────────────────────────────────────────────────────

server.tool(
  "nexus_memory_search",
  "Search persistent memory for relevant past interactions and context.",
  {
    query: z.string().max(10_000).describe("Search query"),
    limit: z.number().int().min(1).max(100).optional().describe("Max results (default: 10, maximum: 100)"),
  },
  async ({ query, limit }) => {
    const store = getMemoryStore();
    const results = store.search(limitInput(query, 10_000), limit ?? 10);
    // Defense in depth for memories created by older Nexus releases: never
    // return a stored instruction payload to the agent without reapplying the
    // current trust boundary.
    const safeResults = results.map((result) => {
      const sanitized = sanitizeExternalContent(result.observation.content);
      return {
        ...result,
        observation: { ...result.observation, content: sanitized.displayText },
        related: result.related?.map((observation) => ({
          ...observation,
          content: sanitizeExternalContent(observation.content).displayText,
        })),
        trust: {
          verdict: sanitized.verdict,
          reason: sanitized.reason,
          secretsRedacted: sanitized.secretsRedacted,
        },
      };
    });
    // The whole serialized envelope is a trust boundary too: observations
    // written by older releases may contain hostile domain/topic/tag/session
    // metadata even when their content field itself is clean.
    const safeEnvelope = sanitizeExternalContent(JSON.stringify(safeResults, null, 2));
    return { content: [{ type: "text" as const, text: safeEnvelope.displayText }] };
  },
);

server.tool(
  "nexus_memory_save",
  "Save information to persistent memory for future reference.",
  {
    content: z.string().max(500_000).describe("Content to remember"),
    tags: z.array(z.string().max(64)).max(50).optional().describe("Tags for categorization"),
  },
  async ({ content, tags }) => {
    const store = getMemoryStore();
    const sanitized = sanitizeExternalContent(content);
    if (sanitized.persistText === null) {
      return { content: [{ type: "text" as const, text: JSON.stringify({
        saved: false,
        quarantined: true,
        verdict: sanitized.verdict,
        reason: sanitized.reason,
        observations: 0,
      }) }] };
    }
    const count = store.ingest(sanitized.persistText, "manual", undefined, tags ?? []);
    store.save();
    return { content: [{ type: "text" as const, text: JSON.stringify({
      saved: true,
      observations: count,
      secretsRedacted: sanitized.secretsRedacted,
    }) }] };
  },
);

// ─── Web Data Collector ─────────────────────────────────────────

server.tool(
  "nexus_collect",
  "Fetch a web page, extract article text, and save to memory. Works with news sites, government pages, research reports.",
  {
    url: z.string().max(16_384).describe("URL to fetch"),
    domain: z.string().max(120).optional().describe("Domain label for memory (default: hostname)"),
  },
  async ({ url, domain }) => {
    const { collectUrl } = await import("../collector/fetch.js");
    const store = getMemoryStore();
    const result = await collectUrl(url, store, { domain });
    return safeExternalResponse(result);
  },
);

server.tool(
  "nexus_collect_feed",
  "Fetch an RSS/Atom feed and save all items to memory.",
  {
    url: z.string().max(16_384).describe("Feed URL"),
    max_items: z.number().int().min(0).max(100).optional().describe("Max items to fetch (default: 20, maximum: 100)"),
    domain: z.string().max(120).optional().describe("Domain label for memory"),
  },
  async ({ url, max_items, domain }) => {
    const { collectFeed } = await import("../collector/fetch.js");
    const store = getMemoryStore();
    const result = await collectFeed(url, store, { maxItems: max_items, domain });
    return safeExternalResponse(result);
  },
);

// ─── Document Parser ────────────────────────────────────────────

server.tool(
  "nexus_parse_document",
  "Parse a document (PDF, DOCX, or text file), extract text, and save to memory.",
  {
    file_path: z.string().max(32_768).describe("Path to the document file"),
    domain: z.string().max(120).optional().describe("Domain label for memory (default: filename)"),
    chunk_size: z.number().int().min(100).max(100_000).optional().describe("Target chunk size in characters (default: 1000)"),
  },
  async ({ file_path, domain, chunk_size }) => {
    const { parseDocument } = await import("../docparser/parse-document.js");
    const safePath = validateFilePath(file_path);
    const store = getMemoryStore();
    const result = parseDocument(safePath, store, { domain, chunkSize: chunk_size });
    return safeExternalResponse({
      filePath: result.filePath,
      format: result.format,
      title: result.title,
      textLength: result.text.length,
      chunks: result.chunks.length,
      observationsAdded: result.observationsAdded,
      pageCount: result.pageCount,
    });
  },
);

// ─── Knowledge (Skills + Tips + Facts) ───────────────────────────

server.tool(
  "nexus_skills",
  "List all knowledge: skills (complex patterns), tips (quick advice), and facts (reference info).",
  {
    tier: z.enum(["all", "skill", "tip", "fact"]).optional().describe("Filter by tier (default: all)"),
  },
  async ({ tier }) => {
    // Read cached knowledge from last reorganize
    const statusPath = join(dataDir, "status.json");
    const kbPath = join(dataDir, "knowledge.json");
    let knowledge: { skills: unknown[]; tips: unknown[]; facts: unknown[] } = { skills: [], tips: [], facts: [] };

    try {
      if (existsSync(kbPath)) {
        knowledge = JSON.parse(readFileSync(kbPath, "utf-8"));
      }
    } catch { /* empty */ }

    const filtered = tier === "skill" ? { skills: knowledge.skills }
      : tier === "tip" ? { tips: knowledge.tips }
      : tier === "fact" ? { facts: knowledge.facts }
      : knowledge;

    const sanitized = sanitizeExternalContent(JSON.stringify(filtered, null, 2));
    return { content: [{ type: "text" as const, text: sanitized.displayText }] };
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
