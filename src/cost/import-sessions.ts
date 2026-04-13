/**
 * Import token usage from Claude Code session JSONL files.
 * Properly detects model per-message (not per-session).
 */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { CostEntry } from "./types.js";

// Pricing per million tokens
const PRICING: Record<string, { input: number; output: number; cacheRead: number; cacheWrite: number }> = {
  "opus-4-6":     { input: 15, output: 75, cacheRead: 1.5, cacheWrite: 18.75 },
  "opus-4-5":     { input: 15, output: 75, cacheRead: 1.5, cacheWrite: 18.75 },
  "sonnet-4-6":   { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
  "sonnet-4-5":   { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
  "sonnet-3.5":   { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
  "haiku-4-5":    { input: 0.8, output: 4, cacheRead: 0.08, cacheWrite: 1 },
  "haiku-3.5":    { input: 0.25, output: 1.25, cacheRead: 0.025, cacheWrite: 0.3 },
};

function matchPricing(model: string): { input: number; output: number; cacheRead: number; cacheWrite: number } {
  for (const [key, val] of Object.entries(PRICING)) {
    if (model.includes(key)) return val;
  }
  // Default: sonnet pricing
  return PRICING["sonnet-4-6"];
}

function computeCost(model: string, input: number, output: number, cacheRead: number, cacheWrite: number): number {
  const p = matchPricing(model);
  return (input / 1e6) * p.input +
    (output / 1e6) * p.output +
    (cacheRead / 1e6) * p.cacheRead +
    (cacheWrite / 1e6) * p.cacheWrite;
}

export type SessionCost = {
  sessionId: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  cost: number;
  timestamp: string;
  messageCount: number;
};

export function importSessionCosts(claudeDir?: string): SessionCost[] {
  const dir = claudeDir ?? join(homedir(), ".claude", "projects");
  if (!existsSync(dir)) return [];

  const results: SessionCost[] = [];

  for (const project of readdirSync(dir)) {
    const projectDir = join(dir, project);
    let files: string[];
    try {
      files = readdirSync(projectDir).filter((f) => f.endsWith(".jsonl"));
    } catch { continue; }

    for (const file of files) {
      const filePath = join(projectDir, file);
      const sessionId = file.replace(".jsonl", "");

      try {
        const content = readFileSync(filePath, "utf-8");
        const lines = content.split("\n").filter(Boolean);

        let totalInput = 0;
        let totalOutput = 0;
        let totalCacheRead = 0;
        let totalCacheWrite = 0;
        let model = "";
        let timestamp = "";
        let msgCount = 0;

        for (const line of lines) {
          try {
            const obj = JSON.parse(line);

            // Track model PER MESSAGE — check both top-level and message.model
            if (obj.model) model = obj.model;
            if (obj.message?.model) model = obj.message.model;
            if (obj.timestamp && !timestamp) timestamp = obj.timestamp;

            if (obj.message?.usage) {
              const u = obj.message.usage;
              totalInput += u.input_tokens ?? 0;
              totalOutput += u.output_tokens ?? 0;
              totalCacheRead += u.cache_read_input_tokens ?? 0;
              totalCacheWrite += u.cache_creation_input_tokens ?? 0;
              msgCount++;
            }
          } catch { /* skip */ }
        }

        if (msgCount === 0) continue;

        const cost = computeCost(model, totalInput, totalOutput, totalCacheRead, totalCacheWrite);

        results.push({
          sessionId,
          model: model || "unknown",
          inputTokens: totalInput,
          outputTokens: totalOutput,
          cacheReadTokens: totalCacheRead,
          cacheWriteTokens: totalCacheWrite,
          cost,
          timestamp: timestamp || new Date().toISOString(),
          messageCount: msgCount,
        });
      } catch { /* skip unreadable */ }
    }
  }

  return results;
}

/** Get a summary report from imported sessions. */
export function summarizeCosts(sessions: SessionCost[]): {
  totalCost: number;
  totalInput: number;
  totalOutput: number;
  totalCacheRead: number;
  totalCacheWrite: number;
  byModel: Record<string, { cost: number; sessions: number }>;
  sessionCount: number;
} {
  const byModel: Record<string, { cost: number; sessions: number }> = {};
  let totalCost = 0;
  let totalInput = 0;
  let totalOutput = 0;
  let totalCacheRead = 0;
  let totalCacheWrite = 0;

  for (const s of sessions) {
    totalCost += s.cost;
    totalInput += s.inputTokens;
    totalOutput += s.outputTokens;
    totalCacheRead += s.cacheReadTokens;
    totalCacheWrite += s.cacheWriteTokens;

    const modelKey = s.model || "unknown";
    if (!byModel[modelKey]) byModel[modelKey] = { cost: 0, sessions: 0 };
    byModel[modelKey].cost += s.cost;
    byModel[modelKey].sessions++;
  }

  return { totalCost, totalInput, totalOutput, totalCacheRead, totalCacheWrite, byModel, sessionCount: sessions.length };
}
