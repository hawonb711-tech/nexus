/**
 * Auto-Update System
 *
 * Fetches new attack patterns from remote sources,
 * runs the evolution engine, and applies improved rules.
 *
 * Sources:
 * - GitHub Issues (community-reported attacks)
 * - Published attack datasets
 * - Honeypot captures
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { loadCorpus, saveCorpus, addSample, generateReport } from "./corpus.js";
import { evolveRules, reevaluateCorpus, exportEvolvedRules } from "./rule-evolver.js";
import { scan } from "../scanner.js";
import type { AttackCategory, AttackSource } from "./corpus.js";
import type { DetectionRule } from "../types.js";

export type UpdateResult = {
  /** New samples added to corpus. */
  samplesAdded: number;
  /** New rules evolved. */
  rulesEvolved: number;
  /** Samples now detected that were missed before. */
  improved: number;
  /** Samples still missed. */
  stillMissed: number;
  /** Current detection rate. */
  detectionRate: number;
  /** Evolved rules (ready to use). */
  rules: DetectionRule[];
};

export type FeedEntry = {
  text: string;
  category?: AttackCategory;
  techniques?: string[];
  languages?: string[];
  source?: AttackSource;
};

/**
 * Ingest a batch of attack samples, evolve rules, and return results.
 *
 * @example
 * ```ts
 * import { evolve } from "@hawon/promptguard";
 *
 * const result = await evolve({
 *   dataDir: "./.promptguard",
 *   feed: [
 *     { text: "New attack pattern here", category: "instruction_ignore" },
 *   ],
 * });
 *
 * console.log(`Detection rate: ${result.detectionRate}`);
 * console.log(`New rules: ${result.rulesEvolved}`);
 * ```
 */
export function evolve(params: {
  dataDir: string;
  feed?: FeedEntry[];
  generations?: number;
}): UpdateResult {
  const { dataDir, feed = [], generations = 3 } = params;
  mkdirSync(dataDir, { recursive: true });

  // Load corpus
  const corpus = loadCorpus(dataDir);

  // Ingest new samples
  let samplesAdded = 0;
  for (const entry of feed) {
    // Scan to see if current rules catch it
    const result = scan(entry.text, {
      context: "unknown",
    });

    const added = addSample(corpus, {
      text: entry.text,
      category: entry.category ?? "unknown",
      techniques: entry.techniques ?? [],
      languages: entry.languages ?? ["en"],
      detected: result.injected,
      matchedRules: result.findings.map((f) => f.ruleId),
      severity: result.maxSeverity,
      source: entry.source ?? "community",
    });

    if (added) samplesAdded++;
  }

  // Evolve rules from missed samples
  const evolved = evolveRules(corpus, { generations });

  // Re-evaluate corpus with evolved rules
  const { improved, stillMissed } = reevaluateCorpus(corpus, evolved);

  // Save updated corpus
  saveCorpus(corpus, dataDir);

  // Save evolved rules
  const rules = exportEvolvedRules(evolved);
  if (rules.length > 0) {
    const rulesPath = join(dataDir, "evolved-rules.json");
    const serializable = rules.map((r) => ({
      id: r.id,
      severity: r.severity,
      message: r.message,
      pattern: r.pattern.source,
      flags: r.pattern.flags,
    }));
    writeFileSync(rulesPath, JSON.stringify(serializable, null, 2), "utf-8");
  }

  // Save report
  const report = generateReport(corpus);
  writeFileSync(join(dataDir, "report.txt"), report, "utf-8");

  const detectionRate = corpus.stats.detectionRate;

  return {
    samplesAdded,
    rulesEvolved: rules.length,
    improved,
    stillMissed,
    detectionRate,
    rules,
  };
}

/**
 * Load previously evolved rules from disk.
 */
export function loadEvolvedRules(dataDir: string): DetectionRule[] {
  const rulesPath = join(dataDir, "evolved-rules.json");
  if (!existsSync(rulesPath)) return [];

  const raw = JSON.parse(readFileSync(rulesPath, "utf-8")) as Array<{
    id: string;
    severity: string;
    message: string;
    pattern: string;
    flags: string;
  }>;

  return raw.map((r) => ({
    id: r.id,
    severity: r.severity as DetectionRule["severity"],
    message: r.message,
    pattern: new RegExp(r.pattern, r.flags),
  }));
}

/**
 * Create a scanner that automatically includes evolved rules.
 *
 * @example
 * ```ts
 * import { createEvolvingScanner } from "@hawon/promptguard";
 *
 * const scanner = createEvolvingScanner({ dataDir: "./.promptguard" });
 * const result = scanner.scan("some input");
 * ```
 */
export function createEvolvingScanner(params: { dataDir: string }) {
  const evolvedRules = loadEvolvedRules(params.dataDir);

  return {
    scan: (input: string, options?: Parameters<typeof scan>[1]) =>
      scan(input, { ...options, customRules: [...(options?.customRules ?? []), ...evolvedRules] }),

    /** Re-run evolution with new attack data. */
    evolve: (feed: FeedEntry[], generations?: number) =>
      evolve({ dataDir: params.dataDir, feed, generations }),

    /** Get current evolved rule count. */
    evolvedRuleCount: evolvedRules.length,
  };
}
