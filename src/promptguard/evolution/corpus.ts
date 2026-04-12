/**
 * Attack Corpus — Manages a local database of known attack patterns.
 * Supports adding new attacks, categorizing them, and extracting
 * patterns for rule generation.
 *
 * Zero external dependencies.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { Severity, InjectionContext } from "../types.js";

export type AttackSample = {
  /** Unique hash of the input text. */
  id: string;
  /** The attack text. */
  text: string;
  /** Attack category. */
  category: AttackCategory;
  /** Techniques used. */
  techniques: string[];
  /** Languages detected. */
  languages: string[];
  /** Whether our scanner caught it. */
  detected: boolean;
  /** Which rules caught it (if detected). */
  matchedRules: string[];
  /** Severity assigned. */
  severity: Severity | null;
  /** Source of this sample. */
  source: AttackSource;
  /** When this sample was added. */
  addedAt: string;
  /** Context where this attack applies. */
  context: InjectionContext;
};

export type AttackCategory =
  | "role_override"
  | "instruction_ignore"
  | "exfiltration"
  | "delimiter_escape"
  | "encoding_evasion"
  | "tool_abuse"
  | "multi_turn"
  | "indirect_injection"
  | "payload_splitting"
  | "few_shot"
  | "virtualization"
  | "authority_confusion"
  | "hypothetical_framing"
  | "language_switching"
  | "unknown";

export type AttackSource =
  | "community"      // GitHub Issues
  | "honeypot"       // Honeypot captures
  | "ctf"            // CTF challenge data
  | "research"       // Academic papers
  | "manual"         // Manually added
  | "auto_generated"; // Evolution engine generated

export type Corpus = {
  version: number;
  updatedAt: string;
  samples: AttackSample[];
  stats: CorpusStats;
};

export type CorpusStats = {
  totalSamples: number;
  detectedCount: number;
  missedCount: number;
  detectionRate: number;
  byCategory: Record<string, number>;
  byTechnique: Record<string, number>;
  bySource: Record<string, number>;
};

function hashText(text: string): string {
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

function computeStats(samples: AttackSample[]): CorpusStats {
  const detected = samples.filter((s) => s.detected).length;
  const missed = samples.filter((s) => !s.detected).length;
  const byCategory: Record<string, number> = {};
  const byTechnique: Record<string, number> = {};
  const bySource: Record<string, number> = {};

  for (const sample of samples) {
    byCategory[sample.category] = (byCategory[sample.category] ?? 0) + 1;
    bySource[sample.source] = (bySource[sample.source] ?? 0) + 1;
    for (const tech of sample.techniques) {
      byTechnique[tech] = (byTechnique[tech] ?? 0) + 1;
    }
  }

  return {
    totalSamples: samples.length,
    detectedCount: detected,
    missedCount: missed,
    detectionRate: samples.length > 0 ? detected / samples.length : 0,
    byCategory,
    byTechnique,
    bySource,
  };
}

/**
 * Load or create the attack corpus from disk.
 */
export function loadCorpus(dataDir: string): Corpus {
  const filePath = join(dataDir, "corpus.json");
  if (existsSync(filePath)) {
    const raw = readFileSync(filePath, "utf-8");
    return JSON.parse(raw) as Corpus;
  }
  return {
    version: 1,
    updatedAt: new Date().toISOString(),
    samples: [],
    stats: computeStats([]),
  };
}

/**
 * Save corpus to disk.
 */
export function saveCorpus(corpus: Corpus, dataDir: string): void {
  mkdirSync(dataDir, { recursive: true });
  corpus.stats = computeStats(corpus.samples);
  corpus.updatedAt = new Date().toISOString();
  const filePath = join(dataDir, "corpus.json");
  writeFileSync(filePath, JSON.stringify(corpus, null, 2), "utf-8");
}

/**
 * Add an attack sample to the corpus. Deduplicates by text hash.
 */
export function addSample(
  corpus: Corpus,
  params: {
    text: string;
    category: AttackCategory;
    techniques: string[];
    languages?: string[];
    detected: boolean;
    matchedRules?: string[];
    severity?: Severity | null;
    source: AttackSource;
    context?: InjectionContext;
  },
): AttackSample | null {
  const id = hashText(params.text);
  if (corpus.samples.some((s) => s.id === id)) {
    return null; // Duplicate
  }

  const sample: AttackSample = {
    id,
    text: params.text,
    category: params.category,
    techniques: params.techniques,
    languages: params.languages ?? ["en"],
    detected: params.detected,
    matchedRules: params.matchedRules ?? [],
    severity: params.severity ?? null,
    source: params.source,
    addedAt: new Date().toISOString(),
    context: params.context ?? "unknown",
  };

  corpus.samples.push(sample);
  return sample;
}

/**
 * Get all samples that were missed by the scanner.
 */
export function getMissedSamples(corpus: Corpus): AttackSample[] {
  return corpus.samples.filter((s) => !s.detected);
}

/**
 * Get samples by category.
 */
export function getSamplesByCategory(
  corpus: Corpus,
  category: AttackCategory,
): AttackSample[] {
  return corpus.samples.filter((s) => s.category === category);
}

/**
 * Export corpus stats as a human-readable report.
 */
export function generateReport(corpus: Corpus): string {
  const s = corpus.stats;
  const lines: string[] = [
    `=== PromptGuard Attack Corpus Report ===`,
    `Updated: ${corpus.updatedAt}`,
    `Total Samples: ${s.totalSamples}`,
    `Detection Rate: ${(s.detectionRate * 100).toFixed(1)}% (${s.detectedCount}/${s.totalSamples})`,
    `Missed: ${s.missedCount}`,
    ``,
    `By Category:`,
    ...Object.entries(s.byCategory)
      .sort(([, a], [, b]) => b - a)
      .map(([cat, count]) => `  ${cat}: ${count}`),
    ``,
    `By Technique:`,
    ...Object.entries(s.byTechnique)
      .sort(([, a], [, b]) => b - a)
      .map(([tech, count]) => `  ${tech}: ${count}`),
    ``,
    `By Source:`,
    ...Object.entries(s.bySource)
      .sort(([, a], [, b]) => b - a)
      .map(([src, count]) => `  ${src}: ${count}`),
  ];
  return lines.join("\n");
}
