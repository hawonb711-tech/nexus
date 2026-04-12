/**
 * Rule Evolution Engine
 *
 * Automatically generates and refines detection rules based on
 * attack corpus data. Inspired by genetic/evolutionary approaches
 * (similar to Hermes Agent's GEPA).
 *
 * Process:
 * 1. Analyze missed attacks from corpus
 * 2. Extract common patterns (n-grams, keywords, structure)
 * 3. Generate candidate rules
 * 4. Evaluate against corpus (fitness = detection rate - false positive rate)
 * 5. Select best rules, mutate/crossover, repeat
 */

import type { DetectionRule, Severity, InjectionContext } from "../types.js";
import type { AttackSample, Corpus } from "./corpus.js";
import { scan } from "../scanner.js";

export type CandidateRule = DetectionRule & {
  /** How many attacks this rule catches. */
  truePositives: number;
  /** How many clean inputs this rule falsely flags. */
  falsePositives: number;
  /** Fitness score (higher = better). */
  fitness: number;
  /** Generation number. */
  generation: number;
  /** How this rule was created. */
  origin: "extracted" | "mutated" | "crossover" | "manual";
};

export type EvolutionConfig = {
  /** Maximum candidate rules per generation. */
  maxCandidates?: number;
  /** Minimum fitness to keep a rule. */
  minFitness?: number;
  /** Number of generations to run. */
  generations?: number;
  /** Clean inputs for false positive testing. */
  cleanInputs?: string[];
};

const DEFAULT_CLEAN_INPUTS = [
  "What is the weather in Tokyo today?",
  "Can you help me write a Python function to sort a list?",
  "Tell me about the history of JavaScript",
  "How do I install Node.js on Ubuntu?",
  "What are the best practices for REST API design?",
  "Explain the difference between TCP and UDP",
  "Help me debug this React component",
  "What is the capital of France?",
  "How do I create a Docker container?",
  "Summarize this article for me",
  "I need to schedule a meeting for next Tuesday",
  "Can you review my resume?",
  "What are some good books about machine learning?",
  "How do I set up a PostgreSQL database?",
  "Explain async/await in JavaScript",
  "What is the time complexity of quicksort?",
  "Help me write a unit test for this function",
  "What is the difference between git merge and rebase?",
  "How do I deploy to AWS Lambda?",
  "Can you explain what Kubernetes does?",
];

/**
 * Extract n-grams from text.
 */
function extractNgrams(text: string, n: number): string[] {
  const words = text.toLowerCase().split(/\s+/);
  const ngrams: string[] = [];
  for (let i = 0; i <= words.length - n; i++) {
    ngrams.push(words.slice(i, i + n).join(" "));
  }
  return ngrams;
}

/**
 * Find common patterns across missed attack samples.
 */
function findCommonPatterns(
  missed: AttackSample[],
): Map<string, { count: number; samples: string[] }> {
  const patternCounts = new Map<string, { count: number; samples: string[] }>();

  for (const sample of missed) {
    // Extract bigrams and trigrams
    const bigrams = extractNgrams(sample.text, 2);
    const trigrams = extractNgrams(sample.text, 3);

    for (const ngram of [...bigrams, ...trigrams]) {
      // Skip very common phrases
      if (ngram.length < 6) continue;
      const existing = patternCounts.get(ngram);
      if (existing) {
        existing.count++;
        if (!existing.samples.includes(sample.id)) {
          existing.samples.push(sample.id);
        }
      } else {
        patternCounts.set(ngram, { count: 1, samples: [sample.id] });
      }
    }
  }

  return patternCounts;
}

/**
 * Escape regex special characters.
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Generate candidate rules from common patterns in missed attacks.
 */
function generateCandidates(
  missed: AttackSample[],
  generation: number,
): CandidateRule[] {
  const patterns = findCommonPatterns(missed);
  const candidates: CandidateRule[] = [];

  // Sort by frequency
  const sorted = [...patterns.entries()]
    .filter(([, v]) => v.count >= 2) // Appears in 2+ missed samples
    .sort(([, a], [, b]) => b.count - a.count)
    .slice(0, 50);

  for (const [ngram, info] of sorted) {
    // Create flexible regex: allow variable whitespace
    const words = ngram.split(/\s+/);
    const flexPattern = words.map(escapeRegex).join("\\s+");

    const categorySamples = missed.filter((s) =>
      info.samples.includes(s.id),
    );
    const primaryCategory = categorySamples[0]?.category ?? "unknown";

    const severity: Severity =
      primaryCategory === "role_override" ||
      primaryCategory === "instruction_ignore" ||
      primaryCategory === "exfiltration"
        ? "critical"
        : primaryCategory === "tool_abuse" || primaryCategory === "authority_confusion"
          ? "high"
          : "medium";

    candidates.push({
      id: `evolved-gen${generation}-${candidates.length}`,
      severity,
      message: `Evolved rule: pattern "${ngram}" found in ${info.count} missed attacks`,
      pattern: new RegExp(flexPattern, "i"),
      truePositives: 0,
      falsePositives: 0,
      fitness: 0,
      generation,
      origin: "extracted",
    });
  }

  return candidates;
}

/**
 * Mutate a rule by widening or narrowing the pattern.
 */
function mutateRule(rule: CandidateRule, generation: number): CandidateRule {
  const source = rule.pattern.source;

  // Mutation strategies
  const mutations = [
    // Add optional word boundary
    () => `(?:^|\\s)${source}(?:\\s|$)`,
    // Make whitespace more flexible
    () => source.replace(/\\s\+/g, "\\s*"),
    // Add case-insensitive word variants
    () => source.replace(/\\s\+/g, "[\\s\\-_]*"),
  ];

  const mutation = mutations[generation % mutations.length];
  const mutated = mutation();

  return {
    ...rule,
    id: `evolved-gen${generation}-mut-${Math.random().toString(36).slice(2, 6)}`,
    pattern: new RegExp(mutated, "i"),
    truePositives: 0,
    falsePositives: 0,
    fitness: 0,
    generation,
    origin: "mutated",
  };
}

/**
 * Evaluate candidate rules against corpus and clean inputs.
 */
function evaluateCandidates(
  candidates: CandidateRule[],
  corpus: Corpus,
  cleanInputs: string[],
): CandidateRule[] {
  for (const candidate of candidates) {
    // Test against missed attacks (true positives)
    const missed = corpus.samples.filter((s) => !s.detected);
    for (const sample of missed) {
      if (candidate.pattern.test(sample.text)) {
        candidate.truePositives++;
      }
    }

    // Test against clean inputs (false positives)
    for (const clean of cleanInputs) {
      if (candidate.pattern.test(clean)) {
        candidate.falsePositives++;
      }
    }

    // Fitness = true positives - (false positives * 10)
    // Heavy penalty for false positives
    candidate.fitness =
      candidate.truePositives - candidate.falsePositives * 10;
  }

  return candidates;
}

/**
 * Run the evolution engine.
 *
 * @returns Array of evolved rules that improve detection without adding false positives.
 */
export function evolveRules(
  corpus: Corpus,
  config: EvolutionConfig = {},
): CandidateRule[] {
  const maxCandidates = config.maxCandidates ?? 20;
  const minFitness = config.minFitness ?? 1;
  const generations = config.generations ?? 3;
  const cleanInputs = config.cleanInputs ?? DEFAULT_CLEAN_INPUTS;

  const missed = corpus.samples.filter((s) => !s.detected);

  if (missed.length === 0) {
    return []; // Nothing to improve
  }

  let bestRules: CandidateRule[] = [];

  for (let gen = 0; gen < generations; gen++) {
    // Generate candidates from missed patterns
    let candidates = generateCandidates(missed, gen);

    // Add mutations of best rules from previous generation
    if (bestRules.length > 0) {
      const mutations = bestRules
        .slice(0, 5)
        .map((r) => mutateRule(r, gen));
      candidates = [...candidates, ...mutations];
    }

    // Cap candidates
    candidates = candidates.slice(0, maxCandidates);

    // Evaluate
    evaluateCandidates(candidates, corpus, cleanInputs);

    // Select best (fitness > threshold, no false positives preferred)
    const selected = candidates
      .filter((c) => c.fitness >= minFitness && c.falsePositives === 0)
      .sort((a, b) => b.fitness - a.fitness)
      .slice(0, 10);

    bestRules = [...bestRules, ...selected];
  }

  // Deduplicate by pattern
  const seen = new Set<string>();
  const unique: CandidateRule[] = [];
  for (const rule of bestRules.sort((a, b) => b.fitness - a.fitness)) {
    const key = rule.pattern.source;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(rule);
    }
  }

  return unique.slice(0, maxCandidates);
}

/**
 * Re-evaluate the entire corpus with current scanner + evolved rules.
 * Updates detected/matchedRules for each sample.
 */
export function reevaluateCorpus(
  corpus: Corpus,
  evolvedRules: CandidateRule[],
): { improved: number; stillMissed: number } {
  let improved = 0;
  let stillMissed = 0;

  // Convert CandidateRules to DetectionRules
  const customRules: DetectionRule[] = evolvedRules.map((r) => ({
    id: r.id,
    severity: r.severity,
    message: r.message,
    pattern: r.pattern,
  }));

  for (const sample of corpus.samples) {
    const result = scan(sample.text, {
      context: sample.context,
      customRules,
    });

    const wasDetected = sample.detected;
    sample.detected = result.injected;
    sample.matchedRules = result.findings.map((f) => f.ruleId);
    sample.severity = result.maxSeverity;

    if (!wasDetected && result.injected) {
      improved++;
    } else if (!result.injected) {
      stillMissed++;
    }
  }

  return { improved, stillMissed };
}

/**
 * Export evolved rules as DetectionRule[] for use in scanner.
 */
export function exportEvolvedRules(candidates: CandidateRule[]): DetectionRule[] {
  return candidates
    .filter((c) => c.fitness > 0 && c.falsePositives === 0)
    .map((c) => ({
      id: c.id,
      severity: c.severity,
      message: c.message,
      pattern: c.pattern,
    }));
}
