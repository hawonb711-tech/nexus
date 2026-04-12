/**
 * Pattern Evolution Engine
 *
 * A sophisticated algorithm that:
 * 1. Extracts task-completion patterns from sessions
 * 2. Captures surrounding context (why this task was needed)
 * 3. Finds similar past patterns across all sessions
 * 4. Analyzes WHY approaches changed between similar tasks
 * 5. Builds an evolution graph of how skills matured over time
 * 6. Generates refined skills incorporating full evolution history
 *
 * The core insight: a skill isn't just "what Claude did" —
 * it's WHY the approach was chosen given the context,
 * and HOW it evolved from earlier attempts.
 */

import { createHash } from "node:crypto";
import type { ParsedSession, ParsedMessage, ToolCall } from "../parser/types.js";

// ─── Types ───────────────────────────────────────────────────────

export type ContextWindow = {
  /** Messages leading up to the task (motivation, constraints, prior failures). */
  before: ParsedMessage[];
  /** The core task: user request + Claude execution. */
  core: TaskSequence;
  /** Messages after: user feedback, corrections, follow-ups. */
  after: ParsedMessage[];
};

export type TaskSequence = {
  /** User's original request. */
  request: ParsedMessage;
  /** Claude's response(s) with tool calls. */
  responses: ParsedMessage[];
  /** All tool calls made. */
  toolCalls: ToolCall[];
  /** Files touched. */
  files: string[];
  /** Was the outcome successful? (inferred from follow-up). */
  outcome: "success" | "failure" | "partial" | "unknown";
  /** User's feedback if any. */
  feedback?: string;
};

export type PatternFingerprint = {
  /** Unique hash of the pattern. */
  id: string;
  /** Action verb + object (e.g., "fix lint-errors"). */
  action: string;
  /** Normalized keywords from the request. */
  keywords: string[];
  /** Tool sequence signature (e.g., "Bash→Edit→Bash"). */
  toolSignature: string;
  /** Session this came from. */
  sessionId: string;
  /** Timestamp. */
  timestamp: string;
  /** Semantic vector (bag-of-words TF weights). */
  vector: Map<string, number>;
};

export type PatternMatch = {
  /** The pattern being compared to. */
  pattern: PatternFingerprint;
  /** Context window of this pattern. */
  context: ContextWindow;
  /** Similarity score 0-1. */
  similarity: number;
};

export type DriftAnalysis = {
  /** What changed between the two approaches. */
  changes: DriftChange[];
  /** Why it changed (inferred). */
  reason: DriftReason;
  /** Confidence in the analysis. */
  confidence: number;
};

export type DriftChange = {
  aspect: "tools" | "approach" | "files" | "order" | "scope";
  description: string;
  old: string;
  new: string;
};

export type DriftReason =
  | "user_correction"    // User explicitly said "no, do it this way"
  | "failure_recovery"   // Previous approach failed, this is the fix
  | "optimization"       // Same result, better method
  | "scope_change"       // Task expanded or narrowed
  | "context_dependent"  // Different context required different approach
  | "unknown";

export type EvolvedSkill = {
  id: string;
  name: string;
  description: string;
  /** Current best approach (latest successful). */
  currentApproach: {
    steps: string[];
    tools: string[];
    files: string[];
  };
  /** Full evolution history. */
  evolution: EvolutionEntry[];
  /** Contexts where this skill applies. */
  applicableContexts: string[];
  /** Contexts where this skill should NOT be used. */
  antiPatterns: string[];
  /** Confidence (higher = more validated). */
  confidence: number;
  /** How many times this pattern appeared. */
  occurrences: number;
  /** When first seen / last seen. */
  firstSeen: string;
  lastSeen: string;
};

export type EvolutionEntry = {
  timestamp: string;
  sessionId: string;
  approach: string[];
  outcome: "success" | "failure" | "partial" | "unknown";
  drift?: DriftAnalysis;
  contextSummary: string;
};

// ─── Stop words for keyword extraction ───────────────────────────

const STOP_WORDS = new Set([
  "the", "a", "an", "is", "are", "was", "were", "be", "been", "have", "has",
  "had", "do", "does", "did", "will", "would", "could", "should", "can",
  "i", "me", "my", "we", "you", "your", "he", "she", "it", "they", "them",
  "this", "that", "these", "those", "what", "which", "who", "how", "when",
  "and", "but", "or", "not", "no", "so", "if", "then", "for", "of", "to",
  "in", "on", "at", "by", "with", "from", "as", "into", "about", "up",
  "there", "here", "all", "each", "both", "few", "more", "some", "any",
  "just", "also", "than", "too", "very", "only", "now", "well",
  "please", "thanks", "ok", "okay", "sure", "yes",
]);

// ─── Core Algorithm ──────────────────────────────────────────────

/**
 * Step 1: Extract task sequences with context windows from a session.
 */
export function extractContextualPatterns(session: ParsedSession): ContextWindow[] {
  const messages = session.messages;
  const windows: ContextWindow[] = [];

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role !== "user") continue;

    // Look for a task: user message followed by assistant with tool calls
    const responses: ParsedMessage[] = [];
    const toolCalls: ToolCall[] = [];
    const files: string[] = [];
    let j = i + 1;

    while (j < messages.length && messages[j].role === "assistant") {
      const resp = messages[j];
      responses.push(resp);
      if (resp.toolCalls) {
        for (const tc of resp.toolCalls) {
          toolCalls.push(tc);
          const fp = tc.input["file_path"] ?? tc.input["path"];
          if (typeof fp === "string") files.push(fp);
        }
      }
      j++;
    }

    // Skip if no tool calls (just a chat, not a task)
    if (toolCalls.length === 0) {
      continue;
    }

    // Gather context: up to 3 messages before
    const beforeStart = Math.max(0, i - 3);
    const before = messages.slice(beforeStart, i);

    // Gather after: next user message and up to 2 more
    const afterMessages: ParsedMessage[] = [];
    let k = j;
    let afterCount = 0;
    while (k < messages.length && afterCount < 3) {
      afterMessages.push(messages[k]);
      afterCount++;
      k++;
    }

    // Infer outcome from follow-up
    const outcome = inferOutcome(msg, afterMessages);
    const feedback = extractFeedback(afterMessages);

    const core: TaskSequence = {
      request: msg,
      responses,
      toolCalls,
      files: [...new Set(files)],
      outcome,
      feedback,
    };

    windows.push({ before, core, after: afterMessages });

    // Skip to end of this sequence
    i = j - 1;
  }

  return windows;
}

/**
 * Step 2: Generate a fingerprint for a pattern (for similarity matching).
 */
export function fingerprintPattern(
  window: ContextWindow,
  sessionId: string,
): PatternFingerprint {
  const request = window.core.request.content;
  const keywords = extractKeywords(request);
  const action = extractAction(request);
  const toolSig = window.core.toolCalls.map((tc) => tc.name).join("→");
  const vector = buildTermVector(request);

  const hashInput = `${action}:${toolSig}:${keywords.slice(0, 5).join(",")}`;
  const id = createHash("sha256").update(hashInput).digest("hex").slice(0, 12);

  return {
    id,
    action,
    keywords,
    toolSignature: toolSig,
    sessionId,
    timestamp: window.core.request.timestamp,
    vector,
  };
}

/**
 * Step 3: Find similar patterns across all sessions.
 */
export function findSimilarPatterns(
  target: PatternFingerprint,
  allPatterns: { fingerprint: PatternFingerprint; context: ContextWindow }[],
  threshold = 0.3,
): PatternMatch[] {
  const matches: PatternMatch[] = [];

  for (const { fingerprint, context } of allPatterns) {
    if (fingerprint.id === target.id) continue; // skip self

    const similarity = computePatternSimilarity(target, fingerprint);
    if (similarity >= threshold) {
      matches.push({ pattern: fingerprint, context, similarity });
    }
  }

  return matches.sort((a, b) => b.similarity - a.similarity);
}

/**
 * Step 4: Analyze drift between two similar patterns.
 */
export function analyzeDrift(
  older: ContextWindow,
  newer: ContextWindow,
): DriftAnalysis {
  const changes: DriftChange[] = [];

  // Tool changes
  const oldTools = older.core.toolCalls.map((tc) => tc.name);
  const newTools = newer.core.toolCalls.map((tc) => tc.name);
  const oldToolSig = oldTools.join("→");
  const newToolSig = newTools.join("→");

  if (oldToolSig !== newToolSig) {
    changes.push({
      aspect: "tools",
      description: "Tool sequence changed",
      old: oldToolSig,
      new: newToolSig,
    });
  }

  // File scope changes
  const oldFiles = new Set(older.core.files);
  const newFiles = new Set(newer.core.files);
  const addedFiles = [...newFiles].filter((f) => !oldFiles.has(f));
  const removedFiles = [...oldFiles].filter((f) => !newFiles.has(f));

  if (addedFiles.length > 0 || removedFiles.length > 0) {
    changes.push({
      aspect: "files",
      description: `Files changed: +${addedFiles.length} -${removedFiles.length}`,
      old: [...oldFiles].join(", "),
      new: [...newFiles].join(", "),
    });
  }

  // Scope change (tool count difference)
  const toolCountDiff = newTools.length - oldTools.length;
  if (Math.abs(toolCountDiff) >= 3) {
    changes.push({
      aspect: "scope",
      description: toolCountDiff > 0
        ? `Scope expanded (${oldTools.length}→${newTools.length} tool calls)`
        : `Scope narrowed (${oldTools.length}→${newTools.length} tool calls)`,
      old: String(oldTools.length),
      new: String(newTools.length),
    });
  }

  // Order changes (same tools, different sequence)
  const oldToolSet = new Set(oldTools);
  const newToolSet = new Set(newTools);
  const sameTools = [...oldToolSet].every((t) => newToolSet.has(t)) &&
    [...newToolSet].every((t) => oldToolSet.has(t));
  if (sameTools && oldToolSig !== newToolSig) {
    changes.push({
      aspect: "order",
      description: "Same tools used in different order",
      old: oldToolSig,
      new: newToolSig,
    });
  }

  // Determine reason
  const reason = inferDriftReason(older, newer, changes);

  // Confidence based on evidence
  const confidence = Math.min(1, 0.3 + changes.length * 0.15 +
    (reason !== "unknown" ? 0.2 : 0));

  return { changes, reason, confidence };
}

/**
 * Step 5: Build an evolved skill from a pattern and its history.
 */
export function buildEvolvedSkill(
  primary: { fingerprint: PatternFingerprint; context: ContextWindow },
  history: PatternMatch[],
): EvolvedSkill {
  // Sort all occurrences chronologically
  const allOccurrences = [
    { fp: primary.fingerprint, ctx: primary.context },
    ...history.map((m) => ({ fp: m.pattern, ctx: m.context })),
  ].sort((a, b) => a.fp.timestamp.localeCompare(b.fp.timestamp));

  // Build evolution timeline
  const evolution: EvolutionEntry[] = [];
  for (let i = 0; i < allOccurrences.length; i++) {
    const { fp, ctx } = allOccurrences[i];
    const steps = ctx.core.toolCalls.map((tc) => {
      const fileArg = tc.input["file_path"] ?? tc.input["path"] ?? tc.input["command"] ?? "";
      return `${tc.name}: ${String(fileArg).slice(0, 80)}`;
    });

    const entry: EvolutionEntry = {
      timestamp: fp.timestamp,
      sessionId: fp.sessionId,
      approach: steps,
      outcome: ctx.core.outcome,
      contextSummary: summarizeContext(ctx),
    };

    // Analyze drift from previous occurrence
    if (i > 0) {
      entry.drift = analyzeDrift(allOccurrences[i - 1].ctx, ctx);
    }

    evolution.push(entry);
  }

  // Extract anti-patterns from failures
  const antiPatterns: string[] = [];
  for (const entry of evolution) {
    if (entry.outcome === "failure" && entry.drift) {
      for (const change of entry.drift.changes) {
        antiPatterns.push(`Avoid: ${change.old} (changed to ${change.new})`);
      }
    }
  }

  // Extract applicable contexts from successful entries
  const applicableContexts = evolution
    .filter((e) => e.outcome === "success" || e.outcome === "unknown")
    .map((e) => e.contextSummary)
    .filter((s) => s.length > 0);

  // Current best approach = latest successful
  const latestSuccess = [...evolution]
    .reverse()
    .find((e) => e.outcome === "success" || e.outcome === "unknown");

  const currentApproach = latestSuccess
    ? {
        steps: latestSuccess.approach,
        tools: [...new Set(latestSuccess.approach.map((s) => s.split(":")[0]))],
        files: primary.context.core.files,
      }
    : {
        steps: evolution[evolution.length - 1]?.approach ?? [],
        tools: primary.fingerprint.toolSignature.split("→"),
        files: primary.context.core.files,
      };

  // Confidence: more occurrences + more successes = higher
  const successCount = evolution.filter((e) => e.outcome === "success").length;
  const confidence = Math.min(1,
    0.2 +
    (allOccurrences.length * 0.1) +
    (successCount * 0.15) +
    (evolution.some((e) => e.drift) ? 0.1 : 0),
  );

  return {
    id: primary.fingerprint.id,
    name: primary.fingerprint.action,
    description: buildDescription(primary, history),
    currentApproach,
    evolution,
    applicableContexts: [...new Set(applicableContexts)].slice(0, 5),
    antiPatterns: [...new Set(antiPatterns)].slice(0, 5),
    confidence,
    occurrences: allOccurrences.length,
    firstSeen: allOccurrences[0].fp.timestamp,
    lastSeen: allOccurrences[allOccurrences.length - 1].fp.timestamp,
  };
}

/**
 * Step 6: Run the full pipeline across multiple sessions.
 */
export function analyzePatternEvolution(sessions: ParsedSession[]): EvolvedSkill[] {
  // Phase 1: Extract all contextual patterns
  const allPatterns: { fingerprint: PatternFingerprint; context: ContextWindow }[] = [];

  for (const session of sessions) {
    const windows = extractContextualPatterns(session);
    for (const window of windows) {
      const fingerprint = fingerprintPattern(window, session.sessionId);
      allPatterns.push({ fingerprint, context: window });
    }
  }

  if (allPatterns.length === 0) return [];

  // Phase 2: Cluster similar patterns
  const processed = new Set<string>();
  const evolvedSkills: EvolvedSkill[] = [];

  for (const pattern of allPatterns) {
    if (processed.has(pattern.fingerprint.id)) continue;

    const similar = findSimilarPatterns(pattern.fingerprint, allPatterns, 0.25);

    // Mark all as processed
    processed.add(pattern.fingerprint.id);
    for (const match of similar) {
      processed.add(match.pattern.id);
    }

    // Only create skills for patterns that appeared 2+ times or had tool calls
    if (similar.length > 0 || pattern.context.core.toolCalls.length >= 3) {
      const skill = buildEvolvedSkill(pattern, similar);
      evolvedSkills.push(skill);
    }
  }

  // Sort by confidence * occurrences
  return evolvedSkills
    .sort((a, b) => (b.confidence * b.occurrences) - (a.confidence * a.occurrences));
}

// ─── Helper Functions ────────────────────────────────────────────

function extractKeywords(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z가-힣0-9\s-]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 2 && !STOP_WORDS.has(w))
    .filter((w) => !/^[0-9]+$/.test(w));
}

function extractAction(text: string): string {
  const words = text.toLowerCase().split(/\s+/).slice(0, 10);

  const verbs = [
    "fix", "add", "create", "build", "update", "remove", "delete", "refactor",
    "implement", "write", "setup", "configure", "install", "deploy", "test",
    "debug", "analyze", "review", "optimize", "migrate", "convert", "check",
    "scan", "validate", "generate", "export", "import", "push", "commit",
  ];
  const verb = words.find((w) => verbs.includes(w)) ?? words[0] ?? "task";

  // Find object: first noun-like word after the verb
  const verbIdx = words.indexOf(verb);
  const objectWords = words.slice(verbIdx + 1).filter((w) => !STOP_WORDS.has(w));
  const object = objectWords[0] ?? "unknown";

  return `${verb}-${object}`;
}

function buildTermVector(text: string): Map<string, number> {
  const words = extractKeywords(text);
  const tf = new Map<string, number>();
  for (const word of words) {
    tf.set(word, (tf.get(word) ?? 0) + 1);
  }
  // Normalize
  const max = Math.max(...tf.values(), 1);
  for (const [term, count] of tf) {
    tf.set(term, count / max);
  }
  return tf;
}

function computePatternSimilarity(
  a: PatternFingerprint,
  b: PatternFingerprint,
): number {
  // Weighted combination of:
  // 1. Keyword overlap (Jaccard) — 40%
  // 2. Tool signature similarity — 30%
  // 3. Term vector cosine similarity — 30%

  // Keyword Jaccard
  const aSet = new Set(a.keywords);
  const bSet = new Set(b.keywords);
  const intersection = [...aSet].filter((k) => bSet.has(k)).length;
  const union = new Set([...aSet, ...bSet]).size;
  const jaccard = union > 0 ? intersection / union : 0;

  // Tool signature: longest common subsequence ratio
  const toolSim = lcsRatio(a.toolSignature.split("→"), b.toolSignature.split("→"));

  // Cosine similarity of term vectors
  const cosine = cosineSimilarity(a.vector, b.vector);

  return jaccard * 0.4 + toolSim * 0.3 + cosine * 0.3;
}

function lcsRatio(a: string[], b: string[]): number {
  if (a.length === 0 || b.length === 0) return 0;

  const dp: number[][] = Array.from({ length: a.length + 1 }, () =>
    new Array(b.length + 1).fill(0),
  );

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  const lcsLen = dp[a.length][b.length];
  return (2 * lcsLen) / (a.length + b.length);
}

function cosineSimilarity(a: Map<string, number>, b: Map<string, number>): number {
  let dot = 0;
  let normA = 0;
  let normB = 0;

  for (const [term, weight] of a) {
    normA += weight * weight;
    if (b.has(term)) {
      dot += weight * (b.get(term) ?? 0);
    }
  }
  for (const [, weight] of b) {
    normB += weight * weight;
  }

  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom > 0 ? dot / denom : 0;
}

function inferOutcome(
  _request: ParsedMessage,
  afterMessages: ParsedMessage[],
): "success" | "failure" | "partial" | "unknown" {
  if (afterMessages.length === 0) return "unknown";

  const nextUser = afterMessages.find((m) => m.role === "user");
  if (!nextUser) return "unknown";

  const text = nextUser.content.toLowerCase();

  // Failure signals
  const failureSignals = [
    "안돼", "안 돼", "틀렸", "잘못", "wrong", "error", "fail", "doesn't work",
    "not working", "broken", "bug", "fix this", "try again", "다시",
    "아닌데", "그게 아니라",
  ];
  if (failureSignals.some((s) => text.includes(s))) return "failure";

  // Success signals
  const successSignals = [
    "좋아", "완벽", "됐어", "됐다", "고마워", "감사", "good", "perfect",
    "great", "thanks", "works", "nice", "잘됐", "오케이", "ㅇㅇ", "ㄱㄱ",
    "next", "다음", "이제",
  ];
  if (successSignals.some((s) => text.includes(s))) return "success";

  // If user just continues with a new task, probably success
  if (!text.includes("?") && text.length < 100) return "success";

  return "unknown";
}

function extractFeedback(afterMessages: ParsedMessage[]): string | undefined {
  const nextUser = afterMessages.find((m) => m.role === "user");
  if (!nextUser) return undefined;

  const text = nextUser.content;
  // Only return as feedback if it's short (likely a reaction, not a new task)
  if (text.length > 200) return undefined;
  return text;
}

function inferDriftReason(
  older: ContextWindow,
  newer: ContextWindow,
  changes: DriftChange[],
): DriftReason {
  // Check if older failed and newer is a recovery
  if (older.core.outcome === "failure") return "failure_recovery";

  // Check if user explicitly corrected
  if (older.core.feedback) {
    const fb = older.core.feedback.toLowerCase();
    const correctionWords = [
      "no", "wrong", "not", "don't", "instead", "아니", "말고", "다른",
      "그게 아니라", "이렇게", "대신",
    ];
    if (correctionWords.some((w) => fb.includes(w))) return "user_correction";
  }

  // Check scope change
  if (changes.some((c) => c.aspect === "scope")) return "scope_change";

  // Check if same tools but different order (optimization)
  if (changes.length === 1 && changes[0].aspect === "order") return "optimization";

  // Check if context is very different
  const olderCtx = summarizeContext(older).toLowerCase();
  const newerCtx = summarizeContext(newer).toLowerCase();
  const contextOverlap = computeTextOverlap(olderCtx, newerCtx);
  if (contextOverlap < 0.3) return "context_dependent";

  return "unknown";
}

function computeTextOverlap(a: string, b: string): number {
  const aWords = new Set(a.split(/\s+/));
  const bWords = new Set(b.split(/\s+/));
  const intersection = [...aWords].filter((w) => bWords.has(w)).length;
  const union = new Set([...aWords, ...bWords]).size;
  return union > 0 ? intersection / union : 0;
}

function summarizeContext(ctx: ContextWindow): string {
  const parts: string[] = [];

  // What came before (motivation)
  for (const msg of ctx.before) {
    if (msg.role === "user" && msg.content.length < 200) {
      parts.push(msg.content.slice(0, 100));
    }
  }

  // The request itself
  parts.push(ctx.core.request.content.slice(0, 150));

  return parts.join(" | ").slice(0, 300);
}

function buildDescription(
  primary: { fingerprint: PatternFingerprint; context: ContextWindow },
  history: PatternMatch[],
): string {
  const action = primary.fingerprint.action;
  const occurrences = history.length + 1;
  const tools = primary.fingerprint.toolSignature;

  let desc = `${action} (seen ${occurrences}x, tools: ${tools})`;

  if (history.length > 0) {
    const latestDrift = history[history.length - 1];
    const drift = analyzeDrift(
      history.length > 1 ? history[history.length - 2].context : primary.context,
      latestDrift.context,
    );
    if (drift.reason !== "unknown") {
      desc += `. Approach evolved due to ${drift.reason.replace(/_/g, " ")}`;
    }
  }

  return desc;
}
