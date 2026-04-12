/**
 * Token-level analysis for prompt injection detection.
 * Examines statistical properties of input tokens to flag anomalies.
 * Zero dependencies — pure TypeScript.
 */

import type { Severity } from "./types.js";

export type TokenFinding = {
  type: string;
  message: string;
  severity: Severity;
  evidence: string;
  offset: number;
};

export type TokenAnalysis = {
  totalTokens: number;
  uniqueTokens: number;
  avgTokenLength: number;
  specialCharRatio: number;
  uppercaseRatio: number;
  suspiciousTokenDensity: number;
  findings: TokenFinding[];
};

/** Unicode ranges for script detection. */
const LATIN_RE = /[\u0041-\u024F]/;
const CYRILLIC_RE = /[\u0400-\u04FF]/;
const CJK_RE = /[\u4E00-\u9FFF\u3400-\u4DBF\uF900-\uFAFF]/;

/**
 * Tokenize input by splitting on whitespace and punctuation boundaries.
 * Returns tokens with their byte offsets in the original string.
 */
function tokenizeWithOffsets(input: string): Array<{ token: string; offset: number }> {
  const results: Array<{ token: string; offset: number }> = [];
  const re = /[^\s]+/g;
  let match: RegExpExecArray | null;

  while ((match = re.exec(input)) !== null) {
    results.push({ token: match[0], offset: match.index });
  }

  return results;
}

/**
 * Count characters matching a predicate in a string.
 */
function countChars(str: string, predicate: (ch: string) => boolean): number {
  let count = 0;
  for (const ch of str) {
    if (predicate(ch)) count++;
  }
  return count;
}

/**
 * Check if a single token contains mixed scripts (Latin + Cyrillic or Latin + CJK).
 */
function hasMixedScripts(token: string): boolean {
  const hasLatin = LATIN_RE.test(token);
  const hasCyrillic = CYRILLIC_RE.test(token);
  const hasCJK = CJK_RE.test(token);

  return (hasLatin && hasCyrillic) || (hasLatin && hasCJK);
}

/**
 * Detect consecutive ALL CAPS words (5+ in a row).
 * Returns findings with offsets.
 */
function detectExcessiveCaps(
  tokenEntries: Array<{ token: string; offset: number }>,
): TokenFinding[] {
  const findings: TokenFinding[] = [];
  const THRESHOLD = 5;

  let capsRun: Array<{ token: string; offset: number }> = [];

  for (const entry of tokenEntries) {
    // A token is ALL CAPS if it has 2+ alpha chars and all alpha chars are uppercase
    const alphaChars = entry.token.replace(/[^a-zA-Z]/g, "");
    const isAllCaps = alphaChars.length >= 2 && alphaChars === alphaChars.toUpperCase();

    if (isAllCaps) {
      capsRun.push(entry);
    } else {
      if (capsRun.length >= THRESHOLD) {
        const evidence = capsRun.map((e) => e.token).join(" ");
        findings.push({
          type: "excessive_caps",
          message: `${capsRun.length} consecutive ALL CAPS words detected`,
          severity: "medium",
          evidence: evidence.length > 100 ? evidence.slice(0, 100) + "..." : evidence,
          offset: capsRun[0].offset,
        });
      }
      capsRun = [];
    }
  }

  // Check trailing run
  if (capsRun.length >= THRESHOLD) {
    const evidence = capsRun.map((e) => e.token).join(" ");
    findings.push({
      type: "excessive_caps",
      message: `${capsRun.length} consecutive ALL CAPS words detected`,
      severity: "medium",
      evidence: evidence.length > 100 ? evidence.slice(0, 100) + "..." : evidence,
      offset: capsRun[0].offset,
    });
  }

  return findings;
}

/**
 * Detect tokens that are unusually long (>50 chars), which may indicate
 * encoded payloads (base64, hex, URL-encoded strings).
 */
function detectLongTokens(
  tokenEntries: Array<{ token: string; offset: number }>,
): TokenFinding[] {
  const findings: TokenFinding[] = [];
  const THRESHOLD = 50;

  for (const entry of tokenEntries) {
    if (entry.token.length > THRESHOLD) {
      findings.push({
        type: "long_token",
        message: `Unusually long token (${entry.token.length} chars), possible encoded payload`,
        severity: "medium",
        evidence: entry.token.length > 80 ? entry.token.slice(0, 80) + "..." : entry.token,
        offset: entry.offset,
      });
    }
  }

  return findings;
}

/**
 * Detect token repetition (same token appearing 10+ times).
 */
function detectTokenRepetition(
  tokenEntries: Array<{ token: string; offset: number }>,
): TokenFinding[] {
  const findings: TokenFinding[] = [];
  const THRESHOLD = 10;

  const counts = new Map<string, { count: number; firstOffset: number }>();

  for (const entry of tokenEntries) {
    const lower = entry.token.toLowerCase();
    const existing = counts.get(lower);
    if (existing) {
      existing.count++;
    } else {
      counts.set(lower, { count: 1, firstOffset: entry.offset });
    }
  }

  for (const [token, { count, firstOffset }] of counts) {
    if (count >= THRESHOLD) {
      findings.push({
        type: "token_repetition",
        message: `Token "${token}" repeated ${count} times`,
        severity: "low",
        evidence: `"${token}" x${count}`,
        offset: firstOffset,
      });
    }
  }

  return findings;
}

/**
 * Detect mixed script usage within individual tokens (e.g., Latin + Cyrillic).
 * This is a common technique for homoglyph attacks.
 */
function detectMixedScripts(
  tokenEntries: Array<{ token: string; offset: number }>,
): TokenFinding[] {
  const findings: TokenFinding[] = [];

  for (const entry of tokenEntries) {
    if (hasMixedScripts(entry.token)) {
      findings.push({
        type: "mixed_scripts",
        message: "Token contains mixed Unicode scripts (possible homoglyph attack)",
        severity: "high",
        evidence: entry.token,
        offset: entry.offset,
      });
    }
  }

  return findings;
}

/**
 * Analyze tokens in the input string for statistical anomalies
 * and suspicious patterns that may indicate prompt injection.
 */
export function analyzeTokens(input: string): TokenAnalysis {
  if (!input || input.length === 0) {
    return {
      totalTokens: 0,
      uniqueTokens: 0,
      avgTokenLength: 0,
      specialCharRatio: 0,
      uppercaseRatio: 0,
      suspiciousTokenDensity: 0,
      findings: [],
    };
  }

  const tokenEntries = tokenizeWithOffsets(input);
  const tokens = tokenEntries.map((e) => e.token);

  const totalTokens = tokens.length;
  const uniqueTokens = new Set(tokens.map((t) => t.toLowerCase())).size;

  const totalChars = input.length;
  const totalTokenChars = tokens.reduce((sum, t) => sum + t.length, 0);
  const avgTokenLength = totalTokens > 0 ? totalTokenChars / totalTokens : 0;

  // Special character ratio: non-alphanumeric, non-space characters
  const specialCharCount = countChars(input, (ch) => !/[a-zA-Z0-9\s]/.test(ch));
  const specialCharRatio = totalChars > 0 ? specialCharCount / totalChars : 0;

  // Uppercase ratio: uppercase letters / all letters
  const letterCount = countChars(input, (ch) => /[a-zA-Z]/.test(ch));
  const upperCount = countChars(input, (ch) => /[A-Z]/.test(ch));
  const uppercaseRatio = letterCount > 0 ? upperCount / letterCount : 0;

  // Collect findings
  const findings: TokenFinding[] = [];

  // 1. Excessive ALL CAPS sequences
  findings.push(...detectExcessiveCaps(tokenEntries));

  // 2. Unusual special character density
  if (specialCharRatio > 0.3 && totalChars > 10) {
    findings.push({
      type: "high_special_char_density",
      message: `Special character ratio is ${(specialCharRatio * 100).toFixed(1)}% (threshold: 30%)`,
      severity: "low",
      evidence: input.length > 80 ? input.slice(0, 80) + "..." : input,
      offset: 0,
    });
  }

  // 3. Very long tokens (possible encoded payloads)
  findings.push(...detectLongTokens(tokenEntries));

  // 4. Token repetition
  findings.push(...detectTokenRepetition(tokenEntries));

  // 5. Mixed script detection
  findings.push(...detectMixedScripts(tokenEntries));

  // Suspicious token density: findings weighted by severity / total tokens
  const severityWeights: Record<Severity, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };

  const findingWeight = findings.reduce(
    (sum, f) => sum + severityWeights[f.severity],
    0,
  );
  const suspiciousTokenDensity = totalTokens > 0
    ? Math.min(1.0, findingWeight / totalTokens)
    : 0;

  return {
    totalTokens,
    uniqueTokens,
    avgTokenLength: Math.round(avgTokenLength * 100) / 100,
    specialCharRatio: Math.round(specialCharRatio * 1000) / 1000,
    uppercaseRatio: Math.round(uppercaseRatio * 1000) / 1000,
    suspiciousTokenDensity: Math.round(suspiciousTokenDensity * 1000) / 1000,
    findings,
  };
}
