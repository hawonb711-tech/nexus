/**
 * Statistical analysis for detecting obfuscated or suspicious text segments.
 * Zero dependencies, pure TypeScript.
 */

import type { Severity } from "./types.js";

export type EntropyFinding = {
  type: string;
  message: string;
  severity: Severity;
  evidence: string;
  offset: number;
};

export type EntropyResult = {
  shannonEntropy: number;
  charFrequency: Map<string, number>;
  suspiciousPatterns: EntropyFinding[];
};

// Zero-width / control characters (same set as normalize.ts)
const ZERO_WIDTH_RE =
  /[\u200B-\u200F\u2060-\u2069\uFEFF\u202A-\u202E\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/;

// Unicode block classifiers
const LATIN_RE = /[\u0041-\u024F]/;
const CYRILLIC_RE = /[\u0400-\u04FF]/;
const CJK_RE = /[\u4E00-\u9FFF\u3400-\u4DBF]/;

/**
 * Calculate Shannon entropy (bits per character) for the full input string.
 */
export function shannonEntropy(input: string): number {
  if (input.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of input) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  const len = input.length;
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

/**
 * Build a character frequency map for the input.
 */
export function charFrequency(input: string): Map<string, number> {
  const freq = new Map<string, number>();
  for (const ch of input) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  return freq;
}

/**
 * Detect high-entropy segments using a sliding window.
 * Window size: 64 chars, threshold: 4.5 bits.
 */
export function detectHighEntropySegments(input: string): EntropyFinding[] {
  const findings: EntropyFinding[] = [];
  const windowSize = 64;
  const threshold = 4.5;

  if (input.length < windowSize) return findings;

  // Track ranges we've already flagged to avoid overlapping findings
  let lastFlaggedEnd = -1;

  for (let i = 0; i <= input.length - windowSize; i += 16) {
    if (i < lastFlaggedEnd) continue;

    const window = input.slice(i, i + windowSize);
    const e = shannonEntropy(window);
    if (e > threshold) {
      findings.push({
        type: "high-entropy-segment",
        message: `High entropy segment detected (${e.toFixed(2)} bits/char)`,
        severity: "medium",
        evidence: window.length > 80 ? window.slice(0, 80) + "..." : window,
        offset: i,
      });
      lastFlaggedEnd = i + windowSize;
    }
  }

  return findings;
}

/**
 * Detect low-entropy repetition: same character repeated 20+ times,
 * or same short pattern repeated 20+ times.
 */
export function detectLowEntropyRepetition(input: string): EntropyFinding[] {
  const findings: EntropyFinding[] = [];

  // Single character repeated 20+ times
  const singleCharRepeat = /(.)\1{19,}/g;
  let match: RegExpExecArray | null;
  while ((match = singleCharRepeat.exec(input)) !== null) {
    findings.push({
      type: "low-entropy-repetition",
      message: `Character '${match[1]}' repeated ${match[0].length} times`,
      severity: "low",
      evidence:
        match[0].length > 40 ? match[0].slice(0, 40) + "..." : match[0],
      offset: match.index,
    });
  }

  // Short pattern (2-8 chars) repeated 20+ times
  const patternRepeat = /(.{2,8}?)\1{19,}/g;
  while ((match = patternRepeat.exec(input)) !== null) {
    // Skip if it's just a single char repeat (already caught above)
    const uniqueChars = new Set(match[1]);
    if (uniqueChars.size === 1) continue;

    findings.push({
      type: "low-entropy-repetition",
      message: `Pattern '${match[1]}' repeated ${Math.floor(match[0].length / match[1].length)} times`,
      severity: "low",
      evidence:
        match[0].length > 60 ? match[0].slice(0, 60) + "..." : match[0],
      offset: match.index,
    });
  }

  return findings;
}

/**
 * Detect unusual Unicode block mixing within the same sentence.
 * Flags when Latin, Cyrillic, and CJK characters appear together.
 */
export function detectUnicodeMixing(input: string): EntropyFinding[] {
  const findings: EntropyFinding[] = [];

  // Split into rough sentence-like segments
  const sentences = input.split(/[.!?\n]+/);
  let offset = 0;

  for (const sentence of sentences) {
    const hasLatin = LATIN_RE.test(sentence);
    const hasCyrillic = CYRILLIC_RE.test(sentence);
    const hasCJK = CJK_RE.test(sentence);

    const scriptCount = [hasLatin, hasCyrillic, hasCJK].filter(Boolean).length;

    if (scriptCount >= 2 && hasCyrillic && hasLatin) {
      // Latin + Cyrillic mixing is the most suspicious (homoglyph attacks)
      findings.push({
        type: "unicode-block-mixing",
        message: "Mixed Latin and Cyrillic characters in same segment (possible homoglyph attack)",
        severity: "high",
        evidence:
          sentence.trim().length > 80
            ? sentence.trim().slice(0, 80) + "..."
            : sentence.trim(),
        offset,
      });
    } else if (scriptCount >= 3) {
      findings.push({
        type: "unicode-block-mixing",
        message: "Three or more Unicode script blocks mixed in same segment",
        severity: "medium",
        evidence:
          sentence.trim().length > 80
            ? sentence.trim().slice(0, 80) + "..."
            : sentence.trim(),
        offset,
      });
    }

    // +1 for the delimiter character consumed by split
    offset += sentence.length + 1;
  }

  return findings;
}

/**
 * Detect high density of invisible/control/zero-width characters.
 * Flags if >5% of characters are invisible.
 */
export function detectInvisibleCharDensity(input: string): EntropyFinding[] {
  const findings: EntropyFinding[] = [];
  if (input.length === 0) return findings;

  let invisibleCount = 0;
  for (const ch of input) {
    if (ZERO_WIDTH_RE.test(ch)) {
      invisibleCount++;
    }
  }

  const ratio = invisibleCount / input.length;
  if (ratio > 0.05) {
    findings.push({
      type: "invisible-char-density",
      message: `High invisible/control character density: ${(ratio * 100).toFixed(1)}% (${invisibleCount}/${input.length} chars)`,
      severity: "high",
      evidence: `${invisibleCount} invisible characters out of ${input.length} total`,
      offset: 0,
    });
  }

  return findings;
}

/**
 * Detect encoding fingerprints suggesting embedded encoded payloads.
 * High ratio of +/= suggests base64; high ratio of % suggests URL encoding.
 */
export function detectEncodingFingerprints(input: string): EntropyFinding[] {
  const findings: EntropyFinding[] = [];
  if (input.length < 20) return findings;

  // Base64 fingerprint: count of base64-alphabet chars (+, /, =)
  let base64SignalChars = 0;
  let urlEncodingChars = 0;

  for (const ch of input) {
    if (ch === "+" || ch === "=") base64SignalChars++;
    if (ch === "%") urlEncodingChars++;
  }

  const base64Ratio = base64SignalChars / input.length;
  const urlRatio = urlEncodingChars / input.length;

  // Also check for long stretches of base64-valid characters
  const base64Stretch = /[A-Za-z0-9+/=]{40,}/;
  const base64Match = base64Stretch.exec(input);

  if (base64Ratio > 0.03 && base64Match) {
    findings.push({
      type: "encoding-fingerprint-base64",
      message: `Text has base64 encoding fingerprint (${(base64Ratio * 100).toFixed(1)}% signal chars, long base64 stretch found)`,
      severity: "medium",
      evidence:
        base64Match[0].length > 60
          ? base64Match[0].slice(0, 60) + "..."
          : base64Match[0],
      offset: base64Match.index,
    });
  }

  // URL encoding: %XX pattern
  const urlEncodePattern = /%[0-9A-Fa-f]{2}/g;
  const urlMatches = input.match(urlEncodePattern);
  if (urlRatio > 0.05 && urlMatches && urlMatches.length > 5) {
    const firstPercent = input.indexOf("%");
    findings.push({
      type: "encoding-fingerprint-url",
      message: `Text has URL encoding fingerprint (${urlMatches.length} encoded sequences, ${(urlRatio * 100).toFixed(1)}% percent chars)`,
      severity: "medium",
      evidence: input.slice(
        firstPercent,
        Math.min(firstPercent + 60, input.length),
      ),
      offset: firstPercent,
    });
  }

  return findings;
}

/**
 * Run full entropy analysis on input text.
 */
export function analyzeEntropy(input: string): EntropyResult {
  const freq = charFrequency(input);
  const entropy = shannonEntropy(input);

  const suspiciousPatterns: EntropyFinding[] = [
    ...detectHighEntropySegments(input),
    ...detectLowEntropyRepetition(input),
    ...detectUnicodeMixing(input),
    ...detectInvisibleCharDensity(input),
    ...detectEncodingFingerprints(input),
  ];

  return {
    shannonEntropy: entropy,
    charFrequency: freq,
    suspiciousPatterns,
  };
}
