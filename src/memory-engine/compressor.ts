import type { MemoryEntry } from "./types.js";

const STOP_WORDS = new Set([
  "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
  "have", "has", "had", "do", "does", "did", "will", "would", "could",
  "should", "may", "might", "shall", "can", "need", "dare", "ought",
  "used", "to", "of", "in", "for", "on", "with", "at", "by", "from",
  "as", "into", "through", "during", "before", "after", "above", "below",
  "between", "out", "off", "over", "under", "again", "further", "then",
  "once", "here", "there", "when", "where", "why", "how", "all", "both",
  "each", "few", "more", "most", "other", "some", "such", "no", "nor",
  "not", "only", "own", "same", "so", "than", "too", "very", "just",
  "because", "but", "and", "or", "if", "while", "that", "this", "it",
  "its", "i", "me", "my", "we", "our", "you", "your", "he", "him",
  "his", "she", "her", "they", "them", "their", "what", "which", "who",
]);

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 1 && !STOP_WORDS.has(w));
}

function scoreLineByKeywordDensity(line: string, globalFreq: Map<string, number>): number {
  const tokens = tokenize(line);
  if (tokens.length === 0) return 0;
  let score = 0;
  for (const token of tokens) {
    score += globalFreq.get(token) ?? 0;
  }
  return score / tokens.length;
}

export function extractKeyLines(text: string, maxLines: number): string[] {
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length <= maxLines) return lines;

  const allTokens = tokenize(text);
  const freq = new Map<string, number>();
  for (const t of allTokens) {
    freq.set(t, (freq.get(t) ?? 0) + 1);
  }

  const scored = lines.map((line, idx) => ({
    line,
    idx,
    score: scoreLineByKeywordDensity(line, freq),
  }));

  scored.sort((a, b) => b.score - a.score);
  const selected = scored.slice(0, maxLines);
  selected.sort((a, b) => a.idx - b.idx);

  return selected.map((s) => s.line);
}

export function compressEntry(entry: MemoryEntry): MemoryEntry {
  if (entry.compressed) return entry;

  const lines = entry.content.split("\n").filter((l) => l.trim().length > 0);
  let summary: string;

  if (lines.length <= 3) {
    summary = entry.content;
  } else {
    const firstSentence = extractFirstSentence(entry.content);
    const keyLines = extractKeyLines(entry.content, Math.max(3, Math.ceil(lines.length * 0.2)));
    const parts = [firstSentence];
    for (const kl of keyLines) {
      if (kl !== firstSentence && !parts.includes(kl)) {
        parts.push(kl);
      }
    }
    summary = parts.join("\n");
  }

  return {
    ...entry,
    summary,
    content: summary,
    compressed: true,
  };
}

function extractFirstSentence(text: string): string {
  const match = text.match(/^[^\n]*?[.!?](?:\s|$)/);
  if (match) return match[0].trim();
  const firstLine = text.split("\n")[0] ?? "";
  return firstLine.slice(0, 200);
}

export function estimateSizeBytes(entry: MemoryEntry): number {
  const json = JSON.stringify(entry);
  return Buffer.byteLength(json, "utf-8");
}
