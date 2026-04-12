import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import type { MemoryEntry, MemoryQuery, MemoryStats, MemoryTier } from "./types.js";
import { compressEntry, estimateSizeBytes } from "./compressor.js";

const TIERS: MemoryTier[] = ["working", "short_term", "long_term", "archive"];
const TIER_ORDER: Record<MemoryTier, number> = { working: 0, short_term: 1, long_term: 2, archive: 3 };
const PROMOTE_THRESHOLD = 5;
const DEMOTE_DAYS: Record<MemoryTier, number> = { working: 1, short_term: 7, long_term: 30, archive: Infinity };
const ARCHIVE_MAX_AGE_DAYS = 90;

const STOP_WORDS = new Set([
  "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
  "have", "has", "had", "do", "does", "did", "will", "would", "could",
  "should", "may", "might", "shall", "can", "need", "to", "of", "in",
  "for", "on", "with", "at", "by", "from", "as", "into", "through",
  "during", "before", "after", "all", "both", "each", "few", "more",
  "most", "other", "some", "such", "no", "not", "only", "so", "than",
  "too", "very", "just", "but", "and", "or", "if", "while", "that",
  "this", "it", "its", "i", "me", "my", "we", "our", "you", "your",
]);

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 1 && !STOP_WORDS.has(w));
}

function buildBowVector(tokens: string[], vocab: Map<string, number>): number[] {
  const vec = new Array<number>(vocab.size).fill(0);
  for (const t of tokens) {
    const idx = vocab.get(t);
    if (idx !== undefined) vec[idx]++;
  }
  return vec;
}

function cosineSimilarity(a: number[], b: number[]): number {
  let dot = 0;
  let magA = 0;
  let magB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }
  const denom = Math.sqrt(magA) * Math.sqrt(magB);
  return denom === 0 ? 0 : dot / denom;
}

function daysSince(isoDate: string): number {
  return (Date.now() - new Date(isoDate).getTime()) / (1000 * 60 * 60 * 24);
}

export type MemoryStore = {
  add(entry: Omit<MemoryEntry, "id" | "createdAt" | "accessedAt" | "accessCount" | "relevanceScore" | "compressed"> & Partial<Pick<MemoryEntry, "id" | "createdAt" | "accessedAt" | "accessCount" | "relevanceScore" | "compressed">>): MemoryEntry;
  get(id: string): MemoryEntry | undefined;
  search(query: MemoryQuery): MemoryEntry[];
  promote(id: string): MemoryEntry | undefined;
  demote(id: string): MemoryEntry | undefined;
  compress(id: string): MemoryEntry | undefined;
  prune(): number;
  getStats(): MemoryStats;
};

export function createMemoryStore(dataDir: string): MemoryStore {
  const memoryDir = join(dataDir, "memory");

  function ensureDirs(): void {
    for (const tier of TIERS) {
      const dir = join(memoryDir, tier);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
    }
  }

  function entryPath(tier: MemoryTier, id: string): string {
    return join(memoryDir, tier, `${id}.json`);
  }

  function writeEntry(entry: MemoryEntry): void {
    const p = entryPath(entry.tier, entry.id);
    writeFileSync(p, JSON.stringify(entry, null, 2), "utf-8");
  }

  function readEntry(tier: MemoryTier, id: string): MemoryEntry | undefined {
    const p = entryPath(tier, id);
    if (!existsSync(p)) return undefined;
    return JSON.parse(readFileSync(p, "utf-8")) as MemoryEntry;
  }

  function deleteEntry(tier: MemoryTier, id: string): void {
    const p = entryPath(tier, id);
    if (existsSync(p)) unlinkSync(p);
  }

  function allEntries(tier?: MemoryTier): MemoryEntry[] {
    const tiers = tier ? [tier] : TIERS;
    const entries: MemoryEntry[] = [];
    for (const t of tiers) {
      const dir = join(memoryDir, t);
      if (!existsSync(dir)) continue;
      const files = readdirSync(dir).filter((f) => f.endsWith(".json"));
      for (const f of files) {
        try {
          const data = readFileSync(join(dir, f), "utf-8");
          entries.push(JSON.parse(data) as MemoryEntry);
        } catch {
          // skip corrupt entries
        }
      }
    }
    return entries;
  }

  function findEntry(id: string): MemoryEntry | undefined {
    for (const tier of TIERS) {
      const entry = readEntry(tier, id);
      if (entry) return entry;
    }
    return undefined;
  }

  ensureDirs();

  return {
    add(partial) {
      const now = new Date().toISOString();
      const entry: MemoryEntry = {
        id: partial.id ?? randomUUID(),
        content: partial.content,
        summary: partial.summary,
        embedding: partial.embedding,
        tier: partial.tier ?? "working",
        tags: partial.tags ?? [],
        projectId: partial.projectId,
        filePath: partial.filePath,
        createdAt: partial.createdAt ?? now,
        accessedAt: partial.accessedAt ?? now,
        accessCount: partial.accessCount ?? 0,
        relevanceScore: partial.relevanceScore ?? 1.0,
        compressed: partial.compressed ?? false,
      };
      writeEntry(entry);
      return entry;
    },

    get(id) {
      const entry = findEntry(id);
      if (!entry) return undefined;
      entry.accessedAt = new Date().toISOString();
      entry.accessCount++;
      writeEntry(entry);

      if (entry.accessCount >= PROMOTE_THRESHOLD && TIER_ORDER[entry.tier] > 0) {
        const higherTier = TIERS[TIER_ORDER[entry.tier] - 1];
        deleteEntry(entry.tier, entry.id);
        entry.tier = higherTier;
        writeEntry(entry);
      }

      return entry;
    },

    search(query) {
      const candidates = allEntries(query.tier);
      let filtered = candidates;

      if (query.tags && query.tags.length > 0) {
        const tagSet = new Set(query.tags);
        filtered = filtered.filter((e) => e.tags.some((t) => tagSet.has(t)));
      }
      if (query.projectId) {
        filtered = filtered.filter((e) => e.projectId === query.projectId);
      }

      const queryTokens = tokenize(query.query);
      if (queryTokens.length === 0) {
        const limit = query.limit ?? 10;
        return filtered
          .sort((a, b) => new Date(b.accessedAt).getTime() - new Date(a.accessedAt).getTime())
          .slice(0, limit);
      }

      // Build vocabulary from all candidates + query
      const vocab = new Map<string, number>();
      let idx = 0;
      for (const t of queryTokens) {
        if (!vocab.has(t)) vocab.set(t, idx++);
      }
      for (const entry of filtered) {
        for (const t of tokenize(entry.content)) {
          if (!vocab.has(t)) vocab.set(t, idx++);
        }
      }

      // Compute IDF
      const docCount = filtered.length + 1;
      const df = new Map<string, number>();
      for (const entry of filtered) {
        const unique = new Set(tokenize(entry.content));
        for (const t of unique) {
          df.set(t, (df.get(t) ?? 0) + 1);
        }
      }
      const queryUnique = new Set(queryTokens);
      for (const t of queryUnique) {
        df.set(t, (df.get(t) ?? 0) + 1);
      }

      const idf = new Map<string, number>();
      for (const [term, count] of df) {
        idf.set(term, Math.log(docCount / count));
      }

      // Build reverse index for O(1) lookup instead of O(vocab_size) per term
      const indexToTerm = new Map<number, string>();
      for (const [term, idx] of vocab) {
        indexToTerm.set(idx, term);
      }

      // TF-IDF vectors
      function tfidfVector(tokens: string[]): number[] {
        const bow = buildBowVector(tokens, vocab);
        for (let i = 0; i < bow.length; i++) {
          if (bow[i] > 0) {
            const term = indexToTerm.get(i);
            if (term) {
              bow[i] *= idf.get(term) ?? 1;
            }
          }
        }
        return bow;
      }

      const queryVec = tfidfVector(queryTokens);

      const scored = filtered.map((entry) => {
        const entryTokens = tokenize(entry.content);
        const entryVec = tfidfVector(entryTokens);
        const similarity = cosineSimilarity(queryVec, entryVec);
        // Boost by access count and recency
        const recencyBoost = 1 / (1 + daysSince(entry.accessedAt) * 0.01);
        const accessBoost = 1 + Math.log1p(entry.accessCount) * 0.1;
        const score = similarity * recencyBoost * accessBoost;
        return { entry, score };
      });

      scored.sort((a, b) => b.score - a.score);

      const limit = query.limit ?? 10;
      return scored
        .filter((s) => s.score > 0)
        .slice(0, limit)
        .map((s) => {
          s.entry.relevanceScore = s.score;
          return s.entry;
        });
    },

    promote(id) {
      const entry = findEntry(id);
      if (!entry) return undefined;
      const currentOrder = TIER_ORDER[entry.tier];
      if (currentOrder === 0) return entry; // already at working

      const newTier = TIERS[currentOrder - 1];
      deleteEntry(entry.tier, entry.id);
      entry.tier = newTier;
      entry.accessedAt = new Date().toISOString();
      writeEntry(entry);
      return entry;
    },

    demote(id) {
      const entry = findEntry(id);
      if (!entry) return undefined;
      const currentOrder = TIER_ORDER[entry.tier];
      if (currentOrder === TIERS.length - 1) return entry; // already at archive

      const newTier = TIERS[currentOrder + 1];
      deleteEntry(entry.tier, entry.id);

      // Compress when demoting to long_term or archive
      let updated = entry;
      if (newTier === "long_term" || newTier === "archive") {
        updated = compressEntry(entry);
      }

      updated.tier = newTier;
      writeEntry(updated);
      return updated;
    },

    compress(id) {
      const entry = findEntry(id);
      if (!entry) return undefined;
      const compressed = compressEntry(entry);
      writeEntry(compressed);
      return compressed;
    },

    prune() {
      const archiveEntries = allEntries("archive");
      let pruned = 0;
      for (const entry of archiveEntries) {
        if (daysSince(entry.accessedAt) > ARCHIVE_MAX_AGE_DAYS) {
          deleteEntry("archive", entry.id);
          pruned++;
        }
      }

      // Auto-demote stale entries in other tiers
      for (const tier of TIERS) {
        if (tier === "archive") continue;
        const maxDays = DEMOTE_DAYS[tier];
        if (maxDays === Infinity) continue;
        const entries = allEntries(tier);
        for (const entry of entries) {
          if (daysSince(entry.accessedAt) > maxDays) {
            const currentOrder = TIER_ORDER[tier];
            const newTier = TIERS[currentOrder + 1];
            deleteEntry(tier, entry.id);
            let updated = entry;
            if (newTier === "long_term" || newTier === "archive") {
              updated = compressEntry(entry);
            }
            updated.tier = newTier;
            writeEntry(updated);
          }
        }
      }

      return pruned;
    },

    getStats() {
      const byTier: Record<MemoryTier, number> = { working: 0, short_term: 0, long_term: 0, archive: 0 };
      let totalEntries = 0;
      let totalSizeBytes = 0;
      let originalSize = 0;

      for (const tier of TIERS) {
        const entries = allEntries(tier);
        byTier[tier] = entries.length;
        totalEntries += entries.length;
        for (const entry of entries) {
          const size = estimateSizeBytes(entry);
          totalSizeBytes += size;
          // Estimate original size: if compressed, assume 3x expansion
          originalSize += entry.compressed ? size * 3 : size;
        }
      }

      return {
        totalEntries,
        byTier,
        totalSizeBytes,
        compressionRatio: originalSize === 0 ? 1 : totalSizeBytes / originalSize,
      };
    },
  };
}
