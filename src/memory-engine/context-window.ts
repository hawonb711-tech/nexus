import type { MemoryStore } from "./store.js";
import type { MemoryTier } from "./types.js";

export type ContextWindowConfig = {
  maxTokens: number;
  store: MemoryStore;
};

export type ContextWindow = {
  load(query: string): string;
  save(content: string, tags: string[]): void;
  summarizeAndArchive(): void;
  getContextSize(): number;
};

const TIER_LABELS: Record<MemoryTier, string> = {
  working: "Working Memory",
  short_term: "Short-Term Memory",
  long_term: "Long-Term Memory",
  archive: "Archive",
};

function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

export function createContextWindow(config: ContextWindowConfig): ContextWindow {
  const { maxTokens, store } = config;
  let currentContext = "";

  function formatEntries(entries: { tier: MemoryTier; content: string; tags: string[] }[]): string {
    const sections = new Map<MemoryTier, string[]>();

    for (const entry of entries) {
      if (!sections.has(entry.tier)) {
        sections.set(entry.tier, []);
      }
      sections.get(entry.tier)!.push(entry.content);
    }

    const parts: string[] = [];
    const tierOrder: MemoryTier[] = ["working", "short_term", "long_term", "archive"];
    for (const tier of tierOrder) {
      const items = sections.get(tier);
      if (!items || items.length === 0) continue;
      parts.push(`=== ${TIER_LABELS[tier]} ===`);
      for (const item of items) {
        parts.push(item);
        parts.push("---");
      }
    }

    return parts.join("\n");
  }

  return {
    load(query) {
      const budgetTokens = maxTokens;
      const results = store.search({ query, limit: 50 });

      const selected: typeof results = [];
      let tokenCount = 0;

      for (const entry of results) {
        const entryTokens = estimateTokens(entry.content);
        if (tokenCount + entryTokens > budgetTokens) break;
        selected.push(entry);
        tokenCount += entryTokens;
      }

      currentContext = formatEntries(selected);
      return currentContext;
    },

    save(content, tags) {
      store.add({
        content,
        tags,
        tier: "working",
      });
    },

    summarizeAndArchive() {
      // Trigger pruning which auto-demotes stale entries across tiers
      store.prune();

      // Additionally, compress any working memory entries that have been accessed
      // but are getting old relative to working memory expectations
      const workingEntries = store.search({ query: "", tier: "working", limit: 100 });
      for (const entry of workingEntries) {
        const ageHours = (Date.now() - new Date(entry.accessedAt).getTime()) / (1000 * 60 * 60);
        if (ageHours > 6 && entry.accessCount < 3) {
          store.demote(entry.id);
        }
      }

      // Compress short-term entries that are aging
      const shortTermEntries = store.search({ query: "", tier: "short_term", limit: 100 });
      for (const entry of shortTermEntries) {
        const ageDays = (Date.now() - new Date(entry.accessedAt).getTime()) / (1000 * 60 * 60 * 24);
        if (ageDays > 3 && !entry.compressed) {
          store.compress(entry.id);
        }
      }

      currentContext = "";
    },

    getContextSize() {
      return estimateTokens(currentContext);
    },
  };
}
