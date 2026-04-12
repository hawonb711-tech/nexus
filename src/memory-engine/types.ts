export type MemoryTier = "working" | "short_term" | "long_term" | "archive";

export type MemoryEntry = {
  id: string;
  content: string;
  summary?: string;
  embedding?: number[];
  tier: MemoryTier;
  tags: string[];
  projectId?: string;
  filePath?: string;
  createdAt: string;
  accessedAt: string;
  accessCount: number;
  relevanceScore: number;
  compressed: boolean;
};

export type MemoryQuery = {
  query: string;
  tags?: string[];
  projectId?: string;
  tier?: MemoryTier;
  limit?: number;
};

export type MemoryStats = {
  totalEntries: number;
  byTier: Record<MemoryTier, number>;
  totalSizeBytes: number;
  compressionRatio: number;
};
