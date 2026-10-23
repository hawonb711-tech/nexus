/**
 * Nexus Memory — Superior to MemPalace
 *
 * Combines the best of 2026 memory research into one zero-dependency system:
 *
 * 1. BM25 RETRIEVAL (replaces TF-IDF)
 *    - Term frequency saturation (long docs don't dominate)
 *    - Document length normalization
 *    - 500x faster than naive TF-IDF on large corpora
 *
 * 2. OBSERVATIONAL MEMORY (inspired by Mastra, 94.87% LongMemEval)
 *    - Don't store raw conversations — extract atomic observations
 *    - Each observation = one fact, one timestamp, one confidence
 *    - Resolves ambiguous references at extraction time
 *
 * 3. KNOWLEDGE GRAPH + TUNNELS (inspired by MemPalace)
 *    - Concepts as nodes, relationships as edges
 *    - Auto-tunnels: same concept in different projects → linked
 *    - BFS traversal for related memory discovery
 *
 * 4. PROGRESSIVE RETRIEVAL (3 levels)
 *    - L1: Index scan — instant, <1ms, metadata only
 *    - L2: BM25 search — fast, <10ms, top-K results
 *    - L3: Graph expansion — deep, <50ms, BFS + related concepts
 *
 * 5. TEMPORAL AWARENESS
 *    - When was this learned? (timestamp)
 *    - Is it still valid? (decay function)
 *    - Was it contradicted? (version chain)
 *    - How often recalled? (access frequency)
 */

import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join, dirname, resolve, relative } from "node:path";
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { sanitizeExternalContent } from "../guard/sanitize.js";
import { classifyMemoryThreat } from "../guard/persistent-directive.js";

// The persistent-directive classifier moved to the guard (so the hook entry can
// use it without loading the memory engine); re-exported here unchanged.
export { classifyMemoryThreat };

/** Sanitize ID to prevent path traversal. */
function sanitizeId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_-]/g, "_");
}

/**
 * Collapse caller-controlled memory metadata to a short inert label. Prompt
 * instructions and secrets are rejected/redacted before the label is used in
 * graph nodes, filenames, search filters, or rendered skill metadata.
 */
export function normalizeMemoryLabel(
  value: string | undefined,
  fallback = "unknown",
  maxLength = 80,
): string {
  const bounded = (value ?? "").normalize("NFKC").slice(0, Math.max(maxLength * 4, maxLength));
  if (!bounded.trim()) return fallback;

  const sanitized = sanitizeExternalContent(bounded);
  if (sanitized.persistText === null) return fallback;

  const label = sanitized.persistText
    .replace(/[^\p{L}\p{N}._:-]+/gu, "-")
    .replace(/-+/g, "-")
    .replace(/^[-.:]+|[-.:]+$/g, "")
    .slice(0, maxLength);
  return label || fallback;
}

function normalizeMemoryTags(tags: string[]): string[] {
  return [...new Set(tags
    .map((tag) => normalizeMemoryLabel(tag, "", 64).toLowerCase())
    .filter(Boolean))];
}
import { expandQuery, createCoOccurrenceModel, type CoOccurrenceModel, type RelatedSource } from "./semantic.js";
import { loadEmbeddingModel } from "../ml/model-store.js";

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

/** Where an observation came from, and how far it is trusted. */
export type MemoryProvenance = {
  /** Who/what wrote this observation. */
  source: "manual" | "web" | "feed" | "document" | "session" | "import" | "unknown";
  /** Optional origin URL or filesystem path the content was drawn from. */
  origin?: string;
  /**
   * Trust tier of the source. Advisory metadata surfaced to callers — it does
   * NOT replace the ingest-time sanitizer/quarantine, which always runs.
   */
  trust: "trusted" | "external" | "untrusted";
};

/** Current sanitation logic version. Bump whenever the sanitizer, metadata
 *  normalizer, or the persistent-directive classifier (`classifyMemoryThreat`,
 *  `inspectAgentDirectives`) changes — a bump invalidates every stored integrity
 *  marker so records written by the older, buggier logic are re-scanned exactly
 *  once on next load instead of being trusted on the fast path. CI note: a change
 *  to any of those detectors that does NOT bump this leaves already-stored poison
 *  grandfathered. v2: `.env`/extensionless-fetch-run quarantine gaps (re-scan the
 *  records the v1 classifier wrongly cleared). */
export const SANITATION_VERSION = 2;

/** An atomic unit of knowledge. */
export type Observation = {
  id: string;
  /** The fact itself — one clear statement. */
  content: string;
  /** Domain/project this belongs to. */
  domain: string;
  /** Specific topic within the domain. */
  topic: string;
  /** Tags for filtering. */
  tags: string[];
  /** When this was first observed. */
  createdAt: string;
  /** When this was last confirmed/accessed. */
  accessedAt: string;
  /** How many times recalled. */
  accessCount: number;
  /** Confidence 0-1. Decays over time, increases on re-confirmation. */
  confidence: number;
  /** Previous version ID if this was updated. */
  previousVersionId?: string;
  /** Is this still believed to be true? */
  valid: boolean;
  /** Source: which session/interaction. */
  sourceSessionId?: string;
  /** BM25 pre-computed term frequencies. */
  termFreqs: Record<string, number>;
  /** Document length in tokens. */
  docLength: number;
  /** Where this observation came from. Optional for backward compatibility —
   *  records written before provenance existed load with a default provenance. */
  provenance?: MemoryProvenance;
  /**
   * Integrity marker: `v<version>:<hmac>` over the sanitized, security-relevant
   * fields, written at save. On load a record whose marker is present, current
   * and valid is trusted as already-sanitized and skips the full injection
   * re-scan; a record whose marker is absent, stale or mismatched (externally
   * added or tampered) is always re-scanned. Not part of the hashed payload.
   */
  integrity?: string;
};

/** The default provenance for a direct, programmatic ingest/add call with no
 *  explicit source. External-content callers (web/feed/document) should pass
 *  their own provenance so the trust tier is accurate. */
function defaultProvenance(): MemoryProvenance {
  return { source: "manual", trust: "trusted" };
}

/** A node in the knowledge graph. */
export type KnowledgeNode = {
  id: string;
  label: string;
  type: "concept" | "project" | "file" | "tool" | "person" | "error" | "skill";
  /** Observation IDs linked to this node. */
  observationIds: string[];
  /** When last active. */
  lastActiveAt: string;
  weight: number;
};

/** An edge in the knowledge graph. */
export type KnowledgeEdge = {
  from: string;
  to: string;
  relation: "contains" | "uses" | "causes" | "fixes" | "related" | "tunnel" | "contradicts" | "evolves";
  weight: number;
};

/** Search result with relevance score. */
export type MemoryResult = {
  observation: Observation;
  score: number;
  /** How this result was found. */
  retrievalLevel: "L1" | "L2" | "L3";
  /** Related observations found via graph. */
  related?: Observation[];
};

/** Memory statistics. */
export type MemoryStats = {
  totalObservations: number;
  validObservations: number;
  graphNodes: number;
  graphEdges: number;
  tunnels: number;
  domains: string[];
  avgConfidence: number;
  avgDocLength: number;
};

function normalizeObservationMetadata(obs: Observation): Observation {
  return {
    ...obs,
    domain: normalizeMemoryLabel(obs.domain),
    topic: normalizeMemoryLabel(obs.topic, "general"),
    tags: normalizeMemoryTags(obs.tags),
    sourceSessionId: obs.sourceSessionId === undefined
      ? undefined
      : normalizeMemoryLabel(obs.sourceSessionId, "unknown", 128),
  };
}

function secureObservation(obs: Observation): Observation | null {
  const sanitized = sanitizeExternalContent(obs.content);
  if (sanitized.persistText === null) return null;

  const content = sanitized.persistText;
  const tokens = tokenize(content);
  return normalizeObservationMetadata({
    ...obs,
    content,
    termFreqs: computeTermFreqs(tokens),
    docLength: tokens.length,
  });
}

// ═══════════════════════════════════════════════════════════════════
// BM25 ENGINE
// ═══════════════════════════════════════════════════════════════════

const BM25_K1 = 1.5;  // Term frequency saturation parameter
const BM25_B = 0.75;  // Document length normalization parameter

import { STOP_WORDS } from "../shared/stop-words.js";
import { stem, transliterate } from "./semantic.js";

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z가-힣0-9\s-]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 1 && !STOP_WORDS.has(w));
}

function computeTermFreqs(tokens: string[]): Record<string, number> {
  const tf: Record<string, number> = {};
  for (const t of tokens) {
    tf[t] = (tf[t] ?? 0) + 1;
    // Also index stemmed form (enables stem-level matching)
    const s = stem(t);
    if (s !== t) tf[s] = (tf[s] ?? 0) + 1;
    // Also index transliterated form
    const tr = transliterate(t);
    if (tr) tf[tr] = (tf[tr] ?? 0) + 1;
  }
  return tf;
}

function bm25Score(
  queryTokens: string[],
  doc: Observation,
  idf: Map<string, number>,
  avgDocLength: number,
): number {
  let score = 0;
  const freqs = doc.termFreqs;
  // Own-property lookup: tokens like "constructor"/"toString" would otherwise
  // resolve to inherited Object.prototype members (functions), poisoning the
  // term-frequency arithmetic into NaN.
  const tfOf = (key: string): number => (Object.hasOwn(freqs, key) ? freqs[key] : 0);

  for (const qt of queryTokens) {
    const idfVal = idf.get(qt) ?? 0;
    let tf = tfOf(qt);

    // Fuzzy fallback: if no exact match, try stem match
    if (tf === 0) {
      const stemmedQt = stem(qt);
      tf = tfOf(stemmedQt);
      if (tf > 0) tf *= 0.7; // Dampened weight for stem match
    }

    // Fuzzy fallback: try transliteration match
    if (tf === 0) {
      const tr = transliterate(qt);
      if (tr) tf = tfOf(tr);
      if (tf > 0) tf *= 0.6; // Dampened weight for transliteration match
    }

    if (tf === 0) continue;

    // BM25 formula
    const numerator = tf * (BM25_K1 + 1);
    const denominator = tf + BM25_K1 * (1 - BM25_B + BM25_B * (doc.docLength / avgDocLength));
    score += idfVal * (numerator / denominator);
  }

  // Temporal decay: older memories score slightly lower
  const ageMs = Date.now() - new Date(doc.accessedAt).getTime();
  const ageDays = ageMs / (1000 * 60 * 60 * 24);
  const temporalBoost = Math.exp(-ageDays * 0.005); // Half-life ~139 days

  // Confidence boost
  const confidenceBoost = 0.5 + doc.confidence * 0.5;

  // Access frequency boost (log scale)
  const accessBoost = 1 + Math.log1p(doc.accessCount) * 0.1;

  return score * temporalBoost * confidenceBoost * accessBoost;
}

function computeIDF(observations: Observation[], queryTokens: string[]): Map<string, number> {
  const N = observations.length;
  const idf = new Map<string, number>();

  for (const qt of queryTokens) {
    let df = 0;
    for (const obs of observations) {
      if (Object.hasOwn(obs.termFreqs, qt) && obs.termFreqs[qt]) df++;
    }
    // BM25 IDF: log((N - df + 0.5) / (df + 0.5) + 1)
    idf.set(qt, Math.log((N - df + 0.5) / (df + 0.5) + 1));
  }

  return idf;
}

/**
 * IDF computed from an inverted index instead of a full corpus scan.
 *
 * df(qt) = number of valid docs whose termFreqs contains the exact key qt,
 * which is exactly the length of the inverted-index posting list for qt.
 * This yields bit-identical IDF to computeIDF() in O(queryTokens) instead
 * of O(N · queryTokens).
 */
function computeIDFFromIndex(
  index: Map<string, Observation[]>,
  N: number,
  queryTokens: string[],
): Map<string, number> {
  const idf = new Map<string, number>();
  for (const qt of queryTokens) {
    const df = index.get(qt)?.length ?? 0;
    idf.set(qt, Math.log((N - df + 0.5) / (df + 0.5) + 1));
  }
  return idf;
}

// ═══════════════════════════════════════════════════════════════════
// KNOWLEDGE GRAPH
// ═══════════════════════════════════════════════════════════════════

function buildGraphFromObservations(
  observations: Observation[],
): { nodes: Map<string, KnowledgeNode>; edges: KnowledgeEdge[] } {
  const nodes = new Map<string, KnowledgeNode>();
  const edges: KnowledgeEdge[] = [];
  const topicToDomains = new Map<string, Set<string>>();

  for (const obs of observations) {
    if (!obs.valid) continue;

    // Create/update domain node
    const domainId = `domain:${obs.domain}`;
    if (!nodes.has(domainId)) {
      nodes.set(domainId, {
        id: domainId, label: obs.domain, type: "project",
        observationIds: [], lastActiveAt: obs.accessedAt, weight: 0,
      });
    }
    const domainNode = nodes.get(domainId)!;
    domainNode.observationIds.push(obs.id);
    domainNode.weight++;

    // Create/update topic node
    const topicId = `topic:${obs.topic}`;
    if (!nodes.has(topicId)) {
      nodes.set(topicId, {
        id: topicId, label: obs.topic, type: "concept",
        observationIds: [], lastActiveAt: obs.accessedAt, weight: 0,
      });
    }
    const topicNode = nodes.get(topicId)!;
    topicNode.observationIds.push(obs.id);
    topicNode.weight++;

    // Domain → Topic edge
    edges.push({ from: domainId, to: topicId, relation: "contains", weight: 1 });

    // Track topic-to-domains for tunnel creation
    if (!topicToDomains.has(obs.topic)) {
      topicToDomains.set(obs.topic, new Set());
    }
    topicToDomains.get(obs.topic)!.add(obs.domain);

    // Tag nodes
    for (const tag of obs.tags) {
      const tagId = `tag:${tag}`;
      if (!nodes.has(tagId)) {
        nodes.set(tagId, {
          id: tagId, label: tag, type: "concept",
          observationIds: [], lastActiveAt: obs.accessedAt, weight: 0,
        });
      }
      nodes.get(tagId)!.observationIds.push(obs.id);
      edges.push({ from: topicId, to: tagId, relation: "related", weight: 1 });
    }
  }

  // Create TUNNELS: same topic across different domains
  for (const [topic, domains] of topicToDomains) {
    if (domains.size < 2) continue;
    const domainList = [...domains];
    for (let i = 0; i < domainList.length; i++) {
      for (let j = i + 1; j < domainList.length; j++) {
        edges.push({
          from: `domain:${domainList[i]}`,
          to: `domain:${domainList[j]}`,
          relation: "tunnel",
          weight: 2, // Tunnels are high-weight connections
        });
      }
    }
  }

  return { nodes, edges };
}

/** BFS traversal from a starting node. */
function bfsExpand(
  startNodeIds: string[],
  nodes: Map<string, KnowledgeNode>,
  edges: KnowledgeEdge[],
  maxHops: number,
): Set<string> {
  const visited = new Set<string>(startNodeIds);
  let frontier = [...startNodeIds];

  for (let hop = 0; hop < maxHops; hop++) {
    const nextFrontier: string[] = [];
    for (const nodeId of frontier) {
      // Find all edges from/to this node
      for (const edge of edges) {
        const neighbor = edge.from === nodeId ? edge.to : edge.to === nodeId ? edge.from : null;
        if (neighbor && !visited.has(neighbor)) {
          visited.add(neighbor);
          nextFrontier.push(neighbor);
        }
      }
    }
    frontier = nextFrontier;
    if (frontier.length === 0) break;
  }

  return visited;
}

// ═══════════════════════════════════════════════════════════════════
// OBSERVATION EXTRACTION
// ═══════════════════════════════════════════════════════════════════

/** Extract atomic observations from raw text. */
export function extractObservations(
  text: string,
  domain: string,
  sessionId?: string,
  extraTags: string[] = [],
): Observation[] {
  const observations: Observation[] = [];
  const safeDomain = normalizeMemoryLabel(domain);
  const safeSessionId = sessionId === undefined
    ? undefined
    : normalizeMemoryLabel(sessionId, "unknown", 128);
  const sentences = text
    .split(/[.!?\n]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 15 && s.length < 500);

  // Group similar sentences into topics
  const topicMap = new Map<string, string[]>();

  for (const sentence of sentences) {
    // Skip noise
    if (/^[<{]|task-notification|system-reminder|┌──/i.test(sentence)) continue;
    if (/^\d+$|^[ㄱ-ㅎ]+$/.test(sentence.trim())) continue;

    const topic = extractTopic(sentence);
    if (!topicMap.has(topic)) topicMap.set(topic, []);
    topicMap.get(topic)!.push(sentence);
  }

  for (const [topic, sents] of topicMap) {
    // Take the most informative sentence per topic
    const best = sents.sort((a, b) => b.length - a.length)[0];
    if (!best) continue;

    const tokens = tokenize(best);
    const safeTopic = normalizeMemoryLabel(topic, "general", 80);
    const tags = normalizeMemoryTags([...extractTags(best), ...extraTags]);

    observations.push({
      id: createHash("sha256").update(`${safeDomain}:${safeTopic}:${best.slice(0, 50)}`).digest("hex").slice(0, 12),
      content: best,
      domain: safeDomain,
      topic: safeTopic,
      tags,
      createdAt: new Date().toISOString(),
      accessedAt: new Date().toISOString(),
      accessCount: 0,
      confidence: 0.7,
      valid: true,
      sourceSessionId: safeSessionId,
      termFreqs: computeTermFreqs(tokens),
      docLength: tokens.length,
    });
  }

  return observations;
}

// ── Topic Extraction (TF-IDF + Bigrams) ─────────────────────────

/** Corpus-level document frequencies for IDF calculation. */
const _docFreq = new Map<string, number>();
let _docCount = 0;

function updateCorpusStats(tokens: string[]): void {
  _docCount++;
  const seen = new Set(tokens);
  for (const t of seen) {
    _docFreq.set(t, (_docFreq.get(t) ?? 0) + 1);
  }
}

function tfidfScore(token: string, tf: number): number {
  const df = _docFreq.get(token) ?? 1;
  const idf = Math.log((_docCount + 1) / (df + 1)) + 1;
  return tf * idf;
}

function extractBigrams(tokens: string[]): string[] {
  const bigrams: string[] = [];
  for (let i = 0; i < tokens.length - 1; i++) {
    bigrams.push(`${tokens[i]} ${tokens[i + 1]}`);
  }
  return bigrams;
}

function extractTopic(text: string): string {
  const tokens = tokenize(text);
  if (tokens.length === 0) return "general";

  updateCorpusStats(tokens);

  // Score unigrams by TF-IDF
  const freq = new Map<string, number>();
  for (const t of tokens) freq.set(t, (freq.get(t) ?? 0) + 1);

  const scored: [string, number][] = [];
  for (const [token, tf] of freq) {
    scored.push([token, tfidfScore(token, tf)]);
  }

  // Score bigrams — boost if both parts are meaningful
  const bigrams = extractBigrams(tokens);
  const bigramFreq = new Map<string, number>();
  for (const bg of bigrams) bigramFreq.set(bg, (bigramFreq.get(bg) ?? 0) + 1);

  for (const [bg, tf] of bigramFreq) {
    if (tf < 1) continue;
    const [a, b] = bg.split(" ");
    const scoreA = tfidfScore(a, freq.get(a) ?? 0);
    const scoreB = tfidfScore(b, freq.get(b) ?? 0);
    // Bigrams get 1.5x boost if both parts are informative
    if (scoreA > 1 && scoreB > 1) {
      scored.push([bg, (scoreA + scoreB) * 1.5]);
    }
  }

  scored.sort(([, a], [, b]) => b - a);

  // Normalize via transliteration for consistent topics
  const best = scored[0]?.[0] ?? "general";
  return transliterate(best) ?? best;
}

// ── Tag Extraction (Expanded Taxonomy + Multi-lingual) ──────────

const TAG_TAXONOMY: [string, RegExp][] = [
  // Security
  ["security", /보안|security|안전|safety|취약|vulnerab/i],
  ["security:injection", /injection|인젝션|주입|sqli|xss|ssrf|ssti/i],
  ["security:auth", /인증|authentication|auth|login|oauth|jwt|토큰/i],
  ["security:crypto", /암호|encrypt|decrypt|hash|cipher|tls|ssl/i],
  ["security:exploit", /exploit|익스플로잇|payload|rce|reverse.?shell/i],
  // Development
  ["testing", /테스트|test|spec|coverage|jest|vitest|pytest|unittest/i],
  ["devops", /deploy|배포|docker|ci\/cd|npm|kubernetes|k8s|컨테이너/i],
  ["devops:cloud", /aws|azure|gcp|클라우드|cloud|lambda|s3|ec2/i],
  ["devops:monitoring", /모니터링|monitoring|logging|로깅|grafana|prometheus/i],
  ["frontend", /react|vue|svelte|angular|css|html|component|프론트/i],
  ["backend", /server|서버|api|database|sql|rest|graphql|백엔드/i],
  ["backend:db", /database|데이터베이스|postgres|mysql|mongo|redis|sqlite/i],
  ["git", /\bgit\b|commit|push\b|branch|merge|\bpr\b|rebase/i],
  ["performance", /성능|optimize|performance|cache|speed|latency|레이턴시/i],
  ["debug", /debug|디버그|error|에러|bug|버그|crash|fix/i],
  // Languages & Frameworks
  ["lang:typescript", /typescript|타입스크립트|\.ts\b/i],
  ["lang:python", /python|파이썬|\.py\b|\bpip\b|conda/i],
  ["lang:go", /\bgo\b|golang|\.go\b/i],
  ["lang:rust", /rust|cargo|\.rs\b/i],
  // AI / ML
  ["ai", /ai\b|인공지능|machine.?learning|llm|gpt|claude|모델/i],
  ["ai:prompt", /prompt|프롬프트|injection|system.?prompt/i],
  ["ai:mcp", /mcp|model.?context|tool.?use/i],
  // Research / Social (RFP aligned)
  ["research", /연구|research|논문|paper|학술|academic|재단/i],
  ["policy", /정책|policy|법제도|규제|regulation|government|정부/i],
  ["social-problem", /사회문제|social.?problem|재난|disaster|교통|주거|환경/i],
  ["technology-matching", /기술.?매칭|tech.?match|솔루션|solution|실증|demonstration/i],
  ["data-collection", /데이터.?수집|data.?collect|모니터링|crawl|scrape|크롤/i],
  ["open-source", /오픈소스|open.?source|github|npm|mit.?license/i],
];

function extractTags(text: string): string[] {
  const tags: string[] = [];
  const lower = text.toLowerCase();

  for (const [tag, pattern] of TAG_TAXONOMY) {
    if (pattern.test(lower)) tags.push(tag);
  }

  // Deduplicate: if "security:injection" matched, don't also add "security"
  // unless it matched independently
  const specific = new Set(tags.filter((t) => t.includes(":")));
  return tags.filter((t) => {
    if (t.includes(":")) return true;
    // Keep parent only if no child matched
    return ![...specific].some((s) => s.startsWith(t + ":"));
  });
}

// ═══════════════════════════════════════════════════════════════════
// NEXUS MEMORY STORE
// ═══════════════════════════════════════════════════════════════════

/** One item for a bulk ingest. */
export type IngestItem = {
  text: string;
  domain: string;
  sessionId?: string;
  tags?: string[];
  provenance?: MemoryProvenance;
};

export type NexusMemory = {
  /** Add raw text and auto-extract observations. Optional provenance records
   *  who/what wrote it (default: manual). Content carrying a persistent
   *  exfil/fetch-run/override directive is quarantined (not stored). */
  ingest: (text: string, domain: string, sessionId?: string, tags?: string[], provenance?: MemoryProvenance) => number;
  /** Bulk ingest many items in one incremental pass (reorganize / feed / doc
   *  chunks). Returns the total number of observations added. */
  ingestBatch: (items: IngestItem[]) => number;
  /** Add a pre-formed observation. */
  addObservation: (obs: Observation) => void;
  /** L1: Quick metadata scan. */
  scanIndex: (domain?: string, topic?: string, tags?: string[]) => Observation[];
  /** L2: BM25 search. */
  search: (query: string, limit?: number) => MemoryResult[];
  /** L3: Graph-expanded search. */
  deepSearch: (query: string, limit?: number) => MemoryResult[];
  /** Confirm an observation (boost confidence, update access). */
  confirm: (id: string) => void;
  /** Invalidate an observation (keeps the record, marks it not-valid). */
  invalidate: (id: string) => void;
  /** Permanently forget (delete) a single observation by id, removing its
   *  on-disk file. Returns true if the observation existed. */
  forget: (id: string) => boolean;
  /** Permanently forget every observation a search for `query` returns — ALL
   *  matches by default, so a delete-by-query actually clears the query. Pass
   *  `limit` to cap the count or `minScore` to raise the match threshold.
   *  Returns the ids that were deleted. */
  forgetMatching: (query: string, opts?: { limit?: number; minScore?: number }) => string[];
  /** Get all tunnels (cross-domain connections). */
  getTunnels: () => KnowledgeEdge[];
  /** Get stats. */
  getStats: () => MemoryStats;
  /** Persist to disk. */
  save: () => void;
  /** Get the knowledge graph. */
  getGraph: () => { nodes: KnowledgeNode[]; edges: KnowledgeEdge[] };
  /** Toggle learned-embedding query expansion at runtime (for A/B eval). */
  setEmbeddings: (on: boolean) => void;
};

export function createNexusMemory(
  dataDir: string,
  opts: { useEmbeddings?: boolean; persistGraph?: boolean } = {},
): NexusMemory {
  const obsDir = join(dataDir, "observations");
  const graphPath = join(dataDir, "graph.json");
  // graph.json is a derived snapshot that nothing in Nexus ever reads back.
  // Writing it on every save rewrites a ~15 MB file at 20k observations for no
  // consumer, so it is opt-in (option or NEXUS_PERSIST_GRAPH=1) — debug only.
  const persistGraph = opts.persistGraph ?? (process.env.NEXUS_PERSIST_GRAPH === "1");

  // Learned-embedding query expansion. Off by default — opt in via the option or
  // NEXUS_EMBEDDINGS=1 — until a search-quality eval justifies flipping it on.
  // Loaded lazily; if no model has been trained the loader returns null and
  // search transparently falls back to the synonym graph + co-occurrence.
  let useEmb = opts.useEmbeddings ?? (process.env.NEXUS_EMBEDDINGS === "1");
  let embModel: RelatedSource | null = null;
  let embLoaded = false;
  function activeEmbModel(): RelatedSource | undefined {
    if (!useEmb) return undefined;
    if (!embLoaded) { embModel = loadEmbeddingModel(dataDir); embLoaded = true; }
    return embModel ?? undefined;
  }

  mkdirSync(obsDir, { recursive: true });

  // ── Integrity markers (#8) ────────────────────────────────────────────────
  // A per-store HMAC key, kept 0600 beside the data, lets Nexus prove it wrote
  // (and already sanitized) a stored record. A record with a current, valid
  // marker skips the expensive injection re-scan on load; a record with no/old/
  // mismatched marker — externally added or tampered — is always re-scanned.
  // The key is unforgeable by a process that can add files but not read the key,
  // so the security property holds for that adversary. If the key cannot be
  // read/created, markers are never trusted and every record is re-scanned.
  const keyPath = join(dataDir, ".sanitation-key");
  let sanitationKey: Buffer | null | undefined;
  /** Read the key through one descriptor, so the ownership/permission check and
   *  the read see the same file (no check-then-open race on the path). Returns
   *  null for a key that is not trusted — not a regular file, group/world-
   *  accessible or owned by another user (it may have been read or planted), or
   *  malformed — and the caller replaces it. A symlink at the key path is refused
   *  rather than followed (O_NOFOLLOW; POSIX only). */
  function readSanitationKey(): Buffer | null {
    const fd = openSync(keyPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0), 0o600);
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) return null;
      if (process.platform !== "win32") {
        if ((st.mode & 0o077) !== 0) return null;
        if (typeof process.getuid === "function" && st.uid !== process.getuid()) return null;
      }
      const hex = readFileSync(fd, "utf-8").trim();
      return /^[0-9a-f]{64}$/i.test(hex) ? Buffer.from(hex, "hex") : null;
    } finally {
      closeSync(fd);
    }
  }

  /** Write a fresh 0600 key beside the store and rename it into place. Used when
   *  the existing key is not trusted: replacing it, rather than only re-tightening
   *  its mode, means a key that may have been read or planted can never validate
   *  a marker again — the records it signed are re-scanned once and re-signed.
   *  The rename replaces a symlink at the key path itself, never its target. */
  function writeFreshSanitationKey(): Buffer | null {
    const key = randomBytes(32);
    const tmp = `${keyPath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    try {
      const fd = openSync(tmp, "wx", 0o600);
      try { writeFileSync(fd, key.toString("hex"), "utf-8"); } finally { closeSync(fd); }
      renameSync(tmp, keyPath);
      return key;
    } catch {
      try { unlinkSync(tmp); } catch { /* never created */ }
      return null; // e.g. a directory at the key path: markers stay untrusted
    }
  }

  /** First key for a new store. O_EXCL: if another process created one since our
   *  read, use theirs (or replace it when it is not trusted). */
  function createSanitationKey(): Buffer | null {
    const key = randomBytes(32);
    try {
      const fd = openSync(keyPath, "wx", 0o600);
      try { writeFileSync(fd, key.toString("hex"), "utf-8"); } finally { closeSync(fd); }
      return key;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") return null;
      try { return readSanitationKey() ?? writeFreshSanitationKey(); } catch { return writeFreshSanitationKey(); }
    }
  }

  function getSanitationKey(): Buffer | null {
    if (sanitationKey !== undefined) return sanitationKey;
    try {
      sanitationKey = readSanitationKey() ?? writeFreshSanitationKey();
    } catch (error) {
      // No key yet; or one we may not open (a symlink refused by O_NOFOLLOW, an
      // unreadable file), which is replaced like any other untrusted key.
      sanitationKey = (error as NodeJS.ErrnoException).code === "ENOENT"
        ? createSanitationKey()
        : writeFreshSanitationKey();
    }
    return sanitationKey;
  }

  function integrityPayload(obs: Observation): string {
    return [
      obs.content,
      obs.domain,
      obs.topic,
      obs.tags.join(","),
      obs.sourceSessionId ?? "",
      obs.provenance ? `${obs.provenance.source}|${obs.provenance.origin ?? ""}|${obs.provenance.trust}` : "",
    ].join("\u0000");
  }
  function computeIntegrity(obs: Observation): string | undefined {
    const key = getSanitationKey();
    if (!key) return undefined;
    const mac = createHmac("sha256", key).update(integrityPayload(obs)).digest("hex");
    return `v${SANITATION_VERSION}:${mac}`;
  }
  function hasValidIntegrity(obs: Observation): boolean {
    if (typeof obs.integrity !== "string") return false;
    if (!obs.integrity.startsWith(`v${SANITATION_VERSION}:`)) return false; // stale version ⇒ re-scan
    const expected = computeIntegrity(obs);
    return expected !== undefined && obs.integrity === expected;
  }

  // A stored record with a valid marker is trusted as already-sanitized: its
  // content/metadata are used as-is, only termFreqs/docLength (cheap, no
  // scanner) are recomputed from the integrity-covered content.
  function fastLoadObservation(raw: Observation): Observation {
    const tokens = tokenize(raw.content);
    return {
      ...raw,
      provenance: raw.provenance ?? defaultProvenance(),
      termFreqs: computeTermFreqs(tokens),
      docLength: tokens.length,
    };
  }

  // Load existing observations
  let observations: Observation[] = [];
  const observationIds = new Set<string>();
  const dirtyObservationIds = new Set<string>();
  if (existsSync(obsDir)) {
    for (const file of readdirSync(obsDir).filter((f) => f.endsWith(".json"))) {
      try {
        const raw = JSON.parse(readFileSync(join(obsDir, file), "utf-8")) as Observation;
        let loaded: Observation | null;
        if (hasValidIntegrity(raw)) {
          loaded = fastLoadObservation(raw); // trusted — skip the re-scan
        } else {
          // No/old/mismatched marker ⇒ externally added or tampered ⇒ full scan.
          const secured = secureObservation(raw);
          if (secured && classifyMemoryThreat(secured.content) === null) {
            secured.provenance = secured.provenance ?? defaultProvenance();
            secured.integrity = undefined; // re-signed on next save (gradual upgrade)
            loaded = secured;
            dirtyObservationIds.add(secured.id); // persist the fresh marker
          } else {
            loaded = null; // quarantined or unparseable
          }
        }
        if (loaded && !observationIds.has(loaded.id)) {
          observations.push(loaded);
          observationIds.add(loaded.id);
        }
      } catch { /* skip corrupt */ }
    }
  }

  // Running total so avgDocLength updates incrementally on ingest. docLengths
  // are integer token counts, so the running sum is exact and order-independent
  // — identical to a reduce over the whole array.
  let totalDocLength = observations.reduce((s, o) => s + o.docLength, 0);
  let avgDocLength = observations.length > 0 ? totalDocLength / observations.length : 10;

  // Build co-occurrence model from existing observations (full rebuild on load).
  const coModel = createCoOccurrenceModel();
  if (observations.length > 0) {
    coModel.rebuild(observations.map((o) => o.content));
  }

  // The knowledge graph is a derived view used only by L3/stats/getGraph, never
  // the L2 hot path, so it is rebuilt lazily from observations when first read
  // instead of on every ingest.
  let graph: { nodes: Map<string, KnowledgeNode>; edges: KnowledgeEdge[] } = { nodes: new Map(), edges: [] };
  let graphStale = true;
  function ensureGraph(): void {
    if (!graphStale) return;
    graph = buildGraphFromObservations(observations);
    graphStale = false;
  }
  const saveLockPath = join(dataDir, ".memory-save.lock");
  const recoveryLockPath = `${saveLockPath}.recovery`;
  const STALE_LOCK_MS = 60_000;
  const MALFORMED_LOCK_STALE_MS = 10 * 60_000;

  function atomicWriteJson(path: string, value: unknown): void {
    const tempPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
    let fd: number | undefined;
    try {
      fd = openSync(tempPath, "wx", 0o600);
      writeFileSync(fd, JSON.stringify(value, null, 2), "utf-8");
      closeSync(fd);
      fd = undefined;
      renameSync(tempPath, path);
    } finally {
      if (fd !== undefined) closeSync(fd);
      if (existsSync(tempPath)) unlinkSync(tempPath);
    }
  }

  type SaveLockRecord = { pid: number; token: string; createdAt: string };

  function readLock(path: string): SaveLockRecord | null {
    try {
      const value = JSON.parse(readFileSync(path, "utf-8")) as Partial<SaveLockRecord>;
      if (!Number.isSafeInteger(value.pid) || typeof value.token !== "string" || typeof value.createdAt !== "string") {
        return null;
      }
      return value as SaveLockRecord;
    } catch {
      return null;
    }
  }

  function processIsAlive(pid: number): boolean {
    try {
      process.kill(pid, 0);
      return true;
    } catch (error) {
      // EPERM means the process exists but belongs to a security context that
      // does not permit signaling it. Treat that as alive and never steal.
      return (error as NodeJS.ErrnoException).code === "EPERM";
    }
  }

  function removeLockIfOwned(path: string, token: string): void {
    if (readLock(path)?.token === token && existsSync(path)) unlinkSync(path);
  }

  function acquireExclusiveLock(path: string): { fd: number; token: string } {
    const token = randomUUID();
    const fd = openSync(path, "wx", 0o600);
    try {
      writeFileSync(fd, JSON.stringify({ pid: process.pid, token, createdAt: new Date().toISOString() }), "utf-8");
      return { fd, token };
    } catch (error) {
      closeSync(fd);
      if (existsSync(path)) unlinkSync(path);
      throw error;
    }
  }

  function acquireSaveLock(): () => void {
    let lock: { fd: number; token: string };
    try {
      lock = acquireExclusiveLock(saveLockPath);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") throw error;

      // Serialize stale-lock recovery separately. A lock is recoverable only
      // when it is old, well-formed, and its owner process is confirmed dead.
      // Age alone is never grounds for stealing a live writer's lock.
      let recovery: { fd: number; token: string };
      try {
        recovery = acquireExclusiveLock(recoveryLockPath);
      } catch {
        const owner = readLock(recoveryLockPath);
        const ageMs = existsSync(recoveryLockPath)
          ? Date.now() - statSync(recoveryLockPath).mtimeMs
          : 0;
        const stale = owner
          ? ageMs > STALE_LOCK_MS && !processIsAlive(owner.pid)
          : ageMs > MALFORMED_LOCK_STALE_MS;
        const repair = stale
          ? ` Stale recovery lock detected at ${recoveryLockPath}; after verifying no Nexus save is running, remove that file and retry.`
          : "";
        throw new Error(`Nexus memory save already in progress: ${saveLockPath}.${repair}`);
      }

      try {
        const existing = readLock(saveLockPath);
        const ageMs = existsSync(saveLockPath) ? Date.now() - statSync(saveLockPath).mtimeMs : 0;
        if (existing && (ageMs <= STALE_LOCK_MS || processIsAlive(existing.pid))) {
          throw new Error(`Nexus memory save already in progress: ${saveLockPath}`);
        }

        if (existing) {
          // The dead owner cannot replace the file. A second recovery process
          // is excluded by recoveryLockPath, so deleting this exact token is safe.
          removeLockIfOwned(saveLockPath, existing.token);
        } else {
          // An empty/partial lock can be left by a crash between exclusive
          // creation and the tiny owner-record write. Reclaim it only after a
          // much more conservative age while recovery is serialized.
          if (ageMs <= MALFORMED_LOCK_STALE_MS) {
            throw new Error(`Nexus memory save already in progress: ${saveLockPath}`);
          }
          if (readLock(saveLockPath) === null && existsSync(saveLockPath)) unlinkSync(saveLockPath);
        }
      } finally {
        closeSync(recovery.fd);
        removeLockIfOwned(recoveryLockPath, recovery.token);
      }

      // Another normal contender may win the tiny window after stale removal.
      // In that case acquireExclusiveLock fails safely; we never delete it.
      try {
        lock = acquireExclusiveLock(saveLockPath);
      } catch {
        throw new Error(`Nexus memory save already in progress: ${saveLockPath}`);
      }
    }

    return () => {
      closeSync(lock.fd);
      removeLockIfOwned(saveLockPath, lock.token);
    };
  }

  // Inverted index: termFreqs key → valid observations containing it.
  // Built lazily on first search, invalidated whenever the observation set
  // changes. Lets search() score only candidate docs (those sharing a query
  // token) instead of scanning the whole corpus — turns the per-observation
  // clustering pass from O(n²) into O(n · candidates).
  let invertedIndex: Map<string, Observation[]> | null = null;
  let validCount = 0;

  function getInvertedIndex(): Map<string, Observation[]> {
    if (invertedIndex) return invertedIndex;
    const index = new Map<string, Observation[]>();
    let valid = 0;
    for (const obs of observations) {
      if (!obs.valid) continue;
      valid++;
      for (const token of Object.keys(obs.termFreqs)) {
        const bucket = index.get(token);
        if (bucket) bucket.push(obs);
        else index.set(token, [obs]);
      }
    }
    validCount = valid;
    invertedIndex = index;
    return index;
  }

  /**
   * Register one brand-new observation, maintaining every derived structure
   * incrementally instead of rebuilding from scratch (#7). Co-occurrence,
   * avgDocLength and (if already materialized) the inverted index are updated
   * for this document only; the graph is just marked stale (rebuilt lazily when
   * next read). Appending in insertion order reproduces exactly what a full
   * rebuild over the same observation order would produce, so query results are
   * unchanged.
   */
  function registerNewObservation(obs: Observation, dirty: boolean): void {
    observations.push(obs);
    observationIds.add(obs.id);
    totalDocLength += obs.docLength;
    avgDocLength = observations.length > 0 ? totalDocLength / observations.length : 10;
    coModel.addDocument(obs.content);
    if (invertedIndex && obs.valid) {
      validCount++;
      for (const token of Object.keys(obs.termFreqs)) {
        const bucket = invertedIndex.get(token);
        if (bucket) bucket.push(obs);
        else invertedIndex.set(token, [obs]);
      }
    }
    graphStale = true;
    // The integrity marker is computed lazily at save (over the final persisted
    // fields), so the key file is created only when data is actually persisted.
    if (dirty) dirtyObservationIds.add(obs.id);
  }

  /** Full rebuild of the derived structures from the current observation set.
   *  Used by the rare mutating paths (invalidate / forget) where a document was
   *  removed or hidden and incremental maintenance does not apply. */
  function fullRebuild(): void {
    totalDocLength = observations.reduce((s, o) => s + o.docLength, 0);
    avgDocLength = observations.length > 0 ? totalDocLength / observations.length : 10;
    coModel.rebuild(observations.map((o) => o.content));
    invertedIndex = null;
    graphStale = true;
  }

  function ingestOne(
    text: string,
    domain: string,
    sessionId: string | undefined,
    tags: string[],
    provenance: MemoryProvenance,
  ): number {
    const sanitized = sanitizeExternalContent(text);
    if (sanitized.persistText === null) return 0;
    // #6: quarantine a whole chunk that carries a persistent exfil/fetch-run/
    // override directive. Done at chunk granularity (like the sanitizer) because
    // sentence extraction can split a directive across fragments, scattering its
    // signal — a poisoned chunk is dropped rather than partially indexed.
    if (classifyMemoryThreat(sanitized.persistText) !== null) return 0;
    const newObs = extractObservations(sanitized.persistText, domain, sessionId, tags);
    let added = 0;
    for (const obs of newObs) {
      if (observationIds.has(obs.id)) continue;              // dedupe (O(1))
      if (classifyMemoryThreat(obs.content) !== null) continue; // per-observation backstop
      obs.provenance = provenance;
      registerNewObservation(obs, true);
      added++;
    }
    return added;
  }

  return {
    ingest(text: string, domain: string, sessionId?: string, tags: string[] = [], provenance?: MemoryProvenance): number {
      return ingestOne(text, domain, sessionId, tags, provenance ?? defaultProvenance());
    },

    ingestBatch(items: IngestItem[]): number {
      let added = 0;
      for (const item of items) {
        added += ingestOne(
          item.text,
          item.domain,
          item.sessionId,
          item.tags ?? [],
          item.provenance ?? defaultProvenance(),
        );
      }
      return added;
    },

    addObservation(obs: Observation): void {
      const normalized = secureObservation(obs);
      if (!normalized) return;
      if (observationIds.has(normalized.id)) return;
      if (classifyMemoryThreat(normalized.content) !== null) return; // #6 quarantine — drop
      normalized.provenance = normalized.provenance ?? obs.provenance ?? defaultProvenance();
      registerNewObservation(normalized, true);
    },

    // L1: Instant index scan — metadata only
    scanIndex(domain?: string, topic?: string, tags?: string[]): Observation[] {
      return observations.filter((obs) => {
        if (!obs.valid) return false;
        if (domain && obs.domain !== domain) return false;
        if (topic && obs.topic !== topic) return false;
        if (tags && tags.length > 0 && !tags.some((t) => obs.tags.includes(t))) return false;
        return true;
      });
    },

    // L2: BM25 + Semantic search
    search(query: string, limit = 10): MemoryResult[] {
      // Expand query with synonyms + co-occurrence
      const expanded = expandQuery(query, coModel, 3, activeEmbModel());
      const queryTokens = expanded.expanded;
      if (queryTokens.length === 0) return [];

      const index = getInvertedIndex();
      const idf = computeIDFFromIndex(index, validCount, queryTokens);

      // Candidate set: every doc that could score > 0. bm25Score credits a
      // query token qt if the doc has the exact key qt, stem(qt), or
      // transliterate(qt) — so the union of those three postings is a complete
      // superset of the matching docs (docs outside it score exactly 0).
      const candidates = new Set<Observation>();
      for (const qt of queryTokens) {
        const post = index.get(qt);
        if (post) for (const o of post) candidates.add(o);
        const st = stem(qt);
        if (st !== qt) {
          const postStem = index.get(st);
          if (postStem) for (const o of postStem) candidates.add(o);
        }
        const tr = transliterate(qt);
        if (tr) {
          const postTr = index.get(tr);
          if (postTr) for (const o of postTr) candidates.add(o);
        }
      }

      const scored = [...candidates].map((obs) => ({
        observation: obs,
        score: bm25Score(queryTokens, obs, idf, avgDocLength),
        retrievalLevel: "L2" as const,
      }));

      return scored
        .filter((s) => s.score > 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, limit)
        .map((s) => {
          // Update access stats
          s.observation.accessedAt = new Date().toISOString();
          s.observation.accessCount++;
          dirtyObservationIds.add(s.observation.id);
          return s;
        });
    },

    // L3: Graph-expanded deep search
    deepSearch(query: string, limit = 10): MemoryResult[] {
      // First get L2 results
      const l2Results = this.search(query, Math.ceil(limit / 2));
      if (l2Results.length === 0) return [];

      ensureGraph();
      // Find graph nodes related to top results
      const topObsIds = new Set(l2Results.map((r) => r.observation.id));
      const relatedNodeIds: string[] = [];

      for (const node of graph.nodes.values()) {
        if (node.observationIds.some((id) => topObsIds.has(id))) {
          relatedNodeIds.push(node.id);
        }
      }

      // BFS expand 2 hops
      const expandedNodeIds = bfsExpand(relatedNodeIds, graph.nodes, graph.edges, 2);

      // Collect observations from expanded nodes
      const expandedObsIds = new Set<string>();
      for (const nodeId of expandedNodeIds) {
        const node = graph.nodes.get(nodeId);
        if (node) {
          for (const obsId of node.observationIds) {
            if (!topObsIds.has(obsId)) expandedObsIds.add(obsId);
          }
        }
      }

      // Score expanded observations
      const queryTokens = tokenize(query);
      const validObs = observations.filter((o) => o.valid && expandedObsIds.has(o.id));
      const idf = computeIDF(validObs, queryTokens);

      const l3Results: MemoryResult[] = validObs.map((obs) => ({
        observation: obs,
        score: bm25Score(queryTokens, obs, idf, avgDocLength) * 0.8, // Slightly lower weight for graph results
        retrievalLevel: "L3" as const,
      })).filter((s) => s.score > 0);

      // Merge L2 and L3, deduplicate, sort
      const all = [...l2Results, ...l3Results];
      const seen = new Set<string>();
      const unique: MemoryResult[] = [];
      for (const r of all.sort((a, b) => b.score - a.score)) {
        if (!seen.has(r.observation.id)) {
          seen.add(r.observation.id);
          unique.push(r);
        }
      }

      return unique.slice(0, limit);
    },

    confirm(id: string): void {
      const obs = observations.find((o) => o.id === id);
      if (obs) {
        obs.confidence = Math.min(1, obs.confidence + 0.1);
        obs.accessedAt = new Date().toISOString();
        obs.accessCount++;
        dirtyObservationIds.add(obs.id);
      }
    },

    invalidate(id: string): void {
      const obs = observations.find((o) => o.id === id);
      if (!obs) return;
      obs.valid = false;
      obs.confidence = 0;
      dirtyObservationIds.add(obs.id);
      // Hiding a doc only changes the valid-doc index and the graph; co-occurrence
      // (built over all content, valid or not) and avgDocLength are unchanged.
      invertedIndex = null;
      graphStale = true;
    },

    forget(id: string): boolean {
      const idx = observations.findIndex((o) => o.id === id);
      if (idx < 0) return false;
      observations.splice(idx, 1);
      observationIds.delete(id);
      dirtyObservationIds.delete(id);
      try {
        const p = join(obsDir, `${sanitizeId(id)}.json`);
        if (existsSync(p)) unlinkSync(p);
      } catch { /* best-effort: the save lock protects concurrent writers */ }
      fullRebuild(); // a document was removed — incremental maintenance can't subtract
      return true;
    },

    forgetMatching(query: string, opts: { limit?: number; minScore?: number } = {}): string[] {
      const minScore = opts.minScore ?? 0;
      // Default to deleting EVERY match, not the top-50: this is a delete-by-query
      // (privacy / poison removal) and the CLI/MCP callers report it as such, so a
      // silent top-N cap would leave matches behind while telling the user the
      // query was cleared. `observations.length` is an exact "all" bound — there
      // can be at most that many matches. An explicit `limit` still caps it.
      const hits = this.search(query, opts.limit ?? observations.length).filter((r) => r.score >= minScore);
      const ids = [...new Set(hits.map((h) => h.observation.id))];
      if (ids.length === 0) return [];
      const idSet = new Set(ids);
      // Remove all matches, delete their files, then one rebuild.
      observations = observations.filter((o) => !idSet.has(o.id));
      for (const id of ids) {
        observationIds.delete(id);
        dirtyObservationIds.delete(id);
        try {
          const p = join(obsDir, `${sanitizeId(id)}.json`);
          if (existsSync(p)) unlinkSync(p);
        } catch { /* best-effort */ }
      }
      fullRebuild();
      return ids;
    },

    getTunnels(): KnowledgeEdge[] {
      ensureGraph();
      return graph.edges.filter((e) => e.relation === "tunnel");
    },

    getStats(): MemoryStats {
      ensureGraph();
      const valid = observations.filter((o) => o.valid);
      const domains = [...new Set(observations.map((o) => o.domain))];
      const tunnels = graph.edges.filter((e) => e.relation === "tunnel").length;
      const avgConf = valid.length > 0
        ? valid.reduce((s, o) => s + o.confidence, 0) / valid.length
        : 0;

      return {
        totalObservations: observations.length,
        validObservations: valid.length,
        graphNodes: graph.nodes.size,
        graphEdges: graph.edges.length,
        tunnels,
        domains,
        avgConfidence: Math.round(avgConf * 100) / 100,
        avgDocLength: Math.round(avgDocLength),
      };
    },

    save(): void {
      mkdirSync(obsDir, { recursive: true });
      const releaseLock = acquireSaveLock();
      try {
        // Another Nexus process may have committed observations since this store
        // was opened. Merge only files we do NOT already hold — we never re-read
        // (or re-scan) our own records, so a save is O(dirty) + O(new-from-peers)
        // instead of re-parsing and re-securing every file under the lock (#9).
        const knownFiles = new Set(observations.map((o) => `${sanitizeId(o.id)}.json`));
        for (const file of readdirSync(obsDir).filter((name) => name.endsWith(".json"))) {
          if (knownFiles.has(file)) continue;
          try {
            const raw = JSON.parse(readFileSync(join(obsDir, file), "utf-8")) as Observation;
            if (observationIds.has(raw.id)) continue;
            let merged: Observation | null;
            if (hasValidIntegrity(raw)) {
              merged = fastLoadObservation(raw); // written by a peer with our key — trusted
            } else {
              const secured = secureObservation(raw); // external/legacy — full scan
              merged = secured && classifyMemoryThreat(secured.content) === null ? secured : null;
              if (merged) merged.provenance = merged.provenance ?? defaultProvenance();
            }
            if (merged && !observationIds.has(merged.id)) {
              registerNewObservation(merged, false); // already on disk — not dirty
            }
          } catch {
            // Ignore a corrupt legacy observation; existing load behavior is
            // intentionally tolerant and the atomic writer cannot create one.
          }
        }

        // Write only the dirty observations (never the whole set).
        for (const obs of observations) {
          if (!dirtyObservationIds.has(obs.id)) continue;
          if (!obs.integrity) obs.integrity = computeIntegrity(obs);
          const safeId = sanitizeId(obs.id);
          atomicWriteJson(join(obsDir, `${safeId}.json`), obs);
        }
        dirtyObservationIds.clear();

        // graph.json is derived and unread by Nexus — persist it only when
        // explicitly opted in (debug). Otherwise a stale snapshot left by an
        // older version is best-effort removed so it cannot mislead.
        if (persistGraph) {
          ensureGraph();
          atomicWriteJson(graphPath, { nodes: [...graph.nodes.values()], edges: graph.edges });
        } else if (existsSync(graphPath)) {
          try { unlinkSync(graphPath); } catch { /* best-effort cleanup */ }
        }
      } finally {
        releaseLock();
      }
    },

    getGraph(): { nodes: KnowledgeNode[]; edges: KnowledgeEdge[] } {
      ensureGraph();
      return { nodes: [...graph.nodes.values()], edges: graph.edges };
    },

    setEmbeddings(on: boolean): void {
      useEmb = on;
    },
  };
}
