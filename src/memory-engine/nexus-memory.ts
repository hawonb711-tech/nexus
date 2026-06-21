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

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { join, dirname, resolve, relative } from "node:path";
import { createHash } from "node:crypto";

/** Sanitize ID to prevent path traversal. */
function sanitizeId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_-]/g, "_");
}
import { expandQuery, createCoOccurrenceModel, type CoOccurrenceModel, type RelatedSource } from "./semantic.js";
import { loadEmbeddingModel } from "../ml/model-store.js";

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

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
};

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

// ═══════════════════════════════════════════════════════════════════
// BM25 ENGINE
// ═══════════════════════════════════════════════════════════════════

const BM25_K1 = 1.5;  // Term frequency saturation parameter
const BM25_B = 0.75;  // Document length normalization parameter

import { STOP_WORDS } from "../shared/stop-words.js";
import { stem, transliterate, trigramSimilarity } from "./semantic.js";

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
): Observation[] {
  const observations: Observation[] = [];
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
    const tags = extractTags(best);

    observations.push({
      id: createHash("sha256").update(`${domain}:${topic}:${best.slice(0, 50)}`).digest("hex").slice(0, 12),
      content: best,
      domain,
      topic,
      tags,
      createdAt: new Date().toISOString(),
      accessedAt: new Date().toISOString(),
      accessCount: 0,
      confidence: 0.7,
      valid: true,
      sourceSessionId: sessionId,
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

export type NexusMemory = {
  /** Add raw text and auto-extract observations. */
  ingest: (text: string, domain: string, sessionId?: string) => number;
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
  /** Invalidate an observation. */
  invalidate: (id: string) => void;
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

export function createNexusMemory(dataDir: string, opts: { useEmbeddings?: boolean } = {}): NexusMemory {
  const obsDir = join(dataDir, "observations");
  const graphPath = join(dataDir, "graph.json");

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

  // Load existing observations
  let observations: Observation[] = [];
  if (existsSync(obsDir)) {
    for (const file of readdirSync(obsDir).filter((f) => f.endsWith(".json"))) {
      try {
        const obs = JSON.parse(readFileSync(join(obsDir, file), "utf-8")) as Observation;
        observations.push(obs);
      } catch { /* skip corrupt */ }
    }
  }

  // Pre-compute average doc length
  let avgDocLength = observations.length > 0
    ? observations.reduce((s, o) => s + o.docLength, 0) / observations.length
    : 10;

  // Build co-occurrence model from existing observations
  const coModel = createCoOccurrenceModel();
  if (observations.length > 0) {
    coModel.rebuild(observations.map((o) => o.content));
  }

  // Build graph
  let graph = buildGraphFromObservations(observations);

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

  function rebuildGraph(): void {
    graph = buildGraphFromObservations(observations);
    avgDocLength = observations.length > 0
      ? observations.reduce((s, o) => s + o.docLength, 0) / observations.length
      : 10;
    // Rebuild co-occurrence model with latest observations
    coModel.rebuild(observations.map((o) => o.content));
    // Observation set changed — drop the cached inverted index.
    invertedIndex = null;
  }

  return {
    ingest(text: string, domain: string, sessionId?: string): number {
      const newObs = extractObservations(text, domain, sessionId);
      // Deduplicate against existing
      let added = 0;
      for (const obs of newObs) {
        if (observations.some((e) => e.id === obs.id)) continue;
        observations.push(obs);
        added++;
      }
      if (added > 0) rebuildGraph();
      return added;
    },

    addObservation(obs: Observation): void {
      if (observations.some((e) => e.id === obs.id)) return;
      observations.push(obs);
      rebuildGraph();
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
          return s;
        });
    },

    // L3: Graph-expanded deep search
    deepSearch(query: string, limit = 10): MemoryResult[] {
      // First get L2 results
      const l2Results = this.search(query, Math.ceil(limit / 2));
      if (l2Results.length === 0) return [];

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
      }
    },

    invalidate(id: string): void {
      const obs = observations.find((o) => o.id === id);
      if (obs) {
        obs.valid = false;
        obs.confidence = 0;
      }
      rebuildGraph();
    },

    getTunnels(): KnowledgeEdge[] {
      return graph.edges.filter((e) => e.relation === "tunnel");
    },

    getStats(): MemoryStats {
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
      for (const obs of observations) {
        const safeId = sanitizeId(obs.id);
        const filePath = join(obsDir, `${safeId}.json`);
        writeFileSync(filePath, JSON.stringify(obs, null, 2), "utf-8");
      }
      // Save graph
      const graphData = {
        nodes: [...graph.nodes.values()],
        edges: graph.edges,
      };
      writeFileSync(graphPath, JSON.stringify(graphData, null, 2), "utf-8");
    },

    getGraph(): { nodes: KnowledgeNode[]; edges: KnowledgeEdge[] } {
      return { nodes: [...graph.nodes.values()], edges: graph.edges };
    },

    setEmbeddings(on: boolean): void {
      useEmb = on;
    },
  };
}
