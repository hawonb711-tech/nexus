/**
 * Zero-Dependency Semantic Similarity Engine
 *
 * Captures meaning without embeddings or external APIs.
 *
 * Three mechanisms:
 *
 * 1. SYNONYM GRAPH (src/shared/semantic-similarity.ts, re-exported below)
 *    Hard-coded domain knowledge mapping related concepts.
 *    "deploy" ↔ "release" ↔ "publish" ↔ "배포" ↔ "ship"
 *    Bilingual: English ↔ Korean for dev terminology.
 *
 * 2. CO-OCCURRENCE PMI (Pointwise Mutual Information)
 *    Learns from the corpus itself: words that appear together
 *    more than expected by chance are semantically related.
 *    "authentication" frequently near "password" → related.
 *    No training, no model — pure statistics.
 *
 * 3. QUERY EXPANSION
 *    Expands search query with synonyms + co-occurrence neighbors.
 *    "deploy" → ["deploy", "release", "publish", "배포", "ship"]
 *    Then runs BM25 on expanded query → semantic matches found.
 */

// The stateless lexical pieces (synonym graph, stemmer, transliteration,
// trigram match, tokenizer, semanticSimilarity) live in src/shared so the guard
// can use them without loading the memory engine; re-exported here unchanged.
import { getSynonyms, stem, transliterate, tokenize, type RelatedSource } from "../shared/semantic-similarity.js";
export {
  SYNONYM_GROUPS, getSynonyms, stem, transliterate, trigramSimilarity, tokenize, semanticSimilarity,
  type RelatedSource,
} from "../shared/semantic-similarity.js";

// ═══════════════════════════════════════════════════════════════════
// CO-OCCURRENCE PMI — Learns semantic relationships from corpus
// ═══════════════════════════════════════════════════════════════════

export type CoOccurrenceModel = {
  /** Get top-N semantically related words for a given word. */
  getRelated: (word: string, topN?: number) => { word: string; pmi: number }[];
  /** Rebuild from a new corpus. */
  rebuild: (documents: string[]) => void;
  /**
   * Fold a single new document into the model in place, without rebuilding.
   *
   * Co-occurrence counts, word frequencies and the pair total are plain sums
   * over documents, so adding one document's contributions produces the exact
   * same maps — same values AND same key-insertion order — that a full rebuild
   * over the cumulative corpus (in the same document order) would. getRelated is
   * therefore bit-identical whether the corpus was built incrementally or in one
   * rebuild, which lets ingest stay incremental while preserving ranking.
   */
  addDocument: (document: string) => void;
  /** Number of unique terms. */
  vocabSize: () => number;
};

export function createCoOccurrenceModel(): CoOccurrenceModel {
  // word → (word → count)
  let coOccur = new Map<string, Map<string, number>>();
  let wordFreq = new Map<string, number>();
  let totalPairs = 0;

  const WINDOW = 5; // Co-occurrence window size

  function addDocument(doc: string): void {
    const tokens = tokenize(doc);

    // Count word frequencies
    for (const t of tokens) {
      wordFreq.set(t, (wordFreq.get(t) ?? 0) + 1);
    }

    // Count co-occurrences within window
    for (let i = 0; i < tokens.length; i++) {
      const word = tokens[i];
      if (!coOccur.has(word)) coOccur.set(word, new Map());

      for (let j = Math.max(0, i - WINDOW); j < Math.min(tokens.length, i + WINDOW + 1); j++) {
        if (i === j) continue;
        const neighbor = tokens[j];
        const map = coOccur.get(word)!;
        map.set(neighbor, (map.get(neighbor) ?? 0) + 1);
        totalPairs++;
      }
    }
  }

  function rebuild(documents: string[]): void {
    coOccur = new Map();
    wordFreq = new Map();
    totalPairs = 0;
    for (const doc of documents) addDocument(doc);
  }

  function getRelated(word: string, topN = 10): { word: string; pmi: number }[] {
    const lower = word.toLowerCase();
    const neighbors = coOccur.get(lower);
    if (!neighbors || totalPairs === 0) return [];

    const pWord = (wordFreq.get(lower) ?? 0) / totalPairs;
    if (pWord === 0) return [];

    const results: { word: string; pmi: number }[] = [];

    for (const [neighbor, count] of neighbors) {
      const pNeighbor = (wordFreq.get(neighbor) ?? 0) / totalPairs;
      if (pNeighbor === 0) continue;

      const pJoint = count / totalPairs;
      // PMI = log2(P(x,y) / (P(x) * P(y)))
      const pmi = Math.log2(pJoint / (pWord * pNeighbor));

      // Only keep positive PMI (co-occur more than expected)
      if (pmi > 0) {
        results.push({ word: neighbor, pmi });
      }
    }

    return results
      .sort((a, b) => b.pmi - a.pmi)
      .slice(0, topN);
  }

  return {
    getRelated,
    rebuild,
    addDocument,
    vocabSize: () => wordFreq.size,
  };
}

// ═══════════════════════════════════════════════════════════════════
// QUERY EXPANSION — Combines synonyms + co-occurrence
// ═══════════════════════════════════════════════════════════════════

export type ExpandedQuery = {
  /** Original query tokens. */
  original: string[];
  /** Expanded tokens (includes original + synonyms + co-occurrence). */
  expanded: string[];
  /** Which tokens were added and why. */
  expansions: { token: string; source: "synonym" | "cooccurrence" | "stem" | "transliteration" | "embedding"; relatedTo: string }[];
};

/**
 * Expand a query with semantic neighbors.
 *
 * "deploy error" → ["deploy", "release", "publish", "배포",
 *                    "error", "bug", "issue", "에러",
 *                    + co-occurrence neighbors]
 */
export function expandQuery(
  query: string,
  coModel?: CoOccurrenceModel,
  maxCoOccurrencePerToken = 3,
  embModel?: RelatedSource,
  maxEmbeddingPerToken = 3,
  minEmbeddingScore = 0.55,
): ExpandedQuery {
  const original = tokenize(query);
  const expanded = [...original];
  const expansions: ExpandedQuery["expansions"] = [];
  const seen = new Set(original);

  for (const token of original) {
    // 1. Add ALL synonyms (curated groups — no cap needed)
    const synonyms = getSynonyms(token);
    for (const syn of synonyms) {
      if (!seen.has(syn)) {
        expanded.push(syn);
        expansions.push({ token: syn, source: "synonym", relatedTo: token });
        seen.add(syn);
      }
    }

    // 2. Add stemmed form
    const stemmed = stem(token);
    if (stemmed !== token && !seen.has(stemmed)) {
      expanded.push(stemmed);
      expansions.push({ token: stemmed, source: "stem", relatedTo: token });
      seen.add(stemmed);
    }

    // 3. Add transliteration (KO↔EN loanword)
    const translit = transliterate(token);
    if (translit && !seen.has(translit)) {
      expanded.push(translit);
      expansions.push({ token: translit, source: "transliteration", relatedTo: token });
      seen.add(translit);
      // Also expand the transliterated form's synonyms
      for (const syn of getSynonyms(translit)) {
        if (!seen.has(syn)) {
          expanded.push(syn);
          expansions.push({ token: syn, source: "synonym", relatedTo: translit });
          seen.add(syn);
        }
      }
    }

    // 4. Add co-occurrence neighbors (capped — can be noisy)
    if (coModel) {
      const related = coModel.getRelated(token, maxCoOccurrencePerToken);
      for (const { word } of related) {
        if (!seen.has(word)) {
          expanded.push(word);
          expansions.push({ token: word, source: "cooccurrence", relatedTo: token });
          seen.add(word);
        }
      }
    }

    // 5. Add learned-embedding neighbors (capped — additive, only when a model
    //    has been trained; this is what turns hand-listed synonyms into
    //    relationships learned from the owner's own corpus).
    if (embModel) {
      for (const { word, pmi } of embModel.getRelated(token, maxEmbeddingPerToken)) {
        if (pmi < minEmbeddingScore) continue; // only confident neighbours — cuts expansion noise
        if (!seen.has(word)) {
          expanded.push(word);
          expansions.push({ token: word, source: "embedding", relatedTo: token });
          seen.add(word);
        }
      }
    }
  }

  return { original, expanded, expansions };
}
