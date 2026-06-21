/**
 * Query wrapper around trained embeddings: nearest-neighbour lookup and a
 * getRelated() adapter shaped exactly like the existing CoOccurrenceModel so it
 * can drop into expandQuery()/semanticSimilarity() in place of the PMI model.
 *
 * With subwords, a word's vector is the average of its own row (if in vocab) and
 * its subword rows — so even a rare or unseen word (the Korean long tail) gets a
 * composed vector and can find neighbours. Candidate neighbours are always the
 * in-vocab words; similarity uses L2-normalized rows (cosine == dot). An optional
 * precomputed top-K cache keeps in-vocab getRelated() O(1) on the hot path.
 */

import { l2NormalizeRows, dot, norm, f32ToBase64, base64ToF32 } from "./kernel.js";
import { wordSubwords } from "./subword.js";
import type { EmbeddingArtifact, ModelManifest, TrainedEmbeddings } from "./types.js";

export type Neighbour = { word: string; score: number };

type Subwords = { vocab: string[]; vectors: Float32Array; index: Map<string, number>; counts: number[]; minN: number; maxN: number };

/** A subword backed by more than this many in-vocab words is "generic" — its
 *  centroid sits near the global mean and only adds noise, so it is skipped when
 *  composing an out-of-vocab word. Composition that finds no SPECIFIC subword
 *  declines (returns null) rather than emitting a meaningless near-mean vector. */
const SUBWORD_SPECIFICITY_CAP = 40;

export class EmbeddingModel {
  readonly vocab: string[];
  readonly dim: number;
  private readonly wordVectors: Float32Array;
  private readonly index: Map<string, number>;
  private readonly sub?: Subwords;
  private _search: Float32Array | null = null; // composed + L2-normalized in-vocab matrix
  private readonly neighbors?: number[][];
  private readonly neighborScores?: number[][];

  constructor(
    vocab: string[],
    dim: number,
    wordVectors: Float32Array,
    opts: {
      subwordVocab?: string[];
      subwordVectors?: Float32Array;
      subwordCounts?: number[];
      minN?: number;
      maxN?: number;
      cache?: { neighbors: number[][]; neighborScores: number[][] };
    } = {},
  ) {
    this.vocab = vocab;
    this.dim = dim;
    this.wordVectors = wordVectors;
    this.index = new Map(vocab.map((w, i) => [w, i]));
    if (opts.subwordVocab && opts.subwordVectors) {
      this.sub = {
        vocab: opts.subwordVocab,
        vectors: opts.subwordVectors,
        index: new Map(opts.subwordVocab.map((s, i) => [s, i])),
        counts: opts.subwordCounts ?? [],
        minN: opts.minN ?? 3,
        maxN: opts.maxN ?? 5,
      };
    }
    this.neighbors = opts.cache?.neighbors;
    this.neighborScores = opts.cache?.neighborScores;
  }

  static fromTrained(t: TrainedEmbeddings, cache?: { neighbors: number[][]; neighborScores: number[][] }): EmbeddingModel {
    return new EmbeddingModel(t.vocab, t.dim, t.vectors, {
      subwordVocab: t.subwordVocab, subwordVectors: t.subwordVectors, subwordCounts: t.subwordCounts,
      minN: t.minN, maxN: t.maxN, cache,
    });
  }

  /** Strict word-vocabulary membership (defines the candidate-neighbour set). */
  has(word: string): boolean {
    return this.index.has(word.toLowerCase());
  }

  /**
   * Compose a vector for any word. In-vocab words return their PURE trained
   * vector (the semantic signal — subwords would only dilute it). Out-of-vocab
   * words — the rare Korean tail — return the average of their subword
   * centroids. null when the word has no representable constituents.
   */
  private compose(word: string): Float32Array | null {
    const w = word.toLowerCase();
    const wi = this.index.get(w);
    if (wi !== undefined) {
      const v = new Float32Array(this.dim);
      v.set(this.wordVectors.subarray(wi * this.dim, (wi + 1) * this.dim));
      return v;
    }
    if (!this.sub) return null;
    const v = new Float32Array(this.dim);
    let n = 0;
    for (const sg of wordSubwords(w, this.sub.minN, this.sub.maxN)) {
      const si = this.sub.index.get(sg);
      if (si === undefined) continue;
      if ((this.sub.counts[si] ?? Infinity) > SUBWORD_SPECIFICITY_CAP) continue; // skip generic subwords
      const off = si * this.dim;
      for (let k = 0; k < this.dim; k++) v[k] += this.sub.vectors[off + k];
      n++;
    }
    if (n === 0) return null; // no specific anchor → decline rather than emit noise
    for (let k = 0; k < this.dim; k++) v[k] /= n;
    return v;
  }

  /** Composed, L2-normalized in-vocab matrix used as the neighbour candidate set. */
  private searchMatrix(): Float32Array {
    if (this._search) return this._search;
    const composed = new Float32Array(this.vocab.length * this.dim);
    for (let i = 0; i < this.vocab.length; i++) {
      const v = this.compose(this.vocab[i]);
      if (v) composed.set(v, i * this.dim);
    }
    this._search = l2NormalizeRows(composed, this.vocab.length, this.dim);
    return this._search;
  }

  /** Top-N most similar in-vocab tokens to `word` (works for OOV via subwords). */
  mostSimilar(word: string, topN = 10): Neighbour[] {
    const w = word.toLowerCase();
    const self = this.index.get(w);

    // Cache hit (in-vocab, hot path).
    if (self !== undefined && this.neighbors && this.neighborScores) {
      const idx = this.neighbors[self] ?? [];
      const sc = this.neighborScores[self] ?? [];
      return idx.slice(0, topN).map((j, k) => ({ word: this.vocab[j], score: sc[k] }));
    }

    const q = this.compose(w);
    if (!q) return [];
    const qn = norm(q, 0, this.dim);
    if (qn === 0) return [];
    for (let k = 0; k < this.dim; k++) q[k] /= qn;

    const search = this.searchMatrix();
    const { dim } = this;
    const best: Neighbour[] = [];
    let worst = -Infinity;
    for (let j = 0; j < this.vocab.length; j++) {
      if (j === self) continue;
      const s = dot(q, 0, search, j * dim, dim);
      if (best.length < topN) {
        best.push({ word: this.vocab[j], score: s });
        if (best.length === topN) { best.sort((a, b) => a.score - b.score); worst = best[0].score; }
      } else if (s > worst) {
        best[0] = { word: this.vocab[j], score: s };
        best.sort((a, b) => a.score - b.score);
        worst = best[0].score;
      }
    }
    return best.sort((a, b) => b.score - a.score);
  }

  /** Adapter matching CoOccurrenceModel.getRelated — `pmi` carries the cosine score. */
  getRelated(word: string, topN = 10): { word: string; pmi: number }[] {
    return this.mostSimilar(word, topN).map((n) => ({ word: n.word, pmi: n.score }));
  }

  /** Precompute the top-K in-vocab neighbour cache for every token (one-time). */
  buildNeighborCache(topK: number): { neighbors: number[][]; neighborScores: number[][] } {
    const search = this.searchMatrix();
    const { dim } = this;
    const V = this.vocab.length;
    const neighbors: number[][] = new Array(V);
    const neighborScores: number[][] = new Array(V);
    const scores = new Float32Array(V);
    for (let i = 0; i < V; i++) {
      const off = i * dim;
      for (let j = 0; j < V; j++) scores[j] = j === i ? -Infinity : dot(search, off, search, j * dim, dim);
      const idx: number[] = [];
      const sc: number[] = [];
      for (let t = 0; t < topK; t++) {
        let bi = -1, bs = -Infinity;
        for (let j = 0; j < V; j++) if (scores[j] > bs) { bs = scores[j]; bi = j; }
        if (bi < 0 || bs === -Infinity) break;
        idx.push(bi); sc.push(Math.round(bs * 1000) / 1000);
        scores[bi] = -Infinity;
      }
      neighbors[i] = idx;
      neighborScores[i] = sc;
    }
    return { neighbors, neighborScores };
  }

  toArtifact(manifest: ModelManifest, cache: { neighbors: number[][]; neighborScores: number[][] }): EmbeddingArtifact {
    const a: EmbeddingArtifact = {
      manifest,
      vocab: this.vocab,
      vectorsB64: f32ToBase64(this.wordVectors),
      neighbors: cache.neighbors,
      neighborScores: cache.neighborScores,
    };
    if (this.sub) {
      a.subwordVocab = this.sub.vocab;
      a.subwordVectorsB64 = f32ToBase64(this.sub.vectors);
      a.subwordCounts = this.sub.counts;
      a.minN = this.sub.minN;
      a.maxN = this.sub.maxN;
    }
    return a;
  }

  static fromArtifact(a: EmbeddingArtifact): EmbeddingModel {
    const cache = a.neighbors && a.neighbors.length
      ? { neighbors: a.neighbors, neighborScores: a.neighborScores }
      : undefined;
    return new EmbeddingModel(a.vocab, a.manifest.dim, base64ToF32(a.vectorsB64), {
      subwordVocab: a.subwordVocab,
      subwordVectors: a.subwordVectorsB64 ? base64ToF32(a.subwordVectorsB64) : undefined,
      subwordCounts: a.subwordCounts,
      minN: a.minN, maxN: a.maxN, cache,
    });
  }
}
