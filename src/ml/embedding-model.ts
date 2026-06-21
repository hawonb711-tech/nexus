/**
 * Query wrapper around trained embeddings: nearest-neighbour lookup and a
 * getRelated() adapter shaped exactly like the existing CoOccurrenceModel so it
 * can drop into expandQuery()/semanticSimilarity() in place of the PMI model.
 *
 * Similarity uses L2-normalized rows (so cosine == dot). An optional precomputed
 * top-K neighbour cache makes getRelated() O(1) on the hot clustering path; when
 * absent it falls back to an O(vocab·dim) scan (sub-millisecond for normal use).
 */

import { l2NormalizeRows, dot, f32ToBase64, base64ToF32 } from "./kernel.js";
import type { EmbeddingArtifact, ModelManifest, TrainedEmbeddings } from "./types.js";

export type Neighbour = { word: string; score: number };

export class EmbeddingModel {
  readonly vocab: string[];
  readonly dim: number;
  private readonly vectors: Float32Array;
  private readonly index: Map<string, number>;
  private _normalized: Float32Array | null = null;
  private readonly neighbors?: number[][];
  private readonly neighborScores?: number[][];

  constructor(
    vocab: string[],
    dim: number,
    vectors: Float32Array,
    cache?: { neighbors: number[][]; neighborScores: number[][] },
  ) {
    this.vocab = vocab;
    this.dim = dim;
    this.vectors = vectors;
    this.index = new Map(vocab.map((w, i) => [w, i]));
    this.neighbors = cache?.neighbors;
    this.neighborScores = cache?.neighborScores;
  }

  static fromTrained(t: TrainedEmbeddings, cache?: { neighbors: number[][]; neighborScores: number[][] }): EmbeddingModel {
    return new EmbeddingModel(t.vocab, t.dim, t.vectors, cache);
  }

  private normalized(): Float32Array {
    if (!this._normalized) this._normalized = l2NormalizeRows(this.vectors, this.vocab.length, this.dim);
    return this._normalized;
  }

  has(word: string): boolean {
    return this.index.has(word.toLowerCase());
  }

  /** Top-N most similar tokens to `word` (excludes the word itself). */
  mostSimilar(word: string, topN = 10): Neighbour[] {
    const i = this.index.get(word.toLowerCase());
    if (i === undefined) return [];

    // Cache hit (the common, hot path once a model is trained).
    if (this.neighbors && this.neighborScores) {
      const idx = this.neighbors[i] ?? [];
      const sc = this.neighborScores[i] ?? [];
      return idx.slice(0, topN).map((j, k) => ({ word: this.vocab[j], score: sc[k] }));
    }

    // Lazy scan over the normalized matrix.
    const norm = this.normalized();
    const { dim } = this;
    const off = i * dim;
    const best: Neighbour[] = [];
    let worst = -Infinity;
    for (let j = 0; j < this.vocab.length; j++) {
      if (j === i) continue;
      const s = dot(norm, off, norm, j * dim, dim);
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

  /** Precompute the top-K neighbour cache for every token (one-time, at train). */
  buildNeighborCache(topK: number): { neighbors: number[][]; neighborScores: number[][] } {
    const norm = this.normalized();
    const { dim } = this;
    const V = this.vocab.length;
    const neighbors: number[][] = new Array(V);
    const neighborScores: number[][] = new Array(V);
    const scores = new Float32Array(V);
    for (let i = 0; i < V; i++) {
      const off = i * dim;
      for (let j = 0; j < V; j++) scores[j] = j === i ? -Infinity : dot(norm, off, norm, j * dim, dim);
      // Partial top-K selection.
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

  toArtifact(manifest: ModelManifest, cache?: { neighbors: number[][]; neighborScores: number[][] }): EmbeddingArtifact {
    const c = cache ?? (this.neighbors && this.neighborScores
      ? { neighbors: this.neighbors, neighborScores: this.neighborScores }
      : { neighbors: [], neighborScores: [] });
    return {
      manifest,
      vocab: this.vocab,
      vectorsB64: f32ToBase64(this.vectors),
      neighbors: c.neighbors,
      neighborScores: c.neighborScores,
    };
  }

  static fromArtifact(a: EmbeddingArtifact): EmbeddingModel {
    const cache = a.neighbors && a.neighbors.length
      ? { neighbors: a.neighbors, neighborScores: a.neighborScores }
      : undefined;
    return new EmbeddingModel(a.vocab, a.manifest.dim, base64ToF32(a.vectorsB64), cache);
  }
}
