/**
 * Types for the pure-TypeScript ML kernel.
 *
 * Phase 1 of "self-learning Nexus": learn representations from the owner's own
 * accumulated observation corpus instead of hand-tuned heuristics. All artifacts
 * are plain JSON (Float32 matrices base64-encoded) persisted next to the other
 * ~/.nexus state, and all *inference* is pure typed-array math — no external
 * runtime, no API. Everything here is deterministic given a seed so the eval
 * gate that promotes a model is reproducible.
 */

/** Provenance + config recorded with every trained artifact. */
export type ModelManifest = {
  name: string;
  format: "nexus-sgns";
  version: number;
  dim: number;
  vocabSize: number;
  /** Hash of the training corpus — lets a loader know if the model is stale. */
  corpusHash: string;
  /** ISO timestamp, supplied by the caller (the kernel never reads the clock). */
  trainedAt: string;
  epochs: number;
  window: number;
  minCount: number;
  negatives: number;
  seed: number;
  /** Eval results from the gate that promoted this artifact (e.g. recall@10). */
  metrics?: Record<string, number>;
};

/** On-disk embedding artifact (plain JSON). */
export type EmbeddingArtifact = {
  manifest: ModelManifest;
  /** index → token. */
  vocab: string[];
  /** Row-major vocab×dim Float32 matrix, base64 of the little-endian buffer. */
  vectorsB64: string;
  /** Precomputed top-K neighbour indices per token, for O(1) getRelated(). */
  neighbors: number[][];
  /** Cosine score parallel to `neighbors`. */
  neighborScores: number[][];
  /** Subword feature vocabulary + matrix (present iff trained with subwords). */
  subwordVocab?: string[];
  subwordVectorsB64?: string;
  subwordCounts?: number[];
  minN?: number;
  maxN?: number;
};

export type Word2VecOptions = {
  dim: number;
  window: number;
  minCount: number;
  negatives: number;
  epochs: number;
  /** Subsampling threshold for frequent tokens (word2vec `t`); 0 disables. */
  sampleT: number;
  /** Initial learning rate (decays linearly toward 0). */
  alpha: number;
  seed: number;
  /** Neighbours to precompute per token for the query-time cache. */
  topK: number;
  /** Enable fastText-style subword (char n-gram) features. */
  subword: boolean;
  /** Subword n-gram range (over jamo-decomposed, boundary-marked words). */
  minN: number;
  maxN: number;
  /** Drop subwords whose total weighted count is below this. */
  subwordMinCount: number;
};

export type TrainedEmbeddings = {
  vocab: string[];
  dim: number;
  /** Row-major vocab×dim — the per-word input vectors. */
  vectors: Float32Array;
  /** Present when trained with subwords: the subword feature vocabulary and its
   *  row-major matrix, used to compose vectors for rare / unseen words. */
  subwordVocab?: string[];
  subwordVectors?: Float32Array;
  /** Per-subword backing count (how many in-vocab words contain it). */
  subwordCounts?: number[];
  minN?: number;
  maxN?: number;
};
