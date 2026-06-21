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
};

export type TrainedEmbeddings = {
  vocab: string[];
  dim: number;
  /** Row-major vocab×dim. */
  vectors: Float32Array;
};
