/**
 * Pure-TypeScript numeric kernel: a seeded RNG, sigmoid, and Float32 vector ops.
 * No dependencies. Deterministic given a seed so training and the eval gate are
 * reproducible (a flaky, unseeded SGD would make model promotion non-auditable).
 */

/** Deterministic, fast PRNG (mulberry32) in [0, 1). */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Precomputed sigmoid lookup over [-6, 6] (values saturate outside), the same
 * trick the original word2vec uses to avoid a Math.exp per training update.
 */
const SIG_TABLE_SIZE = 1024;
const SIG_MAX = 6;
const SIG_TABLE = (() => {
  const t = new Float32Array(SIG_TABLE_SIZE);
  for (let i = 0; i < SIG_TABLE_SIZE; i++) {
    const x = (i / SIG_TABLE_SIZE) * 2 * SIG_MAX - SIG_MAX;
    t[i] = 1 / (1 + Math.exp(-x));
  }
  return t;
})();

/** Sigmoid via lookup table; saturates to 0/1 beyond ±6. */
export function sigmoid(x: number): number {
  if (x >= SIG_MAX) return 1;
  if (x <= -SIG_MAX) return 0;
  return SIG_TABLE[((x + SIG_MAX) * (SIG_TABLE_SIZE / (2 * SIG_MAX))) | 0];
}

/** Dot product of two dim-length rows at the given offsets. */
export function dot(a: Float32Array, ao: number, b: Float32Array, bo: number, dim: number): number {
  let s = 0;
  for (let k = 0; k < dim; k++) s += a[ao + k] * b[bo + k];
  return s;
}

/** L2 norm of a dim-length row. */
export function norm(a: Float32Array, ao: number, dim: number): number {
  return Math.sqrt(dot(a, ao, a, ao, dim));
}

/** Cosine similarity of two dim-length rows. */
export function cosine(a: Float32Array, ao: number, b: Float32Array, bo: number, dim: number): number {
  const na = norm(a, ao, dim);
  const nb = norm(b, bo, dim);
  if (na === 0 || nb === 0) return 0;
  return dot(a, ao, b, bo, dim) / (na * nb);
}

/** Return a row-normalized copy of a vocab×dim matrix (unit L2 per row). */
export function l2NormalizeRows(vectors: Float32Array, rows: number, dim: number): Float32Array {
  const out = new Float32Array(vectors.length);
  for (let r = 0; r < rows; r++) {
    const off = r * dim;
    const n = norm(vectors, off, dim);
    if (n === 0) continue;
    for (let k = 0; k < dim; k++) out[off + k] = vectors[off + k] / n;
  }
  return out;
}

// ── Float32 ⇆ base64 (compact plain-JSON serialization) ─────────────────────────
export function f32ToBase64(a: Float32Array): string {
  return Buffer.from(a.buffer, a.byteOffset, a.byteLength).toString("base64");
}

export function base64ToF32(s: string): Float32Array {
  const buf = Buffer.from(s, "base64");
  // Copy out of the (possibly pooled) Buffer into a standalone Float32Array.
  return new Float32Array(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
}
