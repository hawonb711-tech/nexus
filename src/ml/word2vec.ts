/**
 * Skip-gram with negative sampling (word2vec SGNS) in pure TypeScript.
 *
 * Trains token embeddings over the owner's own corpus so semantic relatedness is
 * *learned from their sessions* rather than hand-listed. Input is pre-tokenized
 * sentences (use the same tokenizer as memory search so the vocab lines up).
 * Deterministic given `opts.seed`.
 */

import { mulberry32, sigmoid, dot } from "./kernel.js";
import type { TrainedEmbeddings, Word2VecOptions } from "./types.js";

export const DEFAULT_W2V: Word2VecOptions = {
  dim: 64,
  window: 5,
  minCount: 5,
  negatives: 5,
  epochs: 10,
  sampleT: 1e-3,
  alpha: 0.025,
  seed: 1337,
  topK: 20,
};

const UNIGRAM_TABLE_SIZE = 1e6;
const UNIGRAM_POWER = 0.75;

export type TrainProgress = (epoch: number, epochs: number) => void;

export function trainWord2Vec(
  sentences: string[][],
  options: Partial<Word2VecOptions> = {},
  onProgress?: TrainProgress,
): TrainedEmbeddings {
  const opts = { ...DEFAULT_W2V, ...options };
  const { dim, window, minCount, negatives, epochs, sampleT, seed } = opts;
  const rand = mulberry32(seed);

  // ── Vocabulary (tokens with count >= minCount) ──────────────────────────────
  const counts = new Map<string, number>();
  for (const sent of sentences) for (const w of sent) counts.set(w, (counts.get(w) ?? 0) + 1);

  const vocab: string[] = [];
  const index = new Map<string, number>();
  let totalTokens = 0;
  for (const [w, c] of counts) {
    if (c < minCount) continue;
    index.set(w, vocab.length);
    vocab.push(w);
    totalTokens += c;
  }
  const V = vocab.length;
  if (V === 0) return { vocab, dim, vectors: new Float32Array(0) };

  const freq = new Float64Array(V);
  for (const [w, c] of counts) {
    const i = index.get(w);
    if (i !== undefined) freq[i] = c;
  }

  // Encode every sentence once to vocab indices (drop OOV / subsampled tokens).
  // Subsampling drops very frequent tokens with prob 1 - sqrt(t / f), which both
  // speeds training and improves rare-word quality (word2vec trick).
  const corpus: number[][] = [];
  for (const sent of sentences) {
    const enc: number[] = [];
    for (const w of sent) {
      const i = index.get(w);
      if (i === undefined) continue;
      if (sampleT > 0) {
        const f = freq[i] / totalTokens;
        const keep = (Math.sqrt(f / sampleT) + 1) * (sampleT / f);
        if (keep < 1 && rand() > keep) continue;
      }
      enc.push(i);
    }
    if (enc.length > 1) corpus.push(enc);
  }

  // ── Negative-sampling table (unigram^0.75) ──────────────────────────────────
  const table = new Int32Array(UNIGRAM_TABLE_SIZE);
  {
    let pow = 0;
    for (let i = 0; i < V; i++) pow += Math.pow(freq[i], UNIGRAM_POWER);
    let i = 0;
    let cum = Math.pow(freq[0], UNIGRAM_POWER) / pow;
    for (let a = 0; a < UNIGRAM_TABLE_SIZE; a++) {
      table[a] = i;
      if (a / UNIGRAM_TABLE_SIZE > cum && i < V - 1) {
        i++;
        cum += Math.pow(freq[i], UNIGRAM_POWER) / pow;
      }
    }
  }

  // ── Parameters: input (syn0) random, output (syn1neg) zero ──────────────────
  const syn0 = new Float32Array(V * dim);
  const syn1 = new Float32Array(V * dim);
  for (let i = 0; i < syn0.length; i++) syn0[i] = (rand() - 0.5) / dim;

  const neu1e = new Float32Array(dim);
  const totalPairs = corpus.reduce((s, c) => s + c.length, 0) * epochs;
  let done = 0;
  const minAlpha = opts.alpha * 1e-4;

  for (let epoch = 0; epoch < epochs; epoch++) {
    for (const enc of corpus) {
      const len = enc.length;
      for (let i = 0; i < len; i++) {
        const center = enc[i];
        // Learning rate decays linearly with progress.
        const alpha = Math.max(minAlpha, opts.alpha * (1 - done / totalPairs));
        done++;

        // Dynamic window: reduce the window per target (closer words weighted more).
        const reduced = 1 + ((rand() * window) | 0);
        const start = Math.max(0, i - reduced);
        const end = Math.min(len, i + reduced + 1);

        for (let j = start; j < end; j++) {
          if (j === i) continue;
          const ctx = enc[j];          // context word → output space (syn1)
          const l1 = center * dim;
          neu1e.fill(0);

          // 1 positive (label 1) + `negatives` sampled negatives (label 0).
          for (let d = 0; d <= negatives; d++) {
            let target: number;
            let label: number;
            if (d === 0) {
              target = ctx;
              label = 1;
            } else {
              target = table[(rand() * UNIGRAM_TABLE_SIZE) | 0];
              if (target === ctx) continue;
              label = 0;
            }
            const l2 = target * dim;
            const f = dot(syn0, l1, syn1, l2, dim);
            const g = (label - sigmoid(f)) * alpha;
            for (let k = 0; k < dim; k++) neu1e[k] += g * syn1[l2 + k];
            for (let k = 0; k < dim; k++) syn1[l2 + k] += g * syn0[l1 + k];
          }
          for (let k = 0; k < dim; k++) syn0[l1 + k] += neu1e[k];
        }
      }
    }
    onProgress?.(epoch + 1, epochs);
  }

  return { vocab, dim, vectors: syn0 };
}
