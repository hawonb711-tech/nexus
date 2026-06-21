/**
 * Multilingual sentence encoder — the one optional, local, zero-API model.
 *
 * Pure-TS SGNS hit a wall on the Korean long tail (프리다/후킹 are too rare to
 * learn from this corpus alone). A pretrained multilingual encoder brings
 * EXTERNAL knowledge — it already knows 후킹 ≈ hooking — so cross-lingual
 * retrieval works at the sentence level without any per-corpus training.
 *
 * It runs entirely on-device via transformers.js (onnxruntime under the hood):
 * zero API calls, zero cloud. The dependency is OPTIONAL — it is lazy-imported
 * here, so the core framework still installs and runs without it; only the dense
 * encoder paths require it. Model weights download once to ~/.nexus/models/hf.
 */

import { join } from "node:path";
import { createRequire } from "node:module";

const _require = createRequire(import.meta.url);

/** Small, strong multilingual sentence-embedding model (384-dim, good Korean). */
export const ENCODER_MODEL = "Xenova/paraphrase-multilingual-MiniLM-L12-v2";
export const ENCODER_DIM = 384;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _pipe: any = null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _loading: Promise<any> | null = null;

export function isEncoderInstalled(): boolean {
  try {
    // Resolve without importing the heavy module.
    return !!_require.resolve("@huggingface/transformers");
  } catch {
    return false;
  }
}

/** Lazily load the feature-extraction pipeline (downloads the model on first use). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function getEncoder(dataDir: string): Promise<any> {
  if (_pipe) return _pipe;
  if (!_loading) {
    _loading = (async () => {
      let transformers;
      try {
        transformers = await import("@huggingface/transformers");
      } catch {
        throw new Error(
          "The dense encoder needs the optional dependency. Install it with:\n" +
          "  npm install @huggingface/transformers",
        );
      }
      const { pipeline, env } = transformers;
      env.cacheDir = join(dataDir, "models", "hf"); // keep weights under ~/.nexus
      _pipe = await pipeline("feature-extraction", ENCODER_MODEL, { dtype: "q8" });
      return _pipe;
    })();
  }
  return _loading;
}

/**
 * Embed texts into L2-normalized sentence vectors (mean-pooled). Returns a flat
 * row-major N×dim Float32Array. Batched to bound memory.
 */
export async function embedTexts(
  dataDir: string,
  texts: string[],
  batchSize = 32,
  onProgress?: (done: number, total: number) => void,
): Promise<{ vectors: Float32Array; dim: number }> {
  const pipe = await getEncoder(dataDir);
  const vectors = new Float32Array(texts.length * ENCODER_DIM);
  let dim = ENCODER_DIM;
  for (let i = 0; i < texts.length; i += batchSize) {
    const batch = texts.slice(i, i + batchSize).map((t) => t.slice(0, 512)); // cap length
    const res = await pipe(batch, { pooling: "mean", normalize: true });
    dim = res.dims[res.dims.length - 1];
    const data = res.data as Float32Array;
    for (let b = 0; b < batch.length; b++) {
      vectors.set(data.subarray(b * dim, (b + 1) * dim), (i + b) * dim);
    }
    onProgress?.(Math.min(i + batchSize, texts.length), texts.length);
  }
  return { vectors, dim };
}

/** Embed a single text → its sentence vector. */
export async function embedOne(dataDir: string, text: string): Promise<Float32Array> {
  const { vectors, dim } = await embedTexts(dataDir, [text], 1);
  return vectors.subarray(0, dim) as Float32Array;
}
