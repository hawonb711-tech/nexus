/**
 * Versioned model artifacts on disk, mirroring the existing graph.json /
 * knowledge.json persistence discipline: plain JSON under ~/.nexus/models/, a
 * manifest with provenance, and a loader that returns null when absent so every
 * caller can fall back to the hand-tuned heuristics. Nothing here ever throws on
 * a missing model — a fresh install simply has no learned models yet.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { EmbeddingModel } from "./embedding-model.js";
import type { EmbeddingArtifact, ModelManifest } from "./types.js";

function modelsDir(dataDir: string): string {
  return join(dataDir, "models");
}

export function modelPath(dataDir: string, name: string): string {
  return join(modelsDir(dataDir), `${name}.json`);
}

/** Stable hash of the training corpus — recorded in the manifest so a loader can
 *  tell whether the model is stale relative to current memory. */
export function corpusHash(documents: string[]): string {
  const h = createHash("sha256");
  h.update(String(documents.length));
  for (const d of documents) h.update(d);
  return h.digest("hex").slice(0, 16);
}

export function saveEmbeddingArtifact(dataDir: string, name: string, artifact: EmbeddingArtifact): string {
  const dir = modelsDir(dataDir);
  mkdirSync(dir, { recursive: true });
  const path = modelPath(dataDir, name);
  writeFileSync(path, JSON.stringify(artifact), "utf-8");
  return path;
}

/** Load a trained embedding model, or null if none exists / it is unreadable. */
export function loadEmbeddingModel(dataDir: string, name = "embeddings"): EmbeddingModel | null {
  const path = modelPath(dataDir, name);
  if (!existsSync(path)) return null;
  try {
    const artifact = JSON.parse(readFileSync(path, "utf-8")) as EmbeddingArtifact;
    if (artifact?.manifest?.format !== "nexus-sgns") return null;
    return EmbeddingModel.fromArtifact(artifact);
  } catch {
    return null;
  }
}

/** Read just the manifest (cheap-ish) for `nexus status` / inspection. */
export function loadManifest(dataDir: string, name = "embeddings"): ModelManifest | null {
  const path = modelPath(dataDir, name);
  if (!existsSync(path)) return null;
  try {
    const artifact = JSON.parse(readFileSync(path, "utf-8")) as EmbeddingArtifact;
    return artifact.manifest ?? null;
  } catch {
    return null;
  }
}

export function listModels(dataDir: string): string[] {
  const dir = modelsDir(dataDir);
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f.endsWith(".json")).map((f) => f.replace(/\.json$/, ""));
}
