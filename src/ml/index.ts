export type {
  ModelManifest,
  EmbeddingArtifact,
  Word2VecOptions,
  TrainedEmbeddings,
} from "./types.js";

export { trainWord2Vec, DEFAULT_W2V } from "./word2vec.js";
export { buildSubwordCentroids, decomposeHangul, wordSubwords } from "./subword.js";
export { EmbeddingModel } from "./embedding-model.js";
export type { Neighbour } from "./embedding-model.js";
export {
  saveEmbeddingArtifact,
  loadEmbeddingModel,
  loadManifest,
  listModels,
  modelPath,
  corpusHash,
} from "./model-store.js";
export { evalSynonymRecall } from "./eval.js";
export type { RecallReport } from "./eval.js";

export { mulberry32, sigmoid, cosine } from "./kernel.js";
