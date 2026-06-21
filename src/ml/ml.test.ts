import { test } from "node:test";
import assert from "node:assert/strict";
import { mulberry32, sigmoid, cosine } from "./kernel.js";
import { trainWord2Vec } from "./word2vec.js";
import { EmbeddingModel } from "./embedding-model.js";
import { decomposeHangul, wordSubwords, buildSubwordCentroids } from "./subword.js";

test("mulberry32 is deterministic for a seed", () => {
  const a = mulberry32(42), b = mulberry32(42);
  for (let i = 0; i < 100; i++) assert.equal(a(), b());
  assert.notEqual(mulberry32(1)(), mulberry32(2)());
});

test("sigmoid saturates and is monotonic", () => {
  assert.equal(sigmoid(100), 1);
  assert.equal(sigmoid(-100), 0);
  assert.ok(Math.abs(sigmoid(0) - 0.5) < 0.05);
  assert.ok(sigmoid(1) > sigmoid(-1));
});

test("cosine of identical rows is 1, orthogonal is ~0", () => {
  const v = new Float32Array([1, 0, 0, 1]);
  assert.ok(Math.abs(cosine(v, 0, v, 0, 2) - 1) < 1e-6);
  assert.ok(Math.abs(cosine(v, 0, v, 2, 2)) < 1e-6);
});

test("decomposeHangul splits syllables into jamo and shares prefixes", () => {
  assert.equal(decomposeHangul("후킹"), "ㅎㅜㅋㅣㅇ");
  assert.ok(decomposeHangul("후킹을").startsWith(decomposeHangul("후킹")));
  assert.equal(decomposeHangul("abc"), "abc"); // non-Hangul passes through
});

test("wordSubwords includes the whole-word feature and boundary n-grams", () => {
  const subs = wordSubwords("deploy", 3, 5);
  assert.ok(subs.includes("<deploy>"));
  assert.ok(subs.some((s) => s.startsWith("<")));
  assert.ok(subs.length > 1);
});

test("word2vec is deterministic and learns co-occurrence", () => {
  // Two tight topics that never co-occur — vectors within a topic should be
  // closer than across topics.
  const sentences: string[][] = [];
  for (let i = 0; i < 200; i++) {
    sentences.push(["deploy", "release", "ship", "publish"]);
    sentences.push(["error", "crash", "bug", "fail"]);
  }
  const opts = { dim: 32, epochs: 8, minCount: 2, seed: 7 };
  const a = trainWord2Vec(sentences, opts);
  const b = trainWord2Vec(sentences, opts);
  assert.deepEqual(Array.from(a.vectors), Array.from(b.vectors)); // determinism

  const m = EmbeddingModel.fromTrained(a);
  const top = m.mostSimilar("deploy", 3).map((n) => n.word);
  assert.ok(["release", "ship", "publish"].some((w) => top.includes(w)));
  assert.ok(!top.includes("error")); // cross-topic word should not be nearest
});

test("EmbeddingModel artifact round-trips losslessly", () => {
  const sentences = Array.from({ length: 50 }, () => ["alpha", "beta", "gamma", "delta"]);
  const trained = trainWord2Vec(sentences, { dim: 16, epochs: 3, minCount: 2, seed: 1 });
  const sub = buildSubwordCentroids(trained.vocab, trained.vectors, trained.dim, 3, 5, 1);
  trained.subwordVocab = sub.subwordVocab;
  trained.subwordVectors = sub.subwordVectors;
  trained.subwordCounts = sub.subwordCounts;
  trained.minN = 3; trained.maxN = 5;

  const cache = EmbeddingModel.fromTrained(trained).buildNeighborCache(5);
  const model = EmbeddingModel.fromTrained(trained, cache); // same cache as the artifact
  const artifact = model.toArtifact(
    { name: "t", format: "nexus-sgns", version: 1, dim: 16, vocabSize: trained.vocab.length,
      corpusHash: "x", trainedAt: "now", epochs: 3, window: 5, minCount: 2, negatives: 5, seed: 1 },
    cache,
  );
  const restored = EmbeddingModel.fromArtifact(artifact);
  assert.deepEqual(restored.mostSimilar("alpha", 3), model.mostSimilar("alpha", 3));
});

test("subword composition gives an OOV word a vector when anchored", () => {
  const sentences = Array.from({ length: 80 }, () => ["디버그", "디버깅", "스크립트", "후킹"]);
  const trained = trainWord2Vec(sentences, { dim: 16, epochs: 4, minCount: 2, seed: 3 });
  const sub = buildSubwordCentroids(trained.vocab, trained.vectors, trained.dim, 3, 5, 1);
  trained.subwordVocab = sub.subwordVocab;
  trained.subwordVectors = sub.subwordVectors;
  trained.subwordCounts = sub.subwordCounts;
  trained.minN = 3; trained.maxN = 5;
  const model = EmbeddingModel.fromTrained(trained);
  // "디버그를" is OOV but shares jamo subwords with the in-vocab "디버그".
  const neighbours = model.mostSimilar("디버그를", 4);
  assert.ok(neighbours.length > 0);
});
