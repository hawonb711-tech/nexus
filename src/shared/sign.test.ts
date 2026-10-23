import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { canonicalJson, hmacHex, subkey, timingSafeEqualHex } from "./sign.js";

test("canonicalJson sorts keys at every depth, keeps array order, writes no whitespace", () => {
  const doc = { b: 1, a: { d: [3, 1, { z: true, y: null }], c: "x y" } };
  assert.equal(canonicalJson(doc), '{"a":{"c":"x y","d":[3,1,{"y":null,"z":true}]},"b":1}');
  // Key order of the input never matters; the text parses back to the same value.
  const shuffled = { a: { c: "x y", d: [3, 1, { y: null, z: true }] }, b: 1 };
  assert.equal(canonicalJson(shuffled), canonicalJson(doc));
  assert.deepEqual(JSON.parse(canonicalJson(doc)), doc);
});

test("canonicalJson orders integer-like keys as strings, not in engine order", () => {
  // JSON.stringify emits integer-like keys first and numerically: {"9":…,"10":…}.
  assert.equal(canonicalJson({ b: 3, 10: 1, 9: 2 }), '{"10":1,"9":2,"b":3}');
});

test("canonicalJson follows JSON.stringify for values", () => {
  assert.equal(canonicalJson({ a: undefined, b: () => 1, c: 1 }), '{"c":1}');
  assert.equal(canonicalJson([undefined, () => 1, 1]), "[null,null,1]");
  assert.equal(canonicalJson({ n: Number.NaN, i: Infinity, z: -0 }), '{"i":null,"n":null,"z":0}');
  assert.equal(canonicalJson({ d: new Date(0) }), '{"d":"1970-01-01T00:00:00.000Z"}');
  const text = 'quote " backslash \\ newline \n tab \t nul \u0000 sep \u2028 astral \u{1F6E1}';
  assert.equal(canonicalJson({ text }), JSON.stringify({ text }));
  assert.equal(canonicalJson("s"), '"s"');
  assert.equal(canonicalJson(null), "null");
  assert.equal(canonicalJson(undefined), "null");
  assert.equal(canonicalJson([]), "[]");
  assert.equal(canonicalJson({}), "{}");
});

test("hmacHex and subkey are HMAC-SHA256, the subkey bound to its label", () => {
  const key = randomBytes(32);
  assert.equal(hmacHex(key, "text"), createHmac("sha256", key).update("text").digest("hex"));
  assert.match(hmacHex(key, ""), /^[0-9a-f]{64}$/);
  assert.deepEqual(subkey(key, "store"), createHmac("sha256", key).update("nexus/integrity/v1/store").digest());
  const labels = ["unit", "store", "registry", "ledger", "config", "nonce", "key-id"];
  assert.equal(new Set(labels.map((l) => subkey(key, l).toString("hex"))).size, labels.length);
  assert.notDeepEqual(subkey(key, "store"), subkey(randomBytes(32), "store"));
});

test("timingSafeEqualHex compares exactly, and a length mismatch is unequal rather than a throw", () => {
  const mac = `v1:${hmacHex(randomBytes(32), "doc")}`;
  assert.equal(timingSafeEqualHex(mac, `${mac}`), true);
  assert.equal(timingSafeEqualHex(mac, `${mac.slice(0, -1)}${mac.endsWith("0") ? "1" : "0"}`), false);
  assert.equal(timingSafeEqualHex(mac, mac.slice(0, -1)), false);
  assert.equal(timingSafeEqualHex(mac, ""), false);
  assert.equal(timingSafeEqualHex("", ""), true);
  // Malformed hex is compared as text, so two different strings never collapse to equal buffers.
  assert.equal(timingSafeEqualHex("zz", "yy"), false);
  assert.equal(timingSafeEqualHex("ab", "AB"), false);
});
