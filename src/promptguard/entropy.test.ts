import { test } from "node:test";
import assert from "node:assert/strict";

import {
  shannonEntropy,
  detectHighEntropySegments,
  analyzeEntropy,
} from "./entropy.js";

test("shannonEntropy is 0 for empty and for a single repeated character", () => {
  assert.equal(shannonEntropy(""), 0);
  assert.equal(shannonEntropy("aaaaaaaaaa"), 0);
});

test("shannonEntropy: uniform 2-symbol string is 1 bit, random text is higher", () => {
  // 50/50 split of two symbols => exactly 1 bit/char.
  assert.equal(shannonEntropy("abababab"), 1);

  // A varied/random-ish string has strictly higher entropy than a low-variety one.
  const low = shannonEntropy("aaaaaaaaaaaaaaaab");
  const high = shannonEntropy("aZ7q!Lm3#Xp9vB2&");
  assert.ok(high > low, `expected ${high} > ${low}`);
  // 16 distinct chars over length 16 => the maximum, log2(16) = 4 bits.
  assert.equal(high, 4);
});

test("detectHighEntropySegments flags a long random base64-ish string", () => {
  // 80+ chars of high-variety base64 alphabet; entropy/char well above the 4.5 Latin threshold.
  const blob =
    "aZ9kQ2wX7pL4mN8vB1cR6tY3uH5gF0dS-eJjKlOiPqWzXcVbNmAsDfGhJkLqWeRtYuIoP1234567890";
  const findings = detectHighEntropySegments(blob);

  assert.ok(findings.length >= 1, "expected at least one high-entropy finding");
  const f = findings[0]!;
  assert.equal(f.type, "high-entropy-segment");
  assert.equal(f.severity, "medium");
  assert.equal(typeof f.offset, "number");
  assert.ok(f.offset >= 0);
  assert.ok(typeof f.evidence === "string" && f.evidence.length > 0);
});

test("detectHighEntropySegments ignores normal English prose", () => {
  const prose =
    "The quick brown fox jumps over the lazy dog. " +
    "This is an ordinary sentence written in plain English with normal words and spacing.";
  assert.ok(prose.length >= 64, "fixture must exceed the 64-char window");
  assert.deepEqual(detectHighEntropySegments(prose), []);
});

test("detectHighEntropySegments returns empty for input shorter than the window", () => {
  // 64-char sliding window => anything shorter yields no findings.
  assert.deepEqual(detectHighEntropySegments("short random qZ1p"), []);
});

test("analyzeEntropy returns the documented result shape", () => {
  const result = analyzeEntropy("hello world hello world");

  assert.equal(typeof result.shannonEntropy, "number");
  assert.ok(result.charFrequency instanceof Map);
  assert.ok(Array.isArray(result.suspiciousPatterns));

  // charFrequency must agree with the input counts.
  assert.equal(result.charFrequency.get("l"), 6);
  assert.equal(result.charFrequency.get("o"), 4);

  // Top-level entropy matches the standalone helper on the same input.
  assert.equal(result.shannonEntropy, shannonEntropy("hello world hello world"));
});

test("analyzeEntropy surfaces high-entropy patterns for an obfuscated blob", () => {
  const blob =
    "aZ9kQ2wX7pL4mN8vB1cR6tY3uH5gF0dS-eJjKlOiPqWzXcVbNmAsDfGhJkLqWeRtYuIoP1234567890";
  const result = analyzeEntropy(blob);

  assert.ok(result.suspiciousPatterns.length >= 1);
  assert.ok(
    result.suspiciousPatterns.some((p) => p.type === "high-entropy-segment"),
  );
});
