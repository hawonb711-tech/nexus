import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { inspectContent } from "./guard.js";
import { inspectCommand, inspectFileWrite } from "./command.js";

/**
 * Adversarial regression corpus — the HONEST counterpart to firewall.test.ts.
 *
 * firewall.test.ts uses a friendly, self-made corpus the patterns were written
 * to pass (30/30). This file loads 62 attacks that were red-teamed *against the
 * guard's own regex logic* — each is genuinely malicious yet crafted to evade a
 * specific pattern (runtime-built tokens, unmodeled tools, param-expansion, etc).
 *
 * Pattern matching catches ~3% of these. That is the point: this number is a
 * RATCHET. ADAPTIVE_BASELINE is the floor of what the guard catches today; a
 * change may only push it UP. When a structural defense lands and the catch
 * count rises, bump ADAPTIVE_BASELINE to lock in the gain. It can never silently
 * regress, and the corpus can never silently shrink.
 */

const ADAPTIVE_BASELINE = 36; // caught (block/ask/deny) out of 62 — structural cmd+filewrite layer
const CORPUS_SIZE = 62;

type Attack = { id: number; kind: "command" | "content" | "filewrite"; class: string; filePath?: string; payload: string; why: string };
const corpus = JSON.parse(readFileSync(fileURLToPath(new URL("./adaptive-corpus.json", import.meta.url)), "utf-8")) as { count: number; attacks: Attack[] };

/** True if the guard would stop this attack (anything other than a clean allow). */
function caughtBy(a: Attack): boolean {
  if (a.kind === "command") return inspectCommand(a.payload).decision !== "allow";
  if (a.kind === "filewrite") return inspectFileWrite(a.filePath ?? "", a.payload).decision !== "allow";
  return inspectContent(a.payload).verdict !== "allow";
}

test("adaptive corpus is intact (no silent shrink)", () => {
  assert.equal(corpus.attacks.length, CORPUS_SIZE, "corpus size changed — update CORPUS_SIZE deliberately");
  assert.equal(corpus.count, CORPUS_SIZE);
});

test("guard catches at least the recorded baseline of adaptive attacks (ratchet)", () => {
  const caught = corpus.attacks.filter(caughtBy);
  // Surface the live number in CI logs so improvement is visible at a glance.
  console.log(`  adaptive corpus: guard catches ${caught.length}/${CORPUS_SIZE} (baseline ${ADAPTIVE_BASELINE})`);
  assert.ok(
    caught.length >= ADAPTIVE_BASELINE,
    `regression: guard now catches ${caught.length}/${CORPUS_SIZE}, below baseline ${ADAPTIVE_BASELINE}`,
  );
});
