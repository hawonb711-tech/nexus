import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { scan } from "../promptguard/scanner.js";
import { inspectContent } from "./guard.js";
import { inspectCommand, inspectFileWrite } from "./command.js";

/**
 * Hot-path performance ratchets.
 *
 * The PreToolUse / PostToolUse hooks run inspectCommand / inspectFileWrite /
 * inspectContent synchronously on every command, every file write and every
 * fetched page, so a single super-linear regex on a large or adversarial input
 * stalls the agent for seconds-to-minutes. These budgets are deliberately
 * generous (CI machines are slow and shared) yet an order of magnitude below the
 * multi-second times a quadratic/exponential pattern produces, so they still fail
 * loudly if one is reintroduced. See scripts/perf-audit.ts for the full matrix.
 */

const SRC_ROOT = fileURLToPath(new URL("..", import.meta.url));

/** Deterministic ~`bytes`-long input built by repeating `chunk`. */
function repeat(chunk: string, bytes: number): string {
  return chunk.repeat(Math.ceil(bytes / chunk.length)).slice(0, bytes);
}

/** ~200 KB of ordinary English-ish prose (no injection payload). */
function prose(bytes: number): string {
  const words = (
    "the a of to and in is it that for on with as this was be by are from or at " +
    "system prompt instruction user data value function return request response file " +
    "server client token example step note important config build test run install " +
    "package module error option default string number object array host port network"
  ).split(" ");
  let seed = 7;
  const next = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);
  let out = "";
  let n = 0;
  while (out.length < bytes) {
    const len = 6 + (next() % 12);
    const sentence: string[] = [];
    for (let i = 0; i < len; i++) sentence.push(words[next() % words.length]);
    out += sentence.join(" ") + (n++ % 4 === 3 ? ".\n" : ". ");
  }
  return out.slice(0, bytes);
}

/** Time `fn()` in ms, after one warm-up run to take JIT out of the measurement. */
function timed(fn: () => unknown): number {
  fn();
  const t0 = performance.now();
  fn();
  return performance.now() - t0;
}

function listProdSources(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) listProdSources(p, out);
    else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) out.push(p);
  }
  return out;
}

const BIG = 200_000;
const SMALL = 50_000; // the 4×-smaller size the growth ratios compare against.
// Optional CI headroom: a loaded windows/macOS runner can be 2–3× slower than a
// quiet Linux box, so wall-clock backstops are multiplied by NEXUS_PERF_SLACK.
const SLACK = Math.max(1, Number(process.env.NEXUS_PERF_SLACK) || 1);
// Absolute backstops are generous (a quadratic takes tens of seconds here, an
// order of magnitude over these); the real ratchet is the GROWTH ratio below,
// which is machine-independent. Scaled by SLACK for slow CI.
const BIG_BUDGET_MS = 2000 * SLACK;
const BIG_CMD_BUDGET_MS = 4000 * SLACK;
// 4× the input should cost roughly 4× for a linear pass (~8× tolerates noise and
// the ~log factor); a quadratic pass costs ~16×, so this still trips loudly while
// never depending on how fast — or how loaded — the machine is.
const MAX_GROWTH = 8;

/** Assert a check scales (near-)linearly: time it at 50 KB and 200 KB and require
 *  the 4×-input slowdown to stay under MAX_GROWTH, plus a generous wall-clock cap. */
function assertScales(label: string, run: (s: string) => unknown, build: (bytes: number) => string, capMs: number): void {
  const small = build(SMALL), big = build(BIG);
  const tSmall = Math.max(timed(() => run(small)), 0.5); // floor avoids a divide-by-noise ratio
  const tBig = timed(() => run(big));
  const ratio = tBig / tSmall;
  assert.ok(
    ratio < MAX_GROWTH,
    `${label}: 4× input grew ${ratio.toFixed(1)}× (${tSmall.toFixed(0)}→${tBig.toFixed(0)}ms) — expected < ${MAX_GROWTH}× (super-linear?)`,
  );
  assert.ok(tBig < capMs, `${label}: 200KB took ${tBig.toFixed(0)}ms (cap ${capMs.toFixed(0)}ms)`);
}

test("scan() stays linear on 200KB of pure-ASCII prose", () => {
  assertScales("scan()", (s) => scan(s), prose, BIG_BUDGET_MS);
});

test("inspectContent() stays linear on 200KB of pure-ASCII prose", () => {
  assertScales("inspectContent()", (s) => inspectContent(s), prose, BIG_BUDGET_MS);
});

test("inspectContent() stays linear on 200KB of '|' and 'curl ' repetition", () => {
  for (const [name, chunk] of [["pipes", "| "], ["curl", "curl "], ["pipe-stages", "a | b | c | "]] as const) {
    assertScales(`inspectContent() on ${name}`, (s) => inspectContent(s), (n) => repeat(chunk, n), BIG_BUDGET_MS);
  }
});

test("inspectCommand() stays linear on 200KB of '|' and 'curl ' repetition", () => {
  for (const [name, chunk] of [["pipes", "| "], ["curl", "curl "]] as const) {
    assertScales(`inspectCommand() on ${name}`, (s) => inspectCommand(s), (n) => repeat(chunk, n), BIG_CMD_BUDGET_MS);
  }
});

test("inspectCommand() stays sub-quadratic on 200KB pathological commands", () => {
  for (const [name, chunk] of [
    ["a-repeat", "a"],
    ["transforms", "gunzip | zcat | base64 -d | rev | "],
    ["assignments", ";v=word"],
  ] as const) {
    assertScales(`inspectCommand() on ${name}`, (s) => inspectCommand(s), (n) => repeat(chunk, n), BIG_CMD_BUDGET_MS);
  }
});

test("inspectFileWrite() / inspectContent() are fast on every production source file", () => {
  const files = listProdSources(SRC_ROOT);
  assert.ok(files.length > 50, `expected to find the source tree, found ${files.length} files`);
  const slow: string[] = [];
  for (const file of files) {
    const body = readFileSync(file, "utf8");
    const rel = file.slice(SRC_ROOT.length);
    // Budget scales with file size (linear work) rather than a flat ceiling the
    // largest source files would brush against on a slow runner.
    const budget = (300 + body.length * 0.02) * SLACK;
    const wMs = timed(() => inspectFileWrite(rel, body));
    const cMs = timed(() => inspectContent(body));
    if (wMs >= budget || cMs >= budget) slow.push(`${rel} (write ${wMs.toFixed(0)}ms, content ${cMs.toFixed(0)}ms, budget ${budget.toFixed(0)}ms)`);
  }
  assert.equal(slow.length, 0, `files over budget:\n  ${slow.join("\n  ")}`);
});
