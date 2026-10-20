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
// Budget for a single 200 KB adversarial input through one entry point. A
// quadratic pattern takes tens of seconds here; a linear one is well under 1 s.
const BIG_BUDGET_MS = 2000;
// A 200 KB single shell *command* is pathological (real hook commands are a line),
// but we still audit it. The quadratics it used to hit were 30+ s; this generous
// budget catches any reintroduced super-linear growth while tolerating slow CI.
const BIG_CMD_BUDGET_MS = 4000;
// Per production source file through a file-write / content check.
const FILE_BUDGET_MS = 300;

test("scan() stays linear on 200KB of pure-ASCII prose", () => {
  const input = prose(BIG);
  const ms = timed(() => scan(input));
  assert.ok(ms < BIG_BUDGET_MS, `scan() took ${ms.toFixed(0)}ms (budget ${BIG_BUDGET_MS}ms)`);
});

test("inspectContent() stays linear on 200KB of pure-ASCII prose", () => {
  const input = prose(BIG);
  const ms = timed(() => inspectContent(input));
  assert.ok(ms < BIG_BUDGET_MS, `inspectContent() took ${ms.toFixed(0)}ms (budget ${BIG_BUDGET_MS}ms)`);
});

test("inspectContent() stays linear on 200KB of '|' and 'curl ' repetition", () => {
  for (const [name, chunk] of [["pipes", "| "], ["curl", "curl "], ["pipe-stages", "a | b | c | "]] as const) {
    const input = repeat(chunk, BIG);
    const ms = timed(() => inspectContent(input));
    assert.ok(ms < BIG_BUDGET_MS, `inspectContent() on ${name} took ${ms.toFixed(0)}ms (budget ${BIG_BUDGET_MS}ms)`);
  }
});

test("inspectCommand() stays linear on 200KB of '|' and 'curl ' repetition", () => {
  for (const [name, chunk] of [["pipes", "| "], ["curl", "curl "]] as const) {
    const input = repeat(chunk, BIG);
    const ms = timed(() => inspectCommand(input));
    assert.ok(ms < BIG_BUDGET_MS, `inspectCommand() on ${name} took ${ms.toFixed(0)}ms (budget ${BIG_BUDGET_MS}ms)`);
  }
});

test("inspectCommand() stays sub-quadratic on 200KB pathological commands", () => {
  for (const [name, chunk] of [
    ["a-repeat", "a"],
    ["transforms", "gunzip | zcat | base64 -d | rev | "],
    ["assignments", ";v=word"],
  ] as const) {
    const input = repeat(chunk, BIG);
    const ms = timed(() => inspectCommand(input));
    assert.ok(ms < BIG_CMD_BUDGET_MS, `inspectCommand() on ${name} took ${ms.toFixed(0)}ms (budget ${BIG_CMD_BUDGET_MS}ms)`);
  }
});

test("inspectFileWrite() / inspectContent() are fast on every production source file", () => {
  const files = listProdSources(SRC_ROOT);
  assert.ok(files.length > 50, `expected to find the source tree, found ${files.length} files`);
  const slow: string[] = [];
  for (const file of files) {
    const body = readFileSync(file, "utf8");
    const rel = file.slice(SRC_ROOT.length);
    const wMs = timed(() => inspectFileWrite(rel, body));
    const cMs = timed(() => inspectContent(body));
    if (wMs >= FILE_BUDGET_MS || cMs >= FILE_BUDGET_MS) slow.push(`${rel} (write ${wMs.toFixed(0)}ms, content ${cMs.toFixed(0)}ms)`);
  }
  assert.equal(slow.length, 0, `files over ${FILE_BUDGET_MS}ms budget:\n  ${slow.join("\n  ")}`);
});
