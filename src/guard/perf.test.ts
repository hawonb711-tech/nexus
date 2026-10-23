import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { scan } from "../promptguard/scanner.js";
import { inspectContent } from "./guard.js";
import { inspectCommand, inspectFileWrite } from "./command.js";
import { classify, type ClassifyInput } from "./integrity/classify.js";
import { contextFromHook } from "./integrity/context.js";
import { enumerateWatched } from "./integrity/enumerate.js";
import { importTokens } from "./integrity/imports.js";
import { simulateWrite } from "./integrity/ledger.js";
import { cleanText, displayCommand, redactSecrets, renderSessionStart } from "./integrity/render.js";
import { activityWindowsSince } from "./integrity/session-log.js";
import { signerFor } from "./integrity/store.js";
import { extractTokens } from "./integrity/tokens.js";
import { sha256Hex, unitHasher, unitsOf } from "./integrity/units.js";

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
const SMALL = 25_000; // the 8×-smaller size the growth ratios compare against.
// Optional CI headroom: a loaded windows/macOS runner can be 2–3× slower than a
// quiet Linux box, so wall-clock backstops are multiplied by NEXUS_PERF_SLACK.
const SLACK = Math.max(1, Number(process.env.NEXUS_PERF_SLACK) || 1);
// Absolute backstops are generous (a quadratic takes tens of seconds here, an
// order of magnitude over these); the real ratchet is the GROWTH ratio below,
// which is machine-independent. Scaled by SLACK for slow CI.
const BIG_BUDGET_MS = 2000 * SLACK;
const BIG_CMD_BUDGET_MS = 4000 * SLACK;
// 8× the input costs roughly 8× for a linear pass and ~64× for a quadratic one;
// 24× sits far from both, so the ratchet trips loudly on a quadratic while
// tolerating the 2–3× timing noise of a loaded runner, never depending on how
// fast the machine is.
const MAX_GROWTH = 24;
// Below this the 200 KB run is too fast for a quadratic to be hiding (one costs
// seconds here) and a few-ms ratio is dominated by timer and GC noise, so only the
// wall-clock cap applies.
const RATIO_FLOOR_MS = 50;
const RUNS = 3;

/** Best-of-`RUNS` timings of `a` and `b`, sampled alternately so a burst of load on
 *  a shared runner hits both sizes rather than skewing their ratio. */
function timedPair(a: () => unknown, b: () => unknown): [number, number] {
  a();
  b();
  let ta = Infinity, tb = Infinity;
  for (let i = 0; i < RUNS; i++) {
    let t0 = performance.now();
    a();
    ta = Math.min(ta, performance.now() - t0);
    t0 = performance.now();
    b();
    tb = Math.min(tb, performance.now() - t0);
  }
  return [ta, tb];
}

/** Assert a check scales (near-)linearly: time it at 25 KB and 200 KB and require
 *  the 8×-input slowdown to stay under MAX_GROWTH, plus a generous wall-clock cap. */
function assertScales(label: string, run: (s: string) => unknown, build: (bytes: number) => string, capMs: number): void {
  const small = build(SMALL), big = build(BIG);
  const [rawSmall, tBig] = timedPair(() => run(small), () => run(big));
  const tSmall = Math.max(rawSmall, 0.5); // floor avoids a divide-by-noise ratio
  const ratio = tBig / tSmall;
  assert.ok(
    tBig < RATIO_FLOOR_MS || ratio < MAX_GROWTH,
    `${label}: 8× input grew ${ratio.toFixed(1)}× (${tSmall.toFixed(0)}→${tBig.toFixed(0)}ms) — expected < ${MAX_GROWTH}× (super-linear?)`,
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

test("URL- and markdown-anchored rules stay linear on repeated `http://` and unclosed images", () => {
  // These re-scanned a long whitespace-free run from every `http://` (or every
  // unclosed `![a](`) in it: quadratic in the content guard and command guard,
  // cubic in the markdown rule. See url-scan.ts and advanced-rules.ts.
  const families = [["http-repeat", "http://"], ["url-dollar", "http://x/$A"], ["md-image-unclosed", "![a](http://x"]] as const;
  for (const [name, chunk] of families) {
    assertScales(`scan() on ${name}`, (s) => scan(s), (n) => repeat(chunk, n), BIG_BUDGET_MS);
    assertScales(`inspectContent() on ${name}`, (s) => inspectContent(s), (n) => repeat(chunk, n), BIG_BUDGET_MS);
    assertScales(`inspectCommand() on ${name}`, (s) => inspectCommand(s), (n) => repeat(chunk, n), BIG_CMD_BUDGET_MS);
  }
});

test("inspectCommand() stays linear on a line repeating one command word", () => {
  // `TOOL[^\n]*SUFFIX` rules re-scanned the rest of the line from every repeat of
  // TOOL (50 KB of `eval ` took ~1.7 s), and the curl/`$(` ones also from every
  // `http://` / `$(` after it. See line-scan.ts.
  for (const chunk of ["eval ", "os.system ", "dd ", "env ", "mknod ", "pip install ", "$GITHUB_TOKEN curl ", "$GITHUB_TOKEN dig ", "eval $(", "$GITHUB_TOKEN curl http://"]) {
    assertScales(`inspectCommand() on ${JSON.stringify(chunk)}`, (s) => inspectCommand(s), (n) => repeat(chunk, n), BIG_CMD_BUDGET_MS);
  }
});

test("inspectCommand() resolves an rm with a long run of ambiguous flags", () => {
  // The rm-root check's `(?:\s+-{1,2}[A-Za-z-]+)*` could split `--HOME` two ways,
  // so each such flag doubled the time: 24 took ~2 s, ~30 outlasted the hook
  // timeout. Sized so the old regex still finishes (and fails) rather than hangs.
  const s = "rm\t-" + "HOME\t--HOME\t-".repeat(24) + "HOME";
  const ms = timed(() => inspectCommand(s));
  assert.ok(ms < 250 * SLACK, `rm with 48 ambiguous flags took ${ms.toFixed(0)}ms`);
  // `--rm` inside a flag run must not restart the scan (quadratic in the run).
  assertScales("inspectCommand() on rm\\t-- repeats", (x) => inspectCommand(x), (n) => repeat("rm\t--", n), BIG_CMD_BUDGET_MS);
  assertScales("inspectCommand() on one rm with many flags", (x) => inspectCommand(x), (n) => "rm" + repeat(" -a", n), BIG_CMD_BUDGET_MS);
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

// ── Instruction-file integrity ───────────────────────────────────────────────
// SessionStart cuts every changed watched file into keyed units and diffs them as
// sets (no line diff), then scans the added text for actionable tokens; a
// PreToolUse write to a watched file does the same for the simulated new text.

/** ~`bytes` of settings JSON: allow rules, env variables and hooks in proportion. */
function settingsJson(bytes: number): string {
  const allow: string[] = [];
  const env: Record<string, string> = {};
  const hooks: unknown[] = [];
  for (let i = 0, size = 0; size < bytes; i++, size += 150) {
    allow.push(`Bash(npm run task${i}:*)`);
    env[`VAR_${i}`] = `value-${i}`;
    hooks.push({ matcher: `Tool${i}`, hooks: [{ type: "command", command: `./hooks/h${i}.sh` }] });
  }
  return JSON.stringify({ permissions: { allow }, env, hooks: { PreToolUse: hooks } }, null, 2);
}

test("integrity units stay linear on Markdown, frontmatter and settings JSON", () => {
  const hasher = unitHasher(Buffer.alloc(32, 1));
  const families: [string, Parameters<typeof unitsOf>[0], (n: number) => string][] = [
    ["prose", "ancestor-claude-md", prose],
    ["duplicate lines", "ancestor-claude-md", (n) => repeat("Run npm test before committing.\n", n)],
    ["CRLF and blank lines", "project-rules", (n) => repeat("x \r\n\r\n\t\n", n)],
    ["one long line", "ancestor-claude-md", (n) => repeat("a", n)],
    ["memory frontmatter", "auto-memory-topic", (n) => `---\n${repeat('metadata:\n  modified: 2026-10-23T10:00:00.000Z\nd: "it\\"s"\n', n)}\n---\n`],
    ["memory metadata block", "auto-memory-topic", (n) => `---\nmetadata:\n${repeat("  node_type: memory\n", n)}\n---\n`],
    ["agent frontmatter", "project-agent", (n) => `---\n${repeat("tools:\n  - Bash\nname: x\n", n)}\n---\n`],
    ["settings JSON", "project-settings", settingsJson],
    ["deep JSON", "project-settings", (n) => `{"a":${"[".repeat(n / 2)}${"]".repeat(n / 2)}}`],
  ];
  for (const [name, role, build] of families) {
    assertScales(`unitsOf(${name})`, (s) => unitsOf(role, s, { hasher }), build, BIG_BUDGET_MS);
  }
});

test("actionable-token extraction and the @import parser stay linear", () => {
  const families: [string, (n: number) => string][] = [
    ["prose", prose],
    ["url list", (n) => repeat("see https://cdn.example.net/a/b?q=1#x, then\n", n)],
    ["http repeat", (n) => repeat("http://", n)],
    ["local@ repeat", (n) => repeat("a@", n)],
    ["dotted domain", (n) => `x@${repeat("a.", n)}`],
    ["long local part", (n) => repeat("abcdefgh", n)],
    ["paths", (n) => repeat("~/x /etc/y /home/u/z ", n)],
    ["backtick runs", (n) => repeat("`` ` ``` ", n)],
    ["fences", (n) => repeat("```\n$ curl -fsSL x\n", n)],
    ["commands", (n) => repeat("$ npx -y some-package\n", n)],
    ["ssh and git hosts", (n) => repeat("ssh git@host.example.net: ", n)],
    ["imports", (n) => repeat("@a/b ", n)],
    ["escaped-space imports", (n) => repeat("@a\\ b#c\\", n)],
    ["one long @ token", (n) => `@${repeat("a\\ ", n)}`],
    ["quote run", (n) => `$ curl ${repeat("'", n)}`],
  ];
  for (const [name, build] of families) {
    assertScales(`extractTokens(${name})`, (s) => extractTokens(s, { root: "/home/u/app", home: "/home/u" }), build, BIG_BUDGET_MS);
    assertScales(`importTokens(${name})`, (s) => importTokens(s), build, BIG_BUDGET_MS);
  }
});

test("enumerating the watched set stays fast on @tokens that name no file", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "nexus-perf-enum-")));
  try {
    const home = join(dir, "home");
    const repo = join(dir, "repo");
    mkdirSync(join(home, ".claude"), { recursive: true });
    mkdirSync(join(repo, ".git"), { recursive: true });
    const ctx = contextFromHook({ cwd: repo }, { platform: process.platform, homedir: home, env: {}, dataDir: join(dir, "data"), managedDir: join(dir, "managed") });
    assert.ok(ctx);
    const claudeMd = join(repo, "CLAUDE.md");
    const enumerate = (text: string) => { writeFileSync(claudeMd, text); return enumerateWatched(ctx); };
    const deep = "a/".repeat(240);
    /** ~`bytes` of `line(0) + line(1) + …`: every token distinct. */
    const numbered = (line: (i: number) => string) => (bytes: number) => {
      const parts: string[] = [];
      for (let i = 0, size = 0; size < bytes; i++) { const l = line(i); parts.push(l); size += l.length; }
      return parts.join("").slice(0, bytes);
    };
    const families: [string, (n: number) => string][] = [
      ["distinct @mentions", numbered((i) => ` @m${i}`)],
      ["distinct deep tokens", numbered((i) => ` @${deep}${i}\n`)],
      ["one deep token repeated", (n) => repeat(` @${deep}x\n`, n)],
      ["distinct deep explicit paths", numbered((i) => ` @./${deep}${i}\n`)],
      ["distinct heads, deep tails", numbered((i) => ` @b${i}/${deep}x\n`)],
    ];
    for (const [name, build] of families) assertScales(`enumerateWatched(${name})`, enumerate, build, BIG_BUDGET_MS);
    // a whole 4 MiB CLAUDE.md (the per-file cap) of distinct @mentions
    const flood = numbered((i) => ` @m${i}`)(4 * 1024 * 1024 - 64);
    const ms = timed(() => enumerate(flood));
    assert.ok(ms < BIG_CMD_BUDGET_MS, `enumerateWatched(4 MiB of @mentions) took ${ms.toFixed(0)}ms (cap ${BIG_CMD_BUDGET_MS}ms)`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("simulating a watched write stays bounded however many edits a MultiEdit has", () => {
  // PreToolUse simulates each Write / Edit / MultiEdit to a watched file (read up
  // to 4 MiB). Each exact edit rescans the whole text, so a call has one work
  // budget: past it, the remaining edits are approximated by appending.
  const big = prose(4 * 1024 * 1024);
  const claudeMd = prose(10_000);
  const cases: [string, string, unknown[]][] = [
    ["4,000 edits that miss, on 4 MiB", big, Array.from({ length: 4000 }, (_, i) => ({ old_string: `absent ${i}`, new_string: `line ${i}` }))],
    ["1,000 edits that match, on 4 MiB", big, Array.from({ length: 1000 }, () => ({ old_string: "the", new_string: "teh" }))],
    ["chained expanding replace_all", claudeMd, [
      ...Array.from({ length: 6 }, () => ({ old_string: "e", new_string: "eeee", replace_all: true })),
      ...Array.from({ length: 30 }, (_, i) => ({ old_string: i % 2 ? "E" : "e", new_string: i % 2 ? "e" : "E", replace_all: true })),
    ]],
  ];
  for (const [name, current, edits] of cases) {
    const ms = timed(() => simulateWrite("MultiEdit", { edits }, current));
    assert.ok(ms < BIG_CMD_BUDGET_MS, `simulateWrite(${name}) took ${ms.toFixed(0)}ms (cap ${BIG_CMD_BUDGET_MS}ms)`);
  }
});

test("classifying a changed watched file stays linear in its changed units, however they are spread", () => {
  // SessionStart diffs a changed file's units as sets, attributes them, groups the
  // added ones into hunks and screens those (thousands of one-line hunks are
  // screened in batches, not one detector call each).
  const key = Buffer.alloc(32, 1);
  const signer = signerFor(key);
  const hashers = { unit: unitHasher(key), nonce: (t: string) => signer.hmac16("nonce", t) };
  const root = "/home/u/app";
  type Role = "ancestor-claude-md" | "project-settings";
  const snapshot = (role: Role, text: string): ClassifyInput["snapshot"] => {
    const path = role === "project-settings" ? `${root}/.claude/settings.json` : `${root}/CLAUDE.md`;
    const content = Buffer.from(text);
    const entry = { path, key: path, role, state: "file" as const, sha256: sha256Hex(content), size: content.length, stat: [content.length, 1, 1, 1, 1] as [number, number, number, number, number], link: null, content, reused: false };
    return {
      global: { kind: "global", id: "global", root: null, entries: {} },
      project: { kind: "project", id: "project-0123456789abcdef", root, entries: { [path]: entry } },
      memory: null, prefixes: { memoryDirs: [], configDirs: [], importTargets: [], hookScripts: [] }, unhashed: [], incomplete: false, hashedBytes: 0, files: 0,
    };
  };
  const input = (stores: ClassifyInput["stores"], snap: ClassifyInput["snapshot"]): ClassifyInput => ({
    stores, snapshot: snap, ledger: [], windows: () => [], config: { agentWindowEscalation: true }, now: new Date(0), hashers, home: "/home/u", platform: "linux",
  });
  /** Classify the change from `before(s)` to `s`; the baseline is built once per input, outside the timing. */
  const change = (role: Role, before: (s: string) => string) => {
    const baselines = new Map<string, ClassifyInput["stores"]>();
    return (s: string) => {
      let stores = baselines.get(s);
      if (!stores) {
        const first = classify(input({ global: { doc: null, tamper: null }, project: { doc: null, tamper: null }, memory: null }, snapshot(role, before(s))));
        stores = { global: { doc: first.stores.global.next, tamper: null }, project: { doc: first.stores.project.next, tamper: null }, memory: null };
        baselines.set(s, stores);
      }
      return classify(input(stores, snapshot(role, s)));
    };
  };
  const everyOther = (s: string) => s.split("\n").filter((_, i) => i % 2 === 0).join("\n");
  const families: [string, Role, (s: string) => string, (n: number) => string][] = [
    ["one-line changes between kept lines", "ancestor-claude-md", everyOther, (n) => repeat("keep this line\nx\n", n)],
    ["distinct one-line changes", "ancestor-claude-md", everyOther, (n) => Array.from({ length: Math.ceil(n / 24) }, (_, i) => `kept ${i}\nadded ${i}`).join("\n").slice(0, n)],
    ["appended prose", "ancestor-claude-md", (s) => s.slice(0, 64), prose],
    ["settings with every hook new", "project-settings", () => "{}", settingsJson],
  ];
  for (const [name, role, before, build] of families) {
    assertScales(`classify(${name})`, change(role, before), build, BIG_CMD_BUDGET_MS);
  }
});

test("SessionStart reads the agent-activity logs once, however many changed files need them", () => {
  // An unknown change to a watched file asks whether an agent was active when it
  // landed (H1): the windows of every session log modified since the file was
  // accepted. Files accepted at different times must share one scan of the logs
  // (from the earliest), not re-read them per file — a branch switch touching
  // hundreds of rules files would otherwise re-read every log hundreds of times.
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "nexus-perf-windows-")));
  try {
    const sessions = join(dir, "integrity", "sessions");
    mkdirSync(sessions, { recursive: true });
    const now = Date.now();
    const hour = 3_600_000;
    const LOGS = 400, LINES = 100, FILES = 200;
    for (let k = 0; k < LOGS; k++) {
      const lines = Array.from({ length: LINES }, (_, m) => `a\t${now - 20 * 24 * hour + k * hour + m * 1000}\tBash\t30000\n`).join("");
      writeFileSync(join(sessions, `${(k + 1).toString(16).padStart(16, "0")}.log`), lines, { mode: 0o600 });
    }
    const key = Buffer.alloc(32, 3);
    const signer = signerFor(key);
    const hashers = { unit: unitHasher(key), nonce: (t: string) => signer.hmac16("nonce", t) };
    const root = "/home/u/app";
    const snapshot = (body: (i: number) => string): ClassifyInput["snapshot"] => {
      const entries: ClassifyInput["snapshot"]["project"]["entries"] = {};
      for (let i = 0; i < FILES; i++) {
        const path = `${root}/.claude/rules/r${i}.md`;
        const content = Buffer.from(body(i));
        entries[path] = { path, key: path, role: "project-rules", state: "file", sha256: sha256Hex(content), size: content.length, stat: [content.length, 1, 1, 1, 1], link: null, content, reused: false };
      }
      return {
        global: { kind: "global", id: "global", root: null, entries: {} },
        project: { kind: "project", id: "project-0123456789abcdef", root, entries },
        memory: null, prefixes: { memoryDirs: [], configDirs: [], importTargets: [], hookScripts: [] }, unhashed: [], incomplete: false, hashedBytes: 0, files: FILES,
      };
    };
    let calls = 0;
    const input = (stores: ClassifyInput["stores"], snap: ClassifyInput["snapshot"]): ClassifyInput => ({
      stores, snapshot: snap, ledger: [], config: { agentWindowEscalation: true }, now: new Date(now), hashers, home: "/home/u", platform: "linux",
      windows: (since) => { calls++; return activityWindowsSince(dir, since).windows; },
    });
    const first = classify(input({ global: { doc: null, tamper: null }, project: { doc: null, tamper: null }, memory: null }, snapshot((i) => `- Rule ${i}.\n`)));
    const project = first.stores.project.next!;
    Object.values(project.entries).forEach((e, i) => { e.acceptedAt = new Date(now - 25 * 24 * hour + i * hour).toISOString(); });
    const stores = { global: { doc: first.stores.global.next, tamper: null }, project: { doc: project, tamper: null }, memory: null };
    const changed = snapshot((i) => `- Rule ${i}.\n- Added ${i}.\n`);
    calls = 0;
    const t0 = performance.now();
    const result = classify(input(stores, changed));
    const ms = performance.now() - t0;
    assert.equal(result.items.length, FILES);
    assert.equal(calls, 1, `${calls} reads of the session logs for ${FILES} changed files`);
    assert.ok(ms < BIG_CMD_BUDGET_MS, `classifying ${FILES} changed files with ${LOGS} session logs took ${ms.toFixed(0)}ms (cap ${BIG_CMD_BUDGET_MS}ms)`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("SessionStart classification over 200 files and 2 MB: a first run screens one run's budget, an unchanged tree costs little", () => {
  // §9's synthetic tree. The detectors cost about 2 s per MiB, so a first run (a
  // cloned repo) screens a bounded amount per run and leaves the rest to the next
  // runs, instead of every SessionStart reaching the 5 s deadline on the same work.
  const key = Buffer.alloc(32, 4);
  const signer = signerFor(key);
  const hashers = { unit: unitHasher(key), nonce: (t: string) => signer.hmac16("nonce", t) };
  const root = "/home/u/app";
  const FILES = 200;
  const text = (i: number) => `# Rules ${i}\n\n${prose(10_000)}\n`;
  const snapshot = (withContent: boolean): ClassifyInput["snapshot"] => {
    const entries: ClassifyInput["snapshot"]["project"]["entries"] = {};
    for (let i = 0; i < FILES; i++) {
      const path = `${root}/.claude/rules/r${i}.md`;
      const content = Buffer.from(text(i));
      entries[path] = {
        path, key: path, role: "project-rules", state: "file", sha256: sha256Hex(content), size: content.length, stat: [content.length, 1, 1, 1, 1],
        link: null, content: withContent ? content : null, reused: !withContent,
      };
    }
    return {
      global: { kind: "global", id: "global", root: null, entries: {} },
      project: { kind: "project", id: "project-0123456789abcdef", root, entries },
      memory: null, prefixes: { memoryDirs: [], configDirs: [], importTargets: [], hookScripts: [] }, unhashed: [], incomplete: false, hashedBytes: 0, files: FILES,
    };
  };
  const input = (stores: ClassifyInput["stores"], snap: ClassifyInput["snapshot"], over: Partial<ClassifyInput> = {}): ClassifyInput => ({
    stores, snapshot: snap, ledger: [], windows: () => [], config: { agentWindowEscalation: true }, now: new Date(0), hashers, home: "/home/u", platform: "linux", ...over,
  });
  const none: ClassifyInput["stores"] = { global: { doc: null, tamper: null }, project: { doc: null, tamper: null }, memory: null };
  const full = snapshot(true);
  let first: ReturnType<typeof classify> | null = null;
  const firstMs = timed(() => (first = classify(input(none, full))));
  assert.ok(first!.deferred.length > 0 && first!.deferred.length < FILES, `${first!.deferred.length} of ${FILES} files deferred`);
  assert.ok(firstMs < 2500 * SLACK, `a first run over ${FILES} files and 2 MB took ${firstMs.toFixed(0)}ms (cap ${2500 * SLACK}ms; the deadline is 5 s)`);
  // steady state: nothing changed (the stat fast path reused every sha; no text read)
  const project = first!.stores.project.next!;
  for (const d of first!.deferred) project.entries[d.key] = { ...project.entries[d.key], state: "file", sha256: full.project.entries[d.key].sha256 };
  const stores = { global: { doc: first!.stores.global.next, tamper: null }, project: { doc: project, tamper: null }, memory: null };
  const unchanged = snapshot(false);
  const ms = timed(() => assert.deepEqual(classify(input(stores, unchanged)).items, []));
  assert.ok(ms < 300 * SLACK, `classifying an unchanged tree of ${FILES} files took ${ms.toFixed(0)}ms (cap ${300 * SLACK}ms)`);
});

test("rendering SessionStart output stays bounded, and its text helpers linear", () => {
  const signer = signerFor(Buffer.alloc(32, 2));
  const items = Array.from({ length: 200 }, (_, i) => ({
    store: "project" as const, storeId: "project-0123456789abcdef" as const, key: `/r/p${i}/CLAUDE.md`, path: `/r/p${i}/CLAUDE.md`,
    role: "ledger-learned" as const, roleClass: "notice" as const, tier: "SUSPECT" as const, rule: "S2" as const, rules: ["S2" as const],
    reasons: ["r"], change: "modified" as const, firstRun: false, tamper: null, added: 30, removed: 0, descriptions: [], removedNexusHooks: [],
    dangerous: [], flaggedUnits: [], novel: [], link: null, unquoted: false, scanTruncated: false, inWindow: null, agent: null, heldId: `h_${String(i).padStart(12, "0")}`, next: null,
    hunks: [{ attribution: { kind: "unknown" as const }, line: 1, lines: Array.from({ length: 30 }, () => repeat("\u001b[31m⟦NEXUS x ", 2000)), units: [], verdict: { reason: "r", strong: false } }],
  }));
  const ms = timed(() => renderSessionStart({ result: { items, listing: null, machineFirstRun: false, tamper: [] }, display: { root: "/r", home: "/h", platform: "linux" }, nonce: (t) => signer.hmac16("nonce", t) }));
  assert.ok(ms < 500 * SLACK, `rendering 200 flagged files took ${ms.toFixed(0)}ms`);
  for (const [name, chunk] of [["escapes", "\u001b[\u001b]"], ["urls", "https://a:b"], ["bearer", "Bearer "], ["tokens", "ghp_sk-ant-"], ["controls", "\u0000\u009b1"]] as const) {
    assertScales(`cleanText(${name})`, (s) => cleanText(s), (n) => repeat(chunk, n), BIG_BUDGET_MS);
    assertScales(`redactSecrets(${name})`, (s) => redactSecrets(s), (n) => repeat(chunk, n), BIG_BUDGET_MS);
    assertScales(`displayCommand(${name})`, (s) => displayCommand(s), (n) => repeat(chunk, n), BIG_BUDGET_MS);
  }
});
