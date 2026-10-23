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

test("inspectCommand() stays linear on repeated watched-name writes, redirects and quotes", () => {
  // The instruction-file-shell-write / nexus-store-write / nexus-cli rules segment
  // and tokenise the command; a long run of watched names, redirects, quotes or
  // Nexus invocations must stay linear (bounded quantifiers + a single scan).
  for (const chunk of [
    "echo x > CLAUDE.md\n",
    "tee .claude/settings.json ",
    '"a" >> AGENTS.md; ',
    "rm .nexus/integrity/x && ",
    "nexus guard integrity accept; ",
    "cp a b | ",
    // heredocs: one per line (each body runs to the end), many on one line,
    // quoted words, and bodies that are skipped line by line
    "cat <<A\n", "x<<", "<<'", "cat > a.md <<'EOF'\nbody >| CLAUDE.md\nEOF\n", "# <<X\n",
    '"C:\\a\\b" > ', "echo x >| ",
    "/projects/" + "a".repeat(254), " .claude/",
    // subshells, groups, substitutions and per-heredoc ownership: deep nesting,
    // unclosed constructs, and heredocs whose body a shell or interpreter runs
    "(cd x && echo y >> CLAUDE.md)\n", "( ", "{ ", "} ", "$(", '"$(', "${", "`", "$((", "((1<<2)) ",
    "bash <<A\n", "python3 - <<A\n", "(cat <<A\n", "\"$(cat <<'E'\n", "cat <<A; } | bash\n",
    "sed -i -e s/a/b/ CLAUDE.md\n", "Set-Content -Encoding utf8 CLAUDE.md x\n", "rsync -a --exclude x ",
    "env X=1 nexus guard integrity status; ", "The build runs and the tests pass again, mostly.\n",
    // PowerShell quoting, sh -c / eval strings and scripts a heredoc writes
    'Write-Host "C:\\p\\" ; ', '"a \\"b\\" ', "sh -c 'sh -c ", "eval eval ", "sudo -u x env ",
    "cat > s.sh <<'E'\nE\nbash s.sh\n", "cat > s.sh <<'E'\nbash s.sh\n",
  ]) {
    assertScales(`inspectCommand() on ${JSON.stringify(chunk)}`, (s) => inspectCommand(s), (n) => repeat(chunk, n), BIG_CMD_BUDGET_MS);
  }
});

test("inspectCommand() stays linear on a word with a long interior run of quotes", () => {
  // The shell-write path parse trimmed a word's quotes with `^['"]+|['"]+$`; the
  // unanchored `['"]+$` retried the rest of a quote run from every quote in it,
  // and every word of a segment reaches it (the shell-wrapper lookup takes each
  // word's basename). One such segment just under MAX_SEGMENT took ~0.7 s.
  const word = (k: number) => 'a"' + "'".repeat(k) + '"b';
  for (const head of ["ls ", "git commit -m ", "tee ", "echo x > "]) {
    // one segment with an 8× longer run: linear in the run, not only in segments
    const [rawSmall, tBig] = timedPair(() => inspectCommand(head + word(2_450)), () => inspectCommand(head + word(19_600)));
    const ratio = tBig / Math.max(rawSmall, 0.5);
    assert.ok(tBig < RATIO_FLOOR_MS || ratio < MAX_GROWTH, `${JSON.stringify(head)} + a 19,600-quote run grew ${ratio.toFixed(1)}× (${rawSmall.toFixed(0)}→${tBig.toFixed(0)}ms)`);
    const chunk = head + word(19_900 - head.length) + "\n";
    assertScales(`inspectCommand() on ${JSON.stringify(head)} + a quote run`, (s) => inspectCommand(s), (n) => repeat(chunk, n), BIG_CMD_BUDGET_MS);
  }
});

test("inspectCommand() stays linear on the shapes that broke the nested-frame shell analyzer", () => {
  // shell-write-targets.ts is one flat scan under a work budget. Its predecessor went
  // super-linear on heredoc markers inside groups after `|` (open heredocs copied
  // between frames), interpreter-named flag words (a per-word stdin scan), interior
  // quote runs (a quote-trim regex), deep `(` / `$(` nesting and unbalanced quotes.
  for (const chunk of [
    "x | ( cat <<A <<B; ( cat <<C\n", "| { cat <<A; } | ( <<B ", "( cat <<A\n) | sh\n", "x | (cat <<A\nA\n) | bash\n",
    "python3 -c -e --eval node ", "node -e -e -e ", "perl -i -pe python3 - ", "-python3 -node -c ",
    'a"' + "'".repeat(64) + '"b ', "'\"'\"'\"", '"' + "'".repeat(500) + '" ',
    "( $( ", "$( ( ", '"$( ( `', "$( $( ", "( ( ( ",
    "echo 'it's \"", "\"$(echo ' ", "$'\\' ", "x ' y \" ", "`'",
    // braces and parentheses inside words: brace expansion, `}` operands, `(…)` past the
    // command word, case patterns, a `#` after a substitution
    "cp a{b,c} {} @{u} ", "x } } } ", "{ } ", "tee >(a) <(b) !(c) ", "a(a(a(", "cp (x) ", "case x in (a) ", "$(a)#b ", "      (",
    // heredoc bodies that a code runner makes commands and that end in an open quote:
    // each gets the body's coarse verdict, with a store path, `->` and `>` runs
    "node t\ncat <<'A'\nit's ~/.nexus/integrity -> x\nA\n", "make\ncat <<A\n'" + ">a".repeat(40) + " ~/.nexus/observations\nA\n",
  ]) {
    assertScales(`inspectCommand() on ${JSON.stringify(chunk)}`, (s) => inspectCommand(s), (n) => repeat(chunk, n), BIG_CMD_BUDGET_MS);
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
