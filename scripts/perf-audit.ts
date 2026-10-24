/**
 * Hot-path performance audit for the guard and the promptguard scanner.
 *   node --import tsx scripts/perf-audit.ts [--sizes 25,50,100,200] [--filter <substr>] [--all]
 *
 * The PostToolUse / PreToolUse hooks run synchronously on every WebFetch result
 * and every Write, so one regex that backtracks quadratically on a long ASCII
 * run turns into a multi-second (or multi-minute) stall of the agent. This runs
 * EVERY promptguard pattern rule individually, plus scan(), inspectContent(),
 * inspectCommand() and inspectFileWrite(), over adversarial input families at
 * 25/50/100/200 KB, and flags anything over 50 ms at 200 KB or growing
 * super-linearly. Sizes escalate only while the previous size stayed under the
 * stop budget, so a quadratic rule is reported without hanging the audit.
 *
 * Prints only flagged rows by default; pass --all for the full table.
 */

import { BUILTIN_RULES } from "../src/promptguard/rules.js";
import { ADVANCED_RULES } from "../src/promptguard/advanced-rules.js";
import { MULTILINGUAL_RULES } from "../src/promptguard/multilingual-rules.js";
import { scan } from "../src/promptguard/scanner.js";
import { inspectContent } from "../src/guard/guard.js";
import { inspectCommand, inspectFileWrite } from "../src/guard/command.js";
import { importTokens } from "../src/guard/integrity/imports.js";
import { extractTokens } from "../src/guard/integrity/tokens.js";
import { unitHasher, unitsOf } from "../src/guard/integrity/units.js";
import { cleanText, redactSecrets } from "../src/guard/integrity/render.js";
import { matchIndicator, plainText } from "../src/guard/integrity/overlay.js";

// ── Deterministic input families ──────────────────────────────────────────────

function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const WORDS = (
  "the a of to and in is it that for on with as this was be by are from or at an which " +
  "system prompt instruction ignore user data value function return request response file " +
  "server client token example step part first second note important config build test run " +
  "install package module error option default string number object array list table field " +
  "host port network fetch query cache index record update create delete read write path"
).split(" ");

function fill(n: number, chunk: (r: () => number, i: number) => string, seed = 1): string {
  const r = rng(seed);
  let out = "";
  for (let i = 0; out.length < n; i++) out += chunk(r, i);
  return out.slice(0, n);
}

const pick = <T>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];
const sentence = (r: () => number) => {
  const n = 6 + Math.floor(r() * 14);
  const ws = Array.from({ length: n }, () => pick(r, WORDS));
  ws[0] = ws[0][0].toUpperCase() + ws[0].slice(1);
  return ws.join(" ") + pick(r, [". ", ". ", ", and ", "? ", ": "]);
};
const cjkChar = (r: () => number) => String.fromCharCode(0x4e00 + Math.floor(r() * 0x5000));
const hangulChar = (r: () => number) => String.fromCharCode(0xac00 + Math.floor(r() * 11172));
const cyrChar = (r: () => number) => String.fromCharCode(0x0430 + Math.floor(r() * 32));
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const FAMILIES: Record<string, (n: number) => string> = {
  "ascii-prose": (n) => fill(n, (r, i) => sentence(r) + (i % 5 === 4 ? "\n" : "") + (i % 23 === 22 ? "\n" : "")),
  "ascii-one-line": (n) => fill(n, (r) => sentence(r)),
  "ascii-minified-code": (n) => fill(n, (r, i) => `function f${i}(a,b){var c=a+b*${i};if(c>${i}){return c}else{x${i}=c;return "${pick(r, WORDS)}"+c}};`),
  "a-repeat": (n) => "a".repeat(n),
  "spaces": (n) => " ".repeat(n),
  "newlines": (n) => "\n".repeat(n),
  "ws-mix": (n) => fill(n, () => " \n\t "),
  "pipes": (n) => "|".repeat(n),
  "pipe-stages": (n) => fill(n, (r) => `${pick(r, WORDS)} | `),
  "curl-repeat": (n) => "curl ".repeat(Math.ceil(n / 5)).slice(0, n),
  "transform-repeat": (n) => fill(n, (r, i) => ["gunzip ", "zcat ", "base64 -d ", "rev ", "tr a ", "| "][i % 6]),
  "cjk-run": (n) => fill(n, (r) => cjkChar(r)),
  "hangul-ascii-chars": (n) => fill(n, (r) => hangulChar(r) + "a"),
  "hangul-ascii-runs": (n) => fill(n, (r) => "the quick brown fox jumps over " + Array.from({ length: 6 }, () => hangulChar(r)).join("") + " lazy dog again and "),
  "cyrillic-one-line": (n) => fill(n, (r) => Array.from({ length: 2 + Math.floor(r() * 8) }, () => cyrChar(r)).join("") + " "),
  "base64-blob": (n) => fill(n, (r) => B64[Math.floor(r() * 64)]),
  "base64-wrapped": (n) => fill(n, (r, i) => B64[Math.floor(r() * 64)] + (i % 76 === 75 ? "\n" : "")),
  "minified-json": (n) => fill(n, (r, i) => `{"id":${i},"name":"${pick(r, WORDS)}","host":"h${i}.example.com","tags":["${pick(r, WORDS)}","${pick(r, WORDS)}"],"env":{"PORT":${i}}},`),
  "markdown-table": (n) => "| key | value | notes |\n|---|---|---|\n" + fill(n, (r, i) => `| ${pick(r, WORDS)}${i} | ${pick(r, WORDS)} | ${sentence(r)} |\n`),
  "url-list": (n) => fill(n, (r, i) => `https://${pick(r, WORDS)}.example.com/${pick(r, WORDS)}/${i}?q=${pick(r, WORDS)}&page=${i}\n`),
  // Families aimed at specific rule shapes (lazy/greedy spans anchored on a keyword).
  "keyword-flood": (n) => fill(n, (r, i) => ["first word ", "display:none ", "SYSTEM OVERRIDE ", "<!-- ", "``` ", "user: ", "q: ", "example ", "i g n o r e ", "step 1: x ", "imagine ", "simulate a scenario "][i % 12]),
  "assignments": (n) => fill(n, (r, i) => `;v${i}=${pick(r, WORDS)}`),
  "dollar-vars": (n) => fill(n, (r, i) => `$v${i % 50} \${x${i % 50}} `),
  // URL-anchored rules (`https?://` + an unbounded class run + a suffix that can
  // fail) re-scan the rest of a whitespace-free run from every `http://` in it.
  "http-repeat": (n) => "http://".repeat(Math.ceil(n / 7)).slice(0, n),
  "curl-http-repeat": (n) => "curl http://".repeat(Math.ceil(n / 12)).slice(0, n),
  "md-image-unclosed": (n) => "![a](http://x".repeat(Math.ceil(n / 13)).slice(0, n),
  "url-dollar": (n) => "http://x/$A".repeat(Math.ceil(n / 11)).slice(0, n),
  // `TOOL[^\n]*SUFFIX` command rules re-scan the rest of the line from every repeat
  // of TOOL; the secret-gated ones only run once a secret-named variable is present.
  "eval-repeat": (n) => "eval ".repeat(Math.ceil(n / 5)).slice(0, n),
  "eval-subst-repeat": (n) => ("eval " + "$(".repeat(n)).slice(0, n),
  "secret-curl-repeat": (n) => ("$GITHUB_TOKEN " + "curl ".repeat(Math.ceil(n / 5))).slice(0, n),
  "secret-curl-http-repeat": (n) => ("$GITHUB_TOKEN curl " + "http://".repeat(Math.ceil(n / 7))).slice(0, n),
  "secret-host-repeat": (n) => ("$GITHUB_TOKEN " + "host ".repeat(Math.ceil(n / 5))).slice(0, n),
  // Command words with a long interior run of quotes (`a"''…''"b`), one per line,
  // each line just under the shell-write parse's MAX_SEGMENT.
  "quote-run-words": (n) => fill(n, (r, i) => ["ls ", "git commit -m ", "tee ", "echo x > "][i % 4] + 'a"' + "'".repeat(19_880) + '"b\n'),
};

// ── Targets ───────────────────────────────────────────────────────────────────

type Target = { name: string; run: (s: string) => unknown };

const RULE_TARGETS: Target[] = [...BUILTIN_RULES, ...ADVANCED_RULES, ...MULTILINGUAL_RULES].map((rule) => ({
  name: `rule:${rule.id}`,
  // Same gate the scanner applies: requiresContext first, then the pattern.
  run: (s: string) => (!rule.requiresContext || rule.requiresContext.test(s)) && rule.pattern.exec(s),
}));

// Instruction-file integrity: the single-pass extractors SessionStart and watched
// writes run over a whole instruction file. Gated like a rule (see below).
const INTEGRITY_HASHER = unitHasher(Buffer.alloc(32, 1));
const PATHOLOGICAL_INDICATORS = Array.from({ length: 32 }, (_, i) => ({ t: `${"a".repeat(1000)}b${"a".repeat(1000)}${i}`, file: "CLAUDE.md", tier: "SUSPECT" as const }));
const INTEGRITY_TARGETS: Target[] = [
  { name: "integrity:extractTokens()", run: (s) => extractTokens(s, { root: "/home/u/app", home: "/home/u" }) },
  { name: "integrity:importTokens()", run: (s) => importTokens(s) },
  { name: "integrity:unitsOf(md)", run: (s) => unitsOf("ancestor-claude-md", s, { hasher: INTEGRITY_HASHER }) },
  { name: "integrity:unitsOf(memory)", run: (s) => unitsOf("auto-memory-topic", `---\n${s}`, { hasher: INTEGRITY_HASHER }) },
  { name: "integrity:unitsOf(agent)", run: (s) => unitsOf("project-agent", `---\n${s}`, { hasher: INTEGRITY_HASHER }) },
  { name: "integrity:unitsOf(agent frontmatter)", run: (s) => unitsOf("project-agent", `---\n${s}\n---\n`, { hasher: INTEGRITY_HASHER }) },
  { name: "integrity:unitsOf(settings)", run: (s) => unitsOf("project-settings", s, { hasher: INTEGRITY_HASHER }) },
  { name: "integrity:cleanText()", run: (s) => cleanText(s) },
  { name: "integrity:redactSecrets()", run: (s) => redactSecrets(s) },
  // The PreToolUse / PostToolUse overlay: the tripwire against the most indicators
  // a session keeps (32, each 2 KB, its distinguishing character mid-way), and
  // the cleaning of tokens, file and server names in its messages.
  { name: "integrity:matchIndicator()", run: (s) => matchIndicator(s, PATHOLOGICAL_INDICATORS) },
  { name: "integrity:plainText()", run: (s) => plainText(s, 120) },
];

const ENTRY_TARGETS: Target[] = [
  { name: "scan()", run: (s) => scan(s) },
  { name: "inspectContent()", run: (s) => inspectContent(s) },
  { name: "inspectCommand()", run: (s) => inspectCommand(s) },
  { name: "inspectFileWrite()", run: (s) => inspectFileWrite("src/generated.ts", s) },
];

// ── Measurement ───────────────────────────────────────────────────────────────

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const SIZES_KB = (arg("--sizes") ?? "25,50,100,200").split(",").map(Number);
const FILTER = arg("--filter");
const SHOW_ALL = process.argv.includes("--all");
/** Stop escalating sizes once one measurement exceeds this (ms). */
const STOP_MS = 1500;
/** Flag (display): slower than this at the largest size (ms). */
const FLAG_MS = 50;
/** Exit-gating budget for a SINGLE rule. A quadratic rule costs hundreds of ms to
 *  seconds at 200 KB, so this sits well above the slowest healthy linear rule
 *  (~50 ms) yet far below any super-linear blowup — a `rule:` row near 50 ms no
 *  longer flips the exit code between runs. Entry points (scan/inspect*) do real
 *  work and are expected to exceed FLAG_MS, so a high absolute time there does not
 *  gate; only super-linear GROWTH / STOPPED does. */
const RULE_GATE_MS = 120;

function time(t: Target, input: string): number {
  // Median of three for fast targets; one run when it is already slow.
  const once = () => { const t0 = performance.now(); t.run(input); return performance.now() - t0; };
  const first = once();
  if (first > 100) return first;
  const xs = [first, once(), once()].sort((a, b) => a - b);
  return xs[1];
}

type Row = { target: string; family: string; ms: (number | null)[]; flag: string };

const rows: Row[] = [];
const targets = [...RULE_TARGETS, ...INTEGRITY_TARGETS, ...ENTRY_TARGETS].filter((t) => !FILTER || t.name.includes(FILTER));
const inputs = new Map<string, string[]>();
for (const [family, gen] of Object.entries(FAMILIES)) inputs.set(family, SIZES_KB.map((kb) => gen(kb * 1000)));

for (const t of targets) {
  for (const [family, sized] of inputs) {
    const ms: (number | null)[] = [];
    let stopped = false;
    for (const input of sized) {
      if (stopped) { ms.push(null); continue; }
      const v = time(t, input);
      ms.push(v);
      if (v > STOP_MS) stopped = true;
    }
    const last = ms[ms.length - 1];
    const known = ms.filter((v): v is number => v !== null);
    let flag = "";
    if (last === null) flag = "STOPPED";
    else if (last > FLAG_MS) flag = "SLOW";
    // Super-linear growth: the last doubling more than ~2.8x, on a non-trivial time.
    if (known.length >= 2) {
      const a = known[known.length - 2], b = known[known.length - 1];
      if (b > 10 && b / Math.max(a, 0.01) > 2.8) flag = flag ? `${flag}+GROWTH` : "GROWTH";
    }
    rows.push({ target: t.name, family, ms, flag });
  }
}

const fmt = (v: number | null) => (v === null ? "—" : v < 10 ? v.toFixed(2) : v.toFixed(0)).padStart(8);
console.log(`\n=== Hot-path perf audit (ms; sizes ${SIZES_KB.join("/")} KB; flag > ${FLAG_MS} ms at ${SIZES_KB[SIZES_KB.length - 1]} KB or super-linear) ===\n`);
console.log(`${"target".padEnd(48)} ${"family".padEnd(22)}${SIZES_KB.map((kb) => `${kb}KB`.padStart(8)).join("")}  flag`);
const shown = SHOW_ALL ? rows : rows.filter((r) => r.flag);
for (const r of shown) console.log(`${r.target.padEnd(48)} ${r.family.padEnd(22)}${r.ms.map(fmt).join("")}  ${r.flag}`);
const flagged = rows.filter((r) => r.flag);
// Exit gating is per-RULE: a single pattern that grows super-linearly or exceeds
// RULE_GATE_MS is the regression this audit guards against. The entry points
// (scan/inspect*) run every rule plus the capability analysis, so a higher
// absolute time — and some growth — there is expected; their wall-clock budgets
// live in src/guard/perf.test.ts, not here. The integrity extractors gate like
// rules, except that their growth counts only above INTEGRITY_GROWTH_FLOOR_MS:
// they allocate per line, so at 10-25 ms a doubling is GC jitter, while a
// quadratic one costs seconds at 200 KB (the floor perf.test.ts uses too).
const INTEGRITY_GROWTH_FLOOR_MS = 50;
const gating = rows.filter((r) => {
  const integrity = r.target.startsWith("integrity:");
  if (!r.target.startsWith("rule:") && !integrity) return false;
  const last = r.ms[r.ms.length - 1];
  if (r.flag === "STOPPED") return true;
  if (r.flag.includes("GROWTH") && (!integrity || (last !== null && last > INTEGRITY_GROWTH_FLOOR_MS))) return true;
  return last !== null && last > RULE_GATE_MS;
});
console.log(`\n  ${rows.length} target×family rows, ${flagged.length} flagged, ${gating.length} gating (rule > ${RULE_GATE_MS} ms or super-linear).`);
const worst = [...rows].sort((a, b) => (b.ms[b.ms.length - 1] ?? Infinity) - (a.ms[a.ms.length - 1] ?? Infinity))[0];
if (worst) console.log(`  slowest: ${worst.target} on ${worst.family} (${worst.ms.map((v) => (v === null ? "—" : v.toFixed(1))).join(" / ")} ms)`);
if (gating.length) console.log(`  gating rows: ${gating.map((r) => `${r.target}/${r.family}`).join(", ")}`);
process.exitCode = gating.length ? 1 : 0;
