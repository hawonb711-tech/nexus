import { test } from "node:test";
import assert from "node:assert/strict";
import { BUILTIN_RULES, LinearPattern } from "./rules.js";
import { ADVANCED_RULES } from "./advanced-rules.js";

/**
 * Five rule patterns are LinearPattern subclasses: RegExp objects whose matching
 * is done in code. They must behave as the plain regex they stand for at every
 * RegExp protocol entry point, not only exec / test: String.prototype.split and
 * RegExp.prototype[Symbol.matchAll] build a new instance through Symbol.species
 * (split adds the sticky flag), and global or sticky instances must honor and
 * update lastIndex. Each is compared with its plain regex — the c88cfaa literal
 * where it had one — on structured fuzz holding several matches per input.
 */

/** mulberry32: the low bits of a power-of-two LCG cycle too fast for `% n` picks. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  };
}
type Gen = { next: () => number; pick: <T>(xs: readonly T[]) => T; chance: (n: number) => boolean };
function gen(seed: number): Gen {
  const next = rng(seed);
  return { next, pick: (xs) => xs[next() % xs.length], chance: (n) => next() % n === 0 };
}

const LS = String.fromCharCode(0x2028);
const NBSP = String.fromCharCode(0xa0);
const WS = [" ", "", "\t", "\n", "  ", "\r\n", LS, NBSP];

const rule = (id: string): RegExp => {
  const r = [...BUILTIN_RULES, ...ADVANCED_RULES].find((x) => x.id === id);
  assert.ok(r, `rule ${id} exists`);
  return r.pattern;
};

/** `count` inputs; the corpus must reach `min` matches, `min / 4` inputs with several and `min` sticky hits. */
type Case = { id: string; oracle: RegExp; piece: (g: Gen) => string; count: number; min: number };

const COMMENT_KW = ["ignore", "system prompt", "system \n prompt", "instruction", "override", "IGNORE", "Override", "systemprompt"];
const PAD_KW = ["[SYSTEM]", "[system]", "SYSTEM:", "system :", "ignore all previous", "ignore above", "IGNORE  ALL  ABOVE",
  "new instructions", "new instruction", "ignore all", "ystem:"];
const CODE_KEYWORDS: [string, string][] = [["role", "system"], ["ROLE", "SYSTEM"], ["system", "prompt"], ["System", "PROMPT"],
  ["ignore", "instruction"], ["unrestricted", ""], ["Unrestricted", "x"], ["rol", "system"], ["role", "promp"], ["system", "system"]];
const CODE_ACTIONS = ["run the", "parse  this", "execute\nit", "process above", "apply\tthe", "runthe", "run  x", "FOLLOW THE", "run" + LS + "it"];

const fill = (g: Gen, n: number): string => g.pick(["a", " ", "x\n", "-", "a", " ", "ab`"]).repeat(n).slice(0, n);
const run = (g: Gen): string => {
  const c = g.pick(["a", "A", "s", "-", " ", "k", "K", String.fromCharCode(0x212a), "["]);
  let s = "";
  for (let n = g.chance(10) ? g.pick([399, 401, 452]) : g.pick([20, 100, 101, 102, 110, 150]); n > 0; n--) s += g.chance(5) ? (g.chance(2) ? c.toUpperCase() : c.toLowerCase()) : c;
  return s;
};

const CASES: Case[] = [
  {
    id: "indirect-comment-injection",
    oracle: /<!--(?:(?!-->)[\s\S]){0,1000}?(?:ignore|system\s+prompt|instruction|override)(?:(?!-->)[\s\S]){0,1000}?-->/i,
    piece: (g) => g.pick([
      () => "<!--" + g.pick(["", " ", "x".repeat(g.next() % 30)]) + g.pick(COMMENT_KW) + g.pick(["", " y", "\n"]) + g.pick(["-->", " -->", "--", ""]),
      () => "<!--" + "a".repeat(990 + (g.next() % 20)) + g.pick(COMMENT_KW) + "b".repeat(990 + (g.next() % 20)) + "-->",
      () => g.pick(["<!--", "-->", "<!-->", "--", "x", "<!-- -->", ...WS]),
    ])(),
    count: 600,
    min: 400,
  },
  {
    id: "advanced-markdown-exfil",
    oracle: /!\[[^\]]*\]\(\s*https?:\/\/[^\)]+\b(?:exfil|steal|leak|callback|log|collect|hook|capture|sniff|grab|dump)\b[^\)]*\)/i,
    piece: (g) => g.pick([
      () => "![" + g.pick(["", "a", "img"]) + "](" + g.pick(["", " ", "\t"]) + g.pick(["http://", "https://", "HTTP://"]) +
        g.pick(["x.com/", "e.org/a?", ""]) + g.pick(["leak", "steal", "log", "dump", "LEAK", "capture"]) + g.pick(["", "?q=1", "/y"]) + ")",
      () => "![" + g.pick(["", "a", "x]", "![b"]) + "](" + g.pick(["", " ", "\t"]) + g.pick(["http://", "https://", "ftp://", "http:/"]) +
        g.pick(["x.com/", ""]) + g.pick(["leak", "logx", "blog", "x"]) + g.pick(["", "?q=1"]) + g.pick([")", "", " )"]),
      () => g.pick(["![", "]", "(", ")", "![![b](http://h/grab)", "[x](http://y/leak)", "!", "](http://z/hook)", ...WS]),
    ])(),
    count: 600,
    min: 400,
  },
  {
    id: "advanced-payload-splitting-numbered",
    oracle: /(?:step\s*1|part\s*1|first\s*part)\s*[:=]?\s*["']?\w+["']?[^]{0,100}(?:step\s*2|part\s*2|second\s*part)\s*[:=]?\s*["']?\w+["']?(?:[^]{0,100}(?:step\s*3|part\s*3|third\s*part)\s*[:=]?\s*["']?\w+["']?)?[^]{0,100}(?:execute|combine|run|follow|assemble|concat|join|now\s+do)/is,
    piece: (g) => {
      const gap = () => " ".repeat(g.next() % 121);
      return g.chance(4)
        ? g.pick(["step 1", "part 2", "run", "x", "'", ":", ...WS])
        : `${g.pick(["step 1: a", "first part 'x'", "part1 b", "STEP 1 = c"])}${gap()}${g.pick(["step 2: b", "second part c", "part2\"d\""])}` +
          `${g.pick([" run", "", " join"])}${gap()}${g.pick(["step 3: c", "third part e", ""])}${gap()}${g.pick([" execute", " follow", " now do", ""])}`;
    },
    count: 600,
    min: 600,
  },
  {
    id: "advanced-padding-injection",
    oracle: /(.)\1{100,400}[^]{0,50}(?:\[SYSTEM\]|SYSTEM\s*:|ignore\s+(?:all\s+)?(?:previous|above)|new\s+instructions?)/is,
    piece: (g) => g.pick([
      () => run(g) + "xy \n".repeat(16).slice(0, g.next() % 56) + g.pick(PAD_KW),
      () => run(g) + "xy \n".repeat(16).slice(0, g.next() % 56) + g.pick(PAD_KW),
      () => run(g),
      () => g.pick(PAD_KW) + g.pick(WS),
    ])(),
    // The plain regex tries 301 × 51 ways per run character (split: at every position), so fewer inputs.
    count: 160,
    min: 100,
  },
  {
    id: "advanced-code-block-system",
    oracle: /```(?:(?!```)[\s\S]){0,1500}?(?:role[\s\S]{0,80}?system|system[\s\S]{0,80}?prompt|ignore[\s\S]{0,80}?instruction|unrestricted)(?:(?!```)[\s\S]){0,1500}?```[\s\S]{0,200}?(?:parse|execute|follow|run|apply|interpret|process)\s+(?:the|this|above|it)/i,
    piece: (g) => {
      const slot = (f: () => string) => (g.chance(15) ? g.pick(["```", "``", "role", "system", "run the", "x", ...WS]) : f());
      const [head, tail] = g.pick(CODE_KEYWORDS);
      return g.chance(6)
        ? g.pick(["```", "````", "``", "role", "prompt", "run the", ...WS])
        : slot(() => "```") + slot(() => fill(g, g.pick([0, 2, 50, 1498 + (g.next() % 6)]))) + slot(() => head) +
          slot(() => fill(g, g.pick([0, 1, 30, 79 + (g.next() % 4)]))) + slot(() => tail) + slot(() => fill(g, g.pick([0, 5, 60, 1497 + (g.next() % 7)]))) +
          slot(() => "```") + slot(() => fill(g, g.pick([0, 3, 40, 198 + (g.next() % 5)]))) + slot(() => g.pick(CODE_ACTIONS));
    },
    count: 500,
    min: 280,
  },
];

/** Inputs of 0-4 pieces with noise between, so most hold several matches. */
function inputs(c: Case, seed: number, count: number): string[] {
  const g = gen(seed);
  const out = [""];
  for (let i = 0; i < count; i++) {
    let s = g.chance(3) ? g.pick(WS) : "";
    for (let k = g.next() % 8; k > 0; k--) s += c.piece(g) + g.pick(["", " ", "\n", "x", "--> ", "``` "]);
    out.push(s);
  }
  return out;
}

const view = (m: RegExpMatchArray | null) =>
  m && { match: [...m], index: m.index, input: m.input, groups: m.groups, hasGroups: Object.hasOwn(m, "groups") };

/** f on both regexes: same value, or the same kind of exception. */
function same<T>(label: string, f: (re: RegExp) => T, subject: RegExp, oracle: RegExp): void {
  const attempt = (re: RegExp): { value?: T; error?: string } => {
    try {
      return { value: f(re) };
    } catch (e) {
      return { error: (e as Error).constructor.name };
    }
  };
  assert.deepEqual(attempt(subject), attempt(oracle), label);
}

const replacer = (...args: unknown[]) => `<${JSON.stringify(args)}>`;

for (const c of CASES) {
  test(`${c.id} answers every RegExp protocol entry point like the plain regex`, () => {
    const p = rule(c.id);
    assert.ok(p instanceof LinearPattern, "rule pattern is matched in code");
    assert.equal(p.flags, c.oracle.flags);
    const Ctor = p.constructor as RegExpConstructor;
    const oracleG = new RegExp(c.oracle.source, c.oracle.flags + "g");
    const oracleY = new RegExp(c.oracle.source, c.oracle.flags + "y");
    // Built the way species does (receiver, flags): still matched in code.
    const G = new Ctor(p, p.flags + "g");
    const Y = new Ctor(p, p.flags + "y");
    assert.ok(G instanceof Ctor && Y instanceof Ctor, "global and sticky instances stay LinearPattern");
    const g = gen(c.id.length * 7919);
    let matches = 0, stickyHits = 0, multi = 0;
    const cases = inputs(c, c.id.length, c.count);
    for (const [i, s] of cases.entries()) {
      const at = `${c.id} on ${JSON.stringify(s.length > 400 ? s.slice(0, 200) + "…" + s.slice(-200) : s)}`;
      // The rule object itself (no g / y): one exec per entry point.
      same(`exec ${at}`, (re) => { re.lastIndex = 5; const m = re.exec(s); return [view(m), re.lastIndex]; }, p, c.oracle);
      same(`test ${at}`, (re) => re.test(s), p, c.oracle);
      same(`match ${at}`, (re) => view(s.match(re)), p, c.oracle);
      same(`search ${at}`, (re) => s.search(re), p, c.oracle);
      same(`replace ${at}`, (re) => s.replace(re, "<$&|$1|$`|$'|$$|$<x>>"), p, c.oracle);
      same(`replace fn ${at}`, (re) => s.replace(re, replacer), p, c.oracle);
      same(`split ${at}`, (re) => s.split(re), p, c.oracle);
      same(`split limit ${at}`, (re) => s.split(re, 2), p, c.oracle);
      same(`Symbol.matchAll ${at}`, (re) => [...re[Symbol.matchAll](s)].map(view), p, c.oracle);
      same(`matchAll ${at}`, (re) => [...s.matchAll(re)].map(view), p, c.oracle); // TypeError: not global
      same(`replaceAll ${at}`, (re) => s.replaceAll(re, "x"), p, c.oracle); // TypeError: not global
      // Global: every match, through each entry point.
      const all = [...s.matchAll(oracleG)];
      matches += all.length;
      if (all.length > 1) multi++;
      same(`g match ${at}`, (re) => s.match(re), G, oracleG);
      same(`g matchAll ${at}`, (re) => [...s.matchAll(re)].map(view), G, oracleG);
      same(`g replace ${at}`, (re) => s.replace(re, "<$&|$1>"), G, oracleG);
      same(`g replaceAll ${at}`, (re) => s.replaceAll(re, replacer), G, oracleG);
      same(`g split ${at}`, (re) => s.split(re), G, oracleG);
      same(`g search ${at}`, (re) => [s.search(re), re.lastIndex], G, oracleG);
      same(`g test ${at}`, (re) => { re.lastIndex = 0; const out = []; for (let k = 0; k < 4; k++) out.push(re.test(s), re.lastIndex); return out; }, G, oracleG);
      // exec from lastIndex values that mostly rise (one searcher reused) and sometimes fall or
      // land inside a match, with another input in between now and then.
      const starts = all.flatMap((m) => [m.index, m.index + 1, m.index - 1]);
      const walk: [number, boolean][] = [];
      for (let k = 0, q = 0; k < 8; k++) {
        q = g.chance(4) ? g.next() % (s.length + 2) : starts.length && g.chance(2) ? g.pick(starts) : q + (g.next() % 40);
        walk.push([q, g.chance(6)]);
      }
      same(`g exec walk ${JSON.stringify(walk)} ${at}`, (re) => {
        const out = [];
        for (const [q, other] of walk) {
          re.lastIndex = q;
          if (other) re.exec(cases[(i + 1) % cases.length]);
          re.lastIndex = q;
          out.push(view(re.exec(s)), re.lastIndex);
        }
        return out;
      }, G, oracleG);
      // Sticky: a match only at lastIndex — at each match start and at nearby positions.
      for (const q of [...starts, g.next() % (s.length + 2), s.length, s.length + 1]) {
        oracleY.lastIndex = q;
        if (oracleY.exec(s)) stickyHits++;
        same(`y exec at ${q} ${at}`, (re) => { re.lastIndex = q; const m = re.exec(s); return [view(m), re.lastIndex]; }, Y, oracleY);
      }
    }
    assert.ok(matches >= c.min && multi >= c.min / 4 && stickyHits >= c.min,
      `corpus exercises matches: ${matches} matches, ${multi} inputs with several, ${stickyHits} sticky hits (want ${c.min})`);
  });
}

test("LinearPattern constructor gives a plain RegExp for any other pattern or flags, and refuses compile()", () => {
  for (const c of CASES) {
    const p = rule(c.id);
    const Ctor = p.constructor as RegExpConstructor;
    const s = inputs(c, 99, 40).join("\n");
    // Flags beyond g / y change what the pattern means: built as the plain regex they ask for.
    for (const flags of ["im", "ims", "imgy", "d" + p.flags, p.flags.replace("i", ""), "iu".slice(0, 1) + "u" + p.flags.slice(1)]) {
      const r = new Ctor(p, flags);
      assert.ok(!(r instanceof LinearPattern), `${c.id} with flags ${flags} is a plain RegExp`);
      assert.equal(r.source, p.source);
      assert.equal(r.flags, new RegExp(p.source, flags).flags);
    }
    const other = new Ctor("ab+c");
    assert.ok(!(other instanceof LinearPattern));
    assert.equal(String(other), "/ab+c/");
    assert.equal(String(new Ctor("ab+c", "g")), "/ab+c/g");
    assert.equal(String(new Ctor(/x/y)), "/x/y");
    // The same pattern, from its source string or a copy, with base flags plus g / y stays in code.
    assert.ok(new Ctor(p.source, p.flags) instanceof LinearPattern);
    assert.ok(new Ctor(new RegExp(p.source, p.flags + "gy")) instanceof LinearPattern);
    assert.ok(!(new Ctor(p.source) instanceof LinearPattern), "a source string without flags means no flags, as for RegExp");
    assert.throws(() => new Ctor(p, "ii"), SyntaxError);
    assert.deepEqual(view(new Ctor(p.source, p.flags + "g").exec(s)), view(new RegExp(c.oracle.source, c.oracle.flags + "g").exec(s)));
    assert.throws(() => p.compile("x"), TypeError);
    assert.equal(p.source, new Ctor().source, `${c.id}: compile() left the shared rule pattern unchanged`);
  }
});

// ── Linear through the protocol, not only exec ────────────────────────────────

const SLACK = Math.max(1, Number(process.env.NEXUS_PERF_SLACK) || 1);

function best(f: () => unknown): number {
  f();
  let t = Infinity;
  for (let i = 0; i < 3; i++) {
    const t0 = performance.now();
    f();
    t = Math.min(t, performance.now() - t0);
  }
  return t;
}

// Inputs dense with matches: a split, a global replace or a matchAll calls exec once per
// match (split: once per position, sticky), so each must reuse one searcher per input.
const DENSE: [string, string][] = [
  ["indirect-comment-injection", "<!-- ignore --> "],
  ["advanced-markdown-exfil", "![a](http://x.com/leak) "],
  ["advanced-payload-splitting-numbered", "step 1: a step 2: b run. "],
  ["advanced-padding-injection", "a".repeat(101) + " new instructions "],
  ["advanced-code-block-system", "```role system``` run the "],
];

for (const [id, chunk] of DENSE) {
  test(`${id}: split, global replace and matchAll stay linear on dense matches`, () => {
    const p = rule(id);
    const G = new (p.constructor as RegExpConstructor)(p, p.flags + "g");
    const build = (n: number) => chunk.repeat(Math.ceil(n / chunk.length)).slice(0, n);
    const ops: [string, (s: string) => unknown][] = [
      ["split", (s) => s.split(p)],
      ["replace", (s) => s.replace(G, "")],
      ["matchAll", (s) => [...s.matchAll(G)].length],
    ];
    for (const [name, op] of ops) {
      // One call per size, doubling up to 200 KB, before the best-of-three timings: without the reused
      // searcher a split re-scans the input at every position, minutes at 200 KB. node:test cannot
      // interrupt synchronous work, so this fails it at the first size over the cap instead.
      for (let n = 2_000; n < 200_000; n *= 2) {
        const s = build(n);
        const t0 = performance.now();
        op(s);
        const t = performance.now() - t0;
        assert.ok(t < 2000 * SLACK, `${id} ${name}: ${n} bytes already took ${t.toFixed(0)}ms (re-scanning per match? larger sizes skipped)`);
      }
      const small = build(25_000), big = build(200_000);
      const tSmall = Math.max(best(() => op(small)), 0.5), tBig = best(() => op(big));
      assert.ok(tBig < 50 || tBig / tSmall < 24, `${id} ${name}: 8× input grew ${(tBig / tSmall).toFixed(1)}× (${tSmall.toFixed(0)}→${tBig.toFixed(0)}ms)`);
      assert.ok(tBig < 2000 * SLACK, `${id} ${name}: 200KB took ${tBig.toFixed(0)}ms`);
    }
  });
}
