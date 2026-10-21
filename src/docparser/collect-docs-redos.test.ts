import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extractPlainText, markdownToPlainText } from "./text.js";
import { docxXmlToText } from "./docx.js";

/**
 * The markdown link / image / code-fence steps and the DOCX text-run regex
 * re-scanned the rest of the document from every unclosed `[`, `![`, ```` ``` ````
 * or `<w:t`, so `nexus_parse_document` on such a file was quadratic. Their linear
 * rewrites must keep exactly the old output: the old code is kept below, verbatim,
 * as the oracle and compared on structured fuzz.
 */

function oldMarkdownToPlainText(content: string): string {
  return content
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/\*{1,3}([^*]+)\*{1,3}/g, "$1")
    .replace(/(?<![A-Za-z0-9])_{1,3}([^_]+?)_{1,3}(?![A-Za-z0-9])/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/!\[[^\]]*\]\([^)]+\)/g, "")
    .replace(/```[^\n]*\n([\s\S]*?)```/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/^>\s+/gm, "")
    .replace(/^[-*_]{3,}\s*$/gm, "")
    .trim();
}

function oldDocxXmlToText(xml: string): string {
  const lines: string[] = [];
  const paragraphs = xml.split(/<\/w:p>/);
  for (const para of paragraphs) {
    const texts: string[] = [];
    const textRe = /<w:t[^>]*>([^<]*)<\/w:t>/g;
    let match;
    while ((match = textRe.exec(para)) !== null) {
      texts.push(match[1]);
    }
    if (texts.length > 0) {
      lines.push(texts.join(""));
    }
  }
  return lines.join("\n").trim();
}

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

const LINE_SEP = String.fromCharCode(0x2028);
const SEPARATORS = ["", "", " ", "\n", "\r\n", "\t", "\n\n", LINE_SEP];

/** `count` strings of 1–`maxUnits` units, each piece sometimes swapped for `noise`. */
function corpus(seed: number, count: number, maxUnits: number, noise: readonly string[],
  unit: (pick: <T>(xs: readonly T[]) => T) => string[]): string[] {
  const next = rng(seed);
  const pick = <T,>(xs: readonly T[]): T => xs[next() % xs.length];
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    let s = "";
    for (let k = 1 + (next() % maxUnits); k > 0; k--) {
      s += unit(pick).map((p) => (next() % 8 === 0 ? pick(noise) : p)).join("") + pick(SEPARATORS);
    }
    out.push(s);
  }
  return out;
}

// Link text, URLs, fence info strings, fence bodies and DOCX runs past 900
// characters: the old regexes left these spans unbounded, so a length cap on
// one must fail the oracle tests below rather than pass them.
const LONG_SPAN = 900;
const LONG = ["lorem ipsum ".repeat(80), "lorem ipsum ".repeat(70) + LINE_SEP + "dolor sit amet ".repeat(30)];
const LONG_URL = "https://x.test/" + "a/b".repeat(320);

const MD_NOISE = ["[", "]", "(", ")", "![", "](", "[]", "()", "`", "```", "\n", " ", "*", "_", "#", "> "];
const WORDS = ["", "text", "a b", "x", "ghp_token_1", "**bold**", "_it_", "`code`", "[", "]", "(", ")", "\n", "   ", ...LONG];

const MARKDOWN = corpus(29, 20_000, 7, MD_NOISE, (pick) => {
  switch (pick([0, 1, 2, 3])) {
    // [text](url) and ![alt](url), with every slot sometimes empty or broken.
    case 0: return [pick(["[", "![", "[[", "!["]), pick(WORDS), pick(["]", "]", "]]", ""]), pick(["(", "(", " (", ""]),
      pick(["", "http://x.test/a", "u", " ", ")", "a)b", LONG_URL]), pick([")", ")", "", "))"])];
    // ``` fences: info string, newline, body, closing fence.
    case 1: return [pick(["```", "```", "````", "``"]), pick(["", "ts", " js x", "`", LONG[0]]), pick(["\n", "\n", "", "\r\n"]),
      pick(WORDS), pick(["\n", ""]), pick(["```", "```", "``", ""])];
    case 2: return [pick(["# ", "## ", "> ", "---", "* ", "- "]), pick(WORDS)];
    default: return [pick(WORDS)];
  }
});

test("markdown stripping keeps the old link, image and code-fence output", () => {
  const forms: [string, RegExp][] = [
    ["link", /\[([^\]]+)\]\([^)]+\)/],
    ["image", /!\[[^\]]*\]\([^)]+\)/],
    ["code fence", /```[^\n]*\n([\s\S]*?)```/],
  ];
  const hits = new Map(forms.map(([name]) => [name, 0]));
  const long = new Map(forms.map(([name]) => [name, 0]));
  for (const s of MARKDOWN) {
    for (const [name, re] of forms) {
      const m = re.exec(s);
      if (m) hits.set(name, hits.get(name)! + 1);
      if (m && m[0].length > LONG_SPAN) long.set(name, long.get(name)! + 1);
    }
    assert.equal(markdownToPlainText(s), oldMarkdownToPlainText(s), `on ${JSON.stringify(s)}`);
  }
  for (const [name, n] of hits) {
    assert.ok(n >= 1000 && long.get(name)! >= 100, `corpus exercises the ${name} step (${n} hits, ${long.get(name)} over ${LONG_SPAN} chars)`);
  }
});

test("extractPlainText still applies the markdown stripping to a file", () => {
  const dir = mkdtempSync(join(tmpdir(), "nexus-md-redos-"));
  try {
    const file = join(dir, "doc.md");
    const md = "# Title\n\nSee [the docs](https://x.test/d) ![logo](l.png)\n```ts\nconst a = 1;\n```\n";
    writeFileSync(file, md);
    assert.equal(extractPlainText(file), oldMarkdownToPlainText(md));
    assert.equal(extractPlainText(file, false), md);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("docxXmlToText keeps the old `<w:t …>text</w:t>` runs", () => {
  const inputs = corpus(31, 20_000, 8, ["<", ">", "/", "<w:t", "</w:t>", "</w:p>", " ", "\n"], (pick) => {
    switch (pick([0, 0, 1, 2])) {
      case 0: return [pick(["<w:t", "<w:t", "<w:tab", "<W:t", "<w:"]), pick(["", " xml:space=\"preserve\"", "/", " a<b", ` w:x="${LONG[0]}"`]),
        pick([">", ">", ""]), pick(["", "Hello", "a b", "x>y", "&amp;", ...LONG]), pick(["</w:t>", "</w:t>", "</w:t", "<w:t>", ""])];
      case 1: return [pick(["<w:p>", "</w:p>", "<w:r>", "</w:r>", "<w:p w:x=\"1\">"])];
      default: return [pick(["text", "<", ">", "</", "w:t"])];
    }
  });
  let hits = 0, long = 0;
  for (const s of inputs) {
    const m = /<w:t[^>]*>([^<]*)<\/w:t>/.exec(s);
    if (m) hits++;
    if (m && m[0].length > LONG_SPAN) long++;
    assert.equal(docxXmlToText(s), oldDocxXmlToText(s), `on ${JSON.stringify(s)}`);
  }
  assert.ok(hits >= 1000 && long >= 100, `corpus exercises the text-run regex (${hits} hits, ${long} over ${LONG_SPAN} chars)`);
});

// ─── Growth ratchets ──────────────────────────────────────────────────────────

function repeat(chunk: string, bytes: number, tail = ""): string {
  return chunk.repeat(Math.ceil((bytes - tail.length) / chunk.length)) + tail;
}

const BIG = 200_000;
const SMALL = 25_000; // 8× smaller; the growth ratio compares the two.
const SLACK = Math.max(1, Number(process.env.NEXUS_PERF_SLACK) || 1);
const BIG_BUDGET_MS = 2000 * SLACK;
// 8× the input costs ~8× for a linear pass and ~64× for a quadratic one.
const MAX_GROWTH = 24;
// Below this the 200 KB run is too fast for a quadratic to hide, and the ratio is noise.
const RATIO_FLOOR_MS = 50;
const RUNS = 3;

function once(fn: () => unknown): number {
  const t0 = performance.now();
  fn();
  return performance.now() - t0;
}

/**
 * Best-of-RUNS timings of `a` (25 KB) and `b` (200 KB), sampled alternately,
 * after one checked call of each. A regressed scan costs seconds per 200 KB call
 * and a timeout cannot interrupt synchronous regex work, so the first calls fail
 * fast instead: 25 KB must fit in 1/8 of the budget before 200 KB runs at all,
 * and 200 KB must fit in the budget once before it is timed RUNS more times.
 */
function timedPair(label: string, a: () => unknown, b: () => unknown): [number, number] {
  const firstSmall = once(a);
  assert.ok(firstSmall < BIG_BUDGET_MS / 8,
    `${label}: 25KB took ${firstSmall.toFixed(0)}ms (pre-check cap ${(BIG_BUDGET_MS / 8).toFixed(0)}ms; super-linear?)`);
  const firstBig = once(b);
  assert.ok(firstBig < BIG_BUDGET_MS, `${label}: 200KB took ${firstBig.toFixed(0)}ms (cap ${BIG_BUDGET_MS.toFixed(0)}ms)`);
  let ta = Infinity, tb = Infinity;
  for (let i = 0; i < RUNS; i++) {
    ta = Math.min(ta, once(a));
    tb = Math.min(tb, once(b));
  }
  return [ta, tb];
}

function assertScales(label: string, run: (small: boolean) => unknown): void {
  const [rawSmall, tBig] = timedPair(label, () => run(true), () => run(false));
  const tSmall = Math.max(rawSmall, 0.5);
  const ratio = tBig / tSmall;
  assert.ok(
    tBig < RATIO_FLOOR_MS || ratio < MAX_GROWTH,
    `${label}: 8× input grew ${ratio.toFixed(1)}× (${tSmall.toFixed(0)}→${tBig.toFixed(0)}ms) — expected < ${MAX_GROWTH}× (super-linear?)`,
  );
  assert.ok(tBig < BIG_BUDGET_MS, `${label}: 200KB took ${tBig.toFixed(0)}ms (cap ${BIG_BUDGET_MS.toFixed(0)}ms)`);
}

test("extractPlainText stays linear on unclosed links, images and fences", () => {
  // Each re-scanned the rest of the file from every repeat (~10 s at 100 KB).
  const dir = mkdtempSync(join(tmpdir(), "nexus-md-redos-"));
  try {
    const small = join(dir, "small.md"), big = join(dir, "big.md");
    // "```" + "\n": every fence opener reaches the newline, and none a closer.
    for (const [chunk, tail] of [["[[", ""], ["![", "]![]([)"], ["[a](", ""], ["```", ""], ["```", "\n"]] as const) {
      writeFileSync(small, repeat(chunk, SMALL, tail));
      writeFileSync(big, repeat(chunk, BIG, tail));
      assertScales(`extractPlainText() on ${JSON.stringify(chunk)}…${JSON.stringify(tail)}`, (s) => extractPlainText(s ? small : big));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("docxXmlToText stays linear on a paragraph of unclosed text runs", () => {
  // `<w:t` one per line too: a run boundary at the newline would try every head again.
  for (const chunk of ["<w:t", "<w:t\n"]) {
    const small = repeat(chunk, SMALL, "/><w:t></w:t>"), big = repeat(chunk, BIG, "/><w:t></w:t>");
    assertScales(`docxXmlToText() on ${JSON.stringify(chunk)}`, (s) => docxXmlToText(s ? small : big));
  }
});
