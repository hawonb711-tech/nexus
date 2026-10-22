import { test } from "node:test";
import assert from "node:assert/strict";
import type { NexusMemory } from "../memory-engine/nexus-memory.js";
import { extractText, extractTitle, findBlock } from "./html.js";
import { parseFeed } from "./feed.js";
import { collectFetchedUrl } from "./fetch.js";

/**
 * html.ts and feed.ts scanned pages and feeds with lazy `<tag…>…</tag>` regexes
 * and a `<[^>]*>` tag stripper that re-scanned the rest of the input from every
 * unclosed opener, so `nexus_collect` on a page of `<div` or `<` was quadratic.
 * They are now linear scans that must keep exactly the old matches and outputs:
 * the old regexes and the old extractText / extractTitle / parseFeed are kept
 * below, verbatim, as oracles and compared on structured fuzz.
 */

// ─── Oracles: the pre-rewrite html.ts / feed.ts, verbatim ─────────────────────

const ENTITY_MAP: Record<string, string> = {
  "&amp;": "&", "&lt;": "<", "&gt;": ">",
  "&quot;": '"', "&#39;": "'", "&apos;": "'",
  "&nbsp;": " ",
};

function oldDecodeEntities(text: string): string {
  return text.replace(/&(?:#(\d+)|#x([0-9a-f]+)|(\w+));/gi, (m, dec, hex, name) => {
    if (dec) return String.fromCharCode(parseInt(dec, 10));
    if (hex) return String.fromCharCode(parseInt(hex, 16));
    return ENTITY_MAP[`&${name};`] ?? m;
  });
}

function oldStripNoise(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<nav[\s\S]*?<\/nav>/gi, "")
    .replace(/<header[\s\S]*?<\/header>/gi, "")
    .replace(/<footer[\s\S]*?<\/footer>/gi, "")
    .replace(/<aside[\s\S]*?<\/aside>/gi, "")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, "");
}

function oldFindMainContent(html: string): string {
  const articleMatch = html.match(/<article[^>]*>([\s\S]*?)<\/article>/i);
  if (articleMatch && articleMatch[1].replace(/<[^>]*>/g, "").trim().length > 200) {
    return articleMatch[1];
  }
  const mainMatch = html.match(/<main[^>]*>([\s\S]*?)<\/main>/i);
  if (mainMatch && mainMatch[1].replace(/<[^>]*>/g, "").trim().length > 200) {
    return mainMatch[1];
  }
  const blockRe = /<(?:div|section)[^>]*>([\s\S]*?)<\/(?:div|section)>/gi;
  let best = "";
  let bestScore = 0;
  let match;
  while ((match = blockRe.exec(html)) !== null) {
    const inner = match[1];
    const textOnly = inner.replace(/<[^>]*>/g, "").trim();
    if (textOnly.length < 200) continue;
    const density = textOnly.length / Math.max(inner.length, 1);
    if (density * textOnly.length > bestScore) {
      bestScore = density * textOnly.length;
      best = inner;
    }
  }
  if (best) return best;
  const bodyMatch = html.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  return bodyMatch?.[1] ?? html;
}

function oldStripTags(html: string): string {
  return html
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<\/div>/gi, "\n")
    .replace(/<\/li>/gi, "\n")
    .replace(/<[^>]*>/g, "")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function oldExtractTitle(html: string): string {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? oldDecodeEntities(match[1].trim()) : "";
}

function oldExtractText(html: string): string {
  return oldDecodeEntities(oldStripTags(oldFindMainContent(oldStripNoise(html))));
}

type Item = { title: string; link: string; description: string; pubDate?: string };

function oldExtractTag(xml: string, tag: string): string {
  const cdataRe = new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${tag}>`, "i");
  const cdataMatch = xml.match(cdataRe);
  if (cdataMatch) return cdataMatch[1].trim();
  const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "i");
  const match = xml.match(re);
  return match ? match[1].trim() : "";
}

function oldExtractAttr(xml: string, tag: string, attr: string): string {
  const re = new RegExp(`<${tag}[^>]*${attr}\\s*=\\s*["']([^"']*)["']`, "i");
  const match = xml.match(re);
  return match ? match[1].trim() : "";
}

function oldParseFeed(xml: string): { title: string; items: Item[] } {
  const items: Item[] = [];
  if (/<feed[\s>]/i.test(xml)) {
    const entryRe = /<entry>([\s\S]*?)<\/entry>/gi;
    let match;
    while ((match = entryRe.exec(xml)) !== null) {
      const block = match[1];
      const content = oldExtractTag(block, "summary") || oldExtractTag(block, "content");
      items.push({
        title: oldExtractTag(block, "title"),
        link: oldExtractAttr(block, "link", "href") || oldExtractTag(block, "link"),
        description: content.startsWith("<") ? oldExtractText(content) : content,
        pubDate: oldExtractTag(block, "published") || oldExtractTag(block, "updated"),
      });
    }
    return { title: oldExtractTag(xml, "title"), items };
  }
  const itemRe = /<item>([\s\S]*?)<\/item>/gi;
  let match;
  while ((match = itemRe.exec(xml)) !== null) {
    const block = match[1];
    const desc = oldExtractTag(block, "description");
    items.push({
      title: oldExtractTag(block, "title"),
      link: oldExtractTag(block, "link"),
      description: desc.startsWith("<") ? oldExtractText(desc) : desc,
      pubDate: oldExtractTag(block, "pubDate"),
    });
  }
  return { title: oldExtractTag(xml.match(/<channel>([\s\S]*)/i)?.[1] ?? xml, "title"), items };
}

// ─── Structured fuzz ──────────────────────────────────────────────────────────

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
const PROSE = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ".repeat(2);
// Bodies, attribute lists, CDATA sections and href values past 900 characters:
// the old regexes left these spans unbounded, so a length cap on one must fail
// the oracle tests below rather than pass them.
const LONG = [PROSE.repeat(4), PROSE.repeat(7) + LINE_SEP + PROSE];
const LONG_SPAN = 900;
const SEPARATORS = ["", "", " ", "\n", "\r\n", "\t", "  \n\n\n  ", LINE_SEP];
const NOISE = ["<", ">", "</", "<<", ">>", "\"", "'", "=", "/", " ", "\n", "&amp;", "&#65;", "&#x42;", "&bogus;", "&"];

/** `count` strings of 1–`maxUnits` units from `unit`, glued with SEPARATORS, each
 *  piece sometimes swapped for NOISE so near-misses are as common as matches. */
function corpus(seed: number, count: number, maxUnits: number, unit: (pick: <T>(xs: readonly T[]) => T) => string[]): string[] {
  const next = rng(seed);
  const pick = <T,>(xs: readonly T[]): T => xs[next() % xs.length];
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    let s = "";
    for (let k = 1 + (next() % maxUnits); k > 0; k--) {
      s += unit(pick).map((p) => (next() % 9 === 0 ? pick(NOISE) : p)).join("") + pick(SEPARATORS);
    }
    out.push(s);
  }
  return out;
}

const HTML_TAGS = ["script", "SCRIPT", "style", "nav", "Nav", "header", "headers", "footer", "aside", "noscript",
  "article", "ARTICLE", "main", "div", "DIV", "section", "body", "Body", "title", "TITLE", "p", "li", "br", "span", "a"];
const ATTRS = ["", "", " class=\"x\"", " id='a b'", " data-x=\"1 > 0\"", "/", " /", "\n  lang=en", ` data-long="${LONG[0]}"`];
const TEXT = ["", "Hello world", "Tom &amp; Jerry", PROSE, PROSE.slice(0, 120), "  \t ", "x", "&nbsp;&lt;3", ...LONG];

const NOISE_TAGS = ["script", "SCRIPT", "style", "nav", "header", "footer", "aside", "noscript"];

const HTML = corpus(11, 16_000, 8, (pick) => {
  const tag = pick(HTML_TAGS);
  switch (pick([0, 1, 2, 2, 3, 4])) {
    case 0: return ["<", tag, pick(ATTRS), pick([">", ">", ""])];
    case 1: return ["</", tag, pick([">", ">", "", " >"])];
    case 2: return ["<", tag, pick(ATTRS), ">", pick(TEXT), pick(["</", "</", "<"]), pick([tag, tag, pick(HTML_TAGS)]), ">"];
    // Overlapping noise blocks: which one stripNoise removes first decides the text.
    case 4: {
      const [a, b] = [pick(NOISE_TAGS), pick(NOISE_TAGS)];
      return ["<", a, ">", pick(TEXT), "<", b, ">", pick(TEXT), "</", a, ">", pick(TEXT), "</", b, ">"];
    }
    default: return [pick(TEXT), pick(["<br>", "<br/>", "<br />", "</p>", "</li>", "", "<p>"])];
  }
});

/**
 * Same leftmost match (index, [0], [1]) as `oracle`, and, if global, the same
 * sequence. Returns how many inputs it matched, and in how many a match spanned
 * more than LONG_SPAN characters.
 */
function sameMatches(oracle: RegExp, inputs: string[], subject: (s: string, from: number) => [number, string, string] | null): [number, number] {
  let hits = 0, long = 0;
  for (const s of inputs) {
    const want: [number, string, string | undefined][] = [];
    oracle.lastIndex = 0;
    for (let m; (m = oracle.exec(s)); ) {
      want.push([m.index, m[0], m[1] ?? ""]);
      if (!oracle.global) break;
    }
    const got: [number, string, string][] = [];
    for (let from = 0, b; (b = subject(s, from)); from = b[0] + b[1].length) {
      got.push(b);
      if (!oracle.global) break;
    }
    if (want.length) hits++;
    if (want.some(([, m]) => m!.length > LONG_SPAN)) long++;
    assert.deepEqual(got, want, `${oracle} on ${JSON.stringify(s)}`);
  }
  return [hits, long];
}

test("findBlock keeps each old lazy tag regex's matches and captures", () => {
  const forms: [RegExp, string, string, boolean][] = [
    [/<script[\s\S]*?<\/script>/gi, "script", "script", false],
    [/<style[\s\S]*?<\/style>/gi, "style", "style", false],
    [/<nav[\s\S]*?<\/nav>/gi, "nav", "nav", false],
    [/<header[\s\S]*?<\/header>/gi, "header", "header", false],
    [/<footer[\s\S]*?<\/footer>/gi, "footer", "footer", false],
    [/<aside[\s\S]*?<\/aside>/gi, "aside", "aside", false],
    [/<noscript[\s\S]*?<\/noscript>/gi, "noscript", "noscript", false],
    [/<article[^>]*>([\s\S]*?)<\/article>/i, "article", "article", true],
    [/<main[^>]*>([\s\S]*?)<\/main>/i, "main", "main", true],
    [/<(?:div|section)[^>]*>([\s\S]*?)<\/(?:div|section)>/gi, "(?:div|section)", "(?:div|section)", true],
    [/<body[^>]*>([\s\S]*?)<\/body>/i, "body", "body", true],
    [/<title[^>]*>([\s\S]*?)<\/title>/i, "title", "title", true],
  ];
  for (const [oracle, open, close, attrs] of forms) {
    const openRe = new RegExp(`<${open}`, "gi");
    const closeRe = new RegExp(`<\\/${close}>`, "gi");
    const [hits, long] = sameMatches(oracle, HTML, (s, from) => {
      const b = findBlock(s, from, openRe, closeRe, attrs);
      return b && [b.start, s.slice(b.start, b.end), attrs ? s.slice(b.inner, b.close) : ""];
    });
    assert.ok(hits >= 100 && long >= 50, `corpus exercises ${oracle} (${hits} hits, ${long} over ${LONG_SPAN} chars)`);
  }
});

test("extractText / extractTitle keep the old outputs", () => {
  let tagHits = 0, titles = 0, texts = 0;
  for (const s of HTML) {
    if (/<[^>]*>/.test(s)) tagHits++;
    const title = oldExtractTitle(s);
    const text = oldExtractText(s);
    if (title) titles++;
    if (text) texts++;
    assert.equal(extractTitle(s), title, `extractTitle on ${JSON.stringify(s)}`);
    assert.equal(extractText(s), text, `extractText on ${JSON.stringify(s)}`);
  }
  assert.ok(tagHits >= 1000 && titles >= 100 && texts >= 1000, `corpus exercises the pipeline (${tagHits}/${titles}/${texts})`);
});

test("the tag stripper keeps `/<[^>]*>/g`'s output", () => {
  // No tag names here, so extractText reduces to stripTags + decodeEntities and a
  // difference can only come from the `<…>` step.
  const inputs = corpus(13, 12_000, 10, (pick) => [pick(["<", "<", "<<", ">", "</", "a", "b c", "\n", "<br>", "=\"", "'>'"]), pick(["", "x", ">", "<", " "])]);
  let hits = 0;
  for (const s of inputs) {
    if (/<[^>]*>/.test(s)) hits++;
    assert.equal(extractText(s), oldExtractText(s), `extractText on ${JSON.stringify(s)}`);
  }
  assert.ok(hits >= 1000, `corpus exercises the tag stripper (${hits} hits)`);
});

const FEED_TAGS = ["title", "TITLE", "link", "description", "pubDate", "pubdate", "summary", "content", "published", "updated"];
const VALUES = ["", "News of the day", "https://example.test/a?b=1", "<p>Rich <b>text</b></p>", "  padded  ", "a]]b", "x\"y", PROSE.slice(0, 60), LONG[0]];

function feedUnit(pick: <T>(xs: readonly T[]) => T): string[] {
  const tag = pick(FEED_TAGS);
  switch (pick([0, 1, 2, 2, 2, 3, 4, 5])) {
    case 0: return [pick(["<item>", "<ITEM>", "<entry>", "<Entry>", "<item", "<channel>"])];
    case 1: return [pick(["</item>", "</ITEM>", "</entry>", "</item", "</entry"])];
    case 2: return ["<", tag, pick(ATTRS), ">", pick(["<![CDATA[", "<![CDATA[", "<![cdata[", "<![CDATA", ""]), pick(VALUES),
      pick(["]]>", "]]>", "]]", ""]), "</", pick([tag, tag, pick(FEED_TAGS)]), pick([">", ">", ""])];
    case 3: return ["<link", pick(["", " rel=\"alternate\"", " type='text/html'"]), pick([" href", " HREF", " href ", "href"]),
      pick(["=", " = ", "=\n"]), pick(["\"", "'", ""]), pick(VALUES), pick(["\"", "'", ""]), pick(["/>", ">", ""])];
    case 4: return ["<", tag, pick(ATTRS), pick([">", ""])];
    default: return [pick(VALUES)];
  }
}

test("parseFeed keeps the old output on RSS and Atom", () => {
  let cdata = 0, attr = 0, blocks = 0, plain = 0, longCdata = 0;
  for (const [seed, head] of [[17, "<rss><channel>"], [19, "<feed xmlns=\"http://www.w3.org/2005/Atom\">"], [23, ""]] as const) {
    const inputs = corpus(seed, 8_000, 9, feedUnit).map((s) => head + s);
    for (const s of inputs) {
      if (/<(?:item|entry)>([\s\S]*?)<\/(?:item|entry)>/i.test(s)) blocks++;
      if (/<title[^>]*><!\[CDATA\[([\s\S]*?)\]\]><\/title>/i.test(s)) cdata++;
      if ((/<(\w+)[^>]*><!\[CDATA\[([\s\S]*?)\]\]><\/\1>/i.exec(s)?.[2].length ?? 0) > LONG_SPAN) longCdata++;
      if (/<title[^>]*>([\s\S]*?)<\/title>/i.test(s)) plain++;
      if (/<link[^>]*href\s*=\s*["']([^"']*)["']/i.test(s)) attr++;
      assert.deepEqual(parseFeed(s), oldParseFeed(s), `parseFeed on ${JSON.stringify(s)}`);
    }
  }
  assert.ok(blocks >= 1000 && cdata >= 200 && plain >= 1000 && attr >= 1000 && longCdata >= 100,
    `corpus exercises the feed regexes (${blocks}/${cdata}/${plain}/${attr}/${longCdata})`);
});

// Atom `<link … href=…>`: extractAttr tries only the first `<link` before each
// `>`. These units put several heads, with and without an href, in one entry,
// between every kind of separator (`>`, either quote, `<`, newlines), so a
// wrong run boundary picks a different link or none.
const LINK_HEADS = ["<link", "<link", "<link", "<LINK", "<Link", "<links", "<linkx"];
const LINK_ATTRS = ["", "", " rel=\"alternate\"", " type='text/html'", " title=\"a > b\"", " data-x='<link'", " xhref=\"y\"", "/", "\n", ` title="${LONG[0]}"`];
const HREFS = [" href", " href", " HREF", "href", " Href", " hre", " href "];
const EQUALS = ["=", "=", " = ", "=\n", "", "=="];
const QUOTES = ["\"", "\"", "'", "'", ""];
const LINK_VALUES = ["", "http://x.test/", "https://e.test/a?b=1", " padded ", "a>b", "x y", "<link href='z'>", LONG[0]];
const LINK_ENDS = [">", ">", "/>", " />", "", "</link>"];

function linkUnit(pick: <T>(xs: readonly T[]) => T): string[] {
  switch (pick([0, 0, 0, 1, 1, 2, 3])) {
    case 0: return [pick(LINK_HEADS), pick(LINK_ATTRS), pick(HREFS), pick(EQUALS), pick(QUOTES), pick(LINK_VALUES),
      pick(QUOTES), pick(LINK_ATTRS), pick(LINK_ENDS)];
    case 1: return [pick(LINK_HEADS), pick(LINK_ATTRS), pick(LINK_ENDS)];
    case 2: return [pick(LINK_HEADS), pick(LINK_ATTRS), ">", pick(LINK_VALUES), "</link>"];
    default: return [pick([">", "\"", "'", "<", "</entry><entry>", "text", "\n", "=\"x\""])];
  }
}

test("parseFeed keeps the old Atom link href", () => {
  const head = /<link/gi;
  const hrefRe = /<link[^>]*href\s*=\s*["']([^"']*)["']/i;
  let attr = 0, laterHead = 0, long = 0;
  for (const s of corpus(29, 12_000, 8, linkUnit)) {
    const xml = `<feed><entry>${s}</entry></feed>`;
    const m = s.match(hrefRe);
    if (m) {
      attr++;
      if (m[0].length > LONG_SPAN) long++;
      // The match starts after an earlier `<link`: the case the run boundary decides.
      head.lastIndex = 0;
      if (head.exec(s)!.index < m.index!) laterHead++;
    }
    assert.deepEqual(parseFeed(xml), oldParseFeed(xml), `parseFeed on ${JSON.stringify(xml)}`);
  }
  assert.ok(attr >= 4000 && laterHead >= 2000 && long >= 100,
    `corpus exercises the href regex (${attr} hits, ${laterHead} past an earlier <link, ${long} over ${LONG_SPAN} chars)`);
});

// ─── Growth ratchets ──────────────────────────────────────────────────────────

/** ~`bytes`-long input: `head`, then `chunk` repeated, then `tail`. */
function repeat(chunk: string, bytes: number, head = "", tail = ""): string {
  return head + chunk.repeat(Math.ceil((bytes - head.length - tail.length) / chunk.length)) + tail;
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
function timedPair(label: string, a: () => unknown, b: () => unknown, capMs: number): [number, number] {
  const firstSmall = once(a);
  assert.ok(firstSmall < capMs / 8, `${label}: 25KB took ${firstSmall.toFixed(0)}ms (pre-check cap ${(capMs / 8).toFixed(0)}ms; super-linear?)`);
  const firstBig = once(b);
  assert.ok(firstBig < capMs, `${label}: 200KB took ${firstBig.toFixed(0)}ms (cap ${capMs.toFixed(0)}ms)`);
  let ta = Infinity, tb = Infinity;
  for (let i = 0; i < RUNS; i++) {
    ta = Math.min(ta, once(a));
    tb = Math.min(tb, once(b));
  }
  return [ta, tb];
}

function assertScales(label: string, run: (s: string) => unknown, build: (bytes: number) => string, capMs = BIG_BUDGET_MS): void {
  const small = build(SMALL), big = build(BIG);
  const [rawSmall, tBig] = timedPair(label, () => run(small), () => run(big), capMs);
  const tSmall = Math.max(rawSmall, 0.5);
  const ratio = tBig / tSmall;
  assert.ok(
    tBig < RATIO_FLOOR_MS || ratio < MAX_GROWTH,
    `${label}: 8× input grew ${ratio.toFixed(1)}× (${tSmall.toFixed(0)}→${tBig.toFixed(0)}ms) — expected < ${MAX_GROWTH}× (super-linear?)`,
  );
  assert.ok(tBig < capMs, `${label}: 200KB took ${tBig.toFixed(0)}ms (cap ${capMs.toFixed(0)}ms)`);
}

test("extractText / extractTitle stay linear on unclosed tags", () => {
  // Each of these re-scanned the rest of the page from every repeat (~1–9 s at 200 KB).
  for (const chunk of ["<", "<br ", "<script", "<STYLE", "<nav", "/HEADER><HEADER", "<footer", "<ASIDE", "<noscript",
    "<ARTICLE>", "AIN><MAIN>", "<DIV", "<div>", "<section x>", "<BODY>"]) {
    assertScales(`extractText() on ${JSON.stringify(chunk)}`, (s) => extractText(s), (n) => repeat(chunk, n));
  }
  assertScales("extractTitle() on \"<TITLE>\"", (s) => extractTitle(s), (n) => repeat("<TITLE>", n));
});

test("parseFeed stays linear on unclosed items, entries and fields", () => {
  const families: [string, string, string, string][] = [
    ["items", "<rss>", "<ITEM>", ""],
    ["entries", "<feed>", "/ENTRY><ENTRY>", "/ENTRY>"],
    ["channel title", "<rss><channel>", "<title>", ""],
    ["unterminated title", "<rss><channel>", "<title", ""],
    ["item title", "<rss><item>", "<title", "</item>"],
    ["item CDATA", "<rss><item>", "<title><![CDATA[", "</item>"],
    ["item description", "<rss><item>", "<description>", "</item>"],
    ["entry links", "<feed><entry>", "<link", "</entry>"],
    // One `<link` per line: a run boundary at the newline would try every head again.
    ["entry links on lines", "<feed><entry>", "<link\n", "</entry>"],
    ["entry hrefs", "<feed><entry>", "<link href=", "</entry>"],
    ["entry summary", "<feed><entry>", "<summary>", "</entry>"],
  ];
  for (const [name, head, chunk, tail] of families) {
    assertScales(`parseFeed() on ${name}`, (s) => parseFeed(s), (n) => repeat(chunk, n, head, tail));
  }
});

test("collectFetchedUrl stays linear on pages and feeds of unclosed tags", () => {
  // The nexus_collect entry point (extraction, then sanitizing what was extracted;
  // the memory is a stub so storage is not timed).
  const memory = { ingest: () => 0, save: () => undefined } as unknown as NexusMemory;
  const collect = (s: string) => collectFetchedUrl("https://example.test/p", s, memory);
  for (const [head, chunk] of [["", "<"], ["", "<STYLE"], ["", "<TITLE>"], ["", "<ARTICLE>"], ["", "<div>"],
    ["", "/HEADER><HEADER"], ["<rss>", "<ITEM>"], ["<rss><channel>", "<title>"], ["<feed>", "<entry>"]] as const) {
    assertScales(`collectFetchedUrl() on ${JSON.stringify(head + chunk)}`, collect, (n) => repeat(chunk, n, head));
  }
});
