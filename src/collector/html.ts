const ENTITY_MAP: Record<string, string> = {
  "&amp;": "&", "&lt;": "<", "&gt;": ">",
  "&quot;": '"', "&#39;": "'", "&apos;": "'",
  "&nbsp;": " ",
};

function decodeEntities(text: string): string {
  return text.replace(/&(?:#(\d+)|#x([0-9a-f]+)|(\w+));/gi, (m, dec, hex, name) => {
    if (dec) return String.fromCharCode(parseInt(dec, 10));
    if (hex) return String.fromCharCode(parseInt(hex, 16));
    return ENTITY_MAP[`&${name};`] ?? m;
  });
}

/**
 * Linear forms of the lazy `<tag…>…</tag>` scans below.
 *
 * As a regex (`/<tag[^>]*>([\s\S]*?)<\/tag>/i`), every opener with no closer after
 * it re-scans the rest of the page before the engine moves on to the next one, so
 * a fetched page of unclosed `<style` or `<div` was O(k·n): ~7 s at 200 KB, over
 * an hour at the 5 MB fetch cap. Only the first opener at or after the scan
 * position can match, though: any later opener looks for its `>` and its closer
 * further right, so when the first finds none, none does. `findBlock` tries just
 * that opener, so it returns exactly the regex's leftmost match and capture.
 */
export interface TagBlock {
  /** Index of the opener. */
  start: number;
  /** Start of the capture: after the opener's first `>` (`attrs`) or after the opener. */
  inner: number;
  /** Index of the closer, i.e. the end of the capture. */
  close: number;
  /** End of the closer, i.e. the end of the whole match. */
  end: number;
}

/**
 * The leftmost match at or after `from` of `OPEN[^>]*>([\s\S]*?)CLOSE`, or of
 * `OPEN([\s\S]*?)CLOSE` when `attrs` is false. `open` and `close` are global
 * regexes for the literal opener and closer, with the flags of the original.
 */
export function findBlock(html: string, from: number, open: RegExp, close: RegExp, attrs = true): TagBlock | null {
  open.lastIndex = from;
  const o = open.exec(html);
  if (!o) return null;
  let inner = open.lastIndex;
  if (attrs) {
    // `[^>]*>` can only stop at the first `>`.
    const gt = html.indexOf(">", inner);
    if (gt < 0) return null;
    inner = gt + 1;
  }
  close.lastIndex = inner;
  const c = close.exec(html);
  return c ? { start: o.index, inner, close: c.index, end: close.lastIndex } : null;
}

/** Capture of the first `OPEN[^>]*>([\s\S]*?)CLOSE` match, if there is one. */
function innerOf(html: string, [open, close]: readonly [RegExp, RegExp]): string | undefined {
  const b = findBlock(html, 0, open, close);
  return b ? html.slice(b.inner, b.close) : undefined;
}

const tagPair = (tag: string): [RegExp, RegExp] => [new RegExp(`<${tag}`, "gi"), new RegExp(`<\\/${tag}>`, "gi")];

const NOISE = ["script", "style", "nav", "header", "footer", "aside", "noscript"].map(tagPair);
const ARTICLE = tagPair("article");
const MAIN = tagPair("main");
const BLOCK = tagPair("(?:div|section)");
const BODY = tagPair("body");
const TITLE = tagPair("title");

// `/<[^>]*>/g` re-scanned the rest of the page from every `<` once no `>` followed
// (O(n²) on a page of `<`). A match always ends at a `>`, so only the first `<`
// after a `>` (or the start) can begin one, and when that `<` finds no `>`, no
// later one can. The look-behind turns the others away after walking back only to
// the previous `<` or `>`. Same matches, linear.
const TAG = /<(?<=(?:^|>)[^<>]*<)[^>]*>/g;

function stripNoise(html: string): string {
  // Each step is `html.replace(/<tag[\s\S]*?<\/tag>/gi, "")`, in order.
  return NOISE.reduce((page, [open, close]) => {
    let out = "";
    let pos = 0;
    for (let b = findBlock(page, 0, open, close, false); b; b = findBlock(page, pos, open, close, false)) {
      out += page.slice(pos, b.start);
      pos = b.end;
    }
    return out + page.slice(pos);
  }, html);
}

function findMainContent(html: string): string {
  // Try <article> or <main>
  const article = innerOf(html, ARTICLE);
  if (article !== undefined && article.replace(TAG, "").trim().length > 200) {
    return article;
  }
  const main = innerOf(html, MAIN);
  if (main !== undefined && main.replace(TAG, "").trim().length > 200) {
    return main;
  }

  // Score <div>/<section> blocks by text density
  let best = "";
  let bestScore = 0;
  for (let b = findBlock(html, 0, ...BLOCK); b; b = findBlock(html, b.end, ...BLOCK)) {
    const inner = html.slice(b.inner, b.close);
    const textOnly = inner.replace(TAG, "").trim();
    if (textOnly.length < 200) continue;
    const density = textOnly.length / Math.max(inner.length, 1);
    if (density * textOnly.length > bestScore) {
      bestScore = density * textOnly.length;
      best = inner;
    }
  }
  if (best) return best;

  // Fallback: <body>
  return innerOf(html, BODY) ?? html;
}

function stripTags(html: string): string {
  return html
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<\/div>/gi, "\n")
    .replace(/<\/li>/gi, "\n")
    .replace(TAG, "")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function extractTitle(html: string): string {
  const title = innerOf(html, TITLE);
  return title !== undefined ? decodeEntities(title.trim()) : "";
}

export function extractText(html: string): string {
  const cleaned = stripNoise(html);
  const content = findMainContent(cleaned);
  const text = stripTags(content);
  return decodeEntities(text);
}
