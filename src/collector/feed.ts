import { extractText, findBlock } from "./html.js";
import { firstInRun } from "../guard/line-scan.js";
import type { FeedItem } from "./types.js";

/**
 * Capture of `/<TAG[^>]*><!\[CDATA\[([\s\S]*?)\]\]><\/TAG>/i`, in one pass (see
 * findBlock for why the regex was quadratic). An opener whose `>` is not followed
 * by `<![CDATA[` fails, and so does every other opener before that same `>`, so
 * the scan resumes after it. A CDATA section with no closer after it ends the
 * search: every later opener would look for one further right.
 */
function cdataOf(xml: string, tag: string): string | null {
  const open = new RegExp(`<${tag}`, "gi");
  const marker = /<!\[CDATA\[/iy;
  const close = new RegExp(`\\]\\]></${tag}>`, "gi");
  for (let from = 0; ;) {
    open.lastIndex = from;
    if (!open.exec(xml)) return null;
    const gt = xml.indexOf(">", open.lastIndex);
    if (gt < 0) return null;
    marker.lastIndex = gt + 1;
    if (marker.test(xml)) {
      const body = marker.lastIndex;
      close.lastIndex = body;
      const c = close.exec(xml);
      return c ? xml.slice(body, c.index) : null;
    }
    from = gt + 1;
  }
}

function extractTag(xml: string, tag: string): string {
  // Handle CDATA
  const cdata = cdataOf(xml, tag);
  if (cdata !== null) return cdata.trim();

  // `<TAG[^>]*>([\s\S]*?)</TAG>`, case-insensitive.
  const b = findBlock(xml, 0, new RegExp(`<${tag}`, "gi"), new RegExp(`</${tag}>`, "gi"));
  return b ? xml.slice(b.inner, b.close).trim() : "";
}

function extractAttr(xml: string, tag: string, attr: string): string {
  // `<TAG[^>]*ATTR…`, tried only from the first `<TAG` before each `>`: a later
  // one there sees a subset of the same attributes, and re-scanning them from every
  // repeat of `<TAG` was quadratic. Same match, same capture.
  const re = new RegExp(`${firstInRun(new RegExp(`<${tag}`), ">")}[^>]*${attr}\\s*=\\s*["']([^"']*)["']`, "i");
  const match = xml.match(re);
  return match ? match[1].trim() : "";
}

const ITEM = [/<item>/gi, /<\/item>/gi] as const;
const ENTRY = [/<entry>/gi, /<\/entry>/gi] as const;

function parseRssItems(xml: string): FeedItem[] {
  const items: FeedItem[] = [];
  // Each match of `/<item>([\s\S]*?)<\/item>/gi`, in order.
  for (let b = findBlock(xml, 0, ...ITEM, false); b; b = findBlock(xml, b.end, ...ITEM, false)) {
    const block = xml.slice(b.inner, b.close);
    const desc = extractTag(block, "description");
    items.push({
      title: extractTag(block, "title"),
      link: extractTag(block, "link"),
      description: desc.startsWith("<") ? extractText(desc) : desc,
      pubDate: extractTag(block, "pubDate"),
    });
  }
  return items;
}

function parseAtomEntries(xml: string): FeedItem[] {
  const items: FeedItem[] = [];
  // Each match of `/<entry>([\s\S]*?)<\/entry>/gi`, in order.
  for (let b = findBlock(xml, 0, ...ENTRY, false); b; b = findBlock(xml, b.end, ...ENTRY, false)) {
    const block = xml.slice(b.inner, b.close);
    const content = extractTag(block, "summary") || extractTag(block, "content");
    items.push({
      title: extractTag(block, "title"),
      link: extractAttr(block, "link", "href") || extractTag(block, "link"),
      description: content.startsWith("<") ? extractText(content) : content,
      pubDate: extractTag(block, "published") || extractTag(block, "updated"),
    });
  }
  return items;
}

export function parseFeed(xml: string): { title: string; items: FeedItem[] } {
  const isAtom = /<feed[\s>]/i.test(xml);
  if (isAtom) {
    return {
      title: extractTag(xml, "title"),
      items: parseAtomEntries(xml),
    };
  }
  return {
    title: extractTag(xml.match(/<channel>([\s\S]*)/i)?.[1] ?? xml, "title"),
    items: parseRssItems(xml),
  };
}
