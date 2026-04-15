import { extractText } from "./html.js";
import type { FeedItem } from "./types.js";

function extractTag(xml: string, tag: string): string {
  // Handle CDATA
  const cdataRe = new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${tag}>`, "i");
  const cdataMatch = xml.match(cdataRe);
  if (cdataMatch) return cdataMatch[1].trim();

  const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "i");
  const match = xml.match(re);
  return match ? match[1].trim() : "";
}

function extractAttr(xml: string, tag: string, attr: string): string {
  const re = new RegExp(`<${tag}[^>]*${attr}\\s*=\\s*["']([^"']*)["']`, "i");
  const match = xml.match(re);
  return match ? match[1].trim() : "";
}

function parseRssItems(xml: string): FeedItem[] {
  const items: FeedItem[] = [];
  const itemRe = /<item>([\s\S]*?)<\/item>/gi;
  let match;
  while ((match = itemRe.exec(xml)) !== null) {
    const block = match[1];
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
  const entryRe = /<entry>([\s\S]*?)<\/entry>/gi;
  let match;
  while ((match = entryRe.exec(xml)) !== null) {
    const block = match[1];
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
