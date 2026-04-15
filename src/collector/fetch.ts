import { extractText, extractTitle } from "./html.js";
import { parseFeed } from "./feed.js";
import type { NexusMemory } from "../memory-engine/nexus-memory.js";
import type { CollectorResult, FeedResult, FetchOptions } from "./types.js";

const DEFAULT_UA = "Nexus/0.3 (AI Research Collector)";
const DEFAULT_MAX_BYTES = 5 * 1024 * 1024;
const DEFAULT_TIMEOUT = 15_000;

async function fetchWithLimit(url: string, opts: FetchOptions = {}): Promise<{ html: string; rawBytes: number }> {
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": opts.userAgent ?? DEFAULT_UA },
      redirect: "follow",
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const reader = res.body?.getReader();
    if (!reader) throw new Error("No response body");

    const chunks: Uint8Array[] = [];
    let totalBytes = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        reader.cancel();
        break;
      }
      chunks.push(value);
    }

    const decoder = new TextDecoder("utf-8", { fatal: false });
    const html = decoder.decode(Buffer.concat(chunks));
    return { html, rawBytes: totalBytes };
  } finally {
    clearTimeout(timer);
  }
}

function domainFromUrl(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "").replace(/\./g, "-");
  } catch {
    return "web";
  }
}

function isFeedContent(html: string): boolean {
  const trimmed = html.trimStart().slice(0, 500);
  return /^<\?xml/i.test(trimmed) && (/<rss[\s>]/i.test(trimmed) || /<feed[\s>]/i.test(trimmed));
}

export async function collectUrl(
  url: string,
  memory: NexusMemory,
  options?: FetchOptions,
): Promise<CollectorResult> {
  const { html, rawBytes } = await fetchWithLimit(url, options);

  // Auto-detect feed
  if (isFeedContent(html)) {
    const feedResult = await collectFeedFromXml(url, html, memory, options);
    return {
      url,
      title: feedResult.feedTitle,
      text: `Feed: ${feedResult.itemsIngested} items ingested`,
      observationsAdded: feedResult.itemsIngested,
      rawBytes,
      textBytes: 0,
      fetchedAt: new Date().toISOString(),
    };
  }

  const title = extractTitle(html);
  const text = extractText(html);
  const domain = options?.domain ?? domainFromUrl(url);
  const added = memory.ingest(text, domain);
  if (added > 0) memory.save();

  return {
    url,
    title,
    text: text.slice(0, 500),
    observationsAdded: added,
    rawBytes,
    textBytes: text.length,
    fetchedAt: new Date().toISOString(),
  };
}

async function collectFeedFromXml(
  feedUrl: string,
  xml: string,
  memory: NexusMemory,
  options?: FetchOptions & { maxItems?: number },
): Promise<FeedResult> {
  const { title: feedTitle, items } = parseFeed(xml);
  const max = options?.maxItems ?? 20;
  const domain = options?.domain ?? domainFromUrl(feedUrl);
  let ingested = 0;

  for (const item of items.slice(0, max)) {
    const text = `${item.title}. ${item.description}`;
    if (text.length < 30) continue;
    const added = memory.ingest(text, domain);
    ingested += added;
  }

  if (ingested > 0) memory.save();

  return { feedUrl, feedTitle, items: items.slice(0, max), itemsIngested: ingested };
}

export async function collectFeed(
  feedUrl: string,
  memory: NexusMemory,
  options?: FetchOptions & { maxItems?: number },
): Promise<FeedResult> {
  const { html } = await fetchWithLimit(feedUrl, options);
  return collectFeedFromXml(feedUrl, html, memory, options);
}

export async function collectUrls(
  urls: string[],
  memory: NexusMemory,
  options?: FetchOptions,
): Promise<CollectorResult[]> {
  const results: CollectorResult[] = [];
  for (const url of urls) {
    try {
      const result = await collectUrl(url, memory, options);
      results.push(result);
      // 1s delay between requests
      await new Promise((r) => setTimeout(r, 1000));
    } catch { /* skip failed URLs */ }
  }
  return results;
}
