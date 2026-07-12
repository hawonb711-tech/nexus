import { sanitizeExternalContent, type SanitizedExternalContent } from "../guard/sanitize.js";
import { spotlightUntrusted } from "../guard/guard.js";
import type { GuardVerdict } from "../guard/types.js";
import type { NexusMemory } from "../memory-engine/nexus-memory.js";
import { parseFeed } from "./feed.js";
import { extractText, extractTitle } from "./html.js";
import { fetchExternalText, type SafeFetchResult } from "./safe-fetch.js";
import type {
  CollectedFeedItem,
  CollectorResult,
  CollectorTrust,
  FeedResult,
  FetchOptions,
} from "./types.js";

const VERDICT_RANK: Record<GuardVerdict, number> = { allow: 0, warn: 1, block: 2 };
const DEFAULT_MAX_TEXT_CHARS = 500_000;
const MAX_TITLE_CHARS = 8_192;
const MAX_URL_DISPLAY_CHARS = 8_192;
const DISPLAY_EXCERPT_CHARS = 500;
const BOUNDARY_EDGE_CHARS = 2_048;

function textLimit(options: FetchOptions): number {
  const value = options.maxTextChars ?? DEFAULT_MAX_TEXT_CHARS;
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError("maxTextChars must be a positive safe integer.");
  }
  return value;
}

function boundaryProbe(parts: string[]): string {
  const probes: string[] = [];
  for (let i = 0; i < parts.length - 1; i++) {
    probes.push(parts[i].slice(-BOUNDARY_EDGE_CHARS), parts[i + 1].slice(0, BOUNDARY_EDGE_CHARS));
  }
  return probes.join("\n");
}

function displayExcerpt(
  raw: string,
  sanitized: SanitizedExternalContent,
  verdict: GuardVerdict = sanitized.verdict,
): string {
  if (verdict === "block") return sanitized.displayText;
  if (verdict === "allow") return sanitized.displayText.slice(0, DISPLAY_EXCERPT_CHARS);

  // Re-sanitize the bounded excerpt so secrets are masked, then add a fresh
  // complete spotlight wrapper. Slicing an existing wrapper could remove its
  // closing boundary and turn a context cap into a security regression.
  const preview = sanitizeExternalContent(raw.slice(0, DISPLAY_EXCERPT_CHARS));
  return spotlightUntrusted(preview.displayText.slice(0, DISPLAY_EXCERPT_CHARS));
}

function sanitizedUrlForDisplay(rawUrl: string): SanitizedExternalContent {
  if (rawUrl.length > MAX_URL_DISPLAY_CHARS) {
    return sanitizeExternalContent(rawUrl.slice(0, MAX_URL_DISPLAY_CHARS));
  }
  return sanitizeExternalContent(rawUrl);
}

function domainFromUrl(url: string): string {
  try {
    return new URL(url).hostname
      .replace(/^www\./i, "")
      .replace(/[^a-zA-Z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 80) || "web";
  } catch {
    return "web";
  }
}

function collectionDomain(override: string | undefined, finalUrl: string): string {
  const fallback = domainFromUrl(finalUrl);
  if (override === undefined) return fallback;
  if (override.length === 0 || override.length > 120) return fallback;
  const boundary = sanitizeExternalContent(override);
  if (boundary.verdict !== "allow" || boundary.persistText === null || boundary.secretsRedacted > 0) return fallback;
  const slug = boundary.persistText
    .trim()
    .replace(/[^\p{L}\p{N}._-]+/gu, "-")
    .replace(/-+/g, "-")
    .replace(/^[-._]+|[-._]+$/g, "")
    .slice(0, 80);
  return slug || fallback;
}

function isFeedContent(html: string): boolean {
  const trimmed = html.trimStart().slice(0, 1_000);
  return /^(?:<\?xml[\s\S]*?\?>\s*)?<(?:rss|feed)\b/i.test(trimmed);
}

function strictestSanitization(
  combined: SanitizedExternalContent,
  parts: SanitizedExternalContent[],
): { verdict: GuardVerdict; display: SanitizedExternalContent; reason: string; findings: string[] } {
  const all = [combined, ...parts];
  const verdict = all.reduce<GuardVerdict>(
    (worst, item) => VERDICT_RANK[item.verdict] > VERDICT_RANK[worst] ? item.verdict : worst,
    "allow",
  );
  // Prefer a component-level result at the strictest verdict. It avoids a very
  // large page title masking a later body attack at the scanner's size cap.
  const display = parts.find((part) => part.verdict === verdict) ?? combined;
  const findings = [...new Set(all.flatMap((item) => item.findings))].slice(0, 10);
  const reason = all.find((item) => item.verdict === verdict)?.reason ?? combined.reason;
  return { verdict, display, reason, findings };
}

function trustResult(
  verdict: GuardVerdict,
  reason: string,
  findings: string[],
  secretsRedacted: number,
  persistence?: CollectorTrust["persistence"],
): CollectorTrust {
  return {
    verdict,
    persistence: persistence ?? (verdict === "allow" ? "stored" : "quarantined"),
    display: verdict === "allow" ? "redacted" : verdict === "warn" ? "spotlighted" : "blocked",
    reason,
    findings,
    secretsRedacted,
  };
}

function safeFeedLink(link: string, feedUrl: string): string {
  if (!link) return "";
  try {
    const url = new URL(link, feedUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") return "";
    const boundary = sanitizedUrlForDisplay(url.href);
    return boundary.verdict === "allow" ? boundary.displayText : "";
  } catch {
    return "";
  }
}

type FetchMetadata = Pick<SafeFetchResult, "finalUrl" | "redirects"> & { rawBytes: number };

/**
 * Process already-fetched page/feed bytes through the collector trust boundary.
 * Exported for deterministic integration tests; network callers use collectUrl.
 */
export function collectFetchedUrl(
  url: string,
  html: string,
  memory: NexusMemory,
  options: FetchOptions = {},
  metadata: FetchMetadata = { finalUrl: url, redirects: 0, rawBytes: Buffer.byteLength(html) },
): CollectorResult {
  if (isFeedContent(html)) {
    const feedResult = collectFeedFromXml(url, html, memory, options, metadata);
    const verdict = feedResult.trust.verdict;
    return {
      url: feedResult.feedUrl,
      finalUrl: feedResult.finalUrl,
      redirects: metadata.redirects,
      title: feedResult.feedTitle,
      text: `Feed: ${feedResult.itemsIngested} observations ingested; ${feedResult.trust.quarantinedItems} items quarantined`,
      observationsAdded: feedResult.itemsIngested,
      rawBytes: metadata.rawBytes,
      textBytes: 0,
      textTruncated: feedResult.trust.sourceTruncated || feedResult.trust.truncatedItems > 0,
      fetchedAt: new Date().toISOString(),
      trust: trustResult(
        verdict,
        feedResult.trust.reason,
        feedResult.trust.findings,
        feedResult.trust.secretsRedacted,
        feedResult.trust.persistence,
      ),
    };
  }

  const extractedTitle = extractTitle(html);
  const extractedText = extractText(html);
  const maxChars = textLimit(options);
  const rawTitle = extractedTitle.slice(0, Math.min(MAX_TITLE_CHARS, maxChars));
  const rawText = extractedText.slice(0, Math.max(0, maxChars - rawTitle.length));
  const contentTruncated = rawTitle.length < extractedTitle.length || rawText.length < extractedText.length;
  const requestUrl = sanitizedUrlForDisplay(url);
  const finalUrl = sanitizedUrlForDisplay(metadata.finalUrl);
  const title = sanitizeExternalContent(rawTitle);
  const text = sanitizeExternalContent(rawText);
  const retainedParts = [metadata.finalUrl.slice(0, MAX_URL_DISPLAY_CHARS), rawTitle, rawText];
  const combined = sanitizeExternalContent(boundaryProbe(retainedParts));
  const boundary = strictestSanitization(combined, [finalUrl, title, text]);
  // Attribute redirected content to the host that actually supplied it, not a
  // potentially trusted-looking redirector chosen by the caller.
  const domain = collectionDomain(options.domain, metadata.finalUrl);
  let added = 0;
  if (boundary.verdict === "allow" && text.persistText !== null) {
    added = memory.ingest(text.persistText, domain, undefined, options.tags ?? []);
    if (added > 0) memory.save();
  }
  const trust = trustResult(
    boundary.verdict,
    boundary.reason,
    boundary.findings,
    requestUrl.secretsRedacted + finalUrl.secretsRedacted + title.secretsRedacted + text.secretsRedacted,
    boundary.verdict === "allow"
      ? (contentTruncated ? "partial" : added > 0 ? "stored" : "skipped")
      : undefined,
  );

  return {
    url: requestUrl.verdict === "allow" ? requestUrl.displayText : "",
    finalUrl: finalUrl.verdict === "allow" ? finalUrl.displayText : "",
    redirects: metadata.redirects,
    title: boundary.verdict === "allow"
      ? displayExcerpt(rawTitle, title)
      : "[Nexus quarantined untrusted external title]",
    text: boundary.verdict === "allow"
      ? displayExcerpt(rawText, text)
      : displayExcerpt(boundaryProbe(retainedParts), boundary.display, boundary.verdict),
    observationsAdded: added,
    rawBytes: metadata.rawBytes,
    textBytes: extractedText.length,
    textTruncated: contentTruncated,
    fetchedAt: new Date().toISOString(),
    trust,
  };
}

export async function collectUrl(
  url: string,
  memory: NexusMemory,
  options?: FetchOptions,
): Promise<CollectorResult> {
  const fetched = await fetchExternalText(url, options);
  return collectFetchedUrl(url, fetched.text, memory, options, {
    finalUrl: fetched.finalUrl,
    redirects: fetched.redirects,
    rawBytes: fetched.rawBytes,
  });
}

/**
 * Parse, sanitize, and conditionally persist an already-fetched feed. Every item
 * is an independent trust boundary so one poisoned entry cannot taint memory.
 */
export function collectFeedFromXml(
  feedUrl: string,
  xml: string,
  memory: NexusMemory,
  options: FetchOptions & { maxItems?: number } = {},
  metadata: FetchMetadata = { finalUrl: feedUrl, redirects: 0, rawBytes: Buffer.byteLength(xml) },
): FeedResult {
  const parsed = parseFeed(xml);
  const max = options.maxItems ?? 20;
  if (!Number.isSafeInteger(max) || max < 0) throw new RangeError("maxItems must be a non-negative safe integer.");

  const maxChars = textLimit(options);
  const retainedFeedTitle = parsed.title.slice(0, Math.min(MAX_TITLE_CHARS, maxChars));
  const sourceTruncated = retainedFeedTitle.length < parsed.title.length;
  let retainedBudget = Math.max(0, maxChars - retainedFeedTitle.length);
  const requestUrlBoundary = sanitizedUrlForDisplay(feedUrl);
  const finalUrlBoundary = sanitizedUrlForDisplay(metadata.finalUrl);
  const feedTitleBoundary = sanitizeExternalContent(retainedFeedTitle);
  const sourceCombined = sanitizeExternalContent(boundaryProbe([
    metadata.finalUrl.slice(0, MAX_URL_DISPLAY_CHARS),
    retainedFeedTitle,
  ]));
  const sourceBoundary = strictestSanitization(sourceCombined, [finalUrlBoundary, feedTitleBoundary]);
  const domain = collectionDomain(options.domain, metadata.finalUrl);
  const returnedItems: CollectedFeedItem[] = [];
  let ingested = 0;
  let storedItems = 0;
  let quarantinedItems = 0;
  let skippedItems = 0;
  let secretsRedacted = requestUrlBoundary.secretsRedacted + finalUrlBoundary.secretsRedacted + feedTitleBoundary.secretsRedacted;
  let worstVerdict = sourceBoundary.verdict;
  const findings = new Set(sourceBoundary.findings);
  let worstReason = sourceBoundary.reason;
  let truncatedItems = 0;

  for (const item of parsed.items.slice(0, max)) {
    const originalParts = [item.title, item.link, item.description, item.pubDate ?? ""];
    const rawParts = originalParts.map((part) => {
      const retained = part.slice(0, retainedBudget);
      retainedBudget -= retained.length;
      return retained;
    });
    const itemTruncated = rawParts.some((part, index) => part.length < originalParts[index].length);
    if (itemTruncated) truncatedItems++;
    const partBoundaries = rawParts.map((part) => sanitizeExternalContent(part));
    const combined = sanitizeExternalContent(boundaryProbe(rawParts));
    const boundary = strictestSanitization(combined, partBoundaries);
    const itemSecretsRedacted = partBoundaries.reduce((sum, part) => sum + part.secretsRedacted, 0);
    secretsRedacted += itemSecretsRedacted;
    for (const finding of boundary.findings) findings.add(finding);
    if (VERDICT_RANK[boundary.verdict] > VERDICT_RANK[worstVerdict]) {
      worstVerdict = boundary.verdict;
      worstReason = boundary.reason;
    }

    if (boundary.verdict === "allow") {
      const [safeTitle, safeLink, safeDescription, safePubDate] = partBoundaries;
      const memoryText = `${safeTitle.persistText ?? ""}. ${safeDescription.persistText ?? ""}`;
      let itemAdded = 0;
      if (memoryText.length >= 30) {
        itemAdded = memory.ingest(memoryText, domain, undefined, options.tags ?? []);
        ingested += itemAdded;
        if (itemAdded > 0) storedItems++;
      }
      const retainedChars = rawParts.reduce((sum, part) => sum + part.length, 0);
      const itemPersistence: CollectorTrust["persistence"] = itemTruncated
        ? (retainedChars > 0 ? "partial" : "quarantined")
        : itemAdded > 0 ? "stored" : "skipped";
      if (itemPersistence === "quarantined") quarantinedItems++;
      if (itemPersistence === "skipped") skippedItems++;
      const itemTrust = trustResult(
        boundary.verdict,
        boundary.reason,
        boundary.findings,
        itemSecretsRedacted,
        itemPersistence,
      );
      returnedItems.push({
        title: displayExcerpt(rawParts[0], safeTitle),
        link: safeFeedLink(safeLink.displayText, metadata.finalUrl),
        description: displayExcerpt(rawParts[2], safeDescription),
        pubDate: safePubDate.displayText
          ? displayExcerpt(rawParts[3], safePubDate)
          : undefined,
        trust: itemTrust,
        truncated: itemTruncated,
      });
    } else {
      quarantinedItems++;
      const itemTrust = trustResult(
        boundary.verdict,
        boundary.reason,
        boundary.findings,
        itemSecretsRedacted,
      );
      returnedItems.push({
        title: "[Nexus quarantined untrusted feed item]",
        link: "",
        description: displayExcerpt(rawParts.join("\n"), boundary.display, boundary.verdict),
        trust: itemTrust,
        truncated: itemTruncated,
      });
    }
  }

  if (ingested > 0) memory.save();

  const hasQuarantine = quarantinedItems > 0 || sourceBoundary.verdict !== "allow";
  const hasPartial = truncatedItems > 0 || sourceTruncated;
  const persistence: CollectorTrust["persistence"] = storedItems > 0
    ? (hasQuarantine || hasPartial ? "partial" : "stored")
    : hasQuarantine ? "quarantined" : hasPartial ? "partial" : "skipped";

  return {
    feedUrl: requestUrlBoundary.verdict === "allow" ? requestUrlBoundary.displayText : "",
    finalUrl: finalUrlBoundary.verdict === "allow" ? finalUrlBoundary.displayText : "",
    redirects: metadata.redirects,
    feedTitle: feedTitleBoundary.verdict === "allow"
      ? displayExcerpt(retainedFeedTitle, feedTitleBoundary)
      : "[Nexus quarantined untrusted feed title]",
    items: returnedItems,
    itemsIngested: ingested,
    trust: {
      verdict: worstVerdict,
      storedItems,
      quarantinedItems,
      skippedItems,
      secretsRedacted,
      findings: [...findings].slice(0, 10),
      reason: worstReason,
      persistence,
      truncatedItems,
      sourceTruncated,
    },
  };
}

export async function collectFeed(
  feedUrl: string,
  memory: NexusMemory,
  options?: FetchOptions & { maxItems?: number },
): Promise<FeedResult> {
  const fetched = await fetchExternalText(feedUrl, options);
  return collectFeedFromXml(feedUrl, fetched.text, memory, options, {
    finalUrl: fetched.finalUrl,
    redirects: fetched.redirects,
    rawBytes: fetched.rawBytes,
  });
}

export async function collectUrls(
  urls: string[],
  memory: NexusMemory,
  options?: FetchOptions,
): Promise<CollectorResult[]> {
  const results: CollectorResult[] = [];
  for (const url of urls) {
    try {
      results.push(await collectUrl(url, memory, options));
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    } catch {
      // Bulk collection remains best-effort; callers that need failure detail
      // should call collectUrl so CollectorSecurityError is preserved.
    }
  }
  return results;
}
