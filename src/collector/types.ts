import type { GuardVerdict } from "../guard/types.js";

export type FetchOptions = {
  maxBytes?: number;
  timeoutMs?: number;
  userAgent?: string;
  domain?: string;
  tags?: string[];
  /** Maximum number of HTTP redirects followed after validating every hop. */
  maxRedirects?: number;
  /** Maximum extracted text retained for trust scanning and display/persistence. */
  maxTextChars?: number;
};

/** How untrusted external content crossed the collector trust boundary. */
export type CollectorTrust = {
  verdict: GuardVerdict;
  /** Warn/block content is quarantined and is never handed to persistent memory. */
  persistence: "stored" | "quarantined" | "partial" | "skipped";
  /** Treatment applied to the value exposed to the caller. */
  display: "redacted" | "spotlighted" | "blocked";
  reason: string;
  findings: string[];
  secretsRedacted: number;
};

export type CollectorResult = {
  /** URL requested by the caller. */
  url: string;
  /** Final URL after safely validated redirects. */
  finalUrl: string;
  redirects: number;
  title: string;
  /** Safe display excerpt. Warn content is spotlighted; block payloads are omitted. */
  text: string;
  observationsAdded: number;
  rawBytes: number;
  textBytes: number;
  /** True when extracted source text exceeded maxTextChars and was discarded. */
  textTruncated: boolean;
  fetchedAt: string;
  trust: CollectorTrust;
};

export type FeedItem = {
  title: string;
  link: string;
  description: string;
  pubDate?: string;
};

export type CollectedFeedItem = FeedItem & {
  trust: CollectorTrust;
  truncated: boolean;
};

export type FeedTrustSummary = {
  verdict: GuardVerdict;
  storedItems: number;
  quarantinedItems: number;
  skippedItems: number;
  secretsRedacted: number;
  findings: string[];
  reason: string;
  persistence: CollectorTrust["persistence"];
  truncatedItems: number;
  sourceTruncated: boolean;
};

export type FeedResult = {
  feedUrl: string;
  finalUrl: string;
  redirects: number;
  feedTitle: string;
  items: CollectedFeedItem[];
  itemsIngested: number;
  trust: FeedTrustSummary;
};
