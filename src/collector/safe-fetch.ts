import { lookup } from "node:dns/promises";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { Readable } from "node:stream";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";

import { sanitizeExternalContent } from "../guard/sanitize.js";
import { VERSION } from "../version.js";
import type { FetchOptions } from "./types.js";

const DEFAULT_UA = `Nexus/${VERSION} (AI Research Collector)`;
const DEFAULT_MAX_BYTES = 5 * 1024 * 1024;
const DEFAULT_TIMEOUT = 15_000;
const DEFAULT_MAX_REDIRECTS = 5;
const MAX_OUTBOUND_URL_CHARS = 16_384;
const MAX_USER_AGENT_CHARS = 512;

export type CollectorSecurityErrorCode =
  | "INVALID_URL"
  | "UNSAFE_PROTOCOL"
  | "UNSAFE_CREDENTIALS"
  | "UNSAFE_HOST"
  | "DNS_FAILED"
  | "TOO_MANY_REDIRECTS"
  | "UNSAFE_REDIRECT"
  | "RESPONSE_TOO_LARGE"
  | "UNSUPPORTED_ENCODING"
  | "TIMEOUT"
  | "UNSAFE_REQUEST_DATA";

/** A stable, machine-readable failure for collector trust-boundary violations. */
export class CollectorSecurityError extends Error {
  readonly code: CollectorSecurityErrorCode;

  constructor(code: CollectorSecurityErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "CollectorSecurityError";
    this.code = code;
  }
}

export type ResolvedAddress = { address: string; family: 4 | 6 };

export type SafeResolvedTarget = {
  url: URL;
  /** A public address selected after checking every DNS answer. */
  address: string;
  family: 4 | 6;
  /** All validated answers, retained for dual-stack connection fallback. */
  addresses: readonly ResolvedAddress[];
};

export type SafeTransportResponse = {
  statusCode: number;
  statusMessage: string;
  headers: IncomingHttpHeaders;
  body: AsyncIterable<Uint8Array>;
  cancel: () => void;
};

export type SafeFetchDependencies = {
  resolve?: (hostname: string) => Promise<readonly ResolvedAddress[]>;
  request?: (
    target: SafeResolvedTarget,
    init: { signal: AbortSignal; userAgent: string },
  ) => Promise<SafeTransportResponse>;
};

export type SafeFetchResult = {
  text: string;
  rawBytes: number;
  finalUrl: string;
  redirects: number;
};

const BLOCKED_HOSTS = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata.google",
  "metadata.goog",
  "instance-data.ec2.internal",
  "metadata.azure.internal",
]);

function normalizedHostname(hostname: string): string {
  const unbracketed = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  return unbracketed.toLowerCase().replace(/\.$/, "");
}

function decodedUrlInspection(url: URL): string {
  const parts = [url.href];
  for (const value of [url.pathname, url.hash]) {
    try {
      parts.push(decodeURIComponent(value));
    } catch {
      parts.push(value);
    }
  }
  for (const [key, value] of url.searchParams) parts.push(key, value);
  return parts.join("\n");
}

function assertNoSensitiveOutboundData(text: string): void {
  const boundary = sanitizeExternalContent(text);
  if (boundary.verdict !== "allow" || boundary.secretsRedacted > 0) {
    throw new CollectorSecurityError(
      "UNSAFE_REQUEST_DATA",
      "Collector refused to send a secret or agent-directed instruction in request metadata.",
    );
  }
}

function safeUserAgent(value: string): string {
  if (!value || value.length > MAX_USER_AGENT_CHARS || !/^[\x20-\x7e]+$/.test(value)) {
    throw new CollectorSecurityError("UNSAFE_REQUEST_DATA", "Collector User-Agent must be bounded printable ASCII.");
  }
  assertNoSensitiveOutboundData(value);
  return value;
}

function ipv4Number(address: string): number | null {
  const parts = address.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = ((value << 8) | octet) >>> 0;
  }
  return value;
}

function inIpv4Cidr(address: number, base: string, prefix: number): boolean {
  const baseNumber = ipv4Number(base);
  if (baseNumber === null) return false;
  if (prefix === 0) return true;
  return (address >>> (32 - prefix)) === (baseNumber >>> (32 - prefix));
}

const BLOCKED_IPV4_RANGES: ReadonlyArray<readonly [string, number]> = [
  ["0.0.0.0", 8],       // current host / unspecified
  ["10.0.0.0", 8],      // RFC 1918
  ["100.64.0.0", 10],   // carrier-grade NAT (includes Alibaba metadata)
  ["127.0.0.0", 8],     // loopback
  ["168.63.129.16", 32],// Azure WireServer / platform virtual IP
  ["169.254.0.0", 16],  // link-local and cloud metadata
  ["172.16.0.0", 12],   // RFC 1918
  ["192.0.0.0", 24],    // IETF protocol assignments / metadata endpoints
  ["192.0.2.0", 24],    // documentation
  ["192.88.99.0", 24],  // deprecated 6to4 relay anycast
  ["192.168.0.0", 16],  // RFC 1918
  ["198.18.0.0", 15],   // benchmark networks
  ["198.51.100.0", 24], // documentation
  ["203.0.113.0", 24],  // documentation
  ["224.0.0.0", 4],     // multicast
  ["240.0.0.0", 4],     // reserved / broadcast
];

function ipv6Words(input: string): number[] | null {
  let address = normalizedHostname(input);
  if (address.includes("%")) return null; // scoped/zone addresses are never web destinations

  const ipv4Tail = address.match(/(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/)?.[1];
  if (ipv4Tail) {
    const v4 = ipv4Number(ipv4Tail);
    if (v4 === null) return null;
    address = address.slice(0, -ipv4Tail.length) +
      `${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }

  if ((address.match(/::/g) ?? []).length > 1) return null;
  const [leftRaw, rightRaw] = address.split("::");
  const left = leftRaw ? leftRaw.split(":") : [];
  const right = rightRaw ? rightRaw.split(":") : [];
  const hasCompression = address.includes("::");
  if ((!hasCompression && left.length !== 8) || left.length + right.length > 8) return null;
  const missing = hasCompression ? 8 - left.length - right.length : 0;
  if (hasCompression && missing < 1) return null;

  const words = [...left, ...Array<string>(missing).fill("0"), ...right].map((word) => {
    if (!/^[0-9a-f]{1,4}$/i.test(word)) return -1;
    return parseInt(word, 16);
  });
  return words.length === 8 && words.every((word) => word >= 0) ? words : null;
}

/** True when an address must never be contacted by the web collector. */
export function isUnsafeCollectorAddress(address: string): boolean {
  const family = isIP(normalizedHostname(address));
  if (family === 4) {
    const value = ipv4Number(address);
    return value === null || BLOCKED_IPV4_RANGES.some(([base, prefix]) => inIpv4Cidr(value, base, prefix));
  }
  if (family !== 6) return true;

  const words = ipv6Words(address);
  if (!words) return true;

  // IPv4-compatible/mapped forms are not global IPv6 destinations. Callers can
  // use the equivalent public IPv4 literal directly; blocking these closes
  // legacy SIIT/translation interpretations that vary by host network.
  if (words.slice(0, 5).every((word) => word === 0) && (words[5] === 0 || words[5] === 0xffff)) {
    return true;
  }

  // Well-known and local-use NAT64 prefixes can otherwise disguise metadata or
  // private IPv4 destinations as globally shaped IPv6 literals.
  const nat64WellKnown = words[0] === 0x0064 && words[1] === 0xff9b && words.slice(2, 6).every((word) => word === 0);
  const nat64Local = words[0] === 0x0064 && words[1] === 0xff9b && words[2] === 1;
  // RFC 8215's local-use /48 can place the embedded IPv4 bits at multiple
  // offsets depending on the network prefix length. It is non-global anyway,
  // so block the entire range instead of trying to decode the last 32 bits.
  if (nat64Local) return true;
  if (nat64WellKnown) {
    const embedded = `${words[6] >>> 8}.${words[6] & 0xff}.${words[7] >>> 8}.${words[7] & 0xff}`;
    return isUnsafeCollectorAddress(embedded);
  }

  const first = words[0];
  // Public IPv6 web destinations live in the assignable global-unicast
  // envelope. Default-deny legacy translation, reserved, and internally routed
  // ranges outside it instead of trying to enumerate every future special use.
  if ((first & 0xe000) !== 0x2000) return true;                   // not 2000::/3
  if (first === 0x2001 && (words[1] & 0xfe00) === 0) return true;// 2001::/23 special-use block
  if (words.every((word) => word === 0)) return true;             // unspecified
  if ((first & 0xfe00) === 0xfc00) return true;                  // unique-local fc00::/7
  if ((first & 0xffc0) === 0xfe80) return true;                  // link-local fe80::/10
  if ((first & 0xffc0) === 0xfec0) return true;                  // deprecated site-local
  if ((first & 0xff00) === 0xff00) return true;                  // multicast
  if (first === 0x0100 && words.slice(1, 4).every((w) => w === 0)) return true; // discard-only 100::/64
  if (first === 0x2001 && words[1] === 0x0000) return true;      // Teredo
  if (first === 0x2001 && words[1] === 0x0db8) return true;      // documentation
  if (first === 0x2002) return true;                             // 6to4 tunnelling
  if (first === 0x3fff && (words[1] & 0xf000) === 0) return true;// documentation 3fff::/20
  if (first === 0x3ffe) return true;                             // retired 6bone
  return false;
}

function assertSafeHostname(hostname: string): void {
  if (!hostname || hostname.includes("%")) {
    throw new CollectorSecurityError("UNSAFE_HOST", "Collector URL has an invalid or scoped hostname.");
  }
  if (
    BLOCKED_HOSTS.has(hostname) ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    !hostname.includes(".")
  ) {
    throw new CollectorSecurityError("UNSAFE_HOST", `Collector refused non-public hostname: ${hostname}`);
  }
}

async function defaultResolver(hostname: string): Promise<readonly ResolvedAddress[]> {
  const addresses = await lookup(hostname, { all: true, verbatim: true });
  return addresses.map(({ address, family }) => ({ address, family: family as 4 | 6 }));
}

/**
 * Resolve and validate a URL, rejecting every target that is not public HTTP(S).
 * Every DNS answer is checked, then one approved address is pinned into the
 * socket request so a second DNS lookup cannot rebind it to a private service.
 */
export async function resolveSafeCollectorTarget(
  rawUrl: string | URL,
  resolver: (hostname: string) => Promise<readonly ResolvedAddress[]> = defaultResolver,
): Promise<SafeResolvedTarget> {
  let url: URL;
  try {
    url = rawUrl instanceof URL ? new URL(rawUrl.href) : new URL(rawUrl);
  } catch (cause) {
    throw new CollectorSecurityError("INVALID_URL", "Collector URL is invalid.", { cause });
  }

  if (url.href.length > MAX_OUTBOUND_URL_CHARS) {
    throw new CollectorSecurityError("UNSAFE_REQUEST_DATA", "Collector URL exceeds the outbound request limit.");
  }
  // The URL itself leaves the machine before any response can be sanitized.
  // Inspect decoded components too so percent-encoding cannot hide a token or
  // an agent/exfiltration directive in the query/path.
  assertNoSensitiveOutboundData(decodedUrlInspection(url));

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new CollectorSecurityError("UNSAFE_PROTOCOL", `Collector only permits HTTP(S), not ${url.protocol || "an empty protocol"}.`);
  }
  if (url.username || url.password) {
    throw new CollectorSecurityError("UNSAFE_CREDENTIALS", "Collector URLs must not contain embedded credentials.");
  }

  const hostname = normalizedHostname(url.hostname);
  const literalFamily = isIP(hostname);
  if (literalFamily) {
    if (isUnsafeCollectorAddress(hostname)) {
      throw new CollectorSecurityError("UNSAFE_HOST", `Collector refused non-public address: ${hostname}`);
    }
    const literal = { address: hostname, family: literalFamily as 4 | 6 };
    return { url, ...literal, addresses: [literal] };
  }

  assertSafeHostname(hostname);
  let addresses: readonly ResolvedAddress[];
  try {
    addresses = await resolver(hostname);
  } catch (cause) {
    throw new CollectorSecurityError("DNS_FAILED", `DNS resolution failed for ${hostname}.`, { cause });
  }
  if (addresses.length === 0) {
    throw new CollectorSecurityError("DNS_FAILED", `DNS resolution returned no addresses for ${hostname}.`);
  }

  for (const answer of addresses) {
    const actualFamily = isIP(normalizedHostname(answer.address));
    if ((actualFamily !== 4 && actualFamily !== 6) || actualFamily !== answer.family) {
      throw new CollectorSecurityError("DNS_FAILED", `DNS returned an invalid address for ${hostname}.`);
    }
    if (isUnsafeCollectorAddress(answer.address)) {
      // Reject mixed public/private answer sets too. Picking only the public
      // answer would make behavior dependent on DNS order and invite rebinding.
      throw new CollectorSecurityError("UNSAFE_HOST", `DNS for ${hostname} included a non-public address.`);
    }
  }

  const normalized = addresses.map((answer) => ({
    address: normalizedHostname(answer.address),
    family: answer.family,
  }));
  const selected = normalized[0];
  return { url, ...selected, addresses: normalized };
}

async function requestAddress(
  target: SafeResolvedTarget,
  address: ResolvedAddress,
  init: { signal: AbortSignal; userAgent: string },
): Promise<SafeTransportResponse> {
  const isHttps = target.url.protocol === "https:";
  const request = isHttps ? httpsRequest : httpRequest;
  const originHostname = normalizedHostname(target.url.hostname);

  return new Promise((resolve, reject) => {
    let settled = false;
    const req = request({
      // Connect directly to the vetted address. Host and TLS SNI retain the
      // original hostname, so certificate/virtual-host checks still work while
      // DNS rebinding is impossible between validation and socket creation.
      hostname: address.address,
      port: target.url.port || undefined,
      path: `${target.url.pathname}${target.url.search}`,
      method: "GET",
      headers: {
        Host: target.url.host,
        "User-Agent": init.userAgent,
        Accept: "text/html, application/xml, application/rss+xml, application/atom+xml, text/plain;q=0.9, */*;q=0.1",
        "Accept-Encoding": "gzip, deflate, br",
      },
      signal: init.signal,
      agent: false,
      ...(isHttps && isIP(originHostname) === 0 ? { servername: originHostname } : {}),
    }, (response) => {
      settled = true;
      resolve({
        statusCode: response.statusCode ?? 0,
        statusMessage: response.statusMessage ?? "",
        headers: response.headers,
        body: response,
        cancel: () => response.destroy(),
      });
    });
    req.once("error", (error) => {
      if (!settled) reject(error);
    });
    req.end();
  });
}

async function nodeTransport(
  target: SafeResolvedTarget,
  init: { signal: AbortSignal; userAgent: string },
): Promise<SafeTransportResponse> {
  let lastError: unknown;
  for (const address of target.addresses) {
    if (init.signal.aborted) throw init.signal.reason;
    try {
      return await requestAddress(target, address, init);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error("Unable to connect to the validated destination.");
}

function firstHeader(headers: IncomingHttpHeaders, name: string): string | undefined {
  const value = headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function decodedBody(response: SafeTransportResponse): { body: AsyncIterable<Uint8Array>; cancel: () => void } {
  const encoding = (firstHeader(response.headers, "content-encoding") ?? "identity").trim().toLowerCase();
  if (!encoding || encoding === "identity") return { body: response.body, cancel: response.cancel };
  if (!(response.body instanceof Readable)) {
    response.cancel();
    throw new CollectorSecurityError("UNSUPPORTED_ENCODING", "Cannot decode the response body encoding.");
  }

  const decoder = encoding === "gzip" || encoding === "x-gzip"
    ? createGunzip()
    : encoding === "deflate"
      ? createInflate()
      : encoding === "br"
        ? createBrotliDecompress()
        : null;
  if (!decoder) {
    response.cancel();
    throw new CollectorSecurityError("UNSUPPORTED_ENCODING", "Unsupported response content encoding.");
  }
  response.body.pipe(decoder);
  return {
    body: decoder,
    cancel: () => {
      response.cancel();
      decoder.destroy();
    },
  };
}

function isRedirect(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function withAbort<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      cleanup();
      reject(signal.reason);
    };
    const cleanup = () => signal.removeEventListener("abort", onAbort);
    signal.addEventListener("abort", onAbort, { once: true });
    operation.then(
      (value) => { cleanup(); resolve(value); },
      (error) => { cleanup(); reject(error); },
    );
  });
}

/** Fetch text through the SSRF-safe, redirect-validating transport. */
export async function fetchExternalText(
  rawUrl: string,
  options: FetchOptions = {},
  dependencies: SafeFetchDependencies = {},
): Promise<SafeFetchResult> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT;
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new RangeError("maxBytes must be a positive safe integer.");
  }
  if (!Number.isSafeInteger(maxRedirects) || maxRedirects < 0) {
    throw new RangeError("maxRedirects must be a non-negative safe integer.");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError("timeoutMs must be a positive safe integer.");
  }
  const userAgent = safeUserAgent(options.userAgent ?? DEFAULT_UA);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(
    new CollectorSecurityError("TIMEOUT", `Collector request exceeded its ${timeoutMs}ms deadline.`),
  ), timeoutMs);
  const resolver = dependencies.resolve ?? defaultResolver;
  const transport = dependencies.request ?? nodeTransport;
  let current = rawUrl;
  let redirects = 0;

  try {
    while (true) {
      const target = await withAbort(resolveSafeCollectorTarget(current, resolver), controller.signal);
      const response = await withAbort(
        Promise.resolve().then(() => transport(target, {
          signal: controller.signal,
          userAgent,
        })),
        controller.signal,
      );

      if (isRedirect(response.statusCode)) {
        const location = firstHeader(response.headers, "location");
        response.cancel();
        if (!location) {
          throw new CollectorSecurityError("UNSAFE_REDIRECT", `HTTP ${response.statusCode} response omitted Location.`);
        }
        if (redirects >= maxRedirects) {
          throw new CollectorSecurityError("TOO_MANY_REDIRECTS", `Collector stopped after ${maxRedirects} redirects.`);
        }
        try {
          current = new URL(location, target.url).href;
        } catch (cause) {
          throw new CollectorSecurityError("UNSAFE_REDIRECT", "Collector received an invalid redirect target.", { cause });
        }
        redirects++;
        continue;
      }

      if (response.statusCode < 200 || response.statusCode >= 300) {
        response.cancel();
        // statusMessage is controlled by the remote server; do not reflect it
        // into an agent-visible error without the content trust boundary.
        throw new Error(`HTTP ${response.statusCode}`);
      }

      const decoded = decodedBody(response);
      const chunks: Uint8Array[] = [];
      let totalBytes = 0;
      const iterator = decoded.body[Symbol.asyncIterator]();
      try {
        while (true) {
          const next = await withAbort(Promise.resolve(iterator.next()), controller.signal);
          if (next.done) break;
          const chunk = next.value;
          const value = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
          totalBytes += value.byteLength;
          if (totalBytes > maxBytes) {
            throw new CollectorSecurityError("RESPONSE_TOO_LARGE", `Collector response exceeded ${maxBytes} bytes.`);
          }
          chunks.push(value);
        }
      } catch (error) {
        decoded.cancel();
        throw error;
      }

      const text = new TextDecoder("utf-8", { fatal: false }).decode(Buffer.concat(chunks));
      return { text, rawBytes: totalBytes, finalUrl: target.url.href, redirects };
    }
  } finally {
    clearTimeout(timer);
  }
}
