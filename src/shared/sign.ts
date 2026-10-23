/**
 * Keyed signing primitives shared by the memory engine's integrity markers and
 * the instruction-file integrity store. Pure `node:crypto`; no state.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

/** Prefix of every derived subkey label, so a subkey for one purpose can never
 *  equal one derived for another purpose or by another scheme version. */
const SUBKEY_PREFIX = "nexus/integrity/v1/";

const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

/**
 * Deterministic JSON for signing: object keys sorted (by UTF-16 code unit, at
 * every depth), no whitespace, array order kept. Values follow `JSON.stringify`
 * — `toJSON` is honoured, `undefined`/functions/symbols are dropped from objects
 * and become `null` in arrays — so a document that round-trips through
 * `JSON.parse` serializes to the same text it was signed as.
 */
export function canonicalJson(value: unknown): string {
  if (value !== null && typeof value === "object" && typeof (value as { toJSON?: unknown }).toJSON === "function") {
    return canonicalJson((value as { toJSON(): unknown }).toJSON());
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => (isOmitted(v) ? "null" : canonicalJson(v))).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const parts: string[] = [];
    for (const key of Object.keys(record).sort()) {
      if (!isOmitted(record[key])) parts.push(`${JSON.stringify(key)}:${canonicalJson(record[key])}`);
    }
    return `{${parts.join(",")}}`;
  }
  return isOmitted(value) ? "null" : JSON.stringify(value);
}

function isOmitted(v: unknown): boolean {
  return v === undefined || typeof v === "function" || typeof v === "symbol";
}

/** Lowercase hex HMAC-SHA256 of `text` under `key`. */
export function hmacHex(key: Buffer, text: string): string {
  return createHmac("sha256", key).update(text).digest("hex");
}

/** A purpose-bound subkey: HMAC-SHA256(key, "nexus/integrity/v1/" + label). */
export function subkey(key: Buffer, label: string): Buffer {
  return createHmac("sha256", key).update(SUBKEY_PREFIX + label).digest();
}

/**
 * Constant-time equality for MACs and markers. Compares the strings' own bytes
 * rather than decoding them as hex, so malformed hex can never collapse to an
 * equal (e.g. empty) buffer. A length mismatch is simply unequal. MACs are
 * printable ASCII; anything else is unequal, because UTF-8 encoding maps every
 * lone surrogate to U+FFFD and two different strings could otherwise match.
 */
export function timingSafeEqualHex(a: string, b: string): boolean {
  if (!PRINTABLE_ASCII.test(a) || !PRINTABLE_ASCII.test(b)) return false;
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  return left.length === right.length && timingSafeEqual(left, right);
}
