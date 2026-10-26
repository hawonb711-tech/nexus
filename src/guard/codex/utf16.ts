/**
 * Text cut by UTF-16 code unit without splitting a character, and hook answers
 * made well-formed.
 *
 * JavaScript strings count UTF-16 code units, so a cut at a fixed length can
 * land between the two halves of a surrogate pair (an emoji, say).
 * JSON.stringify writes the half left behind as a `\udXXX` escape and Claude
 * Code reads it back without complaint, but Codex reads a hook's answer with
 * serde_json, which rejects a string holding an unpaired surrogate: the whole
 * answer is then ignored and the call runs as if Nexus had said nothing (a
 * deny lost, a masked secret shown raw). So the display cuts use `headUnits`
 * and `tailFrom`, which never split a pair, and every Codex answer goes
 * through `wellFormedAnswer` last, for text cut anywhere else.
 *
 * Imports nothing: the command guard's hot path uses it.
 */

const isHigh = (c: number) => c >= 0xd800 && c <= 0xdbff;
const isLow = (c: number) => c >= 0xdc00 && c <= 0xdfff;

/** `text`'s first `n` code units, one fewer when the last of them would be the first half of a surrogate pair. */
export function headUnits(text: string, n: number): string {
  if (text.length <= n) return text;
  if (n <= 0) return "";
  return text.slice(0, isHigh(text.charCodeAt(n - 1)) ? n - 1 : n);
}

/** `text` from code unit `from` on, one later when that unit would be the second half of a surrogate pair. */
export function tailFrom(text: string, from: number): string {
  if (from <= 0) return text;
  return text.slice(from < text.length && isLow(text.charCodeAt(from)) ? from + 1 : from);
}

/** A high surrogate no low one follows, or a low surrogate no high one precedes (code units: no `u` flag). */
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;

/** Does `text` hold an unpaired surrogate, which serde_json (Codex's JSON reader) refuses? (String.prototype.isWellFormed, ES2024, negated.) */
export function hasLoneSurrogate(text: string): boolean {
  return ONE_LONE_SURROGATE.test(text);
}
const ONE_LONE_SURROGATE = new RegExp(LONE_SURROGATE.source);

/** `text` with each unpaired surrogate as U+FFFD, as String.prototype.toWellFormed (ES2024) gives it. */
export function wellFormed(text: string): string {
  return text.replace(LONE_SURROGATE, "�");
}

/** A hook answer (JSON data) with every string in it `wellFormed`: one Codex's parser can read. */
export function wellFormedAnswer<T>(value: T): T {
  if (typeof value === "string") return wellFormed(value) as T;
  if (Array.isArray(value)) return value.map((v: unknown) => wellFormedAnswer(v)) as T;
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [wellFormed(k), wellFormedAnswer(v)])) as T;
  }
  return value;
}
