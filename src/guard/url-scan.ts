/**
 * Linear-time "does a URL carry X" checks.
 *
 * The obvious single regex — `https?:\/\/[^\s…]*(?:X)` — re-scans the rest of a
 * long whitespace-free run from every `http://` inside it before failing, so it
 * is quadratic on attacker-controlled content (CodeQL js/polynomial-redos; a
 * page of `http://` repeated stalled the content guard for seconds per 100 KB).
 * Here each URL token is visited once and `marker` is searched only inside it,
 * which keeps exactly the same matches.
 */

/**
 * True when, for some URL token matched by `token` (a global `https?:\/\/` +
 * character-class-run regex), `marker` matches starting inside the token's body
 * — at least `minBody` characters after the `//`. `overrun` lets a marker that
 * contains a character the class stops at (e.g. a space) run that many
 * characters past the token's end. `marker` must not be global.
 */
export function urlTokenCarries(
  text: string,
  token: RegExp,
  marker: RegExp,
  opts: { minBody?: number; overrun?: number } = {},
): boolean {
  const { minBody = 0, overrun = 0 } = opts;
  for (const m of text.matchAll(token)) {
    const start = m.index ?? 0;
    const end = start + m[0].length;
    const from = start + m[0].indexOf("//") + 2 + minBody;
    if (from >= end) continue;
    const hit = marker.exec(text.slice(from, end + overrun));
    if (hit && from + hit.index < end) return true;
  }
  return false;
}
