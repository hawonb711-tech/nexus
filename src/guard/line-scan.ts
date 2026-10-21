/**
 * Linear-time forms of the `HEAD[^\n]*TAIL` rule shape.
 *
 * Tried as written, `/HEAD[^\n]*TAIL/` starts a match at every HEAD, and each
 * attempt re-scans the rest of the line for TAIL before failing, so a line that
 * repeats HEAD k times costs O(k·n): 50 KB of `eval eval …` took ~1.7 s in
 * inspectCommand, and 200 KB tens of seconds, which is past the hook timeout.
 *
 * Only the head that ENDS first on a line can matter. TAIL may start anywhere
 * after a head on the line its match ends on, so whatever a head ending later on
 * that line reaches, the earlier one reaches too. (Keyed on the end, not the
 * start: a head with `\s+` in it — `openssl\ns_client` — can start on one line
 * and end on the next.) The builders here keep the rule a RegExp but let it
 * continue past a head only there, and make every intermediate `[^\n]*` stop at
 * the next part's first occurrence for the same reason, so each line is walked a
 * bounded number of times. The last gap stays greedy, so `exec()` returns the
 * same match, index and captures as the plain form.
 */

const group = (r: RegExp): string => `(?:${r.source})`;

/**
 * Source for `head`, matching only where it is the first `head` to end in its run
 * of characters not in `stop` (a character-class body; the default run is a
 * line). The look-behind runs only after a `head` has matched and walks back only
 * as far as the previous `head`'s end, so the whole scan stays linear.
 */
export function firstInRun(head: RegExp, stop = "\\n"): string {
  const h = group(head);
  return `${h}(?<=(?:^|[${stop}])(?:(?<!${h})[^${stop}])*)`;
}

/**
 * Source for `parts[0] G* parts[1] G* … parts[n-1]`, where G is any character
 * not in `stop`, in linear time. It matches the same text as the plain form as
 * long as no middle part (not the first, not the last) can match a `stop`
 * character, so that its first occurrence is also the first to end.
 */
export function runSeq(stop: string, ...parts: RegExp[]): string {
  const [head, ...rest] = parts;
  return firstInRun(head, stop) + rest.map((p, i) => {
    const s = group(p);
    return (i < rest.length - 1 ? `(?:(?!${s})[^${stop}])*` : `[^${stop}]*`) + s;
  }).join("");
}

/** `runSeq` over lines: `parts[0][^\n]*parts[1][^\n]*…`. */
export function lineSeq(...parts: RegExp[]): string {
  return runSeq("\\n", ...parts);
}

/** One RegExp of `flags` alternating the given sources (builder output or regex literals). */
export function oneOf(flags: string, ...alts: (RegExp | string)[]): RegExp {
  return new RegExp(alts.map((a) => (typeof a === "string" ? a : a.source)).join("|"), flags);
}
