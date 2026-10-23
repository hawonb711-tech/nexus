/**
 * Instruction-file integrity — the little Markdown structure the `@path` import
 * parser and the actionable-token extractor need: which lines sit inside a
 * fenced code block, and where a line's inline code spans are. Not a Markdown
 * parser; one linear pass, no regex.
 */

/** A line's place in the document: prose, a fence's own marker line, or code inside a fence. */
export type MdLineKind = "text" | "fence" | "code";

/** An inline code span on one line: `[start, end)` covers the backticks too; `ticks` is their run length. */
export type CodeSpan = { start: number; end: number; ticks: number };

/** A fence opener or closer: up to 3 spaces, then 3+ backticks or tildes. Returns the run, or null. */
function fenceRun(line: string): { ch: number; len: number; rest: string } | null {
  let i = 0;
  while (i < 3 && line.charCodeAt(i) === 32) i++;
  const ch = line.charCodeAt(i);
  if (ch !== 96 && ch !== 126) return null; // ` or ~
  let j = i;
  while (j < line.length && line.charCodeAt(j) === ch) j++;
  return j - i >= 3 ? { ch, len: j - i, rest: line.slice(j) } : null;
}

/**
 * Visit every line of `text` (split on `\n`, a trailing `\r` kept) with its kind.
 * A fence opened by ``` or ~~~ closes at the next line with a run of the same
 * character at least as long and nothing else on it; an unclosed fence runs to
 * the end, as in CommonMark.
 */
export function forEachMarkdownLine(text: string, visit: (line: string, kind: MdLineKind, index: number) => void): void {
  let open: { ch: number; len: number } | null = null;
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const run = fenceRun(line);
    if (open) {
      if (run && run.ch === open.ch && run.len >= open.len && run.rest.trim() === "") {
        open = null;
        visit(line, "fence", i);
      } else {
        visit(line, "code", i);
      }
    } else if (run && !(run.ch === 96 && run.rest.includes("`"))) {
      // A backtick fence's info string may not contain a backtick (CommonMark);
      // such a line is an inline code span instead.
      open = { ch: run.ch, len: run.len };
      visit(line, "fence", i);
    } else {
      visit(line, "text", i);
    }
  }
}

/**
 * The inline code spans of one line: a run of N backticks opens a span that the
 * next run of exactly N backticks closes; a run with no partner is literal.
 * Linear: each run length keeps a forward-only cursor over its runs.
 */
export function codeSpans(line: string): CodeSpan[] {
  const starts: number[] = [];
  const lens: number[] = [];
  for (let i = 0; i < line.length;) {
    if (line.charCodeAt(i) !== 96) { i++; continue; }
    let j = i;
    while (j < line.length && line.charCodeAt(j) === 96) j++;
    starts.push(i);
    lens.push(j - i);
    i = j;
  }
  if (starts.length < 2) return [];
  const byLen = new Map<number, number[]>();
  lens.forEach((len, r) => {
    const list = byLen.get(len);
    if (list) list.push(r);
    else byLen.set(len, [r]);
  });
  const cursor = new Map<number, number>();
  const spans: CodeSpan[] = [];
  for (let r = 0; r < starts.length;) {
    const len = lens[r];
    const list = byLen.get(len)!;
    let p = cursor.get(len) ?? 0;
    while (p < list.length && list[p] <= r) p++;
    cursor.set(len, p);
    if (p === list.length) { r++; continue; }
    const close = list[p];
    spans.push({ start: starts[r], end: starts[close] + len, ticks: len });
    r = close + 1;
  }
  return spans;
}

/** `line` with every inline code span (backticks included) blanked to spaces. */
export function maskCodeSpans(line: string, spans: readonly CodeSpan[] = codeSpans(line)): string {
  if (spans.length === 0) return line;
  let out = "";
  let at = 0;
  for (const s of spans) {
    out += line.slice(at, s.start) + " ".repeat(s.end - s.start);
    at = s.end;
  }
  return out + line.slice(at);
}

/** The text inside a span, without its backticks or the one space CommonMark strips at each end. */
export function spanText(line: string, span: CodeSpan): string {
  return line.slice(span.start + span.ticks, span.end - span.ticks).trim();
}
