/**
 * The text an apply_patch operation leaves in a file, worked out before the
 * patch lands so the integrity layer can diff it (pre-tool.ts) and predict the
 * file's sha256, as `simulateWrite` does for Claude Code's file tools.
 *
 * Codex 0.164.0's rules (codex-rs/apply-patch/src/file_update.rs,
 * seek_sequence.rs, text_file.rs), mirrored:
 *
 * - An Add writes its contents as they are (over any existing file).
 * - An Update reads the file as lines, each keeping its own ending (\r\n, a
 *   lone \r or \n); the first ending found is the one inserted lines get (\n
 *   when there is none). Chunk by chunk, from where the last one matched: a
 *   chunk's `@@` context line is looked for first, then its old lines; a chunk
 *   with no old lines is appended at the end of the file. A match is tried
 *   exactly, then ignoring trailing blanks, then ignoring blanks at both ends,
 *   then with typographic dashes, quotes and spaces read as ASCII; an
 *   `*** End of File` chunk is looked for at the end only. Old lines ending in
 *   an empty one that do not match are tried again without it. Context lines
 *   keep the file's own text. Every line of the result ends with a line break.
 *
 * Where Codex would refuse the patch (a context or old line not found, no
 * file to update, overlapping chunks), the simulation cannot be exact: that
 * chunk's added lines are appended to the end instead and `approx` is set,
 * so the lines still diff as added (like `simulateWrite`'s appended
 * new_string). The work is bounded: line comparisons are charged, by length,
 * against MAX_PATCH_WORK, and once it is spent every chunk not yet placed is
 * appended the same way.
 */

import { rustTrim, rustTrimEnd, type PatchChunk, type PatchOp } from "./patch.js";

/** What an operation leaves; `approx`: some chunk could not be placed as Codex would. */
export type SimulatedPatch = { text: string; approx: boolean };

/** Characters compared (and lines normalised) at most per simulated operation. */
export const MAX_PATCH_WORK = 32 * 1024 * 1024;

const OVER = new Error("apply_patch simulation over budget");

/** The text `op` leaves in a file whose current text is `current` (null: absent or unreadable); null for a Delete. */
export function simulatePatchOp(op: PatchOp, current: string | null): SimulatedPatch | null {
  if (op.op === "add") return { text: op.contents, approx: false };
  if (op.op === "delete") return null;
  return applyChunks(current, op.chunks);
}

type Line = { text: string; ending: string };

/** Codex's SourceFile.parse: lines with their own endings; a final line without one keeps "". */
function parseLines(text: string): { lines: Line[]; preferred: string } {
  const lines: Line[] = [];
  let preferred: string | null = null;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c !== 0x0a && c !== 0x0d) continue;
    const ending = c === 0x0d && text.charCodeAt(i + 1) === 0x0a ? "\r\n" : c === 0x0d ? "\r" : "\n";
    preferred ??= ending;
    lines.push({ text: text.slice(start, i), ending });
    i += ending.length - 1;
    start = i + 1;
  }
  if (start < text.length) lines.push({ text: text.slice(start), ending: "" });
  return { lines, preferred: preferred ?? "\n" };
}

/** seek_sequence's last pass: blanks trimmed, typographic dashes, quotes and spaces read as ASCII. */
function normalise(s: string): string {
  let out = "";
  const t = rustTrim(s);
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if ((c >= 0x2010 && c <= 0x2015) || c === 0x2212) out += "-";
    else if (c >= 0x2018 && c <= 0x201b) out += "'";
    else if (c >= 0x201c && c <= 0x201f) out += '"';
    else if (c === 0xa0 || (c >= 0x2002 && c <= 0x200a) || c === 0x202f || c === 0x205f || c === 0x3000) out += " ";
    else out += t[i];
  }
  return out;
}

type Work = { left: number };
const spend = (w: Work, n: number) => {
  if ((w.left -= n) < 0) throw OVER;
};

/** The four comparisons seek_sequence tries, in order; each line's form is made once, when first needed, and charged. */
const FORMS: ((s: string) => string)[] = [(s) => s, rustTrimEnd, rustTrim, normalise];

class Seeker {
  private readonly views: (string[] | undefined)[] = [];
  constructor(private readonly lines: readonly string[], private readonly work: Work) {}

  private view(form: number): string[] {
    let v = this.views[form];
    if (!v) {
      if (form === 0) v = this.lines as string[];
      else {
        spend(this.work, this.lines.reduce((n, l) => n + l.length + 1, 0));
        v = this.lines.map(FORMS[form]);
      }
      this.views[form] = v;
    }
    return v;
  }

  /** Where `pattern` starts at or after `start` (at the end only, for `eof`), or null. */
  seek(pattern: readonly string[], start: number, eof: boolean): number | null {
    const n = this.lines.length;
    if (pattern.length === 0) return start;
    if (pattern.length > n) return null;
    const from = eof ? Math.max(n - pattern.length, start) : start;
    for (let form = 0; form < FORMS.length; form++) {
      const lines = this.view(form);
      const pat = form === 0 ? pattern : pattern.map(FORMS[form]);
      if (form > 0) spend(this.work, pattern.reduce((k, l) => k + l.length + 1, 0));
      for (let i = from; i + pat.length <= n; i++) {
        let j = 0;
        for (; j < pat.length; j++) {
          spend(this.work, pat[j].length + 1);
          if (lines[i + j] !== pat[j]) break;
        }
        if (j === pat.length) return i;
      }
    }
    return null;
  }
}

/** A replacement: from line `at`, `remove` lines give way to `insert`. */
type Replacement = { at: number; remove: number; insert: readonly string[] };

/** A chunk's `+` lines (not its context lines), in order. */
function addedLines(chunk: PatchChunk): string[] {
  const context = new Set(chunk.contextAt.map(([, n]) => n));
  return chunk.new.filter((_, i) => !context.has(i));
}

function applyChunks(current: string | null, chunks: readonly PatchChunk[]): SimulatedPatch {
  const { lines, preferred } = parseLines(current ?? "");
  const work: Work = { left: MAX_PATCH_WORK };
  const seeker = new Seeker(lines.map((l) => l.text), work);
  const replacements: Replacement[] = [];
  const appended: string[] = [];
  let approx = current === null; // Codex cannot update a file it cannot read
  let index = 0;
  for (let c = 0; c < chunks.length; c++) {
    const chunk = chunks[c];
    if (current === null) {
      appended.push(...addedLines(chunk));
      continue;
    }
    try {
      const placed = place(chunk, seeker, lines.length, index);
      if (!placed) {
        approx = true;
        appended.push(...addedLines(chunk));
        continue;
      }
      replacements.push(...placed.replacements);
      index = placed.next;
    } catch (error) {
      if (error !== OVER) throw error;
      approx = true;
      for (const rest of chunks.slice(c)) appended.push(...addedLines(rest));
      break;
    }
  }
  // A stable sort, as Rust's sort_by_key; overlapping replacements are a patch Codex cannot apply as written.
  replacements.sort((a, b) => a.at - b.at);
  const out: Line[] = [];
  let source = 0;
  for (const r of replacements) {
    if (r.at < source) {
      approx = true;
      continue;
    }
    for (; source < r.at; source++) out.push(lines[source]);
    source += r.remove;
    for (const text of r.insert) out.push({ text, ending: preferred });
  }
  for (; source < lines.length; source++) out.push(lines[source]);
  for (const text of appended) out.push({ text, ending: preferred });
  // Updates always end every line, the last one included (text_file.rs).
  return { text: out.map((l) => l.text + (l.ending || preferred)).join(""), approx };
}

/** compute_replacements for one chunk: its replacements and where the next chunk starts looking, or null when it does not match. */
function place(chunk: PatchChunk, seeker: Seeker, lineCount: number, start: number): { replacements: Replacement[]; next: number } | null {
  let index = start;
  if (chunk.context !== null) {
    const at = seeker.seek([chunk.context], index, false);
    if (at === null) return null;
    index = at + 1;
  }
  if (chunk.old.length === 0) return { replacements: [{ at: lineCount, remove: 0, insert: chunk.new }], next: index };
  let pattern: readonly string[] = chunk.old;
  let insert: readonly string[] = chunk.new;
  let found = seeker.seek(pattern, index, chunk.eof);
  if (found === null && pattern[pattern.length - 1] === "") {
    // the empty last line stands for the final line break, which is not a line of its own
    pattern = pattern.slice(0, -1);
    if (insert[insert.length - 1] === "") insert = insert.slice(0, -1);
    found = seeker.seek(pattern, index, chunk.eof);
  }
  if (found === null) return null;
  const replacements: Replacement[] = [];
  let oldStart = 0;
  let newStart = 0;
  for (const [oldAt, newAt] of chunk.contextAt) {
    if (oldAt >= pattern.length || newAt >= insert.length) break;
    if (oldStart !== oldAt || newStart !== newAt) {
      replacements.push({ at: found + oldStart, remove: oldAt - oldStart, insert: insert.slice(newStart, newAt) });
    }
    oldStart = oldAt + 1;
    newStart = newAt + 1;
  }
  if (oldStart !== pattern.length || newStart !== insert.length) {
    replacements.push({ at: found + oldStart, remove: pattern.length - oldStart, insert: insert.slice(newStart) });
  }
  return { replacements, next: found + pattern.length };
}
