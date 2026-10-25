/**
 * Codex's apply_patch format: which files a patch adds, updates, moves and
 * deletes, and what it puts in them.
 *
 *     *** Begin Patch
 *     *** Add File: <path>          then `+<line>` lines
 *     *** Delete File: <path>
 *     *** Update File: <path>       then an optional `*** Move to: <path>`, and
 *                                   chunks: `@@` / `@@ <context line>`, then
 *                                   ` ` (context), `+` (added), `-` (removed)
 *                                   lines, an optional `*** End of File`
 *     *** End Patch
 *
 * Paths are relative to the session's cwd (or absolute). The rules follow
 * Codex 0.164.0's own parser (codex-rs/apply-patch/src/streaming_parser.rs,
 * in lenient mode) line for line, with one deliberate difference: where Codex
 * rejects the whole patch (a line it cannot place, text after
 * `*** End Patch`, a missing `*** Begin Patch` on the first line), this
 * parser skips that line and keeps reading. A patch Codex refuses writes
 * nothing, so the extra files this may find only make the guard stricter;
 * reading less than Codex would let a write through unseen.
 *
 * This runs on the hook's hot path (the apply_patch tool, and a patch fed to
 * `apply_patch` in a shell command), so it is one forward pass over the text
 * with a hard size limit: past MAX_PATCH_CHARS, or past MAX_PATCH_FILES file
 * headers, the result says `overflow` and the caller treats the patch as one
 * it could not check.
 */

const BEGIN_PATCH = "*** Begin Patch";
const END_PATCH = "*** End Patch";
const ADD_FILE = "*** Add File: ";
const DELETE_FILE = "*** Delete File: ";
const UPDATE_FILE = "*** Update File: ";
const MOVE_TO = "*** Move to: ";
const END_OF_FILE = "*** End of File";
const CONTEXT = "@@ ";
const EMPTY_CONTEXT = "@@";

/** Characters of patch text read at most (a larger patch is `overflow`). */
export const MAX_PATCH_CHARS = 16 * 1024 * 1024;
/** File operations read at most (more is `overflow`). */
export const MAX_PATCH_FILES = 256;

/** One `@@` chunk of an Update, as Codex's UpdateFileChunk. */
export type PatchChunk = {
  /** The `@@ <line>` the chunk's old lines come after, or null for a bare `@@`. */
  context: string | null;
  /** The lines the chunk replaces: its context and `-` lines, in order. */
  old: string[];
  /** Their replacement: its context and `+` lines, in order. */
  new: string[];
  /** Where each context line sits in `old` and in `new`: Codex keeps the file's own line there. */
  contextAt: [old: number, new: number][];
  /** `*** End of File`: `old` must end the file. */
  eof: boolean;
};

export type PatchOp =
  | { op: "add"; path: string; contents: string }
  | { op: "delete"; path: string }
  | { op: "update"; path: string; moveTo: string | null; chunks: PatchChunk[] };

export type ParsedPatch = {
  /** The file operations, in patch order. */
  ops: PatchOp[];
  /** The text was longer than MAX_PATCH_CHARS or named more than MAX_PATCH_FILES files: `ops` holds only what came first. */
  overflow: boolean;
};

type Mode = "out" | "between" | "add" | "update";

/**
 * Rust's `char::is_whitespace` (Unicode White_Space), which Codex's `trim`
 * uses. JavaScript's `trim` differs: it also drops U+FEFF and keeps U+0085,
 * so `*** Add File: .envrc\u0085` would name another file than the one Codex
 * writes.
 */
export function isRustWhitespace(c: number): boolean {
  return (c >= 0x09 && c <= 0x0d) || c === 0x20 || c === 0x85 || c === 0xa0 || c === 0x1680 ||
    (c >= 0x2000 && c <= 0x200a) || c === 0x2028 || c === 0x2029 || c === 0x202f || c === 0x205f || c === 0x3000;
}

/** `s` without trailing White_Space, as Rust's `trim_end`. */
export function rustTrimEnd(s: string): string {
  let end = s.length;
  while (end > 0 && isRustWhitespace(s.charCodeAt(end - 1))) end--;
  return end === s.length ? s : s.slice(0, end);
}

/** `s` without leading or trailing White_Space, as Rust's `trim`. */
export function rustTrim(s: string): string {
  let start = 0;
  while (start < s.length && isRustWhitespace(s.charCodeAt(start))) start++;
  return rustTrimEnd(start === 0 ? s : s.slice(start));
}

/**
 * The file operations in `text` (see the header). Never throws; text with no
 * `*** Begin Patch` line has no operations.
 */
export function parsePatch(text: string): ParsedPatch {
  const ops: PatchOp[] = [];
  let overflow = text.length > MAX_PATCH_CHARS;
  const src = overflow ? text.slice(0, MAX_PATCH_CHARS) : text;
  let mode = "out" as Mode; // widened: header() moves it
  let full = false;
  let add: string[] = [];
  let update: Extract<PatchOp, { op: "update" }> | null = null;
  const closeAdd = () => {
    const last = ops[ops.length - 1];
    if (mode === "add" && last?.op === "add") last.contents = add.join("");
    add = [];
  };
  /** A file header or `*** End Patch` on `head` (as Codex trims it in this mode); true when it was one. */
  const header = (head: string): boolean => {
    let op: PatchOp | null = null;
    if (head === END_PATCH) {
      closeAdd();
      mode = "between";
      update = null;
      return true;
    }
    if (head.startsWith(ADD_FILE)) op = { op: "add", path: head.slice(ADD_FILE.length), contents: "" };
    else if (head.startsWith(DELETE_FILE)) op = { op: "delete", path: head.slice(DELETE_FILE.length) };
    else if (head.startsWith(UPDATE_FILE)) op = { op: "update", path: head.slice(UPDATE_FILE.length), moveTo: null, chunks: [] };
    if (!op) return false;
    closeAdd();
    if (ops.length >= MAX_PATCH_FILES) {
      overflow = full = true;
      return true;
    }
    ops.push(op);
    mode = op.op === "add" ? "add" : op.op === "update" ? "update" : "between";
    update = op.op === "update" ? op : null;
    return true;
  };

  // Codex trims the whole patch first, and its parser reads the last line
  // (`finish`) fully trimmed: there an indented `*** End Patch` still ends an Update.
  const lastLine = lastLineStart(src);
  for (let at = 0; at < src.length && !full; ) {
    const start = at;
    const nl = src.indexOf("\n", at);
    const end = nl < 0 ? src.length : nl;
    // Codex reads the patch with `.lines()` (no empty last line after a final
    // newline, a trailing \r dropped) and its streaming parser drops one more \r.
    let line = src.slice(at, end);
    for (let k = 0; k < 2 && line.endsWith("\r"); k++) line = line.slice(0, -1);
    at = end + 1;
    if (mode === "out") {
      if (rustTrim(line) === BEGIN_PATCH) mode = "between";
      continue;
    }
    if (mode !== "update") {
      if (header(rustTrim(line))) continue;
      if (mode === "add" && line.startsWith("+")) add.push(line.slice(1), "\n");
      continue; // Codex: not a valid hunk header (or an `*** Environment ID:` line)
    }
    // An Update: headers are matched with only trailing blanks dropped, so an
    // indented `*** Add File:` is a context line, as Codex reads it.
    const u = update!;
    const head = start === lastLine && rustTrim(line) === END_PATCH ? END_PATCH : rustTrimEnd(line);
    if (header(head)) continue;
    const chunks = u.chunks;
    const last = chunks[chunks.length - 1];
    if (last?.eof && head === "") continue;
    if (chunks.length === 0 && u.moveTo === null && head.startsWith(MOVE_TO)) {
      u.moveTo = head.slice(MOVE_TO.length);
      continue;
    }
    if (head === EMPTY_CONTEXT || head.startsWith(CONTEXT)) {
      chunks.push({ context: head === EMPTY_CONTEXT ? null : head.slice(CONTEXT.length), old: [], new: [], contextAt: [], eof: false });
      continue;
    }
    if (head === END_OF_FILE) {
      if (last) last.eof = true;
      continue;
    }
    const marker = line[0];
    if (line !== "" && marker !== " " && marker !== "+" && marker !== "-") continue; // Codex: an unexpected line
    let chunk = last;
    if (!chunk) chunks.push((chunk = { context: null, old: [], new: [], contextAt: [], eof: false }));
    const body = line.slice(1);
    if (line === "" || marker === " ") {
      chunk.contextAt.push([chunk.old.length, chunk.new.length]);
      chunk.old.push(body);
      chunk.new.push(body);
    } else if (marker === "+") chunk.new.push(body);
    else chunk.old.push(body);
  }
  closeAdd();
  return { ops, overflow };
}

/** Where the last line holding anything but White_Space starts (the last line of the patch once Codex trims it), or -1. */
function lastLineStart(src: string): number {
  let end = src.length;
  while (end > 0 && isRustWhitespace(src.charCodeAt(end - 1))) end--;
  return end === 0 ? -1 : src.lastIndexOf("\n", end - 1) + 1;
}

/**
 * The text an operation adds, as the static file-write guard screens it: an
 * Add's contents; an Update's `+` lines (context lines are already in the
 * file), one per line; nothing for a Delete.
 */
export function addedText(op: PatchOp): string {
  if (op.op === "add") return op.contents;
  if (op.op === "delete") return "";
  const out: string[] = [];
  for (const c of op.chunks) {
    let k = 0;
    for (let i = 0; i < c.new.length; i++) {
      if (k < c.contextAt.length && c.contextAt[k][1] === i) {
        k++;
        continue;
      }
      out.push(c.new[i]);
    }
  }
  return out.join("\n");
}

/** Every path an operation writes or removes: its own, and a Move's destination. */
export function opPaths(op: PatchOp): string[] {
  return op.op === "update" && op.moveTo !== null ? [op.path, op.moveTo] : [op.path];
}
