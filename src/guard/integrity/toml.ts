/**
 * Instruction-file integrity — a small, tolerant reader of TOML, enough to cut
 * Codex CLI's config files (config.toml, its profiles, a project's
 * `.codex/config.toml`, the managed requirements) into one unit per key
 * (units.ts) and to read the few keys enumeration needs (where the project
 * root is, which other instruction files Codex reads, the scripts its hooks
 * run).
 *
 * It is not a validating parser. One forward pass tracks table headers
 * (`[a.b]`, `[[a.b]]`) and `key = value` pairs, with dotted and quoted keys,
 * strings of all four kinds (decoded), arrays and inline tables (an inline
 * table's keys become keys of their own; inside an array it stays a value),
 * across as many lines as they span. Anything it cannot read is a line of its
 * own (`unparsed`; every line of a statement that failed on a later line), and
 * reading goes on at the next line: Codex refuses a file it cannot parse, but
 * a fingerprint still has to notice the line changed.
 *
 * Linear in the text: every character is passed once (a multi-line string or
 * array is scanned, never searched again from each position), nesting stops at
 * MAX_DEPTH, and nothing recurses past it. A key's whole path (its table's and
 * its own) is at most MAX_KEY_SEGMENTS segments and MAX_KEY_CHARS characters,
 * since every key under a table repeats the table's path: a longer one is
 * unparsed. Pure; never throws.
 */

/** A value as read: strings decoded, numbers and dates as written. */
export type TomlValue =
  | { t: "str"; v: string }
  | { t: "bool"; v: boolean }
  /** A number, date or other bare value, as written. */
  | { t: "raw"; v: string }
  | { t: "arr"; v: TomlValue[] }
  /** An inline table inside an array (one at a key's place is read as that key's own keys); a nested one stays nested. */
  | { t: "tbl"; v: [string[], TomlValue][] };

/** One key: its table's path and its own (dotted) path, decoded, and its value. */
export type TomlEntry = { path: string[]; value: TomlValue; line: number };

/**
 * A line the reader could not read (each line of a statement that spans
 * several): `text` its first MAX_UNPARSED_CHARS characters, and `whole` the
 * line when that cut it, so a change past the cut is still a change.
 */
export type TomlUnparsed = { line: number; text: string; whole?: string };

export type TomlDoc = { entries: TomlEntry[]; unparsed: TomlUnparsed[] };

/** Arrays and inline tables nested deeper than this are not read (the statement is unparsed). */
const MAX_DEPTH = 32;
/** Characters of an unparsed line shown. */
const MAX_UNPARSED_CHARS = 512;
/** A key's whole path past this many segments, or characters in all, is not read (the statement is unparsed). */
const MAX_KEY_SEGMENTS = 32;
const MAX_KEY_CHARS = 1024;

const BARE_KEY = /^[A-Za-z0-9_-]+$/;

/** A path as TOML spells it: bare segments as they are, the rest quoted. */
export function tomlPath(path: readonly string[]): string {
  return path.map((k) => (BARE_KEY.test(k) ? k : JSON.stringify(k))).join(".");
}

/** A value in one canonical spelling (strings JSON-quoted, which TOML reads back), so formatting alone never changes a unit. */
export function tomlValueText(value: TomlValue): string {
  switch (value.t) {
    case "str":
      return JSON.stringify(value.v);
    case "bool":
      return value.v ? "true" : "false";
    case "raw":
      return value.v;
    case "arr":
      return `[${value.v.map(tomlValueText).join(", ")}]`;
    case "tbl":
      return `{${value.v.map(([p, v]) => `${tomlPath(p)} = ${tomlValueText(v)}`).join(", ")}}`;
  }
}

/** The strings of an array value (non-strings skipped), or null when it is not an array. */
export function tomlStrings(value: TomlValue | undefined): string[] | null {
  if (!value || value.t !== "arr") return null;
  return value.v.filter((v): v is { t: "str"; v: string } => v.t === "str").map((v) => v.v);
}

/** Read `text` (see the module comment). */
export function readToml(text: string): TomlDoc {
  return new Reader(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text).read();
}

// Character codes the reader compares with.
const TAB = 9, NL = 10, CR = 13, SPACE = 32, QUOTE = 34, HASH = 35, APOS = 39, COMMA = 44, DOT = 46;
const EQ = 61, LBRACKET = 91, BACKSLASH = 92, RBRACKET = 93, LBRACE = 123, RBRACE = 125;

/** A statement the reader gave up on; reading resumes at the next line. */
class Unreadable extends Error {}
const FAIL = new Unreadable("unreadable TOML statement");

/** `a` then `b`, checked against MAX_KEY_SEGMENTS and MAX_KEY_CHARS before anything is copied. */
function joined(a: readonly string[], b: readonly string[]): string[] {
  if (a.length + b.length > MAX_KEY_SEGMENTS) throw FAIL;
  let chars = 0;
  for (const k of a) chars += k.length;
  for (const k of b) chars += k.length;
  if (chars > MAX_KEY_CHARS) throw FAIL;
  return [...a, ...b];
}

/**
 * The entries of `path = value`: an inline table's keys each one of its own,
 * nested ones too. Each path is built once, from its parent's (never copied
 * again for every key below it), so this is linear in the keys.
 */
function flatten(path: string[], value: TomlValue, line: number, out: TomlEntry[]): void {
  if (value.t !== "tbl") {
    out.push({ path, value, line });
    return;
  }
  for (const [k, v] of value.v) flatten(joined(path, k), v, line, out);
}

class Reader {
  private i = 0;
  private line = 1;
  private readonly n: number;
  private table: string[] = [];
  private readonly entries: TomlEntry[] = [];
  private readonly unparsed: TomlUnparsed[] = [];

  constructor(private readonly s: string) {
    this.n = s.length;
  }

  read(): TomlDoc {
    for (;;) {
      this.skipBlank(true);
      if (this.i >= this.n) break;
      const start = this.i;
      const line = this.line;
      try {
        if (this.code() === LBRACKET) this.header();
        else this.keyValue(line);
        this.endOfLine(line);
      } catch (error) {
        if (!(error instanceof Unreadable)) throw error;
        this.giveUp(start, line);
      }
    }
    return { entries: this.entries, unparsed: this.unparsed };
  }

  // ── Characters ──

  private code(at = this.i): number {
    return at < this.n ? this.s.charCodeAt(at) : -1;
  }

  /** Step past one character, counting lines. */
  private step(): void {
    if (this.s.charCodeAt(this.i) === NL) this.line++;
    this.i++;
  }

  /** Move to `to`, counting the lines passed. */
  private moveTo(to: number): void {
    for (let k = this.i; k < to; k++) if (this.s.charCodeAt(k) === NL) this.line++;
    this.i = to;
  }

  /** Skip spaces and tabs, and with `lines` also line breaks and comments. */
  private skipBlank(lines: boolean): void {
    while (this.i < this.n) {
      const c = this.code();
      if (c === SPACE || c === TAB) this.i++;
      else if (lines && (c === NL || c === CR)) this.step();
      else if (lines && c === HASH) this.skipComment();
      else break;
    }
  }

  private skipComment(): void {
    const nl = this.s.indexOf("\n", this.i);
    this.i = nl < 0 ? this.n : nl;
  }

  /** After a statement: blanks, a comment, then a line break or the end; anything else is unparsed text of its own. */
  private endOfLine(line: number): void {
    this.skipBlank(false);
    const c = this.code();
    if (c === HASH) this.skipComment();
    else if (c !== -1 && c !== NL && c !== CR) this.giveUp(this.i, line);
  }

  /**
   * Record every line from the one `start` is on to the one the reader stopped
   * on as unparsed (a statement that failed on a later line took those lines
   * with it: each still counts), and resume after the last.
   */
  private giveUp(start: number, line: number): void {
    const nl = this.s.indexOf("\n", Math.max(this.i, start));
    const end = nl < 0 ? this.n : nl;
    let at = line;
    for (let from = this.s.lastIndexOf("\n", start - 1) + 1; from <= end && from < this.n; at++) {
      const lineEnd = this.s.indexOf("\n", from);
      const to = lineEnd < 0 || lineEnd > end ? end : lineEnd;
      const text = this.s.slice(from, to).replace(/\r$/, "").trim();
      if (text.length > MAX_UNPARSED_CHARS) this.unparsed.push({ line: at, text: text.slice(0, MAX_UNPARSED_CHARS), whole: text });
      else if (text !== "") this.unparsed.push({ line: at, text });
      from = to + 1;
    }
    this.moveTo(end);
  }

  // ── Statements ──

  private header(): void {
    this.i++; // [
    const array = this.code() === LBRACKET;
    if (array) this.i++;
    this.skipBlank(false);
    const path = this.keyPath();
    this.skipBlank(false);
    if (this.code() !== RBRACKET) throw FAIL;
    this.i++;
    if (array) {
      if (this.code() !== RBRACKET) throw FAIL;
      this.i++;
    }
    this.table = path;
  }

  private keyValue(line: number): void {
    const key = this.keyPath();
    this.skipBlank(false);
    if (this.code() !== EQ) throw FAIL;
    this.i++;
    this.skipBlank(false);
    const value = this.value(0);
    // every entry is checked before any is kept, so a statement is read whole or not at all
    const out: TomlEntry[] = [];
    flatten(joined(this.table, key), value, line, out);
    for (const e of out) this.entries.push(e);
  }

  /** `a.b."c d".'e'`: bare or quoted segments, dots between, blanks around the dots; within the path bounds. */
  private keyPath(): string[] {
    const path: string[] = [];
    let chars = 0;
    for (;;) {
      this.skipBlank(false);
      const segment = this.keySegment();
      chars += segment.length;
      if (path.push(segment) > MAX_KEY_SEGMENTS || chars > MAX_KEY_CHARS) throw FAIL;
      this.skipBlank(false);
      if (this.code() !== DOT) return path;
      this.i++;
    }
  }

  private keySegment(): string {
    const c = this.code();
    if (c === QUOTE) return this.basicString();
    if (c === APOS) return this.literalString();
    const start = this.i;
    // TOML's bare keys are ASCII; any other character that cannot end a key is taken too (tolerance)
    while (this.i < this.n) {
      const k = this.code();
      if (k === SPACE || k === TAB || k === NL || k === CR || k === DOT || k === EQ || k === RBRACKET
        || k === LBRACKET || k === QUOTE || k === APOS || k === HASH || k === COMMA || k === LBRACE || k === RBRACE) break;
      this.i++;
    }
    if (this.i === start) throw FAIL;
    return this.s.slice(start, this.i);
  }

  // ── Values ──

  private value(depth: number): TomlValue {
    if (depth > MAX_DEPTH) throw FAIL;
    const c = this.code();
    if (c === QUOTE) return { t: "str", v: this.s.startsWith('"""', this.i) ? this.multilineBasic() : this.basicString() };
    if (c === APOS) return { t: "str", v: this.s.startsWith("'''", this.i) ? this.multilineLiteral() : this.literalString() };
    if (c === LBRACKET) return this.array(depth);
    if (c === LBRACE) return this.inlineTable(depth);
    return this.bare();
  }

  /** A number, date, boolean or other bare value: up to a separator, a comment or the end of the line. */
  private bare(): TomlValue {
    const start = this.i;
    while (this.i < this.n) {
      const k = this.code();
      if (k === COMMA || k === RBRACKET || k === RBRACE || k === HASH || k === NL || k === CR) break;
      this.i++;
    }
    const raw = this.s.slice(start, this.i).trim();
    if (raw === "") throw FAIL;
    if (raw === "true" || raw === "false") return { t: "bool", v: raw === "true" };
    return { t: "raw", v: raw };
  }

  private array(depth: number): TomlValue {
    this.i++; // [
    const items: TomlValue[] = [];
    for (;;) {
      this.skipBlank(true);
      const c = this.code();
      if (c === -1) throw FAIL;
      if (c === RBRACKET) {
        this.i++;
        return { t: "arr", v: items };
      }
      items.push(this.value(depth + 1));
      this.skipBlank(true);
      const sep = this.code();
      if (sep === COMMA) this.i++;
      else if (sep !== RBRACKET) throw FAIL;
    }
  }

  /** `{ a = 1, b.c = "x" }`, line breaks allowed inside (TOML 1.1). */
  private inlineTable(depth: number): TomlValue {
    this.i++; // {
    const pairs: [string[], TomlValue][] = [];
    for (;;) {
      this.skipBlank(true);
      const c = this.code();
      if (c === -1) throw FAIL;
      if (c === RBRACE) {
        this.i++;
        return { t: "tbl", v: pairs };
      }
      const key = this.keyPath();
      this.skipBlank(false);
      if (this.code() !== EQ) throw FAIL;
      this.i++;
      this.skipBlank(false);
      pairs.push([key, this.value(depth + 1)]);
      this.skipBlank(true);
      const sep = this.code();
      if (sep === COMMA) this.i++;
      else if (sep !== RBRACE) throw FAIL;
    }
  }

  // ── Strings ──

  /** `"…"` on one line, decoded. */
  private basicString(): string {
    const start = ++this.i;
    while (this.i < this.n) {
      const c = this.code();
      if (c === BACKSLASH) this.i += 2;
      else if (c === QUOTE) break;
      else if (c === NL) throw FAIL;
      else this.i++;
    }
    if (this.i >= this.n) throw FAIL;
    const body = this.s.slice(start, this.i);
    this.i++;
    return unescape(body, false);
  }

  /** `'…'` on one line, as written. */
  private literalString(): string {
    const start = ++this.i;
    const close = this.s.indexOf("'", start);
    const nl = this.s.indexOf("\n", start);
    if (close < 0 || (nl >= 0 && nl < close)) throw FAIL;
    this.i = close + 1;
    return this.s.slice(start, close);
  }

  /** `"""…"""`, decoded; one that is never closed runs to the end of the text. */
  private multilineBasic(): string {
    this.i += 3;
    const start = this.i;
    let end = this.n;
    while (this.i < this.n) {
      const c = this.code();
      if (c === BACKSLASH) {
        this.step();
        if (this.i < this.n) this.step();
      } else if (c === QUOTE && this.s.startsWith('"""', this.i)) {
        // up to two more quotes belong to the content: `""""` ends with one
        let k = 3;
        while (k < 5 && this.code(this.i + k) === QUOTE) k++;
        end = this.i + k - 3;
        this.i += k;
        return unescape(stripFirstNewline(this.s.slice(start, end)), true);
      } else {
        this.step();
      }
    }
    return unescape(stripFirstNewline(this.s.slice(start, end)), true);
  }

  /** `'''…'''`, as written; one that is never closed runs to the end of the text. */
  private multilineLiteral(): string {
    this.i += 3;
    const start = this.i;
    const close = this.s.indexOf("'''", start);
    if (close < 0) {
      this.moveTo(this.n);
      return stripFirstNewline(this.s.slice(start));
    }
    let k = 3;
    while (k < 5 && this.code(close + k) === APOS) k++;
    const end = close + k - 3;
    this.moveTo(close + k);
    return stripFirstNewline(this.s.slice(start, end));
  }
}

/** A multi-line string drops a line break right after its opening delimiter. */
function stripFirstNewline(body: string): string {
  if (body.startsWith("\r\n")) return body.slice(2);
  return body.startsWith("\n") ? body.slice(1) : body;
}

const ESCAPES: Readonly<Record<string, string>> = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", e: "\u001b", '"': '"', "\\": "\\" };

/**
 * A basic string's escapes decoded: the single-character ones, `\xHH`,
 * `\uXXXX`, `\UXXXXXXXX`, and in a multi-line string a backslash at the end of
 * a line, which drops the line break and the blanks after it. An escape TOML
 * does not have is kept as written.
 */
function unescape(body: string, multiline: boolean): string {
  if (!body.includes("\\")) return body;
  let out = "";
  let i = 0;
  while (i < body.length) {
    const c = body[i];
    if (c !== "\\" || i + 1 >= body.length) {
      out += c;
      i++;
      continue;
    }
    const e = body[i + 1];
    if (e in ESCAPES) {
      out += ESCAPES[e];
      i += 2;
      continue;
    }
    const hex = e === "x" ? 2 : e === "u" ? 4 : e === "U" ? 8 : 0;
    if (hex) {
      const digits = body.slice(i + 2, i + 2 + hex);
      const cp = digits.length === hex && /^[0-9A-Fa-f]+$/.test(digits) ? parseInt(digits, 16) : NaN;
      if (cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff)) {
        out += String.fromCodePoint(cp);
        i += 2 + hex;
        continue;
      }
    }
    if (multiline) {
      // a line-ending backslash: the blanks before the break, the break and the blanks after it go
      let j = i + 1;
      while (j < body.length && (body[j] === " " || body[j] === "\t")) j++;
      if (body[j] === "\n" || (body[j] === "\r" && body[j + 1] === "\n")) {
        while (j < body.length && (body[j] === " " || body[j] === "\t" || body[j] === "\n" || body[j] === "\r")) j++;
        i = j;
        continue;
      }
    }
    out += c;
    i++;
  }
  return out;
}
