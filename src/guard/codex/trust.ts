/**
 * Codex CLI's hook trust (0.164.0), and the one edit of its config.toml that
 * `nexus guard install --codex --trust` makes.
 *
 * Codex runs a user's hook only when `$CODEX_HOME/config.toml` holds
 * `[hooks.state."<key>"] trusted_hash = "<hash>"` with the hash it computes for
 * that hook now (codex-rs/hooks/src/engine/discovery.rs `hook_hash`; the key is
 * codex-rs/hooks/src/lib.rs `hook_key`). `codex exec` skips any other hook
 * without a word; the TUI asks first ("Hooks need review"). The key names a hook
 * by position (the hooks.json path, the event, the group and the handler), and
 * the hash covers the event, the group's matcher and the handler as Codex
 * normalizes it, so a hook that is edited, or moved, must be trusted again.
 * Checked against the real binary: hashes computed this way let `codex exec`
 * run the hooks without `--dangerously-bypass-hook-trust`.
 *
 * config.toml is read by a scanner, not a TOML library: one linear pass finds
 * the table headers and key/value statements (a multi-line string, array or
 * inline table is read as one value), which is all the hooks feature switch and
 * the hook state need. The only edit is to `[hooks.state."<key>"]` tables: their
 * `trusted_hash` value replaced or added, a missing table appended, a table
 * removed. The rest of the file stays byte for byte, and a file that defines
 * hook state any other way (an inline table, dotted keys, a table twice) is
 * refused rather than guessed at.
 */

import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";

// ── The trust identity ──────────────────────────────────────────────────────

/** Codex's hook events and each one's label in a trust key (`hook_event_key_label`). */
export const CODEX_EVENT_LABELS: Readonly<Record<string, string>> = {
  PreToolUse: "pre_tool_use",
  PermissionRequest: "permission_request",
  PostToolUse: "post_tool_use",
  PreCompact: "pre_compact",
  PostCompact: "post_compact",
  PreModelRequest: "pre_model_request",
  PostModelRequest: "post_model_request",
  SessionStart: "session_start",
  SessionEnd: "session_end",
  UserPromptSubmit: "user_prompt_submit",
  SubagentStart: "subagent_start",
  SubagentStop: "subagent_stop",
  Stop: "stop",
  Interrupt: "interrupt",
};

/** Events whose groups match on a `matcher` (`matcher_pattern_for_event`); the others ignore it, and so does the hash. */
const MATCHER_EVENTS: ReadonlySet<string> = new Set([
  "PreToolUse", "PermissionRequest", "PostToolUse", "SessionStart", "SessionEnd", "SubagentStart", "SubagentStop", "PreCompact", "PostCompact",
]);
/** Events that can return additionalContext: only their handlers keep an `additionalContextLimit`. */
const CONTEXT_EVENTS: ReadonlySet<string> = new Set(["PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit", "SubagentStart"]);
/** SessionEnd and Interrupt hooks get 1 s by default and at most 3 (`SESSION_END_*_TIMEOUT_SEC`); others 600. */
const SHORT_EVENTS: ReadonlySet<string> = new Set(["SessionEnd", "Interrupt"]);

/** Codex's default `additionalContextLimit`, in tokens (output_spill.rs): a handler that sets exactly this hashes as if unset. */
export const DEFAULT_CONTEXT_LIMIT = 2500;

/** The trust key of handler `handler` in group `group` of `event` in the hooks.json at `hooksPath` (as Codex spells that path). */
export function trustKey(hooksPath: string, event: string, group: number, handler: number): string {
  return `${hooksPath}:${CODEX_EVENT_LABELS[event] ?? event}:${group}:${handler}`;
}

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const isCount = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const isAbsent = (v: unknown) => v === undefined || v === null;

/** JSON with every object's keys sorted and no spaces: what serde_json writes after `sort_all_objects` (fingerprint.rs). */
function sortedJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(sortedJson).join(",")}]`;
  if (isObject(value)) return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${sortedJson(value[k])}`).join(",")}}`;
  return JSON.stringify(value);
}

/**
 * The hash Codex trusts a command hook by: `"sha256:"` and the hex SHA-256 of
 * the sorted, compact JSON of `{event_name, matcher?, hooks: [handler]}`, with
 * the handler normalized as discovery.rs does: `timeout` (seconds) defaulted to
 * 600 and at least 1 (SessionEnd and Interrupt: 1, held to 1-3), `async` a
 * boolean, `statusMessage` when set, `additionalContextLimit` only for an event
 * that can return context and only when it is not Codex's default, and on
 * Windows the `commandWindows` text in place of `command` when there is one. The
 * matcher counts only for an event that matches on one. Null for a handler Codex
 * would not load as a command hook (no command, a field of the wrong type).
 */
export function trustHash(event: string, matcher: unknown, handler: unknown, platform: NodeJS.Platform = process.platform): string | null {
  if (!(event in CODEX_EVENT_LABELS) || !isObject(handler) || handler.type !== "command") return null;
  const { command, commandWindows, timeout, statusMessage, additionalContextLimit } = handler;
  if (typeof command !== "string" || !(isAbsent(commandWindows) || typeof commandWindows === "string")) return null;
  if (!(isAbsent(timeout) || isCount(timeout)) || !(handler.async === undefined || typeof handler.async === "boolean")) return null;
  if (!(isAbsent(statusMessage) || typeof statusMessage === "string")) return null;
  if (!(isAbsent(additionalContextLimit) || isCount(additionalContextLimit))) return null;
  if (!(isAbsent(matcher) || typeof matcher === "string")) return null;
  const run = platform === "win32" && typeof commandWindows === "string" ? commandWindows : command;
  if (run.trim() === "") return null;
  const seconds = isCount(timeout) ? timeout : null;
  const normalized: Record<string, unknown> = {
    type: "command",
    command: run,
    timeout: SHORT_EVENTS.has(event) ? Math.min(Math.max(seconds ?? 1, 1), 3) : Math.max(seconds ?? 600, 1),
    async: handler.async === true,
  };
  if (typeof statusMessage === "string") normalized.statusMessage = statusMessage;
  if (CONTEXT_EVENTS.has(event) && isCount(additionalContextLimit) && additionalContextLimit !== DEFAULT_CONTEXT_LIMIT) {
    normalized.additionalContextLimit = additionalContextLimit;
  }
  const identity: Record<string, unknown> = { event_name: CODEX_EVENT_LABELS[event], hooks: [normalized] };
  if (MATCHER_EVENTS.has(event) && typeof matcher === "string") identity.matcher = matcher;
  return `sha256:${createHash("sha256").update(sortedJson(identity)).digest("hex")}`;
}

// ── Reading config.toml ─────────────────────────────────────────────────────

/** config.toml is read at most this large. */
export const MAX_CONFIG_BYTES = 4 * 1024 * 1024;

export type TextRead = { state: "ok"; text: string } | { state: "missing" } | { state: "invalid"; why: string };

/**
 * The UTF-8 text at `path`, following a symlink (a dotfile manager's link is
 * Codex's config too), or why not: not a regular file, over `max` bytes, or
 * unreadable. One non-blocking descriptor, so a FIFO never hangs the CLI.
 */
export function readTextFile(path: string, max = MAX_CONFIG_BYTES): TextRead {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return { state: "missing" };
    return { state: "invalid", why: code === "EISDIR" ? "it is not a regular file" : `it cannot be read (${code ?? "error"})` };
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { state: "invalid", why: "it is not a regular file" };
    if (st.size > max) return { state: "invalid", why: `it is over ${Math.round(max / (1024 * 1024))} MiB` };
    return { state: "ok", text: readFileSync(fd, "utf-8") };
  } catch (error) {
    return { state: "invalid", why: `it cannot be read (${(error as NodeJS.ErrnoException).code ?? "error"})` };
  } finally {
    closeSync(fd);
  }
}

/** A value as far as Nexus reads one: a string or boolean, an inline table's entries, anything else unread. */
export type TomlValue =
  | { type: "string"; value: string }
  | { type: "boolean"; value: boolean }
  | { type: "table"; entries: { key: string[]; value: TomlValue }[] }
  | { type: "other" };

/** One statement: a `[table]` or `[[array]]` header, or a `key = value` (its value may span lines). */
export type TomlStatement = {
  kind: "table" | "array" | "keyval";
  /** A header's path, or a key/value's own (possibly dotted) key. */
  key: string[];
  /** The header a key/value sits under ([] at the top of the file); for a header, its own path. */
  table: string[];
  /** `table` is an `[[array]]` element: its keys are not the plain table's. */
  inArray: boolean;
  value?: TomlValue;
  /** The 1-based line it starts on. */
  line: number;
  /** Its first line's start, and the end of its last line (after the line break, or the end of the file). */
  start: number;
  end: number;
  /** A key/value's value text. */
  valueStart?: number;
  valueEnd?: number;
};

export type TomlScan = {
  statements: TomlStatement[];
  /** The first thing the scanner could not read; the statements are those before it. */
  error: { line: number; message: string } | null;
  /** The file's line break: CRLF when it has any, else LF. */
  newline: "\n" | "\r\n";
};

/** Deeper nesting of arrays and inline tables than any config needs (it also bounds the recursion). */
const MAX_DEPTH = 64;
/** A TOML number, date, time, inf or nan: what a bare value may be besides true and false. */
const SCALAR = /^(?:[+-]?(?:inf|nan)|[+-]?[0-9][0-9A-Za-z_+\-.:]*)$/;
const ESCAPES: Readonly<Record<string, string>> = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", e: "\x1b", '"': '"', "\\": "\\" };

/** A-Z, a-z, 0-9, `_` and `-`: what a bare key is made of. */
const isBareKeyChar = (c: number) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 95 || c === 45;

class TomlSyntaxError extends Error {}

/** One pass over the text; every method moves `i` forward only, so the scan is linear. */
class Scanner {
  i = 0;
  constructor(private readonly s: string) {}

  private at(o = 0): string {
    return this.s[this.i + o] ?? "";
  }
  private fail(message: string): never {
    throw new TomlSyntaxError(message);
  }
  get done(): boolean {
    return this.i >= this.s.length;
  }

  skipSpaces(): void {
    while (this.at() === " " || this.at() === "\t") this.i++;
  }
  /** At a line break or the end of the file. */
  atLineEnd(): boolean {
    return this.done || this.at() === "\n" || (this.at() === "\r" && this.at(1) === "\n");
  }
  /** Spaces, an optional comment, then the line break (or the end of the file). */
  endLine(): void {
    this.skipSpaces();
    if (this.at() === "#") while (!this.atLineEnd()) this.i++;
    if (this.done) return;
    if (this.at() === "\r" && this.at(1) === "\n") this.i += 2;
    else if (this.at() === "\n") this.i++;
    else this.fail(`unexpected ${JSON.stringify(this.at())} after the value`);
  }
  /** Spaces, line breaks and comments, as allowed between an array's (or an inline table's) values. */
  private skipBlank(): void {
    for (;;) {
      this.skipSpaces();
      if (this.at() === "#") while (!this.atLineEnd()) this.i++;
      if (this.at() === "\n") this.i++;
      else if (this.at() === "\r" && this.at(1) === "\n") this.i += 2;
      else return;
    }
  }

  /** A dotted key: bare or quoted parts joined by `.`. */
  key(): string[] {
    const parts: string[] = [];
    for (;;) {
      this.skipSpaces();
      parts.push(this.simpleKey());
      this.skipSpaces();
      if (this.at() !== ".") return parts;
      this.i++;
    }
  }
  private simpleKey(): string {
    if (this.at() === '"') return this.basicString();
    if (this.at() === "'") return this.literalString();
    const start = this.i;
    while (isBareKeyChar(this.s.charCodeAt(this.i))) this.i++;
    if (this.i === start) this.fail("expected a key");
    return this.s.slice(start, this.i);
  }

  /** `"…"` on one line, its escapes decoded. */
  private basicString(): string {
    this.i++;
    let out = "";
    for (;;) {
      const c = this.at();
      if (c === "" || c === "\n" || c === "\r") this.fail("unterminated string");
      if (c === '"') {
        this.i++;
        return out;
      }
      if (c === "\\") out += this.escape();
      else {
        out += c;
        this.i++;
      }
    }
  }
  /** `'…'` on one line, as written. */
  private literalString(): string {
    const start = ++this.i;
    while (this.at() !== "'") {
      if (this.at() === "" || this.at() === "\n" || this.at() === "\r") this.fail("unterminated string");
      this.i++;
    }
    return this.s.slice(start, this.i++);
  }
  /** The escape at `i` (a backslash), decoded. */
  private escape(): string {
    const c = this.at(1);
    if (c in ESCAPES) {
      this.i += 2;
      return ESCAPES[c];
    }
    const width = c === "u" ? 4 : c === "U" ? 8 : c === "x" ? 2 : 0;
    const hex = this.s.slice(this.i + 2, this.i + 2 + width);
    if (width === 0 || !/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== width) this.fail("invalid escape in a string");
    const code = parseInt(hex, 16);
    if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) this.fail("invalid escape in a string");
    this.i += 2 + width;
    return String.fromCodePoint(code);
  }
  /** `"""…"""` or `'''…'''`, decoded: a line break right after the opening is dropped, and in a basic one a `\` at a line's end joins it to the next. */
  private multilineString(quote: '"' | "'"): string {
    this.i += 3;
    if (this.at() === "\n") this.i++;
    else if (this.at() === "\r" && this.at(1) === "\n") this.i += 2;
    let out = "";
    for (;;) {
      const c = this.at();
      if (c === "") this.fail("unterminated multi-line string");
      if (c === quote) {
        let run = 0;
        while (this.at(run) === quote) run++;
        if (run >= 3) {
          if (run > 5) this.fail("too many quotes closing a multi-line string");
          out += quote.repeat(run - 3);
          this.i += run;
          return out;
        }
        out += quote.repeat(run);
        this.i += run;
      } else if (c === "\\" && quote === '"') {
        let j = this.i + 1;
        while (this.s[j] === " " || this.s[j] === "\t") j++;
        if (this.s[j] === "\n" || (this.s[j] === "\r" && this.s[j + 1] === "\n")) {
          // a line-ending backslash: the break and the blanks after it go
          this.i = j;
          while (this.at() === " " || this.at() === "\t" || this.at() === "\n" || this.at() === "\r") this.i++;
        } else out += this.escape();
      } else {
        out += c;
        this.i++;
      }
    }
  }

  value(depth: number): TomlValue {
    if (depth > MAX_DEPTH) this.fail("arrays or inline tables nested too deeply");
    const c = this.at();
    if (c === '"' || c === "'") {
      if (this.at(1) === c && this.at(2) === c) return { type: "string", value: this.multilineString(c) };
      return { type: "string", value: c === '"' ? this.basicString() : this.literalString() };
    }
    if (c === "[") return this.array(depth);
    if (c === "{") return this.inlineTable(depth);
    return this.scalar();
  }
  private array(depth: number): TomlValue {
    this.i++;
    for (;;) {
      this.skipBlank();
      if (this.at() === "]") break;
      this.value(depth + 1);
      this.skipBlank();
      if (this.at() === ",") this.i++;
      else if (this.at() !== "]") this.fail("expected , or ] in an array");
    }
    this.i++;
    return { type: "other" };
  }
  private inlineTable(depth: number): TomlValue {
    this.i++;
    const entries: { key: string[]; value: TomlValue }[] = [];
    for (;;) {
      this.skipBlank();
      if (this.at() === "}") break;
      const key = this.key();
      if (this.at() !== "=") this.fail("expected = in an inline table");
      this.i++;
      this.skipSpaces();
      entries.push({ key, value: this.value(depth + 1) });
      this.skipBlank();
      if (this.at() === ",") this.i++;
      else if (this.at() !== "}") this.fail("expected , or } in an inline table");
    }
    this.i++;
    return { type: "table", entries };
  }
  private scalar(): TomlValue {
    const stop = (ch: string) => ch === "" || " \t\r\n,]}#".includes(ch);
    const start = this.i;
    while (!stop(this.at())) this.i++;
    // a date and a time may be separated by one space: 1979-05-27 07:32:00Z
    if (/^\d{4}-\d{2}-\d{2}$/.test(this.s.slice(start, this.i)) && this.at() === " " && /^\d{2}:/.test(this.s.slice(this.i + 1, this.i + 4))) {
      this.i++;
      while (!stop(this.at())) this.i++;
    }
    const raw = this.s.slice(start, this.i);
    if (raw === "true" || raw === "false") return { type: "boolean", value: raw === "true" };
    if (!SCALAR.test(raw.replace(" ", "T"))) this.fail(raw === "" ? "expected a value" : `${JSON.stringify(raw.slice(0, 40))} is not a TOML value`);
    return { type: "other" };
  }
}

/**
 * The statements of a TOML document, in one linear pass. It reads what a valid
 * file holds; where it meets something it cannot read it stops, and `error`
 * says where (Codex, which parses the file strictly, would most likely refuse
 * it too). It does not check what TOML forbids across statements (a key
 * defined twice, a table reopened): the callers check what they rely on.
 */
export function scanToml(text: string): TomlScan {
  const s = new Scanner(text);
  const statements: TomlStatement[] = [];
  let table: string[] = [];
  let inArray = false;
  let line = 1;
  let counted = 0;
  /** The 1-based line of offset `at`, counting forward from the last call (offsets only grow). */
  const lineOf = (at: number) => {
    for (; counted < at; counted++) if (text.charCodeAt(counted) === 10) line++;
    return line;
  };
  let start = 0;
  if (text.charCodeAt(0) === 0xfeff) s.i = 1; // a byte-order mark before the first line
  try {
    while (!s.done) {
      start = s.i;
      s.skipSpaces();
      if (s.atLineEnd() || text[s.i] === "#") {
        s.endLine();
        continue;
      }
      if (text[s.i] === "[") {
        const array = text[s.i + 1] === "[";
        s.i += array ? 2 : 1;
        const key = s.key();
        if (text.slice(s.i, s.i + (array ? 2 : 1)) !== (array ? "]]" : "]")) throw new TomlSyntaxError("expected ] closing a table header");
        s.i += array ? 2 : 1;
        s.endLine();
        table = key;
        inArray = array;
        statements.push({ kind: array ? "array" : "table", key, table, inArray, line: lineOf(start), start, end: s.i });
        continue;
      }
      const key = s.key();
      if (text[s.i] !== "=") throw new TomlSyntaxError("expected = after a key");
      s.i++;
      s.skipSpaces();
      const valueStart = s.i;
      const value = s.value(0);
      const valueEnd = s.i;
      s.endLine();
      statements.push({ kind: "keyval", key, table, inArray, value, line: lineOf(start), start, end: s.i, valueStart, valueEnd });
    }
  } catch (error) {
    if (!(error instanceof TomlSyntaxError)) throw error;
    return { statements, error: { line: lineOf(start), message: error.message }, newline: newlineOf(text) };
  }
  return { statements, error: null, newline: newlineOf(text) };
}

const newlineOf = (text: string): "\n" | "\r\n" => (text.includes("\r\n") ? "\r\n" : "\n");

/** A key/value statement's full path: its table's and its own key's parts (an array element's keys are marked off). */
function fullPath(st: TomlStatement): string[] {
  return [...st.table, ...(st.inArray ? ["[]"] : []), ...st.key];
}

/** Every value the file sets, by full path: each key/value, and each entry of an inline table it holds, at any depth. */
function assignmentsOf(scan: TomlScan): { path: string[]; value: TomlValue; statement: TomlStatement }[] {
  const out: { path: string[]; value: TomlValue; statement: TomlStatement }[] = [];
  const add = (path: string[], value: TomlValue, statement: TomlStatement) => {
    out.push({ path, value, statement });
    if (value.type === "table") for (const e of value.entries) add([...path, ...e.key], e.value, statement);
  };
  for (const st of scan.statements) if (st.kind === "keyval" && st.value) add(fullPath(st), st.value, st);
  return out;
}

const samePath = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((p, i) => p === b[i]);

/** What config.toml says about one hook (`HookStateToml`): the hash it was trusted at, and whether it is turned off. */
export type HookState = { trustedHash: string | null; enabled: boolean | null };

/**
 * The hook state the file sets, by trust key, in whatever form it is written:
 * Codex reads `hooks.state` from the user's config.toml whole (config_rules.rs),
 * trimming each key.
 */
export function hookStates(scan: TomlScan): Map<string, HookState> {
  const states = new Map<string, HookState>();
  for (const { path, value } of assignmentsOf(scan)) {
    if (path.length !== 4 || path[0] !== "hooks" || path[1] !== "state") continue;
    const key = path[2].trim();
    if (key === "") continue;
    const state = states.get(key) ?? { trustedHash: null, enabled: null };
    if (path[3] === "trusted_hash" && value.type === "string") state.trustedHash = value.value;
    if (path[3] === "enabled" && value.type === "boolean") state.enabled = value.value;
    states.set(key, state);
  }
  return states;
}

/**
 * Where the file turns Codex's hooks feature off, as `features.hooks = false`
 * (or the deprecated `features.codex_hooks`, or either in the profile `profile`
 * selects), or null while the feature is on, as it is by default. Codex applies
 * `codex_hooks`, then `hooks`, then the profile's two
 * (codex-rs/features/src/lib.rs `apply_map`, `from_sources`).
 */
export function hooksFeatureOff(scan: TomlScan): string | null {
  const all = assignmentsOf(scan);
  const profile = all.find((a) => samePath(a.path, ["profile"]) && a.value.type === "string")?.value as { value: string } | undefined;
  const order: string[][] = [["features", "codex_hooks"], ["features", "hooks"]];
  if (profile) order.push(["profiles", profile.value, "features", "codex_hooks"], ["profiles", profile.value, "features", "hooks"]);
  let off: string | null = null;
  for (const path of order) {
    const set = all.filter((a) => samePath(a.path, path) && a.value.type === "boolean").at(-1);
    if (!set) continue;
    off = (set.value as { value: boolean }).value ? null : `${path.map(keyText).join(".")} = false (line ${set.statement.line})`;
  }
  return off;
}

/** A key part as TOML writes it: bare when it can be, else a basic string. */
function keyText(part: string): string {
  return /^[A-Za-z0-9_-]+$/.test(part) ? part : tomlString(part);
}

/** `text` as a TOML basic string: `"`, `\` and control characters escaped. */
export function tomlString(text: string): string {
  let out = '"';
  for (const ch of text) {
    const code = ch.codePointAt(0)!;
    if (ch === '"' || ch === "\\") out += `\\${ch}`;
    else if (ch === "\n") out += "\\n";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\r") out += "\\r";
    else if (code < 0x20 || code === 0x7f) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else out += ch;
  }
  return `${out}"`;
}

// ── Editing config.toml ─────────────────────────────────────────────────────

/** The changes to make: `trusted_hash` values to set, by key, and tables to remove. */
export type TrustEdit = { set?: ReadonlyMap<string, string>; remove?: ReadonlySet<string> };

export type TrustEditResult =
  | { ok: true; text: string; set: string[]; removed: string[] }
  | { ok: false; reason: string };

/** The `[hooks.state."<key>"]` tables of a file whose hook state is all in that form: each one's header and statements. */
type StateTable = { header: TomlStatement; body: TomlStatement[] };

/**
 * The file's `[hooks.state."<key>"]` tables, or why its hook state is in a form
 * this edit does not take on: hook state (or `hooks` itself) set by a dotted
 * key or an inline table, a table under one of those tables, an array of
 * tables, a `[hooks.state]` table with keys of its own, or a table or key
 * defined twice (which Codex would refuse to load).
 */
function stateTables(scan: TomlScan): { tables: Map<string, StateTable> } | { refused: string } {
  const tables = new Map<string, StateTable>();
  const refuse = (st: TomlStatement, what: string) => ({ refused: `line ${st.line} ${what}` });
  let current: StateTable | null = null;
  for (const st of scan.statements) {
    if (st.kind !== "keyval") {
      current = null;
      if (st.key[0] !== "hooks") continue;
      if (st.kind === "array" && (st.key.length === 1 || st.key[1] === "state")) return refuse(st, "makes hooks or hooks.state an array of tables");
      if (st.key[1] !== "state" || st.kind === "array") continue;
      if (st.key.length > 3) return refuse(st, "opens a table inside a hook's state");
      if (st.key.length === 3) {
        const key = st.key[2];
        if (tables.has(key)) return refuse(st, `opens the table for ${tomlString(key)} a second time`);
        current = { header: st, body: [] };
        tables.set(key, current);
      }
      continue;
    }
    const path = fullPath(st);
    if (current) {
      if (current.body.some((b) => samePath(b.key, st.key))) return refuse(st, `sets ${st.key.map(keyText).join(".")} twice in one hook's state`);
      current.body.push(st);
      continue;
    }
    if (path[0] !== "hooks" || st.inArray) continue;
    if (st.table.length === 0) return refuse(st, "sets hooks with a dotted key or an inline table");
    if (path[1] === "state") return refuse(st, "sets hook state with a dotted key or an inline table");
  }
  return { tables };
}

/**
 * Apply `edit` to config.toml's text: for each key to set, the `trusted_hash`
 * value of its `[hooks.state."<key>"]` table replaced (or the line added under
 * the header), or a new table appended at the end; for each key to remove, its
 * table taken out with the blank line it leaves. Every other byte stays as it
 * was. Refused, with the reason, when the file cannot be read or keeps hook
 * state in any other form (`stateTables`).
 */
export function editHookTrust(text: string, edit: TrustEdit): TrustEditResult {
  const scan = scanToml(text);
  if (scan.error) return { ok: false, reason: `Nexus cannot read line ${scan.error.line} (${scan.error.message})` };
  const found = stateTables(scan);
  if ("refused" in found) return { ok: false, reason: found.refused };
  const nl = scan.newline;
  const splices: { start: number; end: number; text: string }[] = [];
  const set: string[] = [];
  const removed: string[] = [];
  const appended: string[] = [];
  for (const [key, hash] of edit.set ?? []) {
    const table = found.tables.get(key);
    if (!table) {
      appended.push(`[hooks.state.${tomlString(key)}]${nl}trusted_hash = ${tomlString(hash)}${nl}`);
      set.push(key);
      continue;
    }
    const line = table.body.find((b) => samePath(b.key, ["trusted_hash"]));
    if (line?.value?.type === "string" && line.value.value === hash) continue;
    if (line) splices.push({ start: line.valueStart!, end: line.valueEnd!, text: tomlString(hash) });
    else {
      const end = table.header.end;
      const lead = end === text.length && !/\n$/.test(text) ? nl : "";
      splices.push({ start: end, end, text: `${lead}trusted_hash = ${tomlString(hash)}${nl}` });
    }
    set.push(key);
  }
  const spans: [number, number][] = [];
  for (const key of edit.remove ?? []) {
    const table = found.tables.get(key);
    if (!table || edit.set?.has(key)) continue;
    spans.push([table.header.start, (table.body.at(-1) ?? table.header).end]);
    removed.push(key);
  }
  splices.push(...removals(text, spans));
  let out = text;
  for (const sp of splices.sort((a, b) => b.start - a.start)) out = out.slice(0, sp.start) + sp.text + out.slice(sp.end);
  if (appended.length) {
    const lead = out === "" ? "" : `${out.endsWith("\n") ? "" : nl}${/\n\r?\n$/.test(out) ? "" : nl}`;
    out += lead + appended.join(nl);
  }
  return { ok: true, text: out, set, removed };
}

/**
 * The splices that remove tables (each span: a header to its last statement).
 * Tables with only blank lines between them go as one span; each span also
 * takes one of the blank lines around it when it stood between two (or at an
 * end of the file), so tables Nexus appended leave the file as it found them.
 */
function removals(text: string, spans: [number, number][]): { start: number; end: number; text: string }[] {
  const merged: [number, number][] = [];
  for (const [start, end] of spans.sort((a, b) => a[0] - b[0])) {
    const last = merged.at(-1);
    if (last && /^(?:[ \t]*\r?\n)*$/.test(text.slice(last[1], start))) last[1] = Math.max(last[1], end);
    else merged.push([start, end]);
  }
  return merged.map(([start, end]) => {
    const blankBefore = start === 0 || /\n\r?\n$/.test(text.slice(Math.max(0, start - 3), start));
    const following = /^\r?\n/.exec(text.slice(end, end + 2));
    if (end === text.length && start > 0 && blankBefore) start -= text.slice(start - 2, start) === "\r\n" ? 2 : 1;
    else if (following && blankBefore) end += following[0].length;
    return { start, end, text: "" };
  });
}
