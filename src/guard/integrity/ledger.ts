/**
 * Instruction-file integrity — the write ledger (spec §4.5, amendments A5, B4).
 *
 * One signed file per event, `ledger/<YYYYMMDD>/<epochMs>-<sid8>-<rand6>.json`
 * (UTC day; `rand6` = 3 random bytes in hex), opened "wx" so nothing is ever
 * overwritten, 0600, with no lock:
 * - PreToolUse records each agent Write / Edit / MultiEdit to a watched file
 *   before it lands (`kind: "write"`; denied writes are not recorded);
 * - its PostToolUse, which Claude Code runs only once the tool succeeded,
 *   confirms it landed (`kind: "confirm"`: the same sid, tool use and path);
 * - `guard install` / `guard uninstall` record the settings changes Nexus itself
 *   makes (`kind: "nexus"`, sid8 `nexus000`).
 *
 * Records are signed with K("ledger"). The reader ignores — and counts — any
 * record that is malformed or does not verify, reads only the day directories
 * inside the retention window (and none dated past tomorrow), newest first, and
 * stops after a maximum number of files, so what a cut keeps is the latest.
 * `landedRecords` keeps the write records a confirmation vouches for: an ask the
 * user rejected must not explain the same lines arriving some other way.
 *
 * `simulateWrite` works out the text a file-tool write leaves (pure string
 * operations), so the caller can diff units against the current file and
 * predict the resulting sha256 (`expectedSha`). This module never cuts units.
 */

import { closeSync, openSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { join } from "node:path";
import { ensurePrivateDir } from "../../shared/atomic-file.js";
import { listDir, readPrivateJson } from "./private-file.js";
import { LEDGER_RECORD_NAME, ledgerDayName, ledgerDayStart, type IntegrityPaths, type Signer } from "./store.js";
import { RETENTION_MS, type LedgerConfirmRecord, type LedgerNexusRecord, type LedgerRecord, type LedgerWriteRecord, type SessionLevel } from "./types.js";

/** The sid8 of records Nexus writes for its own install / uninstall. */
const NEXUS_SID8 = "nexus000";

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

const SID16 = /^[0-9a-f]{16}$/;
const SHA256 = /^[0-9a-f]{64}$/;
/** Identifier-like fields copied from the payload (tool_use_id, permission_mode, agent_id, agent_type) are cut to this. */
const MAX_ID_CHARS = 256;
const MAX_RECORD_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_FILES = 5000;
/**
 * How far ahead of `now` a record's name (its write time) may be, for clock
 * skew: later day directories and files are not read, so planted future-dated
 * names cannot take the `maxFiles` budget from the newest real records.
 */
const FUTURE_SKEW_MS = 24 * 60 * 60 * 1000;
const DAY_DIR_SCAN_LIMIT = 10_000;
/** File names listed per day directory (listing is cheap; `maxFiles` bounds the reads). */
const DAY_FILE_SCAN_LIMIT = 100_000;
const WRITE_ATTEMPTS = 5;
/** Files opened between two `expired()` checks (one clock read per batch). */
const EXPIRY_CHECK_EVERY = 64;

// ── Writing ─────────────────────────────────────────────────────────────────

export type WriteRecordInput = Omit<LedgerWriteRecord, "v" | "kind" | "t" | "mac">;
export type NexusRecordInput = Omit<LedgerNexusRecord, "v" | "kind" | "t" | "mac">;
export type ConfirmRecordInput = Omit<LedgerConfirmRecord, "v" | "kind" | "t" | "mac">;

export type LedgerDeps = {
  /** Epoch ms of the event: the record's `t`, its day directory and file name. */
  now: number;
  /** 6 lowercase hex characters (default: 3 random bytes). */
  rand?: () => string;
};

const cut = (s: string) => (s.length > MAX_ID_CHARS ? s.slice(0, MAX_ID_CHARS) : s);

/**
 * Sign `record` and write it to a new file in its day directory. Returns the
 * record's name relative to `ledger/` (`<YYYYMMDD>/<file>.json`), which is how
 * attribution refers to it. Throws on I/O failure; a partly written file is removed.
 */
function writeRecord(paths: IntegrityPaths, signer: Signer, record: Omit<LedgerRecord | LedgerConfirmRecord, "mac">, sid8: string, deps: LedgerDeps): string {
  const text = JSON.stringify(signer.sign<LedgerRecord | LedgerConfirmRecord>("ledger", record));
  const day = ledgerDayName(deps.now);
  const dir = join(paths.ledgerDir, day);
  const rand = deps.rand ?? (() => randomBytes(3).toString("hex"));
  let madeDir = false;
  for (let attempt = 0; ; ) {
    const name = `${deps.now}-${sid8}-${rand()}.json`;
    const path = join(dir, name);
    let fd: number;
    try {
      fd = openSync(path, "wx", 0o600);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" && !madeDir) {
        ensurePrivateDir(dir);
        madeDir = true;
        continue;
      }
      if (code === "EEXIST" && ++attempt < WRITE_ATTEMPTS) continue;
      throw error;
    }
    try {
      writeFileSync(fd, text);
    } catch (error) {
      closeSync(fd);
      try { unlinkSync(path); } catch { /* already gone */ }
      throw error;
    }
    closeSync(fd);
    return `${day}/${name}`;
  }
}

/** Record an agent file-tool write (PreToolUse, decision allow or ask). `sid` is the 16-hex session id hash. */
export function appendWriteRecord(paths: IntegrityPaths, signer: Signer, input: WriteRecordInput, deps: LedgerDeps): string {
  if (!SID16.test(input.sid)) throw new TypeError("a ledger write record needs a 16-hex sid");
  const record: Omit<LedgerWriteRecord, "mac"> = {
    v: 1,
    kind: "write",
    t: new Date(deps.now).toISOString(),
    sid: input.sid,
    tu: cut(input.tu),
    tool: input.tool,
    path: input.path,
    added: [...input.added],
    removed: [...input.removed],
    expectedSha: input.expectedSha,
    approx: input.approx,
    decision: input.decision,
    mode: input.mode === null ? null : cut(input.mode),
    level: input.level,
    novel: input.novel,
    screen: input.screen,
  };
  if (input.agentId) record.agentId = cut(input.agentId);
  if (input.agentType) record.agentType = cut(input.agentType);
  return writeRecord(paths, signer, record, input.sid.slice(0, 8), deps);
}

/**
 * Confirm that an agent write landed (PostToolUse of the tool use PreToolUse
 * recorded). `sid` is the 16-hex session id hash; `tu` must name the tool use.
 */
export function appendConfirmRecord(paths: IntegrityPaths, signer: Signer, input: ConfirmRecordInput, deps: LedgerDeps): string {
  if (!SID16.test(input.sid)) throw new TypeError("a ledger confirm record needs a 16-hex sid");
  if (input.tu === "") throw new TypeError("a ledger confirm record needs a tool_use_id");
  const record: Omit<LedgerConfirmRecord, "mac"> = {
    v: 1, kind: "confirm", t: new Date(deps.now).toISOString(), sid: input.sid, tu: cut(input.tu), path: input.path,
  };
  return writeRecord(paths, signer, record, input.sid.slice(0, 8), deps);
}

/** Record a settings change Nexus made itself (`guard install` / `guard uninstall`). */
export function appendNexusRecord(paths: IntegrityPaths, signer: Signer, input: NexusRecordInput, deps: LedgerDeps): string {
  const record: Omit<LedgerNexusRecord, "mac"> = {
    v: 1,
    kind: "nexus",
    t: new Date(deps.now).toISOString(),
    action: input.action,
    path: input.path,
    added: [...input.added],
    removed: [...input.removed],
    nexusHooks: [...input.nexusHooks],
  };
  return writeRecord(paths, signer, record, NEXUS_SID8, deps);
}

// ── Reading ─────────────────────────────────────────────────────────────────

const TOOLS: ReadonlySet<string> = new Set(["Write", "Edit", "MultiEdit"]);
const LEVELS: ReadonlySet<string> = new Set<SessionLevel>(["clean", "exposed", "tainted"]);

const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((s) => typeof s === "string");
const isOptString = (v: unknown) => v === undefined || typeof v === "string";
const isStringOrNull = (v: unknown) => v === null || typeof v === "string";

/** The record when its shape is right (the MAC is checked separately), else null. */
function parseRecord(v: unknown): LedgerRecord | LedgerConfirmRecord | null {
  if (!isRecord(v) || v.v !== 1 || typeof v.mac !== "string" || typeof v.path !== "string") return null;
  if (typeof v.t !== "string" || !Number.isFinite(Date.parse(v.t))) return null;
  if (v.kind === "confirm") {
    return typeof v.sid === "string" && SID16.test(v.sid) && typeof v.tu === "string" && v.tu !== "" ? (v as LedgerConfirmRecord) : null;
  }
  if (!isStringArray(v.added) || !isStringArray(v.removed)) return null;
  if (v.kind === "write") {
    const ok =
      typeof v.sid === "string" && SID16.test(v.sid) &&
      typeof v.tu === "string" &&
      typeof v.tool === "string" && TOOLS.has(v.tool) &&
      typeof v.expectedSha === "string" && SHA256.test(v.expectedSha) &&
      typeof v.approx === "boolean" &&
      (v.decision === "allow" || v.decision === "ask") &&
      isStringOrNull(v.mode) &&
      typeof v.level === "string" && LEVELS.has(v.level) &&
      typeof v.novel === "boolean" &&
      isStringOrNull(v.screen) &&
      isOptString(v.agentId) && isOptString(v.agentType);
    return ok ? (v as LedgerWriteRecord) : null;
  }
  if (v.kind === "nexus") {
    return (v.action === "install" || v.action === "uninstall") && isStringArray(v.nexusHooks) ? (v as LedgerNexusRecord) : null;
  }
  return null;
}

/** A verified record and the file it came from (`<YYYYMMDD>/<file>.json`, relative to `ledger/`). */
export type LedgerEntry = LedgerRecord & { file: string };

export type LedgerQuery = {
  /** Store keys whose records are wanted, or null for every path (ledger-learned paths). */
  keys: ReadonlySet<string> | null;
  /** Only records whose `t` is after this (epoch ms), e.g. the entry's `acceptedAt`. */
  since: number;
  /** Epoch ms; day directories older than the retention window before it are not read. */
  now: number;
  /** Record files opened at most (default 5,000), newest first; beyond it the result is `truncated` and lacks the oldest. */
  maxFiles?: number;
  retentionMs?: number;
  /** Asked every EXPIRY_CHECK_EVERY files opened: once it returns true the read stops, `truncated`. */
  expired?: () => boolean;
};

export type LedgerRead = {
  /** Write and Nexus records, sorted by `t` (then by file). */
  records: LedgerEntry[];
  /** The write records PostToolUse confirmed, as `confirmKey`s. */
  confirmed: ReadonlySet<string>;
  /** Files that were malformed, had a bad name, or did not verify. */
  invalid: number;
  /** More files were in range than `maxFiles` allowed. */
  truncated: boolean;
};

/**
 * Valid records for `query.keys` newer than `query.since`, sorted by `t`. Only
 * day directories from the later of `since`'s day and the retention window's
 * start up to the day after `now` are read, newest first; within them, files are
 * read newest first by name (their write time), and those named before `since`,
 * or more than a day after `now`, are skipped unread. A `maxFiles` cut therefore
 * keeps the newest records, which §5.1's expectedSha fast path needs.
 */
export function readLedger(paths: IntegrityPaths, signer: Signer, query: LedgerQuery): LedgerRead {
  const { keys, now, maxFiles = DEFAULT_MAX_FILES, retentionMs = RETENTION_MS } = query;
  // An unparseable `acceptedAt` (NaN) reads the whole retention window rather than throwing.
  const since = Number.isFinite(query.since) ? query.since : 0;
  const firstDay = ledgerDayStart(ledgerDayName(Math.max(since, now - retentionMs)));
  const latest = now + FUTURE_SKEW_MS;
  const lastDay = ledgerDayStart(ledgerDayName(latest)) ?? latest;
  const records: LedgerEntry[] = [];
  const confirmed = new Set<string>();
  let invalid = 0;
  let opened = 0;
  let truncated = false;

  const days = listDir(paths.ledgerDir, DAY_DIR_SCAN_LIMIT);
  if (days.more) truncated = true;
  const inRange = days.names
    .map((name) => ({ name, start: ledgerDayStart(name) }))
    .filter((d): d is { name: string; start: number } => d.start !== null && (firstDay === null || d.start >= firstDay) && d.start <= lastDay)
    .sort((a, b) => b.start - a.start);

  outer: for (const { name: day } of inRange) {
    const files = listDir(join(paths.ledgerDir, day), DAY_FILE_SCAN_LIMIT);
    if (files.more) truncated = true;
    const named: { name: string; ms: number }[] = [];
    for (const name of files.names) {
      const m = LEDGER_RECORD_NAME.exec(name);
      if (m) named.push({ name, ms: Number(m[1]) });
      else invalid++;
    }
    named.sort((a, b) => b.ms - a.ms || (a.name < b.name ? 1 : a.name > b.name ? -1 : 0));
    for (const { name, ms } of named) {
      if (ms > latest) continue; // named in the future: not a record of this machine's clock
      if (ms <= since) break; // named for its write time, which is its `t`: this and the rest are not after `since`
      if (opened >= maxFiles || (query.expired && opened % EXPIRY_CHECK_EVERY === 0 && query.expired())) {
        truncated = true;
        break outer;
      }
      opened++;
      const read = readPrivateJson(join(paths.ledgerDir, day, name), MAX_RECORD_BYTES);
      const record = read.state === "ok" ? parseRecord(read.value) : null;
      if (!record) {
        invalid++;
        continue;
      }
      if (keys && !keys.has(record.path)) continue;
      if (!signer.verify("ledger", record)) {
        invalid++;
        continue;
      }
      if (Date.parse(record.t) <= since) continue;
      if (record.kind === "confirm") confirmed.add(confirmKey(record));
      else records.push({ ...record, file: `${day}/${name}` });
    }
  }

  records.sort((a, b) => Date.parse(a.t) - Date.parse(b.t) || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  return { records, confirmed, invalid, truncated };
}

/** What pairs a write record with its confirmation: the session, the tool use and the path. */
const confirmKey = (r: { sid: string; tu: string; path: string }) => `${r.sid}\u0000${r.tu}\u0000${r.path}`;

/**
 * The records attribution may use (§5.1): Nexus's own, and the agent writes
 * whose PostToolUse confirmed they landed. A write record alone says only that
 * Claude asked: the user may have rejected the prompt (or `-p` turned it into a
 * denial), and then it must not vouch for the same lines arriving through a
 * writer Nexus does not see. A confirmation is newer than its write record, so
 * a read cut to the newest files never keeps a write and drops its confirmation.
 */
export function landedRecords(read: Pick<LedgerRead, "records" | "confirmed">): LedgerEntry[] {
  return read.records.filter((r) => r.kind !== "write" || (r.tu !== "" && read.confirmed.has(confirmKey(r))));
}

// ── Simulating a write (amendment B4) ───────────────────────────────────────

export type SimulatedWrite = {
  /** The file's text after the write. */
  text: string;
  /**
   * Not exact: some `old_string` was not found in the text it applied to (or its
   * replacement would have been oversized, or the call's work budget was spent),
   * so that edit's `new_string` was appended instead (see `simulateWrite`).
   */
  approx: boolean;
};

/** Longest exact replace_all result simulated; a longer one is approximated by appending. */
const MAX_SIMULATED_CHARS = 16 * 1024 * 1024;
/**
 * Characters one call may scan and build exactly, over all its edits. Each exact
 * edit scans the whole text so far and builds about as much again, so without a
 * per-call budget a MultiEdit would cost edits × text (and chained replace_all
 * edits could grow the text each time). A 4 MiB file gets a few exact edits, an
 * ordinary CLAUDE.md thousands.
 */
const MAX_SIMULATION_WORK = 32 * 1024 * 1024;

type EditOp = { oldString: string; newString: string; replaceAll: boolean };

function parseEdit(v: unknown): EditOp | null {
  if (!isRecord(v) || typeof v.old_string !== "string" || typeof v.new_string !== "string") return null;
  return { oldString: v.old_string, newString: v.new_string, replaceAll: v.replace_all === true };
}

/** `text` with `change` appended on a line of its own (nothing to append → unchanged). */
function appendChange(text: string, change: string): string {
  if (change === "") return text;
  return text === "" || text.endsWith("\n") ? text + change : `${text}\n${change}`;
}

/** `text` with each edit's `new_string` appended in turn, exactly as `appendChange` would, in one join. */
function appendAll(text: string, edits: readonly EditOp[]): string {
  const out = [text];
  let last = text;
  for (const { newString } of edits) {
    if (newString === "") continue;
    if (last !== "" && !last.endsWith("\n")) out.push("\n");
    out.push(newString);
    last = newString;
  }
  return out.join("");
}

// Claude Code's Edit, mirrored so the simulated text is the text it writes:
// it reads the file with \r\n made \n, matches old_string there (falling back
// to matching typographic quotes as straight ones), and writes the result with
// the line ending most of the file's first 4096 characters use.

const LEFT_SINGLE = "\u2018";
const RIGHT_SINGLE = "\u2019";
const LEFT_DOUBLE = "\u201c";
const RIGHT_DOUBLE = "\u201d";
const CURLY_QUOTE = /[\u2018\u2019\u201c\u201d]/g;
const LETTER = /\p{L}/u;
/** Characters after which a straight quote opens (Claude Code's rule). */
const OPENS_AFTER: ReadonlySet<string> = new Set([" ", "\t", "\n", "\r", "(", "[", "{", "\u2014", "\u2013"]);
const LINE_ENDING_SAMPLE = 4096;

/** Typographic quotes as straight ones; one UTF-16 unit each way, so offsets carry over. */
const straightQuotes = (text: string) => text.replace(CURLY_QUOTE, (q) => (q === LEFT_DOUBLE || q === RIGHT_DOUBLE ? '"' : "'"));

/** Do more of the first 4096 characters' line breaks end in \r\n than in \n alone? */
function crlfDominant(text: string): boolean {
  const head = text.length > LINE_ENDING_SAMPLE ? text.slice(0, LINE_ENDING_SAMPLE) : text;
  let crlf = 0;
  let lf = 0;
  for (let at = head.indexOf("\n"); at !== -1; at = head.indexOf("\n", at + 1)) {
    if (at > 0 && head.charCodeAt(at - 1) === 0x0d) crlf++;
    else lf++;
  }
  return crlf > lf;
}

/** `next` with the BOM `previous` starts with, as Claude Code keeps it on a whole-file write. */
function keepBom(previous: string | null, next: string): string {
  return next !== "" && previous?.charCodeAt(0) === 0xfeff && next.charCodeAt(0) !== 0xfeff ? `\ufeff${next}` : next;
}

const opensAt = (chars: readonly string[], i: number) => i === 0 || OPENS_AFTER.has(chars[i - 1]);

/**
 * new_string in the file's quote style, when old_string only matched once its
 * typographic quotes were read as straight ones: straight double quotes become
 * “ or ” (opening after a space, bracket or dash), straight single quotes ‘ or ’
 * (’ between two letters).
 */
function inFileQuoteStyle(oldString: string, actual: string, newString: string): string {
  if (oldString === actual) return newString;
  const doubles = actual.includes(LEFT_DOUBLE) || actual.includes(RIGHT_DOUBLE);
  const singles = actual.includes(LEFT_SINGLE) || actual.includes(RIGHT_SINGLE);
  let out = newString;
  if (doubles) {
    const chars = [...out];
    out = chars.map((c, i) => (c === '"' ? (opensAt(chars, i) ? LEFT_DOUBLE : RIGHT_DOUBLE) : c)).join("");
  }
  if (singles) {
    const chars = [...out];
    out = chars.map((c, i) => {
      if (c !== "'") return c;
      const before = chars[i - 1];
      const after = chars[i + 1];
      if (before !== undefined && after !== undefined && LETTER.test(before) && LETTER.test(after)) return RIGHT_SINGLE;
      return opensAt(chars, i) ? LEFT_SINGLE : RIGHT_SINGLE;
    }).join("");
  }
  return out;
}

function applyEdits(current: string | null, edits: readonly EditOp[]): SimulatedWrite {
  const crlf = current !== null && crlfDominant(current);
  let text = current === null ? null : current.replaceAll("\r\n", "\n");
  let approx = false;
  let work = MAX_SIMULATION_WORK;
  const done = (out: string): SimulatedWrite => ({ text: crlf ? out.replaceAll("\r\n", "\n").replaceAll("\n", "\r\n") : out, approx });
  for (let i = 0; i < edits.length; i++) {
    const { oldString, newString, replaceAll } = edits[i];
    const base = text ?? "";
    // Scanning `base` and building a result about as long, charged up front;
    // once the budget cannot cover that, this edit and every later one are appended.
    if (2 * base.length > work) {
      approx = true;
      return done(appendAll(base, edits.slice(i)));
    }
    work -= 2 * base.length;
    if (oldString === "") {
      // Edit's way to create a file: only an absent or blank file takes new_string as its content.
      if (base.trim() === "") text = keepBom(base, newString);
      else {
        text = appendChange(base, newString);
        approx = true;
      }
      continue;
    }
    // The text old_string matches: itself, or (typographic quotes read as straight
    // ones, a second scan the budget is charged for) the file's own text there.
    let actual: string | null = base.includes(oldString) ? oldString : null;
    if (actual === null && 2 * base.length <= work) {
      work -= 2 * base.length;
      const at = straightQuotes(base).indexOf(straightQuotes(oldString));
      if (at !== -1) actual = base.slice(at, at + oldString.length);
    }
    if (actual === null) {
      text = appendChange(base, newString);
      approx = true;
      continue;
    }
    const replacement = inFileQuoteStyle(oldString, actual, newString);
    // Deleting text takes the line break after it too.
    const find = replacement === "" && !actual.endsWith("\n") && base.includes(`${actual}\n`) ? `${actual}\n` : actual;
    if (!replaceAll) {
      const at = base.indexOf(find);
      text = base.slice(0, at) + replacement + base.slice(at + find.length);
      continue;
    }
    // split/join, never String.replace: `$&`, `$1`, … in new_string are literal text.
    const parts = base.split(find);
    const growth = (parts.length - 1) * (replacement.length - find.length);
    // Whatever the result grows beyond `base` is built too, so it is charged as well.
    if (base.length + growth > MAX_SIMULATED_CHARS || growth > work) {
      text = appendChange(base, newString);
      approx = true;
      continue;
    }
    work -= Math.max(0, growth);
    text = parts.join(replacement);
  }
  return done(text ?? "");
}

/**
 * The text a file-tool write leaves, from the tool's `tool_input` and the
 * file's current text (`null` when it does not exist or is over 4 MiB, which
 * the caller does not read). Pure string operations, applied the way Claude
 * Code's tools apply them:
 *
 * - `Write`: `content` (after the file's BOM, which Claude Code keeps).
 * - `Edit`: the first occurrence of `old_string` replaced by `new_string`, or
 *   every (non-overlapping) occurrence with `replace_all: true`, in the file
 *   with `\r\n` read as `\n`; the result is written back with `\r\n` when most
 *   line breaks in the file's first 4096 characters were. An `old_string` not
 *   in the file matches where it would once typographic quotes (‘ ’ “ ”) are
 *   read as straight ones; the file's own text there is replaced, and
 *   `new_string`'s straight quotes take the file's style. An empty
 *   `new_string` also removes the line break right after the text it deletes.
 *   An empty `old_string` on an absent or blank file creates it with
 *   `new_string` (keeping a BOM).
 * - `MultiEdit`: `edits[]` applied in order, each to the previous result.
 * - An `old_string` that is not found (including any non-empty one on an absent
 *   file, and an empty one on a non-empty file) cannot be applied exactly:
 *   `approx` becomes true and that edit's `new_string` is appended to the text
 *   it applied to — after a `\n` unless that text is empty or already ends in
 *   one — so its lines diff as added and nothing as removed. The same applies
 *   to a `replace_all` whose result would exceed 16 Mi characters.
 * - The exact work of one call is bounded: once an edit would take the
 *   characters scanned and built past MAX_SIMULATION_WORK (32 Mi), it and every
 *   later edit are approximated the same way (appended in order, `approx`), so
 *   a MultiEdit costs at most that plus its own size, however many edits it has.
 * - `NotebookEdit` (notebooks are not watched), any other tool, and malformed
 *   input (a missing or non-string field): null.
 */
export function simulateWrite(tool: string, input: unknown, current: string | null): SimulatedWrite | null {
  if (!isRecord(input)) return null;
  if (tool === "Write") return typeof input.content === "string" ? { text: keepBom(current, input.content), approx: false } : null;
  if (tool === "Edit") {
    const edit = parseEdit(input);
    return edit ? applyEdits(current, [edit]) : null;
  }
  if (tool === "MultiEdit") {
    if (!Array.isArray(input.edits)) return null;
    const edits: EditOp[] = [];
    for (const raw of input.edits) {
      const edit = parseEdit(raw);
      if (!edit) return null;
      edits.push(edit);
    }
    return applyEdits(current, edits);
  }
  return null;
}

/** sha256 (hex) of the UTF-8 text a simulated write leaves: the record's `expectedSha`. */
export function expectedShaOf(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}
