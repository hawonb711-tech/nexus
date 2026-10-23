/**
 * Instruction-file integrity — the write ledger (spec §4.5, amendments A5, B4).
 *
 * One signed file per event, `ledger/<YYYYMMDD>/<epochMs>-<sid8>-<rand6>.json`
 * (UTC day; `rand6` = 3 random bytes in hex), opened "wx" so nothing is ever
 * overwritten, 0600, with no lock:
 * - PreToolUse records each agent Write / Edit / MultiEdit to a watched file
 *   before it lands (`kind: "write"`; denied writes are not recorded);
 * - `guard install` / `guard uninstall` record the settings changes Nexus itself
 *   makes (`kind: "nexus"`, sid8 `nexus000`).
 *
 * Records are signed with K("ledger"). The reader ignores — and counts — any
 * record that is malformed or does not verify, reads only the day directories
 * inside the retention window, and stops after a maximum number of files.
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
import { RETENTION_MS, type LedgerNexusRecord, type LedgerRecord, type LedgerWriteRecord, type SessionLevel } from "./types.js";

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
const DAY_DIR_SCAN_LIMIT = 10_000;
/** File names listed per day directory (listing is cheap; `maxFiles` bounds the reads). */
const DAY_FILE_SCAN_LIMIT = 100_000;
const WRITE_ATTEMPTS = 5;

// ── Writing ─────────────────────────────────────────────────────────────────

export type WriteRecordInput = Omit<LedgerWriteRecord, "v" | "kind" | "t" | "mac">;
export type NexusRecordInput = Omit<LedgerNexusRecord, "v" | "kind" | "t" | "mac">;

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
function writeRecord(paths: IntegrityPaths, signer: Signer, record: Omit<LedgerRecord, "mac">, sid8: string, deps: LedgerDeps): string {
  const text = JSON.stringify(signer.sign<LedgerRecord>("ledger", record));
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
function parseRecord(v: unknown): LedgerRecord | null {
  if (!isRecord(v) || v.v !== 1 || typeof v.mac !== "string" || typeof v.path !== "string") return null;
  if (typeof v.t !== "string" || !Number.isFinite(Date.parse(v.t))) return null;
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
  /** Record files opened at most (default 5,000); beyond it the result is `truncated`. */
  maxFiles?: number;
  retentionMs?: number;
};

export type LedgerRead = {
  /** Sorted by `t` (then by file). */
  records: LedgerEntry[];
  /** Files that were malformed, had a bad name, or did not verify. */
  invalid: number;
  /** More files were in range than `maxFiles` allowed. */
  truncated: boolean;
};

/**
 * Valid records for `query.keys` newer than `query.since`, sorted by `t`. Only
 * day directories from the later of `since`'s day and the retention window's
 * start are read; within them, files named before `since` are skipped unread.
 */
export function readLedger(paths: IntegrityPaths, signer: Signer, query: LedgerQuery): LedgerRead {
  const { keys, now, maxFiles = DEFAULT_MAX_FILES, retentionMs = RETENTION_MS } = query;
  // An unparseable `acceptedAt` (NaN) reads the whole retention window rather than throwing.
  const since = Number.isFinite(query.since) ? query.since : 0;
  const firstDay = ledgerDayStart(ledgerDayName(Math.max(since, now - retentionMs)));
  const records: LedgerEntry[] = [];
  let invalid = 0;
  let opened = 0;
  let truncated = false;

  const days = listDir(paths.ledgerDir, DAY_DIR_SCAN_LIMIT);
  if (days.more) truncated = true;
  const inRange = days.names
    .map((name) => ({ name, start: ledgerDayStart(name) }))
    .filter((d): d is { name: string; start: number } => d.start !== null && (firstDay === null || d.start >= firstDay))
    .sort((a, b) => a.start - b.start);

  outer: for (const { name: day } of inRange) {
    const files = listDir(join(paths.ledgerDir, day), DAY_FILE_SCAN_LIMIT);
    if (files.more) truncated = true;
    const named: { name: string; ms: number }[] = [];
    for (const name of files.names) {
      const m = LEDGER_RECORD_NAME.exec(name);
      if (m) named.push({ name, ms: Number(m[1]) });
      else invalid++;
    }
    named.sort((a, b) => a.ms - b.ms || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const { name, ms } of named) {
      if (ms <= since) continue; // named for its write time, which is its `t`: not after `since`
      if (opened >= maxFiles) {
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
      if (Date.parse(record.t) > since) records.push({ ...record, file: `${day}/${name}` });
    }
  }

  records.sort((a, b) => Date.parse(a.t) - Date.parse(b.t) || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  return { records, invalid, truncated };
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

function applyEdits(current: string | null, edits: readonly EditOp[]): SimulatedWrite {
  let text = current;
  let approx = false;
  let work = MAX_SIMULATION_WORK;
  for (let i = 0; i < edits.length; i++) {
    const { oldString, newString, replaceAll } = edits[i];
    const base = text ?? "";
    // Scanning `base` and building a result about as long, charged up front;
    // once the budget cannot cover that, this edit and every later one are appended.
    if (2 * base.length > work) return { text: appendAll(base, edits.slice(i)), approx: true };
    work -= 2 * base.length;
    if (oldString === "") {
      // Edit's way to create a file: only an absent or empty file takes new_string as its content.
      if (base === "") text = newString;
      else {
        text = appendChange(base, newString);
        approx = true;
      }
      continue;
    }
    const at = base.indexOf(oldString);
    if (at === -1) {
      text = appendChange(base, newString);
      approx = true;
      continue;
    }
    if (!replaceAll) {
      text = base.slice(0, at) + newString + base.slice(at + oldString.length);
      continue;
    }
    // split/join, never String.replace: `$&`, `$1`, … in new_string are literal text.
    const parts = base.split(oldString);
    const growth = (parts.length - 1) * (newString.length - oldString.length);
    // Whatever the result grows beyond `base` is built too, so it is charged as well.
    if (base.length + growth > MAX_SIMULATED_CHARS || growth > work) {
      text = appendChange(base, newString);
      approx = true;
      continue;
    }
    work -= Math.max(0, growth);
    text = parts.join(newString);
  }
  return { text: text ?? "", approx };
}

/**
 * The text a file-tool write leaves, from the tool's `tool_input` and the
 * file's current text (`null` when it does not exist or is over 4 MiB, which
 * the caller does not read). Pure string operations:
 *
 * - `Write`: `content`.
 * - `Edit`: the first occurrence of `old_string` replaced by `new_string`, or
 *   every (non-overlapping) occurrence with `replace_all: true`. An empty
 *   `old_string` on an absent or empty file creates it with `new_string`.
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
  if (tool === "Write") return typeof input.content === "string" ? { text: input.content, approx: false } : null;
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
