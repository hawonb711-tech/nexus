/**
 * Instruction-file integrity — per-session activity (spec §4.6).
 *
 * `sessions/<sid16>.log` holds tab-separated lines, each appended with ONE
 * write() on an O_APPEND descriptor so concurrent hooks never tear a line:
 *
 *   s <epochMs> <source> <pid>           SessionStart ran
 *   a <epochMs> <tool> <tailMs>          tool activity (PreToolUse; PostToolUse for mcp__*)
 *   x <epochMs> <tool>                   exposure: a WebFetch / WebSearch / mcp__ result, or a network-fetch Bash
 *   f <epochMs> <tool> <rule>            a tool result was flagged warn/block → tainted
 *   t <epochMs> session-start <heldId>   a SUSPECT item was delivered → tainted
 *
 * The log is unsigned: a line can only raise the session's level or widen an
 * activity window, never lower or narrow anything. Tabs and newlines inside
 * fields become spaces, a line is at most 1 KB, and readers skip malformed lines.
 *
 * `sessions/<sid16>.json` is SessionStart's state for that session (indicator
 * tokens, withheld MCP servers, held items already shown), written atomically.
 *
 * `sid16 = sha256(session_id)[:16]`, so payload text never becomes a path.
 *
 * The hook handler imports this module statically on every PreToolUse and
 * PostToolUse, so it stays tiny: appending costs one existsSync of D/integrity
 * and one append, and nothing here throws on the hot path.
 */

import { closeSync, constants, existsSync, lstatSync, openSync, writeSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { atomicWriteFile, ensurePrivateDir } from "../../shared/atomic-file.js";
import { listDir, readPrivateJson, readPrivateText } from "./private-file.js";
import type { SessionIndicator, SessionLevel, SessionStateDoc } from "./types.js";

// types.ts's INTEGRITY_DIR, SESSIONS_DIR and MAX_INDICATORS, repeated so this
// hot-path module loads no runtime code from types.ts (session-log.test.ts
// checks they agree).
const INTEGRITY_DIR = "integrity";
const SESSIONS_DIR = "sessions";
const MAX_INDICATORS = 32;

const SID16 = /^[0-9a-f]{16}$/;

/** `sha256(session_id)[:16]`: the session's file name and ledger `sid`. */
export function sid16(sessionId: string): string {
  return createHash("sha256").update(sessionId).digest("hex").slice(0, 16);
}

function sessionFile(dataDir: string, sid: string, ext: "log" | "json"): string {
  if (!SID16.test(sid)) throw new TypeError("not a sid16");
  return join(dataDir, INTEGRITY_DIR, SESSIONS_DIR, `${sid}.${ext}`);
}

/** D/integrity exists: integrity was enabled on this machine (state may be written). */
export function integrityDirExists(dataDir: string): boolean {
  return existsSync(join(dataDir, INTEGRITY_DIR));
}

// ── Lines ───────────────────────────────────────────────────────────────────

export type SessionEvent =
  | { kind: "s"; t: number; source: string; pid: number }
  | { kind: "a"; t: number; tool: string; tailMs: number }
  | { kind: "x"; t: number; tool: string }
  | { kind: "f"; t: number; tool: string; rule: string }
  | { kind: "t"; t: number; heldId: string };

/** The longest `a` tail a reader accepts (a background command's). */
const MAX_TAIL_MS = 7_200_000;
const DEFAULT_TAIL_MS = 30_000;
const SHELL_TAIL_SLACK_MS = 30_000;
const SHELL_DEFAULT_TIMEOUT_MS = 120_000;
const SHELL_MAX_TIMEOUT_MS = 600_000;

/**
 * Characters kept per text field. At most 3 UTF-8 bytes per UTF-16 unit, so two
 * text fields, the kind, a 16-digit time, a number and the separators stay
 * under 1 KB per line — and a long field never cuts off the fields after it.
 */
const MAX_FIELD_CHARS = 160;

const field = (s: string) => s.slice(0, MAX_FIELD_CHARS).replace(/[\t\r\n]/g, " ");

/** One line, without its newline: text fields cut to MAX_FIELD_CHARS, tabs and newlines in them made spaces. */
function formatSessionLine(ev: SessionEvent): string {
  const t = String(Math.max(0, Math.floor(ev.t)));
  switch (ev.kind) {
    case "s": return ["s", t, field(ev.source), String(ev.pid)].join("\t");
    case "a": return ["a", t, field(ev.tool), String(Math.min(MAX_TAIL_MS, Math.max(0, Math.floor(ev.tailMs))))].join("\t");
    case "x": return ["x", t, field(ev.tool)].join("\t");
    case "f": return ["f", t, field(ev.tool), field(ev.rule)].join("\t");
    case "t": return ["t", t, "session-start", field(ev.heldId)].join("\t");
  }
}

const UINT = /^\d{1,16}$/;

/** The event on one line, or null for anything malformed (wrong kind, field count or number). */
function parseSessionLine(line: string): SessionEvent | null {
  const f = (line.endsWith("\r") ? line.slice(0, -1) : line).split("\t");
  if (f.length < 3 || !UINT.test(f[1])) return null;
  const t = Number(f[1]);
  switch (f[0]) {
    case "s":
      return f.length === 4 && UINT.test(f[3]) ? { kind: "s", t, source: f[2], pid: Number(f[3]) } : null;
    case "a": {
      if (f.length !== 4 || !UINT.test(f[3])) return null;
      const tailMs = Number(f[3]);
      return tailMs <= MAX_TAIL_MS ? { kind: "a", t, tool: f[2], tailMs } : null;
    }
    case "x":
      return f.length === 3 ? { kind: "x", t, tool: f[2] } : null;
    case "f":
      return f.length === 4 ? { kind: "f", t, tool: f[2], rule: f[3] } : null;
    case "t":
      return f.length === 4 ? { kind: "t", t, heldId: f[3] } : null;
    default:
      return null;
  }
}

/**
 * How long after an `a` line a tool may still be writing: Bash / PowerShell
 * `min(timeout ?? 120000, 600000) + 30000`; `run_in_background: true` 7200000;
 * any other tool 30000.
 */
export function tailMsFor(tool: string, toolInput: unknown): number {
  const input = toolInput && typeof toolInput === "object" ? (toolInput as Record<string, unknown>) : {};
  if (input.run_in_background === true) return MAX_TAIL_MS;
  if (tool === "Bash" || tool === "PowerShell") {
    const timeout = typeof input.timeout === "number" && Number.isFinite(input.timeout) && input.timeout >= 0
      ? Math.floor(input.timeout)
      : SHELL_DEFAULT_TIMEOUT_MS;
    return Math.min(timeout, SHELL_MAX_TIMEOUT_MS) + SHELL_TAIL_SLACK_MS;
  }
  return DEFAULT_TAIL_MS;
}

/** Append, creating the file if needed, but never through a symlink planted at the path. */
const APPEND_FLAGS = constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0);

function appendOnce(path: string, text: string): void {
  const fd = openSync(path, APPEND_FLAGS, 0o600);
  try {
    writeSync(fd, text);
  } finally {
    closeSync(fd);
  }
}

/**
 * Append `events` to the session's log in one write. Does nothing (false) when
 * D/integrity does not exist — a user who never enabled integrity gets no state —
 * and never throws: a failed append is false, and the caller carries on.
 */
export function appendSessionEvents(dataDir: string, sid: string, events: readonly SessionEvent[]): boolean {
  try {
    if (events.length === 0 || !integrityDirExists(dataDir)) return false;
    const path = sessionFile(dataDir, sid, "log");
    const text = events.map((ev) => `${formatSessionLine(ev)}\n`).join("");
    try {
      appendOnce(path, text);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") return false;
      ensurePrivateDir(join(dataDir, INTEGRITY_DIR, SESSIONS_DIR));
      appendOnce(path, text);
    }
    return true;
  } catch {
    return false;
  }
}

// ── Reading the log: level and activity windows ────────────────────────────

/** A log larger than this is not parsed (see `readSessionLog`). */
const MAX_SESSION_LOG_BYTES = 16 * 1024 * 1024;

export type SessionLog = {
  events: SessionEvent[];
  /** Lines skipped as malformed. */
  malformed: number;
  /** The log was over MAX_SESSION_LOG_BYTES (or not a regular file) and was not parsed. */
  unreadable: boolean;
};

function parseLog(text: string): { events: SessionEvent[]; malformed: number } {
  const events: SessionEvent[] = [];
  let malformed = 0;
  for (const line of text.split("\n")) {
    if (line === "") continue;
    const ev = parseSessionLine(line);
    if (ev) events.push(ev);
    else malformed++;
  }
  return { events, malformed };
}

/** The session's log; a missing log is empty. Malformed lines are skipped and counted. */
export function readSessionLog(dataDir: string, sid: string): SessionLog {
  const read = readPrivateText(sessionFile(dataDir, sid, "log"), MAX_SESSION_LOG_BYTES);
  if (read.state === "missing") return { events: [], malformed: 0, unreadable: false };
  if (read.state === "invalid") return { events: [], malformed: 0, unreadable: true };
  return { ...parseLog(read.text), unreadable: false };
}

/**
 * `tainted` if any `f` or `t` line exists, else `exposed` if any `x` line does,
 * else `clean` (a missing log is clean). A log that could not be parsed — only
 * possible when it was inflated past 16 MiB or replaced by something that is
 * not a file — reads as `tainted`, because lines only ever raise the level.
 */
export function sessionLevel(log: Pick<SessionLog, "events" | "unreadable">): SessionLevel {
  if (log.unreadable) return "tainted";
  let level: SessionLevel = "clean";
  for (const ev of log.events) {
    if (ev.kind === "f" || ev.kind === "t") return "tainted";
    if (ev.kind === "x") level = "exposed";
  }
  return level;
}

/** `[start, end]` epoch ms, inclusive. */
export type ActivityWindow = [start: number, end: number];

const MCP_BEFORE_MS = 120_000;
const MCP_AFTER_MS = 2_000;
const ACTIVITY_BEFORE_MS = 2_000;

/**
 * Agent-activity windows, used only to ESCALATE an unknown change: an `a` line
 * at t gives `[t − 2000, t + tailMs]`; an `x` line at t for an `mcp__` tool
 * gives `[t − 120000, t + 2000]` (MCP tools have no PreToolUse point and may
 * write before their result is seen). Sorted and merged.
 */
export function activityWindows(events: readonly SessionEvent[]): ActivityWindow[] {
  const out: ActivityWindow[] = [];
  for (const ev of events) {
    if (ev.kind === "a") out.push([ev.t - ACTIVITY_BEFORE_MS, ev.t + ev.tailMs]);
    else if (ev.kind === "x" && ev.tool.startsWith("mcp__")) out.push([ev.t - MCP_BEFORE_MS, ev.t + MCP_AFTER_MS]);
  }
  return mergeWindows(out);
}

/** Sorted, non-overlapping union of `windows`. */
function mergeWindows(windows: readonly ActivityWindow[]): ActivityWindow[] {
  const sorted = [...windows].sort((a, b) => a[0] - b[0]);
  const out: ActivityWindow[] = [];
  for (const [start, end] of sorted) {
    const last = out[out.length - 1];
    if (last && start <= last[1]) last[1] = Math.max(last[1], end);
    else out.push([start, end]);
  }
  return out;
}

/** Is `t` inside one of `windows` (sorted and merged, as `activityWindows` returns them)? */
export function inWindows(windows: readonly ActivityWindow[], t: number): boolean {
  let lo = 0;
  let hi = windows.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (t < windows[mid][0]) hi = mid - 1;
    else if (t > windows[mid][1]) lo = mid + 1;
    else return true;
  }
  return false;
}

const LOG_NAME = /^[0-9a-f]{16}\.log$/;
const SESSION_DIR_SCAN_LIMIT = 50_000;
const DEFAULT_MAX_LOGS = 5000;

export type WindowScan = {
  windows: ActivityWindow[];
  /** Logs read. */
  scanned: number;
  /** Some logs were not read (too many, or unreadable): the windows may be missing some activity. */
  incomplete: boolean;
};

/**
 * The merged activity windows of every session log (any project) last modified
 * at or after `sinceMs`; older logs are never opened. At most `maxLogs` are read.
 */
export function activityWindowsSince(dataDir: string, sinceMs: number, maxLogs = DEFAULT_MAX_LOGS): WindowScan {
  const dir = join(dataDir, INTEGRITY_DIR, SESSIONS_DIR);
  const listed = listDir(dir, SESSION_DIR_SCAN_LIMIT);
  let incomplete = listed.more;
  let scanned = 0;
  const all: ActivityWindow[] = [];
  for (const name of listed.names) {
    if (!LOG_NAME.test(name)) continue;
    let mtimeMs: number;
    try {
      mtimeMs = lstatSync(join(dir, name)).mtimeMs;
    } catch {
      continue;
    }
    if (mtimeMs < sinceMs) continue;
    if (scanned >= maxLogs) {
      incomplete = true;
      break;
    }
    scanned++;
    const read = readPrivateText(join(dir, name), MAX_SESSION_LOG_BYTES);
    if (read.state !== "ok") {
      if (read.state === "invalid") incomplete = true;
      continue;
    }
    for (const w of activityWindows(parseLog(read.text).events)) all.push(w);
  }
  return { windows: mergeWindows(all), scanned, incomplete };
}

// ── sessions/<sid16>.json ───────────────────────────────────────────────────

/** Shortest indicator kept: shorter tokens would trip on ordinary commands. */
const MIN_INDICATOR_CHARS = 6;
const MAX_INDICATOR_CHARS = 2048;
const MAX_WITHHELD = 64;
const MAX_SHOWN = 256;
const MAX_STATE_BYTES = 1024 * 1024;

const isRec = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/**
 * The state with every list bounded: indicators lower-cased (they are matched
 * against lower-cased commands and write text), at least 6 and at most 2,048
 * characters, deduplicated, at most MAX_INDICATORS (32); malformed items dropped.
 */
function normalizeState(raw: unknown, sid: string): SessionStateDoc | null {
  if (!isRec(raw) || raw.v !== 1 || raw.sid !== sid || typeof raw.at !== "string") return null;
  const indicators: SessionIndicator[] = [];
  const seen = new Set<string>();
  for (const item of Array.isArray(raw.indicators) ? raw.indicators : []) {
    if (indicators.length >= MAX_INDICATORS) break;
    if (!isRec(item) || typeof item.t !== "string" || typeof item.file !== "string") continue;
    if (item.tier !== "HOLD" && item.tier !== "SUSPECT") continue;
    const t = item.t.toLowerCase();
    if (t.length < MIN_INDICATOR_CHARS || t.length > MAX_INDICATOR_CHARS || seen.has(t)) continue;
    seen.add(t);
    indicators.push({ t, file: item.file, tier: item.tier });
  }
  const withheldMcp = (Array.isArray(raw.withheldMcp) ? raw.withheldMcp : [])
    .filter((w): w is { name: string; reason: string } => isRec(w) && typeof w.name === "string" && w.name !== "" && typeof w.reason === "string")
    .slice(0, MAX_WITHHELD)
    .map((w) => ({ name: w.name, reason: w.reason }));
  const shown = (Array.isArray(raw.shown) ? raw.shown : []).filter((s): s is string => typeof s === "string").slice(0, MAX_SHOWN);
  return { v: 1, sid, at: raw.at, indicators, withheldMcp, shown };
}

/** The session's state, or null when it is missing or malformed. */
export function readSessionState(dataDir: string, sid: string): SessionStateDoc | null {
  const read = readPrivateJson(sessionFile(dataDir, sid, "json"), MAX_STATE_BYTES);
  return read.state === "ok" ? normalizeState(read.value, sid) : null;
}

/**
 * Write the session's state atomically (bounded as `readSessionState` reads
 * it). False, writing nothing, when D/integrity does not exist. Throws on I/O
 * failure, or a TypeError for a `sid` that is not a sid16.
 */
export function writeSessionState(dataDir: string, doc: SessionStateDoc): boolean {
  const path = sessionFile(dataDir, doc.sid, "json");
  if (!integrityDirExists(dataDir)) return false;
  const state = normalizeState(doc, doc.sid);
  if (!state) throw new TypeError("malformed session state");
  ensurePrivateDir(join(dataDir, INTEGRITY_DIR, SESSIONS_DIR));
  atomicWriteFile(path, JSON.stringify(state), { mode: 0o600, fsync: true });
  return true;
}
