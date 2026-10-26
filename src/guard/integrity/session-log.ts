/**
 * Instruction-file integrity — per-session activity (spec §4.6).
 *
 * `sessions/<sid16>.log` holds tab-separated lines, each appended with ONE
 * write() on an O_APPEND descriptor so concurrent hooks never tear a line:
 *
 *   s <epochMs> <source> <pid> <claude>  SessionStart ran (claude: the Claude Code process, when CLAUDE_PID names one)
 *   p <epochMs> <root>                   the project root SessionStart resolved for the session
 *   a <epochMs> <tool> <tailMs>          tool activity (PreToolUse; PostToolUse for mcp__*)
 *   x <epochMs> <tool>                   exposure: a WebFetch / WebSearch / mcp__ result, or a network-fetch Bash
 *   f <epochMs> <tool> <rule>            a tool result was flagged warn/block → tainted
 *   t <epochMs> session-start <heldId>   a SUSPECT item was delivered → tainted
 *
 * The log is unsigned: a line can only raise the session's level or widen an
 * activity window, never lower or narrow anything — but for `p`: a session's
 * windows count for the files of its own project (classify.ts), and one with
 * no `p` line for every file. Writing a log takes a write into Nexus's own
 * store, which the guard denies, and then deleting its `a` lines narrows as
 * much. Tabs and newlines inside fields become spaces, a line is at most 1 KB,
 * and readers skip malformed lines.
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

import { existsSync, lstatSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { atomicWriteFile, ensurePrivateDir } from "../../shared/atomic-file.js";
import { appendPrivateText, listDir, readPrivateJson, readPrivateText } from "./private-file.js";
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
  | { kind: "s"; t: number; source: string; pid: number; claudePid?: number }
  | { kind: "p"; t: number; root: string }
  | { kind: "a"; t: number; tool: string; tailMs: number }
  | { kind: "x"; t: number; tool: string }
  | { kind: "f"; t: number; tool: string; rule: string }
  | { kind: "t"; t: number; heldId: string };

/** The longest `a` tail a reader accepts (a background command's): no window starts more than this before what it covers. */
export const MAX_TAIL_MS = 7_200_000;
const DEFAULT_TAIL_MS = 30_000;
const SHELL_TAIL_SLACK_MS = 30_000;
const SHELL_DEFAULT_TIMEOUT_MS = 120_000;
const SHELL_MAX_TIMEOUT_MS = 600_000;
/** A shell call's tail with no timeout given, and the longest a call in the foreground can have: a longer one ran in the background. */
const SHELL_DEFAULT_TAIL_MS = SHELL_DEFAULT_TIMEOUT_MS + SHELL_TAIL_SLACK_MS;
const FOREGROUND_MAX_TAIL_MS = SHELL_MAX_TIMEOUT_MS + SHELL_TAIL_SLACK_MS;

/**
 * Characters kept per text field. At most 3 UTF-8 bytes per UTF-16 unit, so two
 * text fields, the kind, a 16-digit time, a number and the separators stay
 * under 1 KB per line — and a long field never cuts off the fields after it.
 */
const MAX_FIELD_CHARS = 160;

const field = (s: string) => s.slice(0, MAX_FIELD_CHARS).replace(/[\t\r\n]/g, " ");

/**
 * Characters of a `p` line's root, its one text field (at most 3 UTF-8 bytes
 * each: the line stays under 1 KB). A longer root, or one with a tab or line
 * break, is not written — never cut, which would name another directory — and
 * the session's windows then count for every file.
 */
const MAX_ROOT_CHARS = 300;
const rootFits = (root: string) => root !== "" && root.length <= MAX_ROOT_CHARS && !/[\t\r\n]/.test(root);

/** One line, without its newline: text fields cut to MAX_FIELD_CHARS, tabs and newlines in them made spaces. */
function formatSessionLine(ev: SessionEvent): string {
  const t = String(Math.max(0, Math.floor(ev.t)));
  switch (ev.kind) {
    case "s": return ["s", t, field(ev.source), String(ev.pid), ...(ev.claudePid !== undefined ? [String(ev.claudePid)] : [])].join("\t");
    case "p": return ["p", t, ev.root].join("\t");
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
      if (!UINT.test(f[3] ?? "")) return null;
      if (f.length === 4) return { kind: "s", t, source: f[2], pid: Number(f[3]) };
      return f.length === 5 && UINT.test(f[4]) ? { kind: "s", t, source: f[2], pid: Number(f[3]), claudePid: Number(f[4]) } : null;
    case "p":
      return f.length === 3 && rootFits(f[2]) ? { kind: "p", t, root: f[2] } : null;
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
 * `min(timeout ?? 120000, 600000) + 30000`; `run_in_background: true` 7200000
 * (the background process can outlive the call; readers count that only while
 * the session's agent runs, `activityWindows`); any other tool 30000.
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

/**
 * Append `events` to the session's log in one write. Does nothing (false) when
 * D/integrity does not exist — a user who never enabled integrity gets no state —
 * and never throws or blocks: a failed append (a symlink or FIFO planted at the
 * log path included) is false, and the caller carries on.
 */
export function appendSessionEvents(dataDir: string, sid: string, events: readonly SessionEvent[]): boolean {
  try {
    const lines = events.filter((ev) => ev.kind !== "p" || rootFits(ev.root));
    if (lines.length === 0 || !integrityDirExists(dataDir)) return false;
    const path = sessionFile(dataDir, sid, "log");
    const text = lines.map((ev) => `${formatSessionLine(ev)}\n`).join("");
    try {
      appendPrivateText(path, text);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") return false;
      ensurePrivateDir(join(dataDir, INTEGRITY_DIR, SESSIONS_DIR));
      appendPrivateText(path, text);
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
 * write before their result is seen). For a session whose agent has exited
 * (`ended`), a background command's tail is a foreground one's with no
 * timeout (150 s): the long tail covers a process a running agent left
 * working, and once the agent is gone its windows end with its last calls.
 * Sorted and merged.
 */
export function activityWindows(events: readonly SessionEvent[], ended = false): ActivityWindow[] {
  const out: ActivityWindow[] = [];
  for (const ev of events) {
    if (ev.kind === "a") {
      const tail = ended && ev.tailMs > FOREGROUND_MAX_TAIL_MS ? SHELL_DEFAULT_TAIL_MS : ev.tailMs;
      out.push([ev.t - ACTIVITY_BEFORE_MS, ev.t + tail]);
    } else if (ev.kind === "x" && ev.tool.startsWith("mcp__")) {
      out.push([ev.t - MCP_BEFORE_MS, ev.t + MCP_AFTER_MS]);
    }
  }
  return mergeWindows(out);
}

/**
 * Does process `pid` exist? `kill(pid, 0)` sends nothing: EPERM (another
 * user's process) is a yes, and so is any error but ESRCH, or a pid `kill`
 * cannot take.
 */
export function processAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0 || pid > 0x7fffffff) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

/**
 * Has the session's agent exited? Only when its `s` lines name the agent's
 * process (CLAUDE_PID) and none of those processes still runs. A log with no
 * `s` line, or with one from a hook that could not name it (Codex's; a Claude
 * Code without CLAUDE_PID), reads as still running, and so does a pid another
 * process took since: either only keeps a window open.
 */
function sessionEnded(events: readonly SessionEvent[], alive: (pid: number) => boolean): boolean {
  let named = false;
  for (const ev of events) {
    if (ev.kind !== "s") continue;
    if (ev.claudePid === undefined || alive(ev.claudePid)) return false;
    named = true;
  }
  return named;
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
/** Bytes of session logs read per scan, across logs. */
const DEFAULT_MAX_WINDOW_BYTES = 8 * 1024 * 1024;

export type WindowScanOptions = {
  /** Logs read at most (default 5,000). */
  maxLogs?: number;
  /** Bytes read at most, across logs (default 8 MiB). */
  maxBytes?: number;
  /** Epoch ms after which no further log is read (default: none). */
  deadline?: number;
  /** The clock `deadline` is measured on (default `Date.now`). */
  clock?: () => number;
  /** Tests: whether a process runs (default `processAlive`). */
  alive?: (pid: number) => boolean;
};

/**
 * One session's activity windows, the project roots its `p` lines name (none:
 * not known), whether its agent has exited since (`sessionEnded`; its windows
 * are then cut as `activityWindows` says), and its earliest line's time
 * (`first`: nothing it did is older).
 */
export type SessionWindows = { sid: string; roots: string[]; windows: ActivityWindow[]; ended: boolean; first: number };

export type WindowScan = {
  /** Every session's windows, merged. */
  windows: ActivityWindow[];
  /** The same by session (the sessions with a window). */
  sessions: SessionWindows[];
  /** Logs read. */
  scanned: number;
  /** Bytes read. */
  bytes: number;
  /**
   * Some logs in range were not read — too many, more bytes than the budget,
   * unreadable, or the deadline passed — so the windows may miss activity. A
   * caller that uses windows to escalate must then treat a change as inside one,
   * unless it is later than `missedUntil`.
   */
  partial: boolean;
  /**
   * The latest time a window of a log not read could cover: its last write
   * plus MAX_TAIL_MS, for the newest such log (the rest are older); -Infinity
   * when every log in range was read, Infinity when not every log was even
   * listed.
   */
  missedUntil: number;
};

/**
 * The merged activity windows of every session log (any project) last modified
 * at or after `sinceMs`, and each session's with the roots of its `p` lines;
 * older logs are never opened, and the rest are read newest first, so a cap
 * leaves out the oldest. At most `maxLogs` logs and `maxBytes` bytes are read,
 * and none once `deadline` has passed; past any of them the scan is `partial`,
 * up to `missedUntil`. A caller asks from the earliest change it judges minus
 * MAX_TAIL_MS: no older log has a window that reaches the change.
 */
export function activityWindowsSince(dataDir: string, sinceMs: number, opts: WindowScanOptions = {}): WindowScan {
  const { maxLogs = DEFAULT_MAX_LOGS, maxBytes = DEFAULT_MAX_WINDOW_BYTES, deadline = Number.POSITIVE_INFINITY, clock = Date.now, alive = processAlive } = opts;
  const dir = join(dataDir, INTEGRITY_DIR, SESSIONS_DIR);
  const listed = listDir(dir, SESSION_DIR_SCAN_LIMIT);
  const logs: { name: string; mtimeMs: number; size: number }[] = [];
  for (const name of listed.names) {
    if (!LOG_NAME.test(name)) continue;
    try {
      const st = lstatSync(join(dir, name));
      if (st.mtimeMs >= sinceMs) logs.push({ name, mtimeMs: st.mtimeMs, size: st.size });
    } catch {
      // gone since the listing
    }
  }
  logs.sort((a, b) => b.mtimeMs - a.mtimeMs || (a.name < b.name ? -1 : 1));
  let missedUntil = listed.more ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY;
  const missed = (log: { mtimeMs: number }) => {
    missedUntil = Math.max(missedUntil, log.mtimeMs + MAX_TAIL_MS);
  };
  const running = new Map<number, boolean>();
  const isAlive = (pid: number) => {
    let known = running.get(pid);
    if (known === undefined) running.set(pid, (known = alive(pid)));
    return known;
  };
  let scanned = 0;
  let bytes = 0;
  const all: ActivityWindow[] = [];
  const sessions: SessionWindows[] = [];
  for (const log of logs) {
    if (scanned >= maxLogs || bytes + log.size > maxBytes || clock() >= deadline) {
      missed(log); // the newest log left: every later one is older
      break;
    }
    scanned++;
    const read = readPrivateText(join(dir, log.name), Math.min(MAX_SESSION_LOG_BYTES, maxBytes - bytes));
    if (read.state !== "ok") {
      if (read.state === "invalid") missed(log); // replaced, or grew past the budget since its lstat
      continue;
    }
    bytes += Buffer.byteLength(read.text, "utf-8");
    const events = parseLog(read.text).events;
    const ended = sessionEnded(events, isAlive);
    const windows = activityWindows(events, ended);
    if (windows.length === 0) continue;
    for (const w of windows) all.push(w);
    const roots = [...new Set(events.flatMap((ev) => (ev.kind === "p" ? [ev.root] : [])))];
    const first = events.reduce((t, ev) => Math.min(t, ev.t), Number.POSITIVE_INFINITY);
    sessions.push({ sid: log.name.slice(0, 16), roots, windows, ended, first });
  }
  return { windows: mergeWindows(all), sessions, scanned, bytes, partial: missedUntil > Number.NEGATIVE_INFINITY, missedUntil };
}

// ── sessions/<sid16>.json ───────────────────────────────────────────────────

/**
 * An MCP server's name as Claude Code writes it into `mcp__<server>__<tool>`
 * (amendment A9): every character outside `[A-Za-z0-9_-]` becomes `_`, and for
 * a `claude.ai ` connector runs of `_` collapse to one and a leading or
 * trailing `_` is dropped. Withholding matches the raw and this form; two raw
 * names with one form share their tools' names, so withholding one withholds both.
 */
export function normalizeMcpServerName(name: string): string {
  const n = name.replace(/[^A-Za-z0-9_-]/g, "_");
  return name.startsWith("claude.ai ") ? n.replace(/_+/g, "_").replace(/^_|_$/g, "") : n;
}

/**
 * The reason a withheld MCP server carries when no detector flagged its
 * configuration: with `withholdMcp` "unreviewed", a server an unknown writer
 * added that the user has not accepted yet. PostToolUse words its message for it.
 */
export const UNREVIEWED_MCP_REASON = "added outside an edit you approved and not reviewed yet";

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
 * characters, deduplicated, at most MAX_INDICATORS (32); malformed items
 * dropped. One token listed twice is kept once, matched the stricter way: as
 * SUSPECT (with that item's file) if either is, and anywhere in the text
 * unless both are `cmd`. Null unless it is a state document for `sid`. What
 * `writeSessionState` writes and `readSessionState` returns.
 */
export function normalizeSessionState(raw: unknown, sid: string): SessionStateDoc | null {
  if (!isRec(raw) || raw.v !== 1 || raw.sid !== sid || typeof raw.at !== "string") return null;
  const indicators: SessionIndicator[] = [];
  const seen = new Map<string, SessionIndicator>();
  for (const item of Array.isArray(raw.indicators) ? raw.indicators : []) {
    if (!isRec(item) || typeof item.t !== "string" || typeof item.file !== "string") continue;
    if (item.tier !== "HOLD" && item.tier !== "SUSPECT") continue;
    const t = item.t.toLowerCase();
    if (t.length < MIN_INDICATOR_CHARS || t.length > MAX_INDICATOR_CHARS) continue;
    const cmd = item.cmd === true;
    const kept = seen.get(t);
    if (kept) {
      if (!cmd) delete kept.cmd;
      if (item.tier === "SUSPECT" && kept.tier !== "SUSPECT") Object.assign(kept, { tier: "SUSPECT", file: item.file });
      continue;
    }
    if (indicators.length >= MAX_INDICATORS) continue;
    const ind: SessionIndicator = { t, file: item.file, tier: item.tier, ...(cmd ? { cmd: true } : {}) };
    seen.set(t, ind);
    indicators.push(ind);
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
  return read.state === "ok" ? normalizeSessionState(read.value, sid) : null;
}

/**
 * Write the session's state atomically (bounded as `readSessionState` reads
 * it). False, writing nothing, when D/integrity does not exist. Throws on I/O
 * failure, or a TypeError for a `sid` that is not a sid16.
 */
export function writeSessionState(dataDir: string, doc: SessionStateDoc): boolean {
  const path = sessionFile(dataDir, doc.sid, "json");
  if (!integrityDirExists(dataDir)) return false;
  const state = normalizeSessionState(doc, doc.sid);
  if (!state) throw new TypeError("malformed session state");
  ensurePrivateDir(join(dataDir, INTEGRITY_DIR, SESSIONS_DIR));
  atomicWriteFile(path, JSON.stringify(state), { mode: 0o600, fsync: true });
  return true;
}
