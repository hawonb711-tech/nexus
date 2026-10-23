/**
 * Instruction-file integrity — the SessionStart hook (spec §6.3-6.5 and §6.9,
 * amendments A1, A2, A3, A5 and A11).
 *
 * `sessionStartResponse(payload, deps)` fingerprints the files that steer
 * Claude Code, compares them with the signed baseline, persists what may
 * advance and answers with the §6.4 case. It never throws:
 *
 *  1. an invalid payload (no `session_id`, a `cwd` that is not an absolute path
 *     to a directory, a `transcript_path` that is not a string) → no output;
 *  2. a valid `.disabled` marker → no output;
 *  3. DEADLINE_MS (5 s) from here: past it, case F — or D/E with
 *     " (check incomplete)" when a SUSPECT or TAMPER was already computed — and
 *     nothing is advanced;
 *  4. an `s` line goes to the session log, and an earlier `s` line of the same
 *     source within 10 s from another process (a duplicate install) → no output;
 *  5. the signed state is loaded and verified (TAMPER, §5.6); on the machine's
 *     first run (no anchor and no key) the directory, key and anchor are
 *     created, and the answer is case B;
 *  6. the watched set is enumerated and hashed (stat fast path);
 *  7. every change is classified against the ledger (§5);
 *  8. under the store lock (1 s wait) the stores, registry, watch prefixes and
 *     log are written — classified again first if another session moved the
 *     registry meanwhile; a busy lock persists nothing and the output stands;
 *  9. `sessions/<sid16>.json` gets the indicator tokens of HOLD and SUSPECT
 *     lines, the MCP servers whose output is withheld and the held items shown,
 *     and a `t` line marks each SUSPECT or TAMPER item the model's frame carried;
 * 10. the answer is rendered for the payload's `source` (§6.5);
 * 11. old ledger days and session files are removed while time remains.
 *
 * Any other error after a valid payload is case G (fail open, but say so).
 * CLAUDE.md is already in the session when this runs (A11): the answer advises
 * the model and tells the user; it never claims to have blocked anything.
 * No subprocess, no network, no model API.
 */

import { isAbsolute, resolve } from "node:path";
import type { HookAnswer, HookDeps } from "../handler.js";
import type { ClassifyResult, EntryResult, StoreOutcome } from "./classify.js";
import { contextFromHook, type IntegrityContext } from "./context.js";
import type { Snapshot } from "./enumerate.js";
import { classifyState, hashersOf, loadState, newlyUnhashed, snapshotOf, type ClassifyOptions } from "./evaluate.js";
import type { LedgerEntry } from "./ledger.js";
import {
  displayPath, internalErrorMessage, loadSecretRedactor, renderNotice, renderSessionStart,
  type DisplayContext, type Incomplete, type SessionStartAnswer,
} from "./render.js";
import {
  appendSessionEvents, integrityDirExists, normalizeMcpServerName, normalizeSessionState, readSessionLog, readSessionState, sid16,
  writeSessionState, type SessionEvent,
} from "./session-log.js";
import {
  appendLog, collectGarbage, commitStores, initIntegrity, integrityPaths, isIntegrityDisabled, readRegistry, readWatchPrefixes,
  withStoreLock, writeWatchPrefixes, type IntegrityPaths, type IntegrityState, type PrefixData,
} from "./store.js";
import {
  DEADLINE_MS, LOCK_WAIT_SESSION_START_MS, NOTICE_CHANNEL, SCREEN_DEADLINE_MS,
  type IntegrityConfig, type NoticeChannel, type SessionIndicator, type SessionStateDoc,
} from "./types.js";

/** An earlier `s` line of the same source this recently, from another process, is a duplicate install's run. */
const DEDUPE_MS = 10_000;

/** The SessionStart answer for `payload` (a parsed JSON object). Never throws. */
export async function sessionStartResponse(payload: Record<string, unknown>, deps: HookDeps): Promise<HookAnswer> {
  const { session_id: sessionId, cwd, transcript_path: transcript } = payload;
  if (typeof sessionId !== "string" || sessionId === "") return { output: null };
  if (typeof cwd !== "string" || !isAbsolute(cwd)) return { output: null };
  if (transcript !== undefined && typeof transcript !== "string") return { output: null };
  const channel = deps.channel ?? NOTICE_CHANNEL;
  try {
    return await sessionStart(payload, sessionId, deps, channel);
  } catch (error) {
    try {
      return answerOf(renderNotice(internalErrorMessage(error), channel));
    } catch {
      return { output: null };
    }
  }
}

function answerOf(a: SessionStartAnswer): HookAnswer {
  return {
    output: a.output,
    ...(a.stderr !== undefined ? { stderr: a.stderr } : {}),
    ...(a.exitCode !== undefined ? { exitCode: a.exitCode } : {}),
  };
}

async function sessionStart(payload: Record<string, unknown>, sessionId: string, deps: HookDeps, channel: NoticeChannel): Promise<HookAnswer> {
  const paths = integrityPaths(resolve(deps.dataDir));
  // 2. Turned off by the human-gated CLI.
  if (isIntegrityDisabled(paths)) return { output: null };

  // 3. The deadline, on the injected clock.
  const clock = deps.now;
  const start = clock();
  const deadline = start + DEADLINE_MS;
  const expired = () => clock() >= deadline;
  const now = new Date(start);

  const ctx = contextFromHook(payload, {
    platform: deps.platform, homedir: deps.homedir, env: deps.env, dataDir: paths.dataDir,
    ...(deps.managedDir !== undefined ? { managedDir: deps.managedDir } : {}),
  });
  if (!ctx) return { output: null }; // cwd is not a directory
  const sid = sid16(sessionId);
  const source = typeof payload.source === "string" ? payload.source : undefined;
  const evalDeps = { dataDir: paths.dataDir, homedir: deps.homedir, platform: deps.platform, ...(deps.nexusEntries ? { nexusEntries: deps.nexusEntries } : {}) };

  // 4. Log this run and dedupe a duplicate install's (once there is a directory to log in).
  let logged = false;
  const duplicate = (): boolean => {
    if (logged || !integrityDirExists(paths.dataDir)) return false;
    logged = true;
    return isDuplicate(paths.dataDir, sid, source ?? "startup", start, deps.pid);
  };
  if (duplicate()) return { output: null };

  // 5. Load and verify; the machine's first run creates the directory, key and anchor.
  let state = loadState(ctx, evalDeps);
  const machineFirstRun = state.machineFirstRun;
  if (machineFirstRun) {
    const init = initIntegrity(paths, now);
    if (!init.ok) throw new Error(`the integrity key ${init.why}`);
    if (duplicate()) return { output: null };
    state = loadState(ctx, evalDeps);
  }

  const redact = await loadSecretRedactor();
  const display: DisplayContext = { root: ctx.root, home: ctx.home, platform: ctx.platform, redact };
  const prior = readSessionState(paths.dataDir, sid);

  // 6-7. Enumerate, hash and classify, within the deadline.
  const { snapshot, ledger } = snapshotOf(ctx, state, evalDeps, { now: start, fastPath: true });
  const run: ClassifyOptions = {
    now, machineFirstRun, expired,
    stopScreening: () => clock() >= start + SCREEN_DEADLINE_MS,
    windows: { deadline, clock },
  };
  let result: ClassifyResult | null = null;
  let late = expired();
  if (!late) {
    result = classifyState(ctx, state, snapshot, ledger, run);
    late = result.incomplete || expired();
  }

  // 8. Persist under the lock (nothing past the deadline).
  if (result && !late) {
    const persisted = persist({ ctx, deps: evalDeps, state, snapshot, ledger, result, run, paths, clock, deadline });
    result = persisted.result;
    state = persisted.state;
    late = result.incomplete;
  }

  // 10. Render for the source (before 9: the session state records what it showed).
  const hashers = hashersOf(state.signer);
  const incomplete: Incomplete | undefined = late
    ? { reason: "deadline" }
    : limitsIncomplete(state, snapshot);
  const answer = renderSessionStart({
    result: result ?? { items: [], listing: null, machineFirstRun, tamper: storesTamper(state, snapshot) },
    ...(source !== undefined ? { source } : {}),
    shown: prior?.shown ?? [],
    quoteFlaggedLines: state.config.quoteFlaggedLines,
    display,
    nonce: hashers.nonce,
    ...(incomplete ? { incomplete } : {}),
    channel,
  });

  // 9. This session's state, and a taint line per SUSPECT / TAMPER item delivered.
  const items = result?.items ?? [];
  saveSessionState(paths.dataDir, prior, {
    v: 1, sid, at: now.toISOString(),
    indicators: indicatorsOf(items, display, late ? prior?.indicators : undefined),
    withheldMcp: withheldOf(items, state.config.withholdMcp, late ? prior?.withheldMcp : undefined),
    shown: answer.shown,
  });
  appendSessionEvents(paths.dataDir, sid, answer.delivered.map((heldId) => ({ kind: "t" as const, t: start, heldId })));

  // 11. Retention, only while time remains.
  if (!expired()) collectGarbage(paths, { now: start, deadline, clock });

  return answerOf(answer);
}

// ── Dedupe (§6.3 step 4) ────────────────────────────────────────────────────

/**
 * Append this run's `s` line, then read the log back: an `s` line before it
 * with the same source, from another process, within 10 s of it, means a
 * second Nexus install already answers this SessionStart. Of two runs racing,
 * the one whose line lands second steps aside. A log that cannot be written or
 * read dedupes nothing.
 */
function isDuplicate(dataDir: string, sid: string, source: string, t: number, pid: number): boolean {
  if (!appendSessionEvents(dataDir, sid, [{ kind: "s", t, source, pid }])) return false;
  const starts = readSessionLog(dataDir, sid).events.filter((ev): ev is Extract<SessionEvent, { kind: "s" }> => ev.kind === "s");
  const at = Math.floor(t);
  let own = -1;
  for (let i = starts.length - 1; i >= 0 && own < 0; i--) if (starts[i].pid === pid && starts[i].t === at) own = i;
  if (own < 0) return false;
  // sources compared as the log stores them (cut and cleaned)
  const stored = starts[own].source;
  return starts.slice(0, own).some((ev) => ev.source === stored && ev.pid !== pid && Math.abs(ev.t - at) <= DEDUPE_MS);
}

// ── Persisting (§6.3 step 8, §4.8) ──────────────────────────────────────────

type PersistInput = {
  ctx: IntegrityContext;
  deps: Parameters<typeof loadState>[1];
  state: IntegrityState;
  snapshot: Snapshot;
  ledger: readonly LedgerEntry[];
  result: ClassifyResult;
  run: ClassifyOptions;
  paths: IntegrityPaths;
  clock: () => number;
  deadline: number;
};

/** The store documents a result commits: those with a next document that differs from the baseline. */
function storesToWrite(result: ClassifyResult): NonNullable<StoreOutcome["next"]>[] {
  const outcomes = [result.stores.global, result.stores.project, result.stores.memory];
  return outcomes.filter((o): o is StoreOutcome => !!o && !!o.next && o.dirty).map((o) => o.next!);
}

function samePrefixes(a: PrefixData | null, b: PrefixData): boolean {
  if (!a) return false;
  const same = (x: readonly string[], y: readonly string[]) => x.length === y.length && x.every((v, i) => v === y[i]);
  return same(a.memoryDirs, b.memoryDirs) && same(a.configDirs, b.configDirs)
    && same(a.importTargets, b.importTargets) && same(a.hookScripts, b.hookScripts);
}

/**
 * Write what the classification advanced, under the store lock (waiting at most
 * 1 s, and never past the deadline). Nothing to write takes no lock. When the
 * registry moved since it was loaded (another session committed), the state is
 * loaded and the snapshot classified again first. A busy lock, a registry that
 * stopped verifying, or a write that fails leaves the stores as they were: the
 * computed answer is still given, and the next session persists.
 */
function persist(p: PersistInput): { result: ClassifyResult; state: IntegrityState } {
  const { paths, snapshot } = p;
  const unchanged = { result: p.result, state: p.state };
  if (!p.state.signer) return unchanged; // no trusted key: nothing can be signed (every store is TAMPER)
  const prefixesChanged = !p.state.tamper.length && !samePrefixes(readWatchPrefixes(paths), snapshot.prefixes);
  if (storesToWrite(p.result).length === 0 && p.result.log.length === 0 && !prefixesChanged) return unchanged;
  const waitMs = Math.max(0, Math.min(LOCK_WAIT_SESSION_START_MS, p.deadline - p.clock()));
  try {
    const locked = withStoreLock(paths, () => {
      let { state, result } = p;
      const onDisk = readRegistry(paths, state.signer);
      const macOnDisk = onDisk.state === "missing" ? null : onDisk.doc?.mac ?? "";
      if (macOnDisk !== (state.registry?.mac ?? null)) {
        state = loadState(p.ctx, p.deps);
        result = classifyState(p.ctx, state, snapshot, p.ledger, p.run);
        if (result.incomplete || !state.signer) return { result, state };
      }
      const writes = storesToWrite(result);
      if (writes.length) commitStores(paths, state.signer!, state.registry, { write: writes }, p.run.now);
      if (prefixesChanged) writeWatchPrefixes(paths, snapshot.prefixes, p.run.now);
      appendLog(paths, result.log);
      return { result, state };
    }, waitMs);
    return locked.ok ? locked.value : unchanged;
  } catch {
    // RegistryTamperError (the registry stopped verifying), or an I/O failure:
    // the answer still stands, and nothing advanced
    return unchanged;
  }
}

// ── Rendering inputs ────────────────────────────────────────────────────────

/** The TAMPER reasons of the context's stores, for an answer given before classification ran. */
function storesTamper(state: IntegrityState, snapshot: Snapshot): ClassifyResult["tamper"] {
  const ids = [snapshot.global.id, snapshot.project.id, ...(snapshot.memory ? [snapshot.memory.id] : [])];
  return ids.flatMap((id) => {
    const reason = state.stores[id]?.tamper ?? state.tamper[0] ?? null;
    return reason ? [{ store: id, reason }] : [];
  });
}

/** Case F's "over the scan limits", when the run left files unhashed that the stores do not record as such. */
function limitsIncomplete(state: IntegrityState, snapshot: Snapshot): Incomplete | undefined {
  const files = newlyUnhashed(state, snapshot);
  return files > 0 ? { reason: "limits", files } : undefined;
}

// ── Session state (§4.6) ────────────────────────────────────────────────────

/**
 * Indicator tokens: the novel URLs, hosts, emails, paths and commands of the
 * added lines of SUSPECT, then HOLD, items, secrets masked, each with the file
 * it came from. With `kept` (a run cut short by the deadline), the session's
 * earlier indicators are kept too: indicators only ever add asks.
 */
function indicatorsOf(items: readonly EntryResult[], display: DisplayContext, kept: readonly SessionIndicator[] = []): SessionIndicator[] {
  const out: SessionIndicator[] = [];
  const redact = display.redact ?? ((s: string) => s);
  for (const tier of ["SUSPECT", "HOLD"] as const) {
    for (const item of items) {
      if (item.tier !== tier || item.tamper) continue;
      const file = displayPath(item.path, display);
      for (const token of item.novel) out.push({ t: redact(token.value), file, tier });
    }
  }
  out.push(...kept);
  return out; // deduplicated, at least 6 characters, at most MAX_INDICATORS: normalizeSessionState
}

/** Does a hunk's text come from the user (an approved prompt) or Nexus? Their MCP servers are never withheld. */
const byUser = (item: EntryResult, i: number) => {
  const a = item.hunks[i].attribution;
  return a.kind === "nexus" || (a.kind === "agent" && a.prompted);
};

/**
 * MCP servers whose output PostToolUse withholds (§6.8): with `withholdMcp`
 * "suspect" (the default), each server a SUSPECT item adds whose configuration
 * a detector flagged (or any it adds under TAMPER); with "unreviewed", every
 * server a HOLD or SUSPECT item adds by a writer other than the user; "off",
 * none. Each is listed by its raw name and, when it differs, by the form
 * Claude Code puts in tool names (A9).
 */
function withheldOf(items: readonly EntryResult[], mode: IntegrityConfig["withholdMcp"], kept: SessionStateDoc["withheldMcp"] = []): SessionStateDoc["withheldMcp"] {
  if (mode === "off") return [];
  const out = new Map<string, string>();
  const add = (name: string, reason: string) => {
    for (const n of [name, normalizeMcpServerName(name)]) if (n !== "" && !out.has(n)) out.set(n, reason);
  };
  for (const item of items) {
    if (item.tier !== "SUSPECT" && !(item.tier === "HOLD" && mode === "unreviewed")) continue;
    item.hunks.forEach((h, i) => {
      if (h.unit?.kind !== "mcp-server" || h.unit.name === undefined || byUser(item, i)) return;
      const flagged = h.verdict !== null || item.tamper !== null;
      if (!flagged && mode !== "unreviewed") return;
      add(h.unit.name, h.verdict?.reason ?? item.reasons[0] ?? "not reviewed");
    });
  }
  for (const w of kept) add(w.name, w.reason);
  return [...out].map(([name, reason]) => ({ name, reason }));
}

/**
 * Write `sessions/<sid16>.json` when it says something new (absent, nothing to
 * say, is the same as empty). Best effort: a session file that cannot be
 * written costs only the tripwires, not the answer.
 */
function saveSessionState(dataDir: string, prior: SessionStateDoc | null, doc: SessionStateDoc): void {
  const next = normalizeSessionState(doc, doc.sid);
  if (!next) return;
  const body = (d: SessionStateDoc) => JSON.stringify([d.indicators, d.withheldMcp, d.shown]);
  const empty = next.indicators.length === 0 && next.withheldMcp.length === 0 && next.shown.length === 0;
  if (prior ? body(prior) === body(next) : empty) return;
  try {
    writeSessionState(dataDir, next);
  } catch {
    // best effort
  }
}
