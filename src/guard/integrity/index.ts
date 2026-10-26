/**
 * Instruction-file integrity — the library API behind `nexus guard integrity`
 * (spec §7).
 *
 * Read-only, exported from the `./guard` barrel:
 * - `integrityStatus(opts)`: the evaluation for a directory (the CLI's cwd),
 *   with no deadline and every file read — store state, hook, watched counts,
 *   auto memory, pending HOLD / SUSPECT items, recent log entries, tainted
 *   sessions — in the shape of `status --json`;
 * - `integrityDiff(opts)`: each changed or held file (or the named ones) with
 *   its tier, provenance per hunk, the added lines (cleaned, secrets masked,
 *   sentinels neutralised) and the count of removed lines, as `diff --json`.
 * Neither creates or replaces a key, takes the lock, or advances anything.
 *
 * Internal — the CLI calls these after its human gate (an interactive terminal,
 * outside Claude Code). No public barrel exports them, and MCP never does:
 * `acceptChanges`, `createBaseline`, `resetBaseline`, `readIntegrityLog`,
 * `getConfig`, `setConfig` (and `parseConfigSetting`, its check). The writers
 * work under the store lock (5 s wait).
 *
 * Context comes from the given cwd, never from a hook payload; the auto-memory
 * directory is the one the project store recorded at SessionStart, when it did.
 * `agent: "codex"` looks at Codex's user-level store instead of Claude Code's
 * (the project's files are the same either way), as a Codex session does.
 * Whether the hooks are present and live is install.ts's `checkNexusHooks`,
 * which `guard status` uses too, and for a Codex install codex/install.ts's
 * `checkCodexHooks`, which `guard status --codex` uses. The secret redactor is imported lazily
 * (`loadSecretRedactor`). Only the filesystem is touched: no subprocess (the
 * CLI adds the git hint), no network.
 */

import { accessSync, constants, existsSync, lstatSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { homedir as osHomedir } from "node:os";
import { dataDirFrom, nexusDataDir } from "../../shared/data-dir.js";
import { checkCodexHooks, type CodexHookCheck } from "../codex/install.js";
import { checkNexusHooks, staleDefaultSettings, type SettingsScope } from "../install.js";
import { pushHistory, versionTokens, type ChangeKind, type ClassifyResult, type EntryResult } from "./classify.js";
import { contextFromCli, type IntegrityContext } from "./context.js";
import type { Snapshot, SnapshotEntry, StoreSnapshot } from "./enumerate.js";
import { classifyState, hashersOf, loadState, snapshotOf, type EvaluateDeps } from "./evaluate.js";
import { canonicalPath, memoryStoreId, projectStoreId, storeKey, userStoreId, type Agent } from "./paths.js";
import { listDir } from "./private-file.js";
import {
  cleanText, displayLines, displayPath, displayText, formatDiffItem, formatStatusItem, loadSecretRedactor, provenanceText,
  type DisplayContext,
} from "./render.js";
import { integrityDirExists, readSessionLog } from "./session-log.js";
import {
  appendLog, commitStores, initIntegrity, integrityPaths, isIntegrityDisabled, loadIntegrity, newStoreDoc, readConfig,
  readIntegrityKey, readLog, readRegistry, readStore, removeDisabled, signerFor, withStoreLock, writeConfig, writeDisabled,
  type IntegrityPaths, type IntegrityState, type Signer, type UnsignedStoreDoc,
} from "./store.js";
import type { TokenOptions } from "./tokens.js";
import {
  CONFIG_KEYS, LOCK_WAIT_CLI_MS,
  type ConfigKey, type HeldTier, type IntegrityConfig, type LogEntry, type StoreEntry, type StoreId, type StoreKind,
  type TamperReason, type Tier,
} from "./types.js";
import { hookEventName, unitsOf, type FileUnits, type UnitHasher } from "./units.js";

// ── Options ─────────────────────────────────────────────────────────────────

export type IntegrityOptions = {
  /** The directory to evaluate, as the CLI's cwd (default `process.cwd()`). */
  cwd?: string;
  /** The Nexus data dir (default `nexusDataDir()`: `$NEXUS_DATA`, else `~/.nexus`). */
  dataDir?: string;
  homedir?: string;
  platform?: NodeJS.Platform;
  /**
   * Only `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `ProgramFiles`, `ProgramData` and (for
   * status's note on an ignored value) `NEXUS_DATA` are read (default `process.env`).
   */
  env?: Readonly<Record<string, string | undefined>>;
  /** Overrides the managed-policy directory (tests). */
  managedDir?: string;
  now?: Date;
  /** This install's entry scripts (tests; default `nexusEntryScripts()`). */
  nexusEntries?: readonly string[];
  /** Whose user-level files to look at: Claude Code's (the default) or Codex's (`--agent codex`). */
  agent?: Agent;
  /** Overrides Codex's system directory (tests). */
  codexSystemDir?: string;
};

type Resolved = EvaluateDeps & {
  cwd: string;
  env: Readonly<Record<string, string | undefined>>;
  managedDir?: string;
  codexSystemDir?: string;
  agent?: Agent;
  now: Date;
  paths: IntegrityPaths;
};

function resolveOptions(opts: IntegrityOptions): Resolved {
  const dataDir = resolve(opts.dataDir ?? nexusDataDir());
  return {
    cwd: resolve(opts.cwd ?? process.cwd()),
    dataDir,
    homedir: opts.homedir ?? osHomedir(),
    platform: opts.platform ?? process.platform,
    env: opts.env ?? process.env,
    ...(opts.managedDir !== undefined ? { managedDir: opts.managedDir } : {}),
    ...(opts.codexSystemDir !== undefined ? { codexSystemDir: opts.codexSystemDir } : {}),
    ...(opts.agent ? { agent: opts.agent } : {}),
    now: opts.now ?? new Date(),
    ...(opts.nexusEntries ? { nexusEntries: opts.nexusEntries } : {}),
    paths: integrityPaths(dataDir),
  };
}

/** Why a library call refused or failed; the CLI prints `message` and exits 1. */
export type IntegrityErrorCode = "invalid" | "uninitialized" | "tamper" | "exists" | "busy" | "changed";

export class IntegrityError extends Error {
  readonly code: IntegrityErrorCode;
  constructor(code: IntegrityErrorCode, message: string) {
    super(message);
    this.name = "IntegrityError";
    this.code = code;
  }
}

/** `baseline --reset` for the user-level store `agent` selects: without `--agent codex` it re-fingerprints Claude Code's, not Codex's. */
const resetCmd = (agent: Agent | undefined) => `nexus guard integrity baseline --reset${agent === "codex" ? " --agent codex" : ""}`;
const resetHint = (agent: Agent | undefined) => `run ${resetCmd(agent)} in your own terminal`;
/** For what is no agent's own (the config). */
const RESET_HINT = resetHint(undefined);

// ── Context and evaluation ──────────────────────────────────────────────────

/**
 * The CLI's context and loaded state. The auto-memory directory is the one the
 * (verified) project store recorded when SessionStart last ran there (§3.1):
 * the CLI has no transcript path to derive it from.
 */
function cliState(d: Resolved): { ctx: IntegrityContext; state: IntegrityState } {
  let ctx = contextFromCli(d.cwd, {
    platform: d.platform, homedir: d.homedir, env: d.env, dataDir: d.dataDir,
    ...(d.managedDir !== undefined ? { managedDir: d.managedDir } : {}),
    ...(d.codexSystemDir !== undefined ? { codexSystemDir: d.codexSystemDir } : {}),
    ...(d.agent ? { agent: d.agent } : {}),
  });
  if (!ctx) throw new IntegrityError("invalid", `not a directory: ${d.cwd}`);
  let state = loadState(ctx, d);
  const project = state.stores[projectStoreId(ctx.root, ctx.platform)];
  const recorded = project?.verified ? project.doc?.autoMemoryDir : undefined;
  if (typeof recorded === "string" && recorded !== ctx.autoMemoryDir) {
    ctx = { ...ctx, autoMemoryDir: recorded, autoMemorySource: ctx.autoMemorySource ?? "projects" };
    state = loadState(ctx, d);
  }
  return { ctx, state };
}

/**
 * The watched set read in full — with every held entry of the stores, wherever
 * it is (a HOLD a session in a subdirectory found) — and (with a key, or under
 * TAMPER) its classification, screening everything.
 */
function evaluateCli(ctx: IntegrityContext, state: IntegrityState, d: Resolved): { snapshot: Snapshot; result: ClassifyResult | null } {
  const { snapshot, ledger } = snapshotOf(ctx, state, d, { now: d.now.getTime(), fastPath: false, held: true });
  if (state.machineFirstRun || (!state.signer && state.tamper.length === 0)) return { snapshot, result: null };
  const result = classifyState(ctx, state, snapshot, ledger, { now: d.now, scanBudget: Number.POSITIVE_INFINITY });
  return { snapshot, result };
}

const TAMPER_ORDER: readonly TamperReason[] = ["permission", "redirect", "store-deleted", "key", "mac", "missing-store", "rollback"];

/** The most significant TAMPER reason among the store-wide ones and the context's stores'. */
function tamperOf(state: IntegrityState, snapshot: Snapshot): TamperReason | null {
  const reasons = new Set<TamperReason>(state.tamper);
  for (const s of storesOf(snapshot)) {
    const t = state.stores[s.id]?.tamper;
    if (t) reasons.add(t);
  }
  return TAMPER_ORDER.find((r) => reasons.has(r)) ?? null;
}

function storesOf(snapshot: Snapshot): StoreSnapshot[] {
  return snapshot.memory ? [snapshot.global, snapshot.project, snapshot.memory] : [snapshot.global, snapshot.project];
}

/** `uninitialized`: no key and no anchor yet; `disabled`: the signed `.disabled` marker is in place. */
export type IntegrityStatusState = "ok" | "uninitialized" | "disabled" | "tamper";

function overallState(state: IntegrityState, tamper: TamperReason | null): IntegrityStatusState {
  if (state.machineFirstRun) return "uninitialized";
  if (state.disabled) return "disabled";
  return tamper ? "tamper" : "ok";
}

function displayOf(ctx: IntegrityContext, redact: DisplayContext["redact"]): DisplayContext {
  return { root: ctx.root, home: ctx.home, platform: ctx.platform, ...(redact ? { redact } : {}), ...(ctx.agent === "codex" ? { dialect: "codex" as const } : {}) };
}

/** A safe ISO time for an epoch-ms value read from a file (null when it is not a valid date). */
function isoOf(ms: number): string | null {
  const d = new Date(ms);
  return Number.isFinite(d.getTime()) ? d.toISOString() : null;
}

// ── Status (§7 `status --json`) ─────────────────────────────────────────────

export type { SettingsScope };

/**
 * The store cannot be written: the first of D/integrity, its stores, ledger,
 * sessions and log that refuses (`unwritableAt`), or, for one not created yet,
 * the directory it would be created in.
 */
export type StoreUnwritable = {
  /** That path; for EACCES / EPERM on one that cannot even be stat'ed, the nearest ancestor that can, whose owner `owner` is. */
  path: string;
  code: "EROFS" | "EACCES" | "EPERM";
  /** The path's owner (uid) for EACCES / EPERM, off Windows; null otherwise. */
  owner: number | null;
};

export type IntegrityStatus = {
  dataDir: string;
  state: IntegrityStatusState;
  tamperReason: TamperReason | null;
  /** Set when Nexus cannot write the store: nothing a session sees is recorded, and no review can be saved. */
  unwritable: StoreUnwritable | null;
  /**
   * `NEXUS_DATA` values Nexus ignores (`dataDirFrom`: not absolute, so D stays
   * ~/.nexus): this process's, and the one the settings layers hand the hooks
   * (`checkNexusHooks`: the layer that wins).
   */
  ignoredDataDir: { from: "environment" | SettingsScope; path: string | null; value: string }[];
  hook: {
    /**
     * Instruction-file integrity's hooks are present and live (`checkNexusHooks`):
     * SessionStart, PreToolUse and the PostToolUse Write|Edit|MultiEdit group, each
     * in some layer with the script it names present.
     */
    live: boolean;
    /** A Nexus SessionStart hook is in some settings layer, live or not. */
    sessionStart: boolean;
    /** The first layer (user, project, local, managed) whose SessionStart hook runs, else the first with any Nexus hook. */
    scope: SettingsScope | null;
    /** Why `live` is false, one line per hook. */
    problems: string[];
    /** Settings files with `disableAllHooks: true`: no Nexus hook runs. */
    disableAllHooksIn: string[];
    /** Events of Nexus hooks the baseline recorded and a settings file no longer has, with no Nexus uninstall on record. */
    missingNexusHooks: string[];
    /** `~/.claude/settings.json` when it still holds Nexus hooks that Claude Code does not run, because
     *  `CLAUDE_CONFIG_DIR` points elsewhere; else null. */
    staleDefaultSettings: string | null;
    /** The Claude config dir (U) whose settings this status checked: `CLAUDE_CONFIG_DIR`, else `~/.claude`. */
    configDir: string;
    /**
     * Other Claude config dirs whose `settings.json` the fingerprint records with
     * Nexus's SessionStart hook: sessions launched with another CLAUDE_CONFIG_DIR
     * than this shell's (the global fingerprint serves them all).
     */
    otherConfigDirs: string[];
    /**
     * The Codex install, when `$CODEX_HOME/hooks.json` holds a Nexus hook
     * (`checkCodexHooks`: integrity's hooks there live, trusted and on); null
     * otherwise. The fields above are Claude Code's alone.
     */
    codex: CodexHookCheck | null;
  };
  stores: { id: StoreId; kind: StoreKind; root: string | null; gen: number | null; updatedAt: string | null; files: number; unhashed: number; verified: boolean }[];
  autoMemory: { located: boolean; dir: string | null; writesObserved: boolean };
  pending: {
    path: string;
    display: string;
    tier: HeldTier;
    since: string | null;
    reasons: string[];
    added: number;
    removed: number;
    /** The item as the human `status` prints it. */
    summary: string;
  }[];
  recent: {
    at: string; event: LogEntry["event"]; store: string | null; display: string | null; tier: Tier | null; by: string | null; tool: string | null;
    added: number; removed: number;
  }[];
  taintedSessions: { sid: string; at: string; reason: string }[];
  notWatched: string[];
  /** `status --memory`: what `memoryAudit` returned (the CLI passes nexus-memory's `auditMemoryMarkers`). */
  memory: unknown | null;
};

/** §3.8, listed by `status`. */
export const NOT_WATCHED: readonly string[] = [
  "nested on-demand instruction files",
  "--add-dir directories",
  "plugin caches",
  "--settings/--agents",
  "server-managed settings",
  "output styles",
];

/** What a Codex session loads that `status --agent codex` does not watch. */
export const NOT_WATCHED_CODEX: readonly string[] = [
  "-c/--enable/--disable overrides on the command line",
  "Codex's bundled skills (skills/.system)",
  "plugin caches",
];

/** `otherConfigDirs`: the user settings the verified global store records with Nexus's SessionStart hook, outside U. */
function otherConfigDirs(ctx: IntegrityContext, state: IntegrityState): string[] {
  const global = state.stores.global;
  if (!global?.verified || global.tamper || !global.doc) return [];
  const own = storeKey(ctx.configDir, ctx.platform);
  const dirs = new Set<string>();
  for (const e of Object.values(global.doc.entries)) {
    if (e.role !== "user-settings" || e.state !== "file" || !e.nexusHooks.includes("SessionStart")) continue;
    const dir = dirname(e.path);
    if (storeKey(dir, ctx.platform) !== own) dirs.add(dir);
  }
  return [...dirs].sort();
}

/** The settings layers Claude Code reads for the context: U, R's and cwd's project and local settings, M. */
function hookCheck(ctx: IntegrityContext, d: Resolved): ReturnType<typeof checkNexusHooks> {
  return checkNexusHooks({
    user: join(ctx.configDir, "settings.json"),
    projectDirs: ctx.root === ctx.cwd ? [ctx.root] : [ctx.root, ctx.cwd],
    managedDir: ctx.managedDir,
    homedir: ctx.home,
    platform: ctx.platform,
    ledger: d,
  });
}

function hookStatus(check: ReturnType<typeof checkNexusHooks>, result: ClassifyResult | null, d: Resolved, ctx: IntegrityContext, state: IntegrityState): IntegrityStatus["hook"] {
  const missing = new Set<string>();
  for (const item of result?.items ?? []) for (const e of item.removedNexusHooks) missing.add(hookEventName(e) ?? "a hook");
  return {
    live: check.live, sessionStart: check.sessionStart, scope: check.scope, problems: check.problems,
    disableAllHooksIn: check.disableAllHooksIn, missingNexusHooks: [...missing].sort(),
    staleDefaultSettings: staleDefaultSettings({ env: d.env, homedir: d.homedir, platform: d.platform }),
    configDir: ctx.configDir,
    otherConfigDirs: otherConfigDirs(ctx, state),
    codex: checkCodexHooks({ env: d.env, homedir: d.homedir, platform: d.platform, dataDir: d.dataDir, cwd: d.cwd, now: d.now }),
  };
}

const UNWRITABLE = new Set(["EROFS", "EACCES", "EPERM"]);

/** The errno code of an error that means the store cannot be written (read-only, or another owner's), else null. */
export function unwritableCode(error: unknown): StoreUnwritable["code"] | null {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  return typeof code === "string" && UNWRITABLE.has(code) ? (code as StoreUnwritable["code"]) : null;
}

/** The filesystem calls the writability check makes (tests inject them). */
export type WriteProbe = { access: (path: string, mode: number) => void; stat: (path: string) => { uid: number } };
const FS_PROBE: WriteProbe = { access: accessSync, stat: statSync };

/**
 * Who owns `path`, off Windows (where stat reports 0 for everyone): its uid, or,
 * when it cannot be stat'ed, the nearest ancestor's that can be, with that
 * ancestor. `sudo nexus …` leaves ~/.nexus another user's 0700 directory, so
 * nothing inside it can be stat'ed and ~/.nexus itself names the owner. Null on
 * Windows, or when not even `/` can be stat'ed.
 */
export function ownerOf(path: string, platform: NodeJS.Platform, stat: WriteProbe["stat"] = statSync): { path: string; owner: number } | null {
  if (platform === "win32") return null;
  for (let at = path; ; at = dirname(at)) {
    try {
      return { path: at, owner: stat(at).uid };
    } catch {
      if (dirname(at) === at) return null;
    }
  }
}

/**
 * Why Nexus cannot write `path`, when it is read-only or another user's:
 * access(2) W_OK on the path or, while it does not exist yet, on the nearest
 * ancestor it would be created in (a recursive mkdir reports ENOENT, not EROFS,
 * on a read-only file system). Null when it can be written, or the failure is
 * something else. Root passes wherever it may write.
 */
export function unwritableAt(path: string, platform: NodeJS.Platform = process.platform, probe: WriteProbe = FS_PROBE): StoreUnwritable | null {
  for (let at = path; ; at = dirname(at)) {
    try {
      probe.access(at, constants.W_OK);
      return null;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT" && dirname(at) !== at) continue;
      const code = unwritableCode(error);
      if (code === null) return null;
      if (code === "EROFS") return { path: at, code, owner: null };
      const owner = ownerOf(at, platform, probe.stat);
      return { path: owner?.path ?? at, code, owner: owner?.owner ?? null };
    }
  }
}

/**
 * Can Nexus write the store? `unwritableAt` on the directories and log the
 * writers use, so status stays read-only: a part not created yet is checked by
 * the directory it would be created in.
 */
export function storeUnwritable(paths: IntegrityPaths, platform: NodeJS.Platform = process.platform, probe: WriteProbe = FS_PROBE): StoreUnwritable | null {
  for (const path of [paths.dir, paths.storesDir, paths.ledgerDir, paths.sessionsDir, paths.log]) {
    const u = unwritableAt(path, platform, probe);
    if (u) return u;
  }
  return null;
}

const TAINT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const SESSION_LOG = /^([0-9a-f]{16})\.log$/;
const MAX_TAINT_LOGS = 2000;
const MAX_TAINTED_LISTED = 50;

/** Sessions whose log (modified in the last 7 days) has an `f` or `t` line, newest first. */
function taintedSessions(dataDir: string, nowMs: number): IntegrityStatus["taintedSessions"] {
  const dir = join(dataDir, "integrity", "sessions");
  const out: IntegrityStatus["taintedSessions"] = [];
  let read = 0;
  for (const name of listDir(dir, 50_000).names) {
    const m = SESSION_LOG.exec(name);
    if (!m) continue;
    let mtimeMs: number;
    try {
      mtimeMs = lstatSync(join(dir, name)).mtimeMs;
    } catch {
      continue;
    }
    if (mtimeMs < nowMs - TAINT_WINDOW_MS) continue;
    if (++read > MAX_TAINT_LOGS) break;
    const log = readSessionLog(dataDir, m[1]);
    const sid = m[1].slice(0, 8);
    if (log.unreadable) {
      out.push({ sid, at: isoOf(mtimeMs) ?? new Date(0).toISOString(), reason: "its activity log could not be read" });
      continue;
    }
    const ev = log.events.find((e) => e.kind === "f" || e.kind === "t");
    if (!ev) continue;
    const at = isoOf(ev.t) ?? isoOf(mtimeMs) ?? new Date(0).toISOString();
    const reason = ev.kind === "f"
      ? `${cleanText(ev.tool).slice(0, 64)} result flagged`
      : "flagged instruction text was delivered at session start";
    out.push({ sid, at, reason });
  }
  out.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));
  return out.slice(0, MAX_TAINTED_LISTED);
}

function storeSummaries(state: IntegrityState, snapshot: Snapshot): IntegrityStatus["stores"] {
  return storesOf(snapshot).map((s) => {
    const load = state.stores[s.id];
    const listed = state.registry?.stores[s.id];
    const entries = Object.values(s.entries);
    return {
      id: s.id,
      kind: s.kind,
      root: s.root,
      gen: load?.doc?.gen ?? listed?.gen ?? null,
      updatedAt: load?.doc?.updatedAt ?? listed?.updatedAt ?? null,
      files: entries.filter((e) => e.state !== "missing").length,
      unhashed: entries.filter((e) => e.state === "unhashed").length,
      verified: load?.verified ?? false,
    };
  });
}

function recentOf(paths: IntegrityPaths, display: DisplayContext, limit: number, filter?: (e: LogEntry) => boolean): IntegrityStatus["recent"] {
  const entries = readLog(paths, filter ? 1000 : limit);
  return (filter ? entries.filter(filter).slice(-limit) : entries).map((e) => ({
    at: e.at,
    event: e.event,
    store: typeof e.store === "string" ? cleanText(e.store).slice(0, 64) : null,
    display: typeof e.path === "string" ? displayPath(e.path, display) : null,
    tier: e.tier ?? null,
    by: typeof e.by === "string" ? cleanText(e.by).slice(0, 32) : null,
    tool: typeof e.tool === "string" ? cleanText(e.tool).slice(0, 32) : null,
    added: typeof e.added === "number" ? e.added : 0,
    removed: typeof e.removed === "number" ? e.removed : 0,
  }));
}

const isHeld = (item: EntryResult): item is EntryResult & { tier: HeldTier } => item.tier === "HOLD" || item.tier === "SUSPECT";

/**
 * `nexus guard integrity status`: the evaluation for `opts.cwd` with no
 * deadline. Read-only: it never creates or replaces a key, never takes the lock
 * and never advances anything. `memoryAudit` (the CLI's `--memory`) fills `memory`.
 */
export async function integrityStatus(opts: IntegrityOptions & { memoryAudit?: (dataDir: string) => unknown } = {}): Promise<IntegrityStatus> {
  const d = resolveOptions(opts);
  const { ctx, state } = cliState(d);
  const { snapshot, result } = evaluateCli(ctx, state, d);
  const display = displayOf(ctx, await loadSecretRedactor());
  const tamper = tamperOf(state, snapshot);
  const user = state.stores[userStoreId(ctx.agent)];
  const globalDoc = user?.verified ? user.doc : null;
  const check = hookCheck(ctx, d);
  const envIgnored = opts.dataDir === undefined ? dataDirFrom(d.env.NEXUS_DATA, d.homedir, d.platform).ignored : null;
  return {
    dataDir: d.dataDir,
    state: overallState(state, tamper),
    tamperReason: tamper,
    unwritable: storeUnwritable(d.paths, d.platform),
    ignoredDataDir: [
      ...(envIgnored !== null ? [{ from: "environment" as const, path: null, value: envIgnored }] : []),
      ...check.ignoredDataDir.map((x) => ({ from: x.scope, path: x.path, value: x.value })),
    ],
    hook: hookStatus(check, result, d, ctx, state),
    stores: storeSummaries(state, snapshot),
    autoMemory: {
      located: ctx.autoMemoryDir !== null,
      dir: ctx.autoMemoryDir,
      writesObserved: result?.memoryWritesObserved ?? globalDoc?.memoryWritesObserved === true,
    },
    pending: (result?.items ?? []).filter(isHeld).map((item) => ({
      path: item.path,
      display: displayPath(item.path, display),
      tier: item.tier,
      since: item.next?.held?.since ?? null,
      reasons: item.reasons.map((r) => displayText(r, display)),
      added: item.added,
      removed: item.removed,
      summary: formatStatusItem(item, display),
    })),
    recent: recentOf(d.paths, display, 5),
    taintedSessions: taintedSessions(d.dataDir, d.now.getTime()),
    notWatched: [...(ctx.agent === "codex" ? NOT_WATCHED_CODEX : NOT_WATCHED)],
    memory: opts.memoryAudit ? opts.memoryAudit(d.dataDir) : null,
  };
}

// ── Diff (§7 `diff --json`) ─────────────────────────────────────────────────

export type IntegrityDiffItem = {
  path: string;
  display: string;
  store: StoreId;
  tier: Tier;
  /** The §5.3 rule (or first-run result) that decided the tier. */
  rule: string;
  reasons: string[];
  change: ChangeKind;
  /** When the item was first held, for HOLD and SUSPECT. */
  since: string | null;
  added: number;
  removed: number;
  hunks: { provenance: string; line: number | null; lines: string[]; reason: string | null }[];
  /** The escalating settings changes (new hooks, MCP servers, plugins, permissions, env). */
  descriptions: string[];
  removedNexusHooks: string[];
  /** The added lines could not be compared (no readable old fingerprint). */
  unquoted: boolean;
  /**
   * A keyed id of this version of a held file (it changes with the content):
   * `acceptChanges`'s `expect` takes these, so accept trusts only what was shown.
   */
  heldId: string | null;
  /** The item as the human `diff` prints it. */
  text: string[];
};

export type IntegrityDiff = {
  dataDir: string;
  state: IntegrityStatusState;
  tamperReason: TamperReason | null;
  /** R: `git -C <root> ls-files --error-unmatch` decides the CLI's revert hint. */
  root: string;
  items: IntegrityDiffItem[];
  /** A SUSPECT or TAMPER item is shown (the CLI exits 3). */
  attention: boolean;
  /** `--all`: the last 20 auto-advanced log entries (counts only). */
  advanced: IntegrityStatus["recent"];
};

/** Store keys of the paths the user named, resolved against the cwd. */
function namedKeys(names: readonly string[] | undefined, d: Resolved): Set<string> | null {
  if (!names?.length) return null;
  return new Set(names.map((n) => storeKey(canonicalPath(resolve(d.cwd, n)), d.platform)));
}

function diffItem(item: EntryResult, display: DisplayContext): IntegrityDiffItem {
  return {
    path: item.path,
    display: displayPath(item.path, display),
    store: item.storeId,
    tier: item.tier,
    rule: item.rule,
    reasons: item.reasons.map((r) => displayText(r, display)),
    change: item.change,
    since: isHeld(item) ? item.next?.held?.since ?? null : null,
    added: item.added,
    removed: item.removed,
    hunks: item.hunks.map((h) => ({
      provenance: provenanceText(h.attribution, item.window ?? item.inWindow, display, item.role),
      line: h.line,
      lines: displayLines(h.lines, display),
      reason: h.verdict ? displayText(h.verdict.reason, display) : null,
    })),
    descriptions: item.descriptions.map((x) => displayText(x, display)),
    removedNexusHooks: item.removedNexusHooks.map((e) => hookEventName(e) ?? "a hook"),
    unquoted: item.unquoted,
    heldId: item.heldId,
    text: formatDiffItem(item, display),
  };
}

/**
 * `nexus guard integrity diff`: every changed or held file (or only the named
 * ones), as the evaluation for `opts.cwd` sees it now. Read-only, like status.
 */
export async function integrityDiff(opts: IntegrityOptions & { paths?: readonly string[]; all?: boolean } = {}): Promise<IntegrityDiff> {
  const d = resolveOptions(opts);
  const { ctx, state } = cliState(d);
  const { snapshot, result } = evaluateCli(ctx, state, d);
  const display = displayOf(ctx, await loadSecretRedactor());
  const tamper = tamperOf(state, snapshot);
  const named = namedKeys(opts.paths, d);
  const items = (result?.items ?? [])
    .filter((i) => !(i.tier === "SILENT" && i.change === "unchanged"))
    .filter((i) => !named || named.has(i.key));
  return {
    dataDir: d.dataDir,
    state: overallState(state, tamper),
    tamperReason: tamper,
    root: ctx.root,
    items: items.map((i) => diffItem(i, display)),
    attention: items.some((i) => i.tier === "SUSPECT" || i.tamper !== null),
    advanced: opts.all ? recentOf(d.paths, display, 20, (e) => e.event === "advance" || e.event === "notice") : [],
  };
}

// ── Writers (internal; the CLI calls them after its human gate) ─────────────

/**
 * Run `fn` under the store lock, waiting LOCK_WAIT_CLI_MS; a busy lock is an
 * error, not a wait forever. A lock that cannot be created because the store is
 * read-only or another user's throws that error as it is (`unwritableCode`), so
 * the CLI can say which: trying again would not help.
 */
function locked<T>(d: Resolved, fn: () => T): T {
  if (!integrityDirExists(d.dataDir)) {
    throw new IntegrityError("uninitialized", "instruction-file integrity is not set up here yet; run nexus guard install, or nexus guard integrity baseline");
  }
  const r = withStoreLock(d.paths, fn, LOCK_WAIT_CLI_MS);
  if (!r.ok && unwritableCode(r.error)) throw r.error;
  if (!r.ok) throw new IntegrityError("busy", `the integrity store is ${r.reason === "busy" ? "locked by another Nexus process" : "not writable"}; try again`);
  return r.value;
}

const NO_UNITS: FileUnits = { units: [], ids: [], cat: {}, nexusHooks: [], shaOnly: false };
const SHA_ONLY: FileUnits = { units: [], ids: [], cat: {}, nexusHooks: [], shaOnly: true };
const sha8 = (sha: string | null | undefined) => (sha ? sha.slice(0, 8) : undefined);

/**
 * The entry the user's decision records for the file as it is now: its units,
 * categories, accepted tokens and Nexus hooks; `acceptedBy: "user"`; nothing
 * held. The old accepted version joins `history`, unless it was a first-run
 * version still flagged (nobody reviewed it, so a return to it is compared).
 */
function userEntry(cur: SnapshotEntry, prev: StoreEntry | null, hasher: UnitHasher, tokenOpts: TokenOptions, at: string): StoreEntry {
  let state = cur.state;
  let fu = NO_UNITS;
  if (cur.state === "file") {
    if (cur.content) fu = unitsOf(cur.role, cur.content, { hasher, path: cur.path });
    else if (cur.shaOnly) fu = SHA_ONLY;
    else state = "unhashed"; // not read: compared, as a first run, next session
  }
  const sha = state === "unhashed" ? null : cur.sha256;
  const reviewed = !(prev?.acceptedBy === "first-run" && prev.held?.flaggedUnits.length);
  const history = prev && reviewed && prev.sha256 && prev.sha256 !== sha ? pushHistory(prev.history, prev.sha256, prev.acceptedAt) : prev?.history ?? [];
  return {
    path: cur.path, role: cur.role, state, sha256: sha, size: cur.size, stat: cur.stat, link: cur.link,
    units: fu.ids, cat: fu.cat, tok: state === "file" ? versionTokens(cur, fu, hasher, tokenOpts) : [], nexusHooks: fu.nexusHooks,
    history, acceptedAt: at, acceptedBy: "user", held: null,
  };
}

function hasherOf(signer: Signer): UnitHasher {
  const unit = hashersOf(signer).unit;
  if (!unit) throw new TypeError("a trusted key gives a unit hasher");
  return unit;
}

function cloneDoc(doc: UnsignedStoreDoc): UnsignedStoreDoc {
  const { mac: _mac, ...rest } = structuredClone(doc) as UnsignedStoreDoc & { mac?: string };
  return rest;
}

export type AcceptResult = { accepted: { path: string; display: string; tier: HeldTier; store: StoreId }[] };

/** A pending file as `accept` showed it: its path and the `heldId` of the version shown. */
export type AcceptExpectation = { path: string; heldId: string | null };

/**
 * `nexus guard integrity accept [<path>…]`, after the human gate: trust the
 * pending HOLD and SUSPECT files (all of them, or the named ones) as they are
 * now. Each becomes a user-accepted version (history kept, held cleared,
 * tokens recomputed), the stores' generations are bumped and `accept` is
 * logged. Other changes are left for SessionStart to report. Refuses under
 * TAMPER: only `baseline --reset` recovers from that.
 *
 * `expect` is what the user was shown (`integrityDiff`'s held items): when the
 * pending set or any of its versions differs under the lock (a file changed
 * after it was shown), nothing is accepted and the error's code is `changed`.
 */
export function acceptChanges(opts: IntegrityOptions & { paths?: readonly string[]; expect?: readonly AcceptExpectation[] } = {}): AcceptResult {
  const d = resolveOptions(opts);
  return locked(d, () => {
    const { ctx, state } = cliState(d);
    if (state.machineFirstRun) throw new IntegrityError("uninitialized", "there is no fingerprint to accept changes into yet");
    const { snapshot, result } = evaluateCli(ctx, state, d);
    const tamper = tamperOf(state, snapshot);
    if (tamper || !state.signer || !result) throw new IntegrityError("tamper", `the fingerprint failed verification; ${resetHint(opts.agent)}`);
    const named = namedKeys(opts.paths, d);
    // a held file that could not be read whole this time (`~/.claude.json` mid-rewrite) is only
    // reminded of (classify.ts `remindHeld`): what it holds now is unknown, so it is not accepted
    const readNow = (i: EntryResult) => snapshot[i.store]?.entries[i.key]?.state !== "unhashed";
    const pending = result.items.filter(isHeld).filter((i) => (!named || named.has(i.key)) && readNow(i));
    if (opts.expect && !sameVersions(pending, opts.expect)) {
      throw new IntegrityError("changed", "the pending files changed after they were shown, so nothing was accepted; run accept again to review them");
    }
    const hasher = hasherOf(state.signer);
    const tokenOpts: TokenOptions = { root: snapshot.project.root, home: ctx.home, platform: ctx.platform };
    const at = d.now.toISOString();
    const display = displayOf(ctx, undefined);
    const writes: UnsignedStoreDoc[] = [];
    const log: LogEntry[] = [];
    const accepted: AcceptResult["accepted"] = [];
    for (const snap of storesOf(snapshot)) {
      const mine = pending.filter((i) => i.storeId === snap.id);
      if (mine.length === 0) continue;
      const load = state.stores[snap.id];
      // a store with no baseline yet takes its whole first-run document, with these entries accepted
      const base = load?.verified && load.doc ? load.doc : result.stores[snap.kind]?.next;
      if (!base) continue;
      const doc = cloneDoc(base);
      for (const item of mine) {
        const cur = snap.entries[item.key] ?? missingSnapshot(item);
        const prev = doc.entries[item.key] ?? null;
        doc.entries[item.key] = userEntry(cur, prev, hasher, tokenOpts, at);
        log.push({
          at, event: "accept", store: snap.id, path: item.path, tier: item.tier, by: "user",
          added: item.added, removed: item.removed, old: sha8(prev?.sha256), new: sha8(doc.entries[item.key].sha256),
        });
        accepted.push({ path: item.path, display: displayPath(item.path, display), tier: item.tier, store: snap.id });
      }
      writes.push(doc);
    }
    if (writes.length) {
      commitStores(d.paths, state.signer, state.registry, { write: writes }, d.now);
      appendLog(d.paths, log);
    }
    return { accepted };
  });
}

/** The pending items are exactly the expected paths, each at the version expected. */
function sameVersions(pending: readonly EntryResult[], expect: readonly AcceptExpectation[]): boolean {
  const want = new Map(expect.map((e) => [e.path, e.heldId]));
  return want.size === expect.length && pending.length === want.size
    && pending.every((i) => want.has(i.path) && want.get(i.path) === i.heldId);
}

function missingSnapshot(item: EntryResult): SnapshotEntry {
  return { path: item.path, key: item.key, role: item.role, state: "missing", sha256: null, size: null, stat: null, link: null, content: null, reused: false };
}

/**
 * Fresh store documents for the context, every watched file accepted by the
 * user as it is now. A store that still verifies keeps its creation time,
 * generation (commit bumps it), entry histories and calibration flag.
 */
function userDocs(ctx: IntegrityContext, state: IntegrityState, snapshot: Snapshot, signer: Signer, now: Date): UnsignedStoreDoc[] {
  const hasher = hasherOf(signer);
  const tokenOpts: TokenOptions = { root: snapshot.project.root, home: ctx.home, platform: ctx.platform };
  const at = now.toISOString();
  return storesOf(snapshot).map((snap) => {
    const load = state.stores[snap.id];
    const old = load?.verified && !load.tamper ? load.doc : null;
    const doc = newStoreDoc(snap.kind, snap.id, snap.root, now);
    if (old) {
      doc.createdAt = old.createdAt;
      doc.gen = old.gen;
    }
    if (snap.kind === "project") doc.autoMemoryDir = snapshot.memory?.root ?? null;
    if (snap.kind === "global") doc.memoryWritesObserved = old?.memoryWritesObserved === true;
    for (const cur of Object.values(snap.entries)) doc.entries[cur.key] = userEntry(cur, old?.entries[cur.key] ?? null, hasher, tokenOpts, at);
    return doc;
  });
}

/** Has any store been committed under this data dir (a registry that lists one, or a file in `stores/`)? */
function storesExist(paths: IntegrityPaths): boolean {
  const registry = readRegistry(paths, null);
  if (registry.state !== "missing" && registry.doc && Object.keys(registry.doc.stores).length > 0) return true;
  return listDir(paths.storesDir, 1).names.length > 0;
}

export type BaselineResult = {
  /** A new integrity key was created. */
  createdKey: boolean;
  /** `config.json` did not verify and was replaced with signed defaults (`--reset`). */
  replacedConfig: boolean;
  /** Stores that could not be verified and were deleted, with their registry entries (`--reset`). */
  dropped: string[];
  /** The stores written, and how many watched paths each records. */
  stores: { id: StoreId; kind: StoreKind; files: number }[];
};

function written(docs: readonly UnsignedStoreDoc[]): BaselineResult["stores"] {
  return docs.map((doc) => ({ id: doc.id, kind: doc.kind, files: Object.values(doc.entries).filter((e) => e.state !== "missing").length }));
}

/**
 * `nexus guard integrity baseline`, after the human gate, when no store exists
 * yet: create the key, anchor and registry (if missing), then fingerprint the
 * global store, the current project's and its auto memory's, every file
 * accepted by the user. This is also the recovery for a `redirect` TAMPER
 * (a new NEXUS_DATA). With stores already present it refuses: that is `--reset`.
 */
export function createBaseline(opts: IntegrityOptions = {}): BaselineResult {
  const d = resolveOptions(opts);
  const exists = () => new IntegrityError("exists", `a fingerprint already exists here; to replace it, run ${resetCmd(opts.agent)}`);
  if (storesExist(d.paths)) throw exists();
  const init = initIntegrity(d.paths, d.now);
  if (!init.ok) throw new IntegrityError("tamper", `the integrity key ${init.why}; ${resetHint(opts.agent)}`);
  return locked(d, () => {
    if (storesExist(d.paths)) throw exists();
    const { ctx, state } = cliState(d);
    const { snapshot } = snapshotOf(ctx, state, d, { now: d.now.getTime(), fastPath: false });
    if (!state.signer || tamperOf(state, snapshot)) throw new IntegrityError("tamper", `the integrity key or registry failed verification; ${resetHint(opts.agent)}`);
    const docs = userDocs(ctx, state, snapshot, state.signer, d.now);
    commitStores(d.paths, state.signer, state.registry, { write: docs }, d.now);
    appendLog(d.paths, docs.map((doc) => ({ at: d.now.toISOString(), event: "first-run", store: doc.id, by: "user", added: Object.keys(doc.entries).length })));
    return { createdKey: init.createdKey, replacedConfig: false, dropped: [], stores: written(docs) };
  });
}

const STORE_FILE = /^(global|codex|project-[0-9a-f]{16}|memory-[0-9a-f]{16})\.json$/;

/**
 * `nexus guard integrity baseline --reset`, after the human gate and its
 * challenge: a new key and anchor if the key is missing or untrusted (always a
 * new anchor), signed defaults for a config that does not verify, every other
 * store that cannot be verified (bad MAC, rolled back, or registered but gone)
 * deleted and listed — those projects get a first-run baseline at their next
 * session — and the global, current project and memory stores re-fingerprinted
 * as the user's, generations bumped, `reset` logged.
 */
export function resetBaseline(opts: IntegrityOptions = {}): BaselineResult {
  const d = resolveOptions(opts);
  const init = initIntegrity(d.paths, d.now, { reset: true });
  if (!init.ok) throw new IntegrityError("tamper", `the integrity key ${init.why}`);
  return locked(d, () => {
    const { ctx, state } = cliState(d);
    if (!state.signer) throw new IntegrityError("tamper", "the integrity key could not be read after it was reset");
    const { snapshot } = snapshotOf(ctx, state, d, { now: d.now.getTime(), fastPath: false });
    const own = new Set<string>(storesOf(snapshot).map((s) => s.id));
    const registry = readRegistry(d.paths, state.signer);
    const listed = registry.state === "ok" ? registry.doc.stores : {};
    const dropped = new Set<string>();
    for (const name of listDir(d.paths.storesDir, 100_000).names) {
      const id = STORE_FILE.exec(name)?.[1];
      if (!id || own.has(id)) continue;
      const read = readStore(d.paths, id, state.signer);
      if (read.state !== "ok" || (listed[id] && read.doc.gen < listed[id].gen)) dropped.add(id);
    }
    for (const id of Object.keys(listed)) {
      if (!own.has(id) && !existsSync(join(d.paths.storesDir, `${id}.json`))) dropped.add(id);
    }
    const docs = userDocs(ctx, state, snapshot, state.signer, d.now);
    commitStores(d.paths, state.signer, registry.state === "ok" ? registry.doc : null, { write: docs, drop: [...dropped] }, d.now);
    appendLog(d.paths, docs.map((doc) => ({ at: d.now.toISOString(), event: "reset", store: doc.id, by: "user", added: Object.keys(doc.entries).length })));
    return { createdKey: init.createdKey, replacedConfig: init.replacedConfig, dropped: [...dropped].sort(), stores: written(docs) };
  });
}

/**
 * The ids of `opts.cwd`'s own project and auto-memory stores, as status
 * resolves them (null when the cwd is not a directory or has no auto memory):
 * `log` calls those "this project" and "auto memory". Read-only.
 */
export function contextStoreIds(opts: IntegrityOptions = {}): { project: StoreId | null; memory: StoreId | null } {
  try {
    const { ctx } = cliState(resolveOptions(opts));
    return {
      project: projectStoreId(ctx.root, ctx.platform),
      memory: ctx.autoMemoryDir ? memoryStoreId(ctx.autoMemoryDir, ctx.platform) : null,
    };
  } catch {
    return { project: null, memory: null };
  }
}

/** `nexus guard integrity log`: the last `limit` (default 50) entries of `log.jsonl`, oldest first. */
export function readIntegrityLog(opts: Pick<IntegrityOptions, "dataDir"> & { limit?: number } = {}): LogEntry[] {
  return readLog(integrityPaths(resolve(opts.dataDir ?? nexusDataDir())), opts.limit ?? 50);
}

export type ConfigView = {
  /** Every key, `enabled` from the `.disabled` marker; defaults unless config.json verified. */
  config: IntegrityConfig;
  /** config.json: verified, absent (defaults), or present but not verified (TAMPER; defaults apply). */
  state: "ok" | "missing" | "unverified";
  /** An integrity key exists (trusted or not). */
  initialized: boolean;
  disabled: boolean;
};

/** `nexus guard integrity config`: every key and the disabled state. Read-only. */
export function getConfig(opts: Pick<IntegrityOptions, "dataDir"> = {}): ConfigView {
  const paths = integrityPaths(resolve(opts.dataDir ?? nexusDataDir()));
  const key = readIntegrityKey(paths);
  const read = readConfig(paths, key.state === "ok" ? signerFor(key.key) : null);
  const disabled = isIntegrityDisabled(paths);
  return { config: { ...read.config, enabled: !disabled }, state: read.state, initialized: key.state !== "missing", disabled };
}

/** The values the string-valued config keys take (the others are `true` / `false`). */
export const CONFIG_VALUES: Readonly<Record<Exclude<ConfigKey, "enabled" | "agentWindowEscalation" | "quoteFlaggedLines">, readonly string[]>> = {
  instructionGate: ["always", "risky"],
  memoryGate: ["tainted-only", "novel-tokens", "exposed"],
  withholdMcp: ["off", "suspect", "unreviewed"],
};

/**
 * A config key and value as `setConfig` takes them, checked: the key is one of
 * CONFIG_KEYS and the value one it allows (`true`/`false` for the switches).
 * Throws an `invalid` IntegrityError otherwise. The CLI checks before it asks.
 */
export function parseConfigSetting(key: string, value: string | boolean): { key: ConfigKey; value: IntegrityConfig[ConfigKey] } {
  if (!(CONFIG_KEYS as readonly string[]).includes(key)) {
    throw new IntegrityError("invalid", `unknown key ${JSON.stringify(key).slice(0, 80)} (one of ${CONFIG_KEYS.join(", ")})`);
  }
  return { key: key as ConfigKey, value: parseConfigValue(key as ConfigKey, value) };
}

function parseConfigValue(key: ConfigKey, value: string | boolean): IntegrityConfig[ConfigKey] {
  if (key === "instructionGate" || key === "memoryGate" || key === "withholdMcp") {
    const allowed = CONFIG_VALUES[key];
    if (typeof value === "string" && allowed.includes(value)) return value as IntegrityConfig[ConfigKey];
    throw new IntegrityError("invalid", `${key} must be one of ${allowed.join(", ")}`);
  }
  if (typeof value === "boolean") return value;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new IntegrityError("invalid", `${key} must be true or false`);
}

/**
 * `nexus guard integrity config <key> <value>`, after the human gate.
 * `enabled false` writes the signed `.disabled` marker and `enabled true`
 * removes it; any other key is written to the signed config.json. Refuses
 * (except to turn integrity back on) unless the key is trusted and the store
 * verifies, so a tampered config is never laundered by rewriting it.
 */
export function setConfig(opts: Pick<IntegrityOptions, "dataDir" | "homedir" | "platform" | "now">, key: string, value: string | boolean): ConfigView {
  const { key: k, value: parsed } = parseConfigSetting(key, value);
  const d = resolveOptions(opts);
  locked(d, () => {
    if (k === "enabled" && parsed === true) {
      removeDisabled(d.paths);
      return;
    }
    const st = loadIntegrity({ dataDir: d.dataDir, homedir: d.homedir, platform: d.platform }, []);
    if (st.machineFirstRun) throw new IntegrityError("uninitialized", "there is no integrity key here yet; run nexus guard install");
    if (!st.signer || st.tamper.length) throw new IntegrityError("tamper", `the integrity key or config failed verification; ${RESET_HINT}`);
    if (k === "enabled") {
      writeDisabled(d.paths, st.signer, "cli", d.now);
      return;
    }
    const { enabled: _enabled, ...stored } = st.config;
    writeConfig(d.paths, st.signer, { ...stored, [k]: parsed });
  });
  return getConfig(opts);
}
