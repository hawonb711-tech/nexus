/**
 * Instruction-file integrity — one evaluation of the watched set for a resolved
 * context (spec §6.3 steps 5-7): load and verify the signed state, read the
 * signed ledger, enumerate and hash the watched files, and classify every change.
 *
 * SessionStart runs it under its deadline with the stat fast path and then
 * persists the outcome; the library API behind `nexus guard integrity` runs it
 * with no deadline and every file read — read-only for `status` and `diff`,
 * under the store lock for `accept` and `baseline`. Nothing here writes, spawns
 * a process or touches the network.
 *
 * The ledger is read twice, each bounded: before enumeration, the newest
 * DISCOVERY_MAX_FILES records for new ledger-learned paths (the ones learned
 * before are the project store's own entries); after it, every record of the
 * entries classification compares (changed, created or deleted), since the
 * earliest of their `acceptedAt` (§6.3 step 7), within the deadline. Nothing
 * changed: no attribution read at all.
 */

import { classify, stableKey, type ClassifyHashers, type ClassifyResult } from "./classify.js";
import type { IntegrityContext } from "./context.js";
import {
  enumerateWatched, type BaselineEntry, type EnumerateLimits, type EnumerateOptions, type Snapshot, type SnapshotEntry, type StoreSnapshot,
} from "./enumerate.js";
import { readLedger, type LedgerEntry } from "./ledger.js";
import { isUnder, memoryStoreId, projectStoreId, watchedRoleOf } from "./paths.js";
import { activityWindowsSince, type WindowScanOptions } from "./session-log.js";
import { isCurrentVersion, loadIntegrity, type IntegrityState, type Signer } from "./store.js";
import type { StoreEntry, StoreKind, WatchedRole } from "./types.js";
import { sha256Hex } from "./units.js";

export type EvaluateDeps = {
  /** D. */
  dataDir: string;
  homedir: string;
  platform: NodeJS.Platform;
  /** This install's entry scripts (default `nexusEntryScripts()`): only Nexus hooks naming one leave their script unwatched. */
  nexusEntries?: readonly string[];
};

/** The context's store ids: `global`, its project's, and its auto memory's when that was located. */
export function storeIdsOf(ctx: IntegrityContext): string[] {
  const ids = ["global", projectStoreId(ctx.root, ctx.platform)];
  if (ctx.autoMemoryDir) ids.push(memoryStoreId(ctx.autoMemoryDir, ctx.platform));
  return ids;
}

/** Load and verify the key, anchor, registry, config and the context's stores. Read-only. */
export function loadState(ctx: IntegrityContext, deps: EvaluateDeps): IntegrityState {
  return loadIntegrity({ dataDir: deps.dataDir, homedir: deps.homedir, platform: deps.platform }, storeIdsOf(ctx));
}

/**
 * The keyed hashers classification and rendering use. Without a trusted key
 * every store is under TAMPER and no unit is hashed; held ids and the frame
 * nonce then come from a plain sha256, so a re-emitted frame stays byte-identical.
 */
export function hashersOf(signer: Signer | null): ClassifyHashers {
  if (!signer) return { unit: null, nonce: (t) => sha256Hex(`nexus/integrity/v1/nonce\0${t}`).slice(0, 16) };
  return { unit: (t) => signer.hmac16("unit", t), nonce: (t) => signer.hmac16("nonce", t) };
}

/** Instruction files below R that a ledger write can teach the watched set (§3.3 `ledger-learned`). */
const LEARNABLE_ROLES: ReadonlySet<WatchedRole> = new Set<WatchedRole>([
  "ancestor-claude-md", "ancestor-local-md", "ancestor-agents-md", "project-rules", "project-agent", "project-command", "project-skill",
]);

/**
 * Ledger record files the learned-path discovery opens at most, newest first:
 * a bound on the steady-state cost however busy the ledger is. A path written
 * since this project's last session is found unless more records than this
 * (any project) came after it.
 */
const DISCOVERY_MAX_FILES = 256;

/** An instruction file under R that a ledger write can teach the watched set. */
function learnable(path: string, ctx: IntegrityContext): boolean {
  if (!isUnder(path, ctx.root, ctx.platform)) return false;
  const role = watchedRoleOf(path, { platform: ctx.platform });
  return !!role && LEARNABLE_ROLES.has(role);
}

/**
 * Paths of the agent writes on record to instruction files under R (a nested
 * `src/api/CLAUDE.md`): those in the newest DISCOVERY_MAX_FILES ledger records,
 * and those the verified project store already watches as `ledger-learned` (a
 * learned path stays watched once recorded). Enumeration watches each as
 * `ledger-learned` unless another role already does.
 */
function ledgerLearned(ctx: IntegrityContext, state: IntegrityState, now: number): string[] {
  const out = new Set<string>();
  const project = state.stores[projectStoreId(ctx.root, ctx.platform)];
  if (project?.verified && !project.tamper && project.doc) {
    for (const e of Object.values(project.doc.entries)) if (e.role === "ledger-learned" && learnable(e.path, ctx)) out.add(e.path);
  }
  if (state.signer) {
    const { records } = readLedger(state.paths, state.signer, { keys: null, since: 0, now, maxFiles: DISCOVERY_MAX_FILES });
    for (const r of records) if (r.kind === "write" && learnable(r.path, ctx)) out.add(r.path);
  }
  return [...out].sort();
}

/**
 * The stat fast path's baseline: the accepted entries of every store that
 * verified, is not under TAMPER and is at the current version. Held entries are
 * left out, so a held file is always read and its lines can be quoted again
 * (classify needs their text); a version bump needs every file's text.
 */
function fastPathBaseline(state: IntegrityState, ctx: IntegrityContext): NonNullable<EnumerateOptions["baseline"]> {
  const ids: [StoreKind, string | null][] = [
    ["global", "global"],
    ["project", projectStoreId(ctx.root, ctx.platform)],
    ["memory", ctx.autoMemoryDir ? memoryStoreId(ctx.autoMemoryDir, ctx.platform) : null],
  ];
  const out: NonNullable<EnumerateOptions["baseline"]> = {};
  for (const [kind, id] of ids) {
    const load = id ? state.stores[id] : undefined;
    if (!load?.verified || load.tamper || !load.doc || !isCurrentVersion(load.doc)) continue;
    const entries: Record<string, BaselineEntry> = {};
    for (const [key, e] of Object.entries(load.doc.entries)) if (!e.held) entries[key] = e;
    out[kind] = entries;
  }
  return out;
}

export type SnapshotOptions = {
  /** Epoch ms: the ledger's retention window ends here. */
  now: number;
  /** Reuse a baseline sha when the stat tuple is unchanged (SessionStart; the CLI reads every file). */
  fastPath: boolean;
  limits?: Partial<EnumerateLimits>;
  /** The SessionStart deadline: the attribution read stops, and `ledgerComplete` is false. */
  expired?: () => boolean;
};

export type AttributionLedger = {
  /** Verified records of the entries classification compares, after the earliest of their `acceptedAt`. */
  ledger: LedgerEntry[];
  /**
   * Every such record was read. False when the read was cut (the deadline, or a
   * day directory too large to list): an entry's records may be missing, so its
   * changes cannot be called unattributed, and nothing may be advanced.
   */
  ledgerComplete: boolean;
};

const present = (s: string) => s === "file" || s === "oversize";

/**
 * Does classification compare `key` with its baseline this run (rather than
 * skip it, record it as a first run, or find it unchanged)? Only then does it
 * look at the key's ledger records. Mirrors `classify`'s choice per key.
 */
function compared(snapshot: Snapshot, snap: StoreSnapshot, prev: StoreEntry | undefined, cur: SnapshotEntry | undefined, key: string, platform: NodeJS.Platform): boolean {
  const stable = (role: WatchedRole) => stableKey(snap.kind, role, key, snapshot, platform);
  if (!cur) return !!prev && present(prev.state) && !snapshot.incomplete && stable(prev.role); // a stable path gone
  if (cur.state === "unhashed" || prev?.state === "unhashed") return false; // past a cap, or a first run
  if (!prev) return stable(cur.role); // created where enumeration always looks (else a first run)
  return prev.state !== cur.state || prev.sha256 !== cur.sha256 || (prev.link ?? null) !== (cur.link ?? null);
}

/**
 * The ledger records classification needs for `snapshot` (§6.3 step 7): those
 * of every entry of a store with a trusted baseline that it compares — changed,
 * created or deleted — after the earliest `acceptedAt` among them. Each record
 * file is opened to learn its path, so the read is bounded by `expired`, not by
 * a file count: a count would drop the oldest records first, which are the ones
 * an older baseline needs. A store under TAMPER, a first-run store and an
 * unchanged tree need none.
 */
export function attributionLedger(
  state: IntegrityState,
  snapshot: Snapshot,
  opts: Pick<SnapshotOptions, "now" | "expired"> & { platform: NodeJS.Platform },
): AttributionLedger {
  if (!state.signer) return { ledger: [], ledgerComplete: true };
  const keys = new Set<string>();
  let since = Infinity;
  for (const snap of [snapshot.global, snapshot.project, snapshot.memory]) {
    if (!snap) continue;
    const load = state.stores[snap.id];
    if (!load?.verified || !load.doc || (load.tamper ?? state.tamper[0])) continue;
    const entries = load.doc.entries;
    for (const key of new Set([...Object.keys(snap.entries), ...Object.keys(entries)])) {
      const prev = entries[key];
      if (!compared(snapshot, snap, prev, snap.entries[key], key, opts.platform)) continue;
      keys.add(key);
      const at = prev ? Date.parse(prev.acceptedAt) : 0;
      since = Math.min(since, Number.isFinite(at) ? at : 0);
    }
  }
  if (keys.size === 0) return { ledger: [], ledgerComplete: true };
  const read = readLedger(state.paths, state.signer, {
    keys, since, now: opts.now, maxFiles: Number.POSITIVE_INFINITY, ...(opts.expired ? { expired: opts.expired } : {}),
  });
  return { ledger: read.records, ledgerComplete: !read.truncated };
}

/**
 * The watched set as it is now, and the ledger records its changes need
 * (`attributionLedger`). Without a trusted key there is no ledger.
 */
export function snapshotOf(ctx: IntegrityContext, state: IntegrityState, deps: EvaluateDeps, opts: SnapshotOptions): { snapshot: Snapshot } & AttributionLedger {
  const snapshot = enumerateWatched(ctx, {
    ...(opts.fastPath ? { baseline: fastPathBaseline(state, ctx) } : {}),
    ledgerLearned: ledgerLearned(ctx, state, opts.now),
    ...(opts.limits ? { limits: opts.limits } : {}),
    ...(deps.nexusEntries ? { nexusEntries: deps.nexusEntries } : {}),
  });
  return { snapshot, ...attributionLedger(state, snapshot, { ...opts, platform: ctx.platform }) };
}

export type ClassifyOptions = {
  now: Date;
  /** This run creates the machine's first store (render shows case B). */
  machineFirstRun?: boolean;
  /** The SessionStart deadline: classification stops, and the result is incomplete. */
  expired?: () => boolean;
  /** Screening stops (the rest is deferred to a later run). */
  stopScreening?: () => boolean;
  /** Characters the detectors may screen this run (the CLI passes Infinity). */
  scanBudget?: number;
  /** Bounds of the agent-activity log scan (its deadline and clock). */
  windows?: WindowScanOptions;
};

/**
 * Classify `snapshot` against the state's stores. A store that did not verify
 * is a baseline only under TAMPER (its best-effort parse, for quoting); without
 * a TAMPER it would be a leftover, and is a first run.
 */
export function classifyState(
  ctx: IntegrityContext,
  state: IntegrityState,
  snapshot: Snapshot,
  ledger: readonly LedgerEntry[],
  opts: ClassifyOptions,
): ClassifyResult {
  const input = (id: string) => {
    const load = state.stores[id];
    const tamper = load?.tamper ?? state.tamper[0] ?? null;
    return { doc: load && (load.verified || tamper) ? load.doc : null, tamper };
  };
  return classify({
    stores: {
      global: input(snapshot.global.id),
      project: input(snapshot.project.id),
      memory: snapshot.memory ? input(snapshot.memory.id) : null,
    },
    snapshot,
    ledger,
    windows: (since) => activityWindowsSince(state.paths.dataDir, since, opts.windows),
    config: state.config,
    now: opts.now,
    hashers: hashersOf(state.signer),
    home: ctx.home,
    platform: ctx.platform,
    ...(opts.machineFirstRun ? { machineFirstRun: true } : {}),
    ...(opts.expired ? { expired: opts.expired } : {}),
    ...(opts.stopScreening ? { stopScreening: opts.stopScreening } : {}),
    ...(opts.scanBudget !== undefined ? { scanBudget: opts.scanBudget } : {}),
  });
}

/**
 * Entries the caps left `unhashed` this run that were not unhashed at the last
 * persisted run: the change in the set §6.4 case F reports ("over the scan
 * limits"). Their store records them either as `unhashed` entries or, for a file
 * hashed before and capped since (it keeps its accepted baseline, compared again
 * once the cap clears), in its `capped` list.
 */
export function newlyUnhashed(state: IntegrityState, snapshot: Snapshot): number {
  let n = 0;
  const capped = new Map<string, ReadonlySet<string>>();
  for (const { store, key } of snapshot.unhashed) {
    const doc = state.stores[store]?.doc;
    if (doc?.entries[key]?.state === "unhashed") continue;
    let known = capped.get(store);
    if (!known) capped.set(store, (known = new Set(doc?.capped ?? [])));
    if (!known.has(key)) n++;
  }
  return n;
}
