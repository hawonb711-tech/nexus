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
 */

import { classify, type ClassifyHashers, type ClassifyResult } from "./classify.js";
import type { IntegrityContext } from "./context.js";
import { enumerateWatched, type BaselineEntry, type EnumerateLimits, type EnumerateOptions, type Snapshot } from "./enumerate.js";
import { readLedger, type LedgerEntry } from "./ledger.js";
import { isUnder, memoryStoreId, projectStoreId, watchedRoleOf } from "./paths.js";
import { activityWindowsSince, type WindowScanOptions } from "./session-log.js";
import { isCurrentVersion, loadIntegrity, type IntegrityState, type Signer } from "./store.js";
import type { StoreKind, WatchedRole } from "./types.js";
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
 * Paths of the agent writes on record to instruction files under R (a nested
 * `src/api/CLAUDE.md`). Enumeration watches each as `ledger-learned` unless
 * another role already does.
 */
function ledgerLearned(records: readonly LedgerEntry[], ctx: IntegrityContext): string[] {
  const out = new Set<string>();
  for (const r of records) {
    if (r.kind !== "write" || !isUnder(r.path, ctx.root, ctx.platform)) continue;
    const role = watchedRoleOf(r.path, { platform: ctx.platform });
    if (role && LEARNABLE_ROLES.has(role)) out.add(r.path);
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
};

/**
 * The watched set as it is now, and the verified ledger records of the
 * retention window (every path: classification picks each file's own, after
 * its `acceptedAt`). Without a trusted key there is no ledger.
 */
export function snapshotOf(ctx: IntegrityContext, state: IntegrityState, deps: EvaluateDeps, opts: SnapshotOptions): { snapshot: Snapshot; ledger: LedgerEntry[] } {
  const ledger = state.signer ? readLedger(state.paths, state.signer, { keys: null, since: 0, now: opts.now }).records : [];
  const snapshot = enumerateWatched(ctx, {
    ...(opts.fastPath ? { baseline: fastPathBaseline(state, ctx) } : {}),
    ledgerLearned: ledgerLearned(ledger, ctx),
    ...(opts.limits ? { limits: opts.limits } : {}),
    ...(deps.nexusEntries ? { nexusEntries: deps.nexusEntries } : {}),
  });
  return { snapshot, ledger };
}

export type ClassifyOptions = {
  now: Date;
  /** No anchor and no key existed (render shows case B). */
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
 * Entries the caps left `unhashed` this run that their store does not already
 * record as unhashed: the set §6.4 case F reports ("over the scan limits") when
 * it changes. A file hashed before and capped now keeps its accepted baseline
 * (classification compares it again once the cap clears), so it counts here at
 * every run until then.
 */
export function newlyUnhashed(state: IntegrityState, snapshot: Snapshot): number {
  let n = 0;
  for (const { store, key } of snapshot.unhashed) {
    if (state.stores[store]?.doc?.entries[key]?.state !== "unhashed") n++;
  }
  return n;
}
