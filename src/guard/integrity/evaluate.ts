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
 * changed: no attribution read at all. A third read, of at most
 * MAX_WROTE_HERE_FILES records, happens only when an unexplained addition asks
 * for activity windows and a session ran in another project (`windowsOf`).
 *
 * A project store's first run also reads the stores of other projects with
 * pending reviews, and of moved or deleted ones, for held entries to carry over
 * (`movedHolds`).
 */

import { lstatSync } from "node:fs";
import { dirname, join } from "node:path";
import { classify, heldIdOf, stableKey, type ClassifyHashers, type ClassifyResult, type WindowRead } from "./classify.js";
import { readCodexConfig, type IntegrityContext } from "./context.js";
import {
  enumerateWatched, type BaselineEntry, type EnumerateLimits, type EnumerateOptions, type Snapshot, type SnapshotEntry, type StoreSnapshot,
} from "./enumerate.js";
import { landedRecords, readLedger, type LedgerEntry } from "./ledger.js";
import { canonicalPath, isUnder, memoryStoreId, onDiskPath, projectStoreId, storeKey, userStoreId, watchedRoleOf } from "./paths.js";
import { activityWindowsSince, type WindowScanOptions } from "./session-log.js";
import { isCurrentVersion, loadIntegrity, readStore, type IntegrityState, type Signer } from "./store.js";
import { MAX_FILE_UNITS, RETENTION_MS, type StoreDoc, type StoreEntry, type StoreKind, type WatchedRole } from "./types.js";
import { sha256Hex, unitBound, unitsOf } from "./units.js";

export type EvaluateDeps = {
  /** D. */
  dataDir: string;
  homedir: string;
  platform: NodeJS.Platform;
  /** This install's entry scripts (default `nexusEntryScripts()`): only Nexus hooks naming one leave their script unwatched. */
  nexusEntries?: readonly string[];
};

/** The context's store ids: its agent's user-level store (`global` or `codex`), its project's, and its auto memory's when that was located. */
export function storeIdsOf(ctx: IntegrityContext): string[] {
  const ids: string[] = [userStoreId(ctx.agent), projectStoreId(ctx.root, ctx.platform)];
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
  "codex-project-md",
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
  const out: NonNullable<EnumerateOptions["baseline"]> = {};
  for (const [kind, id] of storeKinds(ctx)) {
    const load = id ? state.stores[id] : undefined;
    if (!load?.verified || load.tamper || !load.doc || !isCurrentVersion(load.doc)) continue;
    const entries: Record<string, BaselineEntry> = {};
    for (const [key, e] of Object.entries(load.doc.entries)) if (!e.held) entries[key] = e;
    out[kind] = entries;
  }
  return out;
}

/**
 * The held entries of the context's verified project and memory stores,
 * wherever they are: the CLI enumerates them too (`SnapshotOptions.held`), so
 * that `status`, `diff` and `accept` see a HOLD a session found from another
 * directory than theirs. (The global store's files do not depend on the cwd.)
 */
function heldEntries(state: IntegrityState, ctx: IntegrityContext): { store: StoreKind; path: string; role: WatchedRole }[] {
  const out: { store: StoreKind; path: string; role: WatchedRole }[] = [];
  for (const [kind, id] of storeKinds(ctx)) {
    if (kind === "global") continue;
    const load = id ? state.stores[id] : undefined;
    if (!load?.verified || load.tamper || !load.doc) continue;
    for (const e of Object.values(load.doc.entries)) if (e.held) out.push({ store: kind, path: e.path, role: e.role });
  }
  return out;
}

/** The context's stores by kind (the user-level one its agent's; no memory store when auto memory was not located). */
function storeKinds(ctx: IntegrityContext): [StoreKind, string | null][] {
  return [
    ["global", userStoreId(ctx.agent)],
    ["project", projectStoreId(ctx.root, ctx.platform)],
    ["memory", ctx.autoMemoryDir ? memoryStoreId(ctx.autoMemoryDir, ctx.platform) : null],
  ];
}

/** Registered project stores of other projects read at most, the most recently updated first. */
const MAX_MOVED_STORES = 8;

/**
 * A held entry of another project's store, and the key and path its file has
 * under this run's root. `entry.held` is the pending review; for a hold that
 * store cleared on a revert (`StoreEntry.reverted`) it is the held item it
 * remembers, and the entry is carried only at that very version (`exact`).
 */
type MovedHold = { oldKey: string; key: string; path: string; entry: StoreEntry; exact: boolean };

/**
 * One other store: its root, whether that root is gone (the project moved, or
 * was deleted), its holds, and its other files as they were accepted
 * (`accepted`: key under this run's root, sha) — a file of this project at one
 * of those versions shows the old store was this project's.
 */
type MovedStore = { root: string; gone: boolean; holds: MovedHold[]; accepted: [key: string, sha: string][] };

/** `movedHolds` once per loaded state: SessionStart and the CLI ask for it twice (enumeration, then classification). */
const movedCache = new WeakMap<IntegrityState, MovedStore[]>();

/**
 * Holds other project stores have that this one should carry over, on this
 * project store's first run (a store's id hashes its root, so a moved project
 * starts a new one). Read from the registered project stores (at most
 * MAX_MOVED_STORES, most recently updated first, each verified and not rolled
 * back) that recorded pending entries (`RegistryEntry.pending`), and from those
 * whose root no longer exists when the registry predates that count. Their held
 * entries, and the holds they cleared on a revert in the last RETENTION_MS — a
 * project moved aside, and a fresh checkout at its old path that reads as a
 * revert there — are re-keyed from the old root to the same relative path under
 * this root; any other (an ancestor file above both) is kept as is.
 * `carriedHolds` then picks those to compare. Nothing for a store with a
 * baseline, under TAMPER, or without a trusted key.
 */
function movedHolds(ctx: IntegrityContext, state: IntegrityState, now: number, expired?: () => boolean): MovedStore[] {
  const cached = movedCache.get(state);
  if (cached) return cached;
  const out: MovedStore[] = [];
  movedCache.set(state, out);
  const id = projectStoreId(ctx.root, ctx.platform);
  const own = state.stores[id];
  if (!state.signer || !state.registryVerified || state.tamper.length || own?.doc || own?.tamper) return out;
  const rootKey = storeKey(ctx.root, ctx.platform);
  const others = Object.entries(state.registry?.stores ?? {})
    .filter(([sid, s]) => sid !== id && sid.startsWith("project-") && typeof s.root === "string" && storeKey(s.root, ctx.platform) !== rootKey
      && (s.pending === undefined ? !lexists(s.root) : s.pending > 0))
    .sort((a, b) => (a[1].updatedAt < b[1].updatedAt ? 1 : a[1].updatedAt > b[1].updatedAt ? -1 : 0))
    .slice(0, MAX_MOVED_STORES);
  const seen = new Set<string>();
  for (const [sid, listed] of others) {
    if (expired?.()) break;
    const read = readStore(state.paths, sid, state.signer);
    if (read.state !== "ok" || read.doc.gen < listed.gen) continue;
    const oldRoot = storeKey(listed.root!, ctx.platform);
    const rekey = (oldKey: string) => {
      const rel = isUnder(oldKey, oldRoot, ctx.platform) && oldKey !== oldRoot ? oldKey.slice(oldRoot.length).replace(/^\/+/, "") : null;
      return rel === null ? null : `${rootKey.replace(/\/+$/, "")}/${rel}`;
    };
    const store: MovedStore = { root: listed.root!, gone: !lexists(listed.root!), holds: [], accepted: [] };
    for (const [oldKey, entry] of Object.entries(read.doc.entries)) {
      const key = rekey(oldKey);
      const reverted = !entry.held && entry.reverted && Date.parse(entry.reverted.at) > now - RETENTION_MS ? entry.reverted : null;
      if (!entry.held && !reverted) {
        if (key !== null && entry.state === "file" && entry.sha256) store.accepted.push([key, entry.sha256]);
        continue;
      }
      if (seen.has(key ?? oldKey)) continue;
      seen.add(key ?? oldKey);
      const { reverted: _reverted, ...held } = entry;
      store.holds.push({
        oldKey, key: key ?? oldKey, path: key === null ? entry.path : onDiskPath(key, ctx.platform),
        entry: reverted ? { ...held, held: reverted.held } : held, exact: !!reverted || !store.gone,
      });
    }
    if (store.holds.length) out.push(store);
  }
  return out;
}

/** Does anything (a dangling link included) sit at `p`? */
function lexists(p: string): boolean {
  try {
    return lstatSync(p, { throwIfNoEntry: false }) !== undefined;
  } catch {
    return true; // unreadable: not known to be gone
  }
}

/**
 * The moved holds (`movedHolds`) classification compares instead of accepting
 * the file as it is, as entries of this project store: the old baseline, with
 * its held item re-keyed when the file is at its held version — a copy of a
 * project keeps its pending review as a moved one does. A file changed again
 * since it was held is carried too, from a project that moved (its old root is
 * gone), only when this is evidently the same project: another held file is
 * here at its held version, or most of the old store's files that exist here
 * (at least two) are at the versions it accepted. It is then compared from
 * that accepted version, as it would have been had the project not moved. A
 * single shared file (an organisation's template settings) or shared lines
 * (the header `/init` writes into every CLAUDE.md) are no such evidence: an
 * unrelated project that replaced a deleted one at the same path would have
 * its own files reported as changes. Without the evidence the file is a
 * first-run file, as in any new project.
 * Claude Code keys `~/.claude.json`'s project section by path, so a moved
 * project starts a new one there: only its very version is carried. `from`:
 * the gone roots something was carried from (their sessions ran in this project).
 */
function carriedHolds(
  ctx: IntegrityContext, state: IntegrityState, snapshot: Snapshot, now: number,
): { entries: Record<string, StoreEntry>; from: string[] } {
  const out: Record<string, StoreEntry> = {};
  const from: string[] = [];
  const moved = movedHolds(ctx, state, now);
  if (!moved.length) return { entries: out, from };
  const { nonce } = hashersOf(state.signer);
  const entries = snapshot.project.entries;
  for (const store of moved) {
    const before = Object.keys(out).length;
    const atHeld = (m: MovedHold) => {
      const cur = entries[m.key];
      return !!cur && cur.state !== "unhashed" && heldIdOf(nonce, m.oldKey, cur) === m.entry.held!.id;
    };
    const sameProject = store.holds.some(atHeld) || mostFilesMatch(store.accepted, entries);
    for (const m of store.holds) {
      const cur = entries[m.key];
      if (!cur || cur.state === "missing") continue;
      if (atHeld(m)) {
        out[m.key] = { ...m.entry, path: cur.path, held: { ...m.entry.held!, id: heldIdOf(nonce, m.key, cur) } };
      } else if (!m.exact && m.entry.role !== "claude-json-project" && sameProject) {
        out[m.key] = { ...m.entry, path: cur.path };
      }
    }
    if (store.gone && Object.keys(out).length > before) from.push(store.root);
  }
  return { entries: out, from };
}

/** Of an old store's accepted files that exist here, are at least two, and more than half, at the version it accepted? */
function mostFilesMatch(accepted: readonly (readonly [string, string])[], entries: Readonly<Record<string, SnapshotEntry>>): boolean {
  let here = 0;
  let same = 0;
  for (const [key, sha] of accepted) {
    const cur = entries[key];
    if (!cur || !present(cur.state)) continue;
    here++;
    if (cur.sha256 === sha) same++;
  }
  return same >= 2 && same * 2 > here;
}

export type SnapshotOptions = {
  /** Epoch ms: the ledger's retention window ends here. */
  now: number;
  /** Reuse a baseline sha when the stat tuple is unchanged (SessionStart; the CLI reads every file). */
  fastPath: boolean;
  /** Also read every held entry of the context's stores, wherever it is (the CLI: `heldEntries`). */
  held?: boolean;
  limits?: Partial<EnumerateLimits>;
  /** The SessionStart deadline: the attribution read stops, and `ledgerComplete` is false. */
  expired?: () => boolean;
};

export type AttributionLedger = {
  /** Verified records of the entries classification compares, after the earliest of their `acceptedAt`; agent writes only once confirmed. */
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
 * created or deleted — after the earliest `acceptedAt` among them, keeping only
 * the agent writes PostToolUse confirmed landed (`landedRecords`). Each record
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
      const cur = snap.entries[key];
      if (!compared(snapshot, snap, prev, cur, key, opts.platform)) continue;
      keys.add(key);
      if (cur?.target) keys.add(cur.target); // a symlink: the records of the file it reaches
      const at = prev ? Date.parse(prev.acceptedAt) : 0;
      since = Math.min(since, Number.isFinite(at) ? at : 0);
    }
  }
  if (keys.size === 0) return { ledger: [], ledgerComplete: true };
  const read = readLedger(state.paths, state.signer, {
    keys, since, now: opts.now, maxFiles: Number.POSITIVE_INFINITY, ...(opts.expired ? { expired: opts.expired } : {}),
  });
  return { ledger: landedRecords(read), ledgerComplete: !read.truncated };
}

/**
 * The Codex homes Codex sessions fingerprinted (`EnumerateOptions.codexHomes`):
 * each records its C's hooks.json in the `codex` store, there or not
 * (enumerate.ts). They come from that signed store, not from the unsigned
 * `watch-prefixes.json`, whose lists only ever add asks: a home keeps a
 * project's `.codex/` out of a Claude Code session's project store until the
 * store holds it as a layer. That session does not load the codex store, and
 * reads it here; without a trusted one there are none.
 */
function codexHomesOf(state: IntegrityState): string[] {
  const id = userStoreId("codex");
  const load = state.stores[id];
  let doc: StoreDoc | null = null;
  if (load) doc = load.verified && !(load.tamper ?? state.tamper[0]) ? load.doc : null;
  else if (state.signer && state.tamper.length === 0) {
    const read = readStore(state.paths, id, state.signer);
    if (read.state === "ok") doc = read.doc;
  }
  return Object.values(doc?.entries ?? {}).filter((e) => e.role === "codex-user-hooks").map((e) => dirname(e.path));
}

/**
 * Does the context's project store hold a `.codex/` (by store key) as a project
 * layer (`EnumerateOptions.codexLayer`)? Every session that fingerprints one
 * records its config.toml, there or not, so a HOLD found there stays compared
 * once the `.codex/` is a Codex home too. A store that did not verify counts as
 * well: it is a first run or under TAMPER, and a layer it names is only
 * compared where it would have been skipped or found, never skipped.
 */
function codexLayerOf(state: IntegrityState, ctx: IntegrityContext): (dot: string) => boolean {
  const entries = state.stores[projectStoreId(ctx.root, ctx.platform)]?.doc?.entries ?? {};
  return (dot) => `${dot}/config.toml` in entries;
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
    codexHomes: () => codexHomesOf(state),
    codexLayer: codexLayerOf(state, ctx),
    held: [
      ...(opts.held ? heldEntries(state, ctx) : []),
      ...movedHolds(ctx, state, opts.now, opts.expired).flatMap((m) => m.holds).map((m) => ({ store: "project" as const, path: m.path, role: m.entry.role })),
    ],
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
  const carried = carriedHolds(ctx, state, snapshot, opts.now.getTime());
  return classify({
    stores: {
      global: input(snapshot.global.id),
      project: input(snapshot.project.id),
      memory: snapshot.memory ? input(snapshot.memory.id) : null,
    },
    snapshot,
    ...(Object.keys(carried.entries).length ? { carried: carried.entries } : {}),
    ledger,
    windows: (since) => windowsOf(ctx, state, since, opts, carried.from),
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

/** Ledger record files read at most to learn which other projects' sessions wrote into this one. */
const MAX_WROTE_HERE_FILES = 2000;

/**
 * The activity windows classification escalates with (H1): every session's
 * windows since `since`, each with the project roots it ran in, whether it ran
 * in this project and whether it wrote into it. That last needs the ledger, read (bounded, within the
 * deadline) only when a session ran where this project's root is not inside
 * its own; a read cut short, or no key to verify it with, counts every such
 * session as having written here: windows only escalate. A session that ran
 * where this project was before it moved (`movedFrom`, the old roots held
 * entries were carried from) ran in this project.
 */
function windowsOf(ctx: IntegrityContext, state: IntegrityState, since: number, opts: ClassifyOptions, movedFrom: readonly string[] = []): WindowRead {
  const scan = activityWindowsSince(state.paths.dataDir, since, opts.windows);
  const rootsOf = (roots: readonly string[]) =>
    movedFrom.length && roots.some((root) => movedFrom.some((old) => isUnder(root, old, ctx.platform))) ? [...roots, ctx.root] : roots;
  const sessions = scan.sessions.map((s) => ({ ...s, roots: rootsOf(s.roots) }));
  const elsewhere = sessions.filter((s) => s.roots.length > 0 && !s.roots.some((root) => isUnder(ctx.root, root, ctx.platform)));
  let wrote: ReadonlySet<string> | null = new Set();
  if (elsewhere.length) {
    if (!state.signer) {
      wrote = null;
    } else {
      const read = readLedger(state.paths, state.signer, {
        keys: null, since, now: opts.now.getTime(), maxFiles: MAX_WROTE_HERE_FILES, ...(opts.expired ? { expired: opts.expired } : {}),
      });
      const here = read.records.filter((r): r is Extract<LedgerEntry, { kind: "write" }> => r.kind === "write" && isUnder(r.path, ctx.root, ctx.platform));
      wrote = read.truncated ? null : new Set(here.map((r) => r.sid));
    }
  }
  return {
    windows: scan.windows,
    partial: scan.partial,
    sessions: sessions.map((s) => ({
      roots: s.roots,
      here: s.roots.some((root) => isUnder(ctx.root, root, ctx.platform) || isUnder(root, ctx.root, ctx.platform)),
      wroteHere: wrote === null || wrote.has(s.sid),
      windows: s.windows,
    })),
  };
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

/** Codex's hooks turned off in its user config, as a Claude Code session reports it (`codexHooksOff`). */
export type CodexHooksOff = {
  /** C/config.toml. */
  path: string;
  /** The switches, as their units read (`features.hooks = false`). */
  switches: string[];
  /** A keyed id of the switches: the session's `shown` list holds it, so a resume or compact does not say it again. */
  id: string;
};

/**
 * In a Claude Code session, the switches in Codex's user config (C/config.toml)
 * that turn every Codex hook off, Nexus's included, and that the `codex`
 * store's accepted fingerprint of the file does not hold. Codex then runs no
 * hook at all, so no Codex session can report them, and a Claude Code session
 * checks Claude Code's user-level files, not Codex's: this is where they show
 * up without `nexus guard integrity status --agent codex`. Null in Codex's
 * session, with no trusted key, when the file turns no hook off, and when the
 * codex store does not verify, is at another version or never fingerprinted
 * this C (Nexus never checked this Codex home: its switches are not Nexus's
 * hooks being turned off). Reads one file of at most 1 MiB, and the store only
 * when the file turns hooks off.
 */
export function codexHooksOff(ctx: IntegrityContext, state: IntegrityState): CodexHooksOff | null {
  const { signer } = state;
  if (ctx.agent === "codex" || !signer) return null;
  const path = join(ctx.codexHome, "config.toml");
  const text = readCodexConfig(path);
  // a file over the units cap is not unitized in the store either (enumerate.ts): nothing to compare
  if (text === null || unitBound("codex-user-config", Buffer.from(text)) > MAX_FILE_UNITS) return null;
  // the store's unit hasher (`hashersOf`), so the ids compare with its entry's
  const off = unitsOf("codex-user-config", text, { hasher: (t) => signer.hmac16("unit", t) }).units.filter((u) => u.hooksOff);
  if (off.length === 0) return null;
  const read = readStore(state.paths, userStoreId("codex"), signer);
  if (read.state !== "ok" || !isCurrentVersion(read.doc)) return null;
  const entry = read.doc.entries[storeKey(canonicalPath(path), ctx.platform)];
  // a file the store could not compare (over a cap) says nothing about what was accepted
  if (!entry || (entry.state !== "file" && entry.state !== "missing")) return null;
  const accepted = new Set(entry.state === "file" ? entry.units : []);
  const fresh = off.filter((u) => !accepted.has(u.id));
  if (fresh.length === 0) return null;
  return { path, switches: fresh.map((u) => u.text), id: signer.hmac16("nonce", `codex-hooks-off\0${fresh.map((u) => u.id).join("\0")}`) };
}
