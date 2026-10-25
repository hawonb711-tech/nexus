/**
 * Instruction-file integrity — the signed store (spec §4.1-4.3, §4.7, §4.8, §5.6).
 *
 * Layout under the data dir D (directories 0700, files 0600):
 *
 *   .integrity-anchor        outside integrity/ on purpose: proves a store existed, and names its key
 *   integrity/
 *     .integrity-key         the key; reading it never creates or replaces it
 *     .disabled              signed marker: integrity is off only while it verifies
 *     .lock                  the O_EXCL lock every write below is made under
 *     registry.json          signed: each store's generation, so a rolled-back or deleted store shows
 *     config.json            signed: the §8 keys (a missing file or key means its default)
 *     watch-prefixes.json    unsigned: it only ever adds asks
 *     log.jsonl              append-only display log, capped
 *     stores/<id>.json       signed store documents (`global`, `codex`, `project-<h16>`, `memory-<h16>`)
 *     ledger/ sessions/      written by ledger.ts and session-log.ts (no lock)
 *
 * Signing: K(label) = HMAC-SHA256(key, "nexus/integrity/v1/" + label); a
 * document's MAC is `"v1:" + hex(HMAC-SHA256(K(label), canonicalJson(doc
 * without "mac")))`, compared in constant time. `keyId = hmac16("key-id", "id")`
 * goes into the anchor, so a replaced key is noticed.
 *
 * Loading reports TAMPER (§5.6) instead of quietly starting over; under TAMPER
 * the old entries are still parsed best-effort (unverified) so the caller can
 * quote what changed. Writes are atomic (temp file, fsync, rename) and are made
 * under `withStoreLock`; a busy lock comes back as a result, not an exception.
 * The store keeps no file content: paths, sizes, stat tuples, hashes, keyed ids.
 */

import { closeSync, constants, existsSync, lstatSync, opendirSync, openSync, rmdirSync, statSync, unlinkSync } from "node:fs";
import { join, resolve } from "node:path";
import { atomicWriteFile, ensurePrivateDir, LockBusyError, withExclusiveLock } from "../../shared/atomic-file.js";
import { createKeyFile, readKeyFile, replaceKeyFile, type KeyFileRead } from "../../shared/key-file.js";
import { canonicalJson, hmacHex, subkey, timingSafeEqualHex } from "../../shared/sign.js";
import { PREFIX_LISTS, prefixListsOf } from "./paths.js";
import { appendPrivateText, listDir, readPrivateJson, readPrivateText } from "./private-file.js";
import {
  ANCHOR_FILE, CONFIG_DEFAULTS, CONFIG_FILE, DISABLED_FILE, HELD_RULES, HISTORY_MAX, INTEGRITY_DIR, INTEGRITY_SCHEMA, KEY_FILE,
  LEDGER_DIR, LOCK_FILE, LOCK_STALE_MS, LOG_FILE, LOG_KEEP_LINES, LOG_MAX_LINES, MAX_GC_DELETIONS, REGISTRY_FILE,
  PENDING_DIR, RETENTION_MS, SESSIONS_DIR, STORES_DIR, WATCH_PREFIXES_FILE, WATCHED_ROLES, WATCHED_SET_VERSION,
  type AcceptedBy, type AnchorDoc, type ConfigDoc, type DisabledMarker, type EntryState, type HeldItem, type HeldVerdict, type IntegrityConfig,
  type LogEntry, type LogEvent, type RegistryDoc, type RegistryEntry, type RevertedHold, type StatTuple, type StoreDoc, type StoreEntry, type StoreId,
  type StoreKind, type SubkeyLabel, type TamperReason, type TierRule, type UnitCategory, type WatchPrefixes, type WatchPrefixScope, type WatchedRole,
} from "./types.js";

// ── Paths ───────────────────────────────────────────────────────────────────

export type IntegrityPaths = {
  /** D. */
  dataDir: string;
  /** D/integrity. */
  dir: string;
  anchor: string;
  key: string;
  disabled: string;
  lock: string;
  registry: string;
  config: string;
  watchPrefixes: string;
  log: string;
  storesDir: string;
  ledgerDir: string;
  sessionsDir: string;
  /** Pending-confirm markers (pending.ts). */
  pendingDir: string;
};

export function integrityPaths(dataDir: string): IntegrityPaths {
  const dir = join(dataDir, INTEGRITY_DIR);
  return {
    dataDir,
    dir,
    anchor: join(dataDir, ANCHOR_FILE),
    key: join(dir, KEY_FILE),
    disabled: join(dir, DISABLED_FILE),
    lock: join(dir, LOCK_FILE),
    registry: join(dir, REGISTRY_FILE),
    config: join(dir, CONFIG_FILE),
    watchPrefixes: join(dir, WATCH_PREFIXES_FILE),
    log: join(dir, LOG_FILE),
    storesDir: join(dir, STORES_DIR),
    ledgerDir: join(dir, LEDGER_DIR),
    sessionsDir: join(dir, SESSIONS_DIR),
    pendingDir: join(dir, PENDING_DIR),
  };
}

const STORE_ID = /^(?:global|codex|project-[0-9a-f]{16}|memory-[0-9a-f]{16})$/;

function isStoreId(id: string): id is StoreId {
  return STORE_ID.test(id);
}

/** `stores/<id>.json`. Throws a TypeError for anything but a store id, so no id can become a path. */
function storeFile(paths: IntegrityPaths, id: string): string {
  if (!isStoreId(id)) throw new TypeError(`not an integrity store id: ${JSON.stringify(id)}`);
  return join(paths.storesDir, `${id}.json`);
}

/** Size caps for reading the store's own files (a planted giant file reads as invalid). */
const MAX_STORE_BYTES = 64 * 1024 * 1024;
const MAX_REGISTRY_BYTES = 4 * 1024 * 1024;
const MAX_SMALL_DOC_BYTES = 64 * 1024;
const MAX_PREFIX_BYTES = 4 * 1024 * 1024;
const MAX_PREFIX_ITEMS = 10_000;
const MAX_LOG_BYTES = 16 * 1024 * 1024;

const WRITE = { mode: 0o600, fsync: true } as const;

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

const isSafeCount = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

// ── Signing ─────────────────────────────────────────────────────────────────

const MAC_PREFIX = "v1:";

/** Keyed operations under one integrity key; subkeys are derived once per label. */
export type Signer = {
  /** `hmac16("key-id", "id")`: names the key in the anchor without revealing it. */
  readonly keyId: string;
  /** `hex(HMAC-SHA256(K(label), text)).slice(0, 16)`. */
  hmac16(label: SubkeyLabel, text: string): string;
  /** The document MAC of `doc`, its own `mac` field excluded. */
  mac(label: SubkeyLabel, doc: object): string;
  /** `doc` plus its MAC. */
  sign<T extends { mac: string }>(label: SubkeyLabel, doc: Omit<T, "mac">): T;
  /** Does `doc` carry a valid MAC for `label`? False for anything that is not a signed object. */
  verify(label: SubkeyLabel, doc: unknown): boolean;
};

export function signerFor(key: Buffer): Signer {
  const subkeys = new Map<SubkeyLabel, Buffer>();
  const k = (label: SubkeyLabel): Buffer => {
    let sk = subkeys.get(label);
    if (!sk) subkeys.set(label, (sk = subkey(key, label)));
    return sk;
  };
  const hmac16 = (label: SubkeyLabel, text: string) => hmacHex(k(label), text).slice(0, 16);
  const mac = (label: SubkeyLabel, doc: object): string => {
    const { mac: _ignored, ...rest } = doc as Record<string, unknown>;
    return MAC_PREFIX + hmacHex(k(label), canonicalJson(rest));
  };
  return {
    keyId: hmac16("key-id", "id"),
    hmac16,
    mac,
    sign: <T extends { mac: string }>(label: SubkeyLabel, doc: Omit<T, "mac">) => ({ ...doc, mac: mac(label, doc) }) as unknown as T,
    verify: (label, doc) => isRecord(doc) && typeof doc.mac === "string" && timingSafeEqualHex(doc.mac, mac(label, doc)),
  };
}

// ── Key and anchor ──────────────────────────────────────────────────────────

/** The key's state (`ok`, `missing` or `untrusted`). Never creates or replaces anything. */
export function readIntegrityKey(paths: IntegrityPaths): KeyFileRead {
  return readKeyFile(paths.key);
}

export type AnchorRead = { state: "ok"; anchor: AnchorDoc } | { state: "missing" } | { state: "malformed" };

function readAnchor(paths: IntegrityPaths): AnchorRead {
  const read = readPrivateJson(paths.anchor, MAX_SMALL_DOC_BYTES);
  if (read.state === "missing") return read;
  const v = read.state === "ok" ? read.value : null;
  if (isRecord(v) && v.v === 1 && typeof v.createdAt === "string" && typeof v.keyId === "string" && /^[0-9a-f]{16}$/.test(v.keyId)) {
    return { state: "ok", anchor: { v: 1, createdAt: v.createdAt, keyId: v.keyId } };
  }
  return { state: "malformed" };
}

function writeAnchor(paths: IntegrityPaths, keyId: string, now: Date): void {
  ensurePrivateDir(paths.dataDir);
  const anchor: AnchorDoc = { v: 1, createdAt: now.toISOString(), keyId };
  atomicWriteFile(paths.anchor, JSON.stringify(anchor), WRITE);
}

/**
 * Has a store been committed under this data dir? Asked when the anchor is
 * missing but a trusted key remains. A first run cut short leaves at most the
 * key and an empty registry: `initIntegrity` writes the anchor last, and only it
 * writes the anchor, so no store is committed before one exists. A registry
 * that lists a store, or any entry in `stores/` (any store's, not only the
 * context's), therefore means the anchor was deleted, and that is
 * `store-deleted`, never a first run: otherwise deleting the anchor with the
 * registry would let a rolled-back or deleted store pass unnoticed.
 */
function storesCommitted(paths: IntegrityPaths, registry: SignedRead<RegistryDoc>): boolean {
  if (registry.state === "ok" && Object.keys(registry.doc.stores).length > 0) return true;
  return listDir(paths.storesDir, 1).names.length > 0;
}

export type InitResult =
  | {
      ok: true;
      signer: Signer;
      createdKey: boolean;
      wroteRegistry: boolean;
      wroteAnchor: boolean;
      /** `reset` replaced a `config.json` that did not verify with signed defaults (for the reset summary). */
      replacedConfig: boolean;
    }
  /** The key exists but is not trusted, and `reset` was not asked: nothing was replaced. */
  | { ok: false; why: string };

/**
 * Create what a store needs: D and `integrity/` (0700), the key, an empty
 * signed registry, the anchor — in that order, so the anchor (the claim that a
 * store exists) is written last. Only the machine's first run, `guard install`
 * and `baseline --reset` call this.
 *
 * - The key is kept when trusted and created when missing. An untrusted key is
 *   replaced only with `reset`.
 * - The registry is written empty when it is missing and so is the anchor (a
 *   first run, or one interrupted before its anchor), when it does not verify
 *   and the key was just created (nothing older can verify), and with `reset`
 *   whenever it is missing or does not verify. Stores that still verify then
 *   load as unregistered, not tampered.
 * - The anchor is written when missing, and always with `reset`. A plain
 *   install therefore never clears a `key` or `store-deleted` TAMPER — a
 *   registry deleted under an existing anchor stays deleted; only
 *   `baseline --reset` does.
 * - Except with `reset`, a lost anchor (missing, the key kept, and a store
 *   already committed: see `storesCommitted`) is left as it is, registry
 *   included, so install cannot launder that `store-deleted` either.
 * - With `reset`, a `config.json` that does not verify (a `mac` TAMPER of its
 *   own) is replaced with signed defaults, and `replacedConfig` says so; the
 *   user's settings in it cannot be trusted, so they are not kept.
 *
 * Throws only on I/O failure (e.g. an unwritable data dir).
 */
export function initIntegrity(paths: IntegrityPaths, now: Date, opts: { reset?: boolean } = {}): InitResult {
  ensurePrivateDir(paths.dataDir);
  ensurePrivateDir(paths.dir);

  let key: Buffer;
  let createdKey = false;
  const before = readKeyFile(paths.key);
  if (before.state === "ok") {
    key = before.key;
  } else if (before.state === "missing") {
    const created = createKeyFile(paths.key);
    if (created.state !== "ok") return { ok: false, why: created.state === "untrusted" ? created.why : "is missing" };
    key = created.key;
    createdKey = true;
  } else {
    if (!opts.reset) return { ok: false, why: before.why };
    key = replaceKeyFile(paths.key);
    createdKey = true;
  }
  const signer = signerFor(key);

  let wroteRegistry = false;
  const anchorMissing = readAnchor(paths).state === "missing";
  const registry = readRegistry(paths, signer);
  if (anchorMissing && !createdKey && !opts.reset && storesCommitted(paths, registry)) {
    return { ok: true, signer, createdKey, wroteRegistry: false, wroteAnchor: false, replacedConfig: false };
  }
  if ((registry.state === "missing" && anchorMissing) || ((createdKey || opts.reset) && registry.state !== "ok")) {
    writeRegistry(paths, signer, emptyRegistry());
    wroteRegistry = true;
  }

  let replacedConfig = false;
  if (opts.reset && readConfig(paths, signer).state === "unverified") {
    writeConfig(paths, signer, STORED_DEFAULTS);
    replacedConfig = true;
  }

  let wroteAnchor = false;
  if (opts.reset || anchorMissing) {
    writeAnchor(paths, signer.keyId, now);
    wroteAnchor = true;
  }
  return { ok: true, signer, createdKey, wroteRegistry, wroteAnchor, replacedConfig };
}

// ── Signed documents ────────────────────────────────────────────────────────

/**
 * A signed document as read: `ok` (verified), `missing`, or `unverified` — the
 * MAC or shape is wrong, or there was no key to check it with. `doc` is then a
 * best-effort parse (never to be trusted, only shown), or null.
 */
export type SignedRead<T> = { state: "ok"; doc: T } | { state: "missing" } | { state: "unverified"; doc: T | null };

function readSigned<T>(
  path: string,
  maxBytes: number,
  label: SubkeyLabel,
  signer: Signer | null,
  parse: (raw: unknown) => T | null,
): SignedRead<T> {
  const read = readPrivateJson(path, maxBytes);
  if (read.state === "missing") return read;
  if (read.state === "invalid") return { state: "unverified", doc: null };
  const doc = parse(read.value);
  if (doc && signer?.verify(label, read.value)) return { state: "ok", doc };
  return { state: "unverified", doc };
}

// ── Registry ────────────────────────────────────────────────────────────────

export type UnsignedRegistry = Omit<RegistryDoc, "mac">;

export function emptyRegistry(): UnsignedRegistry {
  return { schema: "nexus-integrity-registry", v: 1, stores: {} };
}

function parseRegistry(raw: unknown): RegistryDoc | null {
  if (!isRecord(raw) || raw.schema !== "nexus-integrity-registry" || raw.v !== 1 || !isRecord(raw.stores)) return null;
  const stores: RegistryDoc["stores"] = {};
  for (const [id, s] of Object.entries(raw.stores)) {
    if (!isStoreId(id) || !isRecord(s) || !isSafeCount(s.gen) || typeof s.updatedAt !== "string") continue;
    const entry: RegistryEntry = { gen: s.gen, updatedAt: s.updatedAt };
    if (typeof s.root === "string") entry.root = s.root;
    if (isSafeCount(s.pending)) entry.pending = s.pending;
    stores[id] = entry;
  }
  return { schema: "nexus-integrity-registry", v: 1, stores, mac: typeof raw.mac === "string" ? raw.mac : "" };
}

/** The registry; its `mac` changes whenever anything in it does, so comparing MACs tells whether it moved. */
export function readRegistry(paths: IntegrityPaths, signer: Signer | null): SignedRead<RegistryDoc> {
  return readSigned(paths.registry, MAX_REGISTRY_BYTES, "registry", signer, parseRegistry);
}

function writeRegistry(paths: IntegrityPaths, signer: Signer, registry: UnsignedRegistry | RegistryDoc): RegistryDoc {
  const { mac: _old, ...rest } = registry as RegistryDoc;
  const signed = signer.sign<RegistryDoc>("registry", rest);
  atomicWriteFile(paths.registry, JSON.stringify(signed), WRITE);
  return signed;
}

// ── Store documents ─────────────────────────────────────────────────────────

export type UnsignedStoreDoc = Omit<StoreDoc, "mac">;

/** A new, empty store document at generation 0 (the first commit makes it 1). */
export function newStoreDoc(kind: StoreKind, id: StoreId, root: string | null, now: Date): UnsignedStoreDoc {
  const at = now.toISOString();
  const doc: UnsignedStoreDoc = {
    schema: "nexus-integrity-store",
    v: INTEGRITY_SCHEMA,
    watchedSetVersion: WATCHED_SET_VERSION,
    kind,
    id,
    root,
    gen: 0,
    createdAt: at,
    updatedAt: at,
    entries: {},
  };
  if (kind === "project") doc.autoMemoryDir = null;
  if (kind === "global") doc.memoryWritesObserved = false;
  return doc;
}

const ROLES: ReadonlySet<string> = new Set(WATCHED_ROLES);
const ENTRY_STATES: ReadonlySet<string> = new Set<EntryState>(["file", "missing", "oversize", "unhashed"]);
const ACCEPTED_BY: ReadonlySet<string> = new Set<AcceptedBy>(["first-run", "auto", "agent", "nexus", "user"]);
const CATEGORIES: ReadonlySet<string> = new Set<UnitCategory>(["e", "a", "r", "b"]);
const STORE_KINDS: ReadonlySet<string> = new Set<StoreKind>(["global", "project", "memory"]);
const SHA256 = /^[0-9a-f]{64}$/;
const EPOCH = new Date(0).toISOString();

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((s): s is string => typeof s === "string") : []);
const strOrNull = (v: unknown): string | null => (typeof v === "string" ? v : null);
const numOrNull = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

function parseStat(v: unknown): StatTuple | null {
  return Array.isArray(v) && v.length === 5 && v.every((n) => typeof n === "number" && Number.isFinite(n)) ? (v as StatTuple) : null;
}

/** A held item's recorded verdicts; absent (screen again) unless every one is well formed. */
function parseScreened(v: unknown): HeldVerdict[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: HeldVerdict[] = [];
  for (const x of v) {
    if (!isRecord(x) || !Array.isArray(x.units) || typeof x.reason !== "string" || typeof x.strong !== "boolean") return undefined;
    out.push({ units: strings(x.units), reason: x.reason, strong: x.strong });
  }
  return out;
}

/** A held item a revert cleared; dropped (undefined) unless it and its time are well formed. */
function parseReverted(v: unknown): RevertedHold | undefined {
  if (!isRecord(v) || typeof v.at !== "string") return undefined;
  const held = parseHeld(v.held);
  return held ? { held, at: v.at } : undefined;
}

function parseHeld(v: unknown): HeldItem | null {
  if (!isRecord(v) || typeof v.id !== "string" || (v.tier !== "HOLD" && v.tier !== "SUSPECT") || typeof v.since !== "string") return null;
  const held: HeldItem = { id: v.id, tier: v.tier, since: v.since, reasons: strings(v.reasons), flaggedUnits: strings(v.flaggedUnits) };
  if (typeof v.rule === "string" && HELD_RULES.has(v.rule)) held.rule = v.rule as TierRule;
  const screened = parseScreened(v.screened);
  if (screened) held.screened = screened;
  return held;
}

/** One entry, field by field: anything malformed becomes its empty value; no path, role or state → dropped. */
function parseEntry(v: unknown): StoreEntry | null {
  if (!isRecord(v) || typeof v.path !== "string" || typeof v.role !== "string" || !ROLES.has(v.role)) return null;
  if (typeof v.state !== "string" || !ENTRY_STATES.has(v.state)) return null;
  const cat: Record<string, UnitCategory> = {};
  if (isRecord(v.cat)) {
    for (const [unit, c] of Object.entries(v.cat)) if (typeof c === "string" && CATEGORIES.has(c)) cat[unit] = c as UnitCategory;
  }
  const history = Array.isArray(v.history)
    ? v.history
        .filter((h): h is { sha256: string; at: string } => isRecord(h) && typeof h.sha256 === "string" && typeof h.at === "string")
        .map((h) => ({ sha256: h.sha256, at: h.at }))
        .slice(-HISTORY_MAX)
    : [];
  const entry: StoreEntry = {
    path: v.path,
    role: v.role as WatchedRole,
    state: v.state as EntryState,
    sha256: typeof v.sha256 === "string" && SHA256.test(v.sha256) ? v.sha256 : null,
    size: numOrNull(v.size),
    stat: parseStat(v.stat),
    link: strOrNull(v.link),
    units: strings(v.units),
    cat,
    tok: strings(v.tok),
    nexusHooks: strings(v.nexusHooks),
    history,
    acceptedAt: typeof v.acceptedAt === "string" ? v.acceptedAt : EPOCH,
    acceptedBy: typeof v.acceptedBy === "string" && ACCEPTED_BY.has(v.acceptedBy) ? (v.acceptedBy as AcceptedBy) : "auto",
    held: parseHeld(v.held),
  };
  const reverted = parseReverted(v.reverted);
  if (reverted) entry.reverted = reverted;
  return entry;
}

function parseStore(raw: unknown): StoreDoc | null {
  if (!isRecord(raw) || raw.schema !== "nexus-integrity-store" || !isRecord(raw.entries)) return null;
  if (typeof raw.kind !== "string" || !STORE_KINDS.has(raw.kind) || typeof raw.id !== "string" || !isStoreId(raw.id)) return null;
  if (!isSafeCount(raw.gen) || !isSafeCount(raw.v) || !isSafeCount(raw.watchedSetVersion)) return null;
  const entries: Record<string, StoreEntry> = {};
  for (const [key, value] of Object.entries(raw.entries)) {
    const entry = parseEntry(value);
    if (entry) entries[key] = entry;
  }
  const doc: StoreDoc = {
    schema: "nexus-integrity-store",
    v: raw.v,
    watchedSetVersion: raw.watchedSetVersion,
    kind: raw.kind as StoreKind,
    id: raw.id,
    root: strOrNull(raw.root),
    gen: raw.gen,
    createdAt: typeof raw.createdAt === "string" ? raw.createdAt : EPOCH,
    updatedAt: typeof raw.updatedAt === "string" ? raw.updatedAt : EPOCH,
    entries,
    mac: typeof raw.mac === "string" ? raw.mac : "",
  };
  if ("autoMemoryDir" in raw) doc.autoMemoryDir = strOrNull(raw.autoMemoryDir);
  if (typeof raw.memoryWritesObserved === "boolean") doc.memoryWritesObserved = raw.memoryWritesObserved;
  if (Array.isArray(raw.capped)) doc.capped = strings(raw.capped);
  return doc;
}

/**
 * The store document `id`. It verifies only with a valid MAC *and* its own id
 * inside, so a validly signed document copied over another store's file does
 * not pass as that store.
 */
export function readStore(paths: IntegrityPaths, id: string, signer: Signer | null): SignedRead<StoreDoc> {
  const read = readSigned(storeFile(paths, id), MAX_STORE_BYTES, "store", signer, parseStore);
  if (read.state === "ok" && read.doc.id !== id) return { state: "unverified", doc: read.doc };
  return read;
}

/** `commitStores` found a registry on disk that does not verify: it stays as it is (TAMPER), and nothing was written. */
export class RegistryTamperError extends Error {
  readonly reason = "mac" as const;
  constructor() {
    super("the integrity registry does not verify; nothing was written (run nexus guard integrity baseline --reset)");
    this.name = "RegistryTamperError";
  }
}

export type StoreCommit = {
  /** Stores to write. `gen` and `updatedAt` are set here; the given `mac`, if any, is replaced. */
  write?: readonly (UnsignedStoreDoc | StoreDoc)[];
  /** Store ids to delete, with their registry entries (`baseline --reset`). */
  drop?: readonly string[];
};

/** The registry's `pending` for a store: its held entries, and those that remember a revert of one. */
function pendingCount(doc: Pick<StoreDoc, "entries">): number {
  let n = 0;
  for (const e of Object.values(doc.entries)) if (e.held || e.reverted) n++;
  return n;
}

/**
 * Write stores and the registry. Call it under `withStoreLock`.
 *
 * `registry` is the caller's copy, read before the lock was taken; another
 * session may have committed since. So the registry on disk is read again here:
 * - when it verifies, it is the base — every store registered in the meantime
 *   is kept, and a store dropped in the meantime stays dropped — and a written
 *   store's gen is above both copies' (a stale copy can neither drop a store nor
 *   roll its generation back);
 * - when it is missing, the caller's copy is the base;
 * - when it does not verify, nothing is written and `RegistryTamperError` is
 *   thrown: the TAMPER stays for `baseline --reset` (which re-creates the
 *   registry through `initIntegrity` first).
 *
 * Each written store gets `gen = max(its gen, the registry's gen) + 1`, and its
 * registry entry the count of its pending entries (`pendingCount`). Stores
 * are written before the registry, so a crash in between leaves a store one
 * generation ahead (still valid), never behind (a rollback). The anchor is
 * never written here (only `initIntegrity` writes it), so a commit cannot
 * re-anchor a store whose anchor was deleted.
 */
export function commitStores(
  paths: IntegrityPaths,
  signer: Signer,
  registry: UnsignedRegistry | RegistryDoc | null,
  commit: StoreCommit,
  now: Date,
): { registry: RegistryDoc; stores: StoreDoc[] } {
  const onDisk = readRegistry(paths, signer);
  if (onDisk.state === "unverified") throw new RegistryTamperError();
  ensurePrivateDir(paths.storesDir);
  const at = now.toISOString();
  const given = registry?.stores ?? {};
  const stores: RegistryDoc["stores"] = { ...(onDisk.state === "ok" ? onDisk.doc.stores : given) };
  const written: StoreDoc[] = [];
  for (const doc of commit.write ?? []) {
    const { mac: _old, ...rest } = doc as StoreDoc;
    const gen = Math.max(rest.gen, stores[rest.id]?.gen ?? 0, given[rest.id]?.gen ?? 0) + 1;
    const signed = signer.sign<StoreDoc>("store", { ...rest, gen, updatedAt: at });
    atomicWriteFile(storeFile(paths, rest.id), JSON.stringify(signed), WRITE);
    stores[rest.id] = { gen, updatedAt: at, ...(rest.root === null ? {} : { root: rest.root }), pending: pendingCount(rest) };
    written.push(signed);
  }
  for (const id of commit.drop ?? []) {
    try {
      unlinkSync(storeFile(paths, id));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    delete stores[id];
  }
  const signedRegistry = writeRegistry(paths, signer, { schema: "nexus-integrity-registry", v: 1, stores });
  return { registry: signedRegistry, stores: written };
}

// ── Version bumps (§5.4) ────────────────────────────────────────────────────

/** The fields a schema or watched-set bump recomputes; provenance is kept. */
export type DerivedFields = Pick<StoreEntry, "units" | "cat" | "tok" | "nexusHooks">;

export function isCurrentVersion(doc: Pick<StoreDoc, "v" | "watchedSetVersion">): boolean {
  return doc.v === INTEGRITY_SCHEMA && doc.watchedSetVersion === WATCHED_SET_VERSION;
}

/**
 * Bring a store written under an older INTEGRITY_SCHEMA or WATCHED_SET_VERSION
 * up to date without a wave of reports: every hashed entry whose current sha256
 * (`currentSha`) still equals its baseline gets its derived fields from
 * `recompute` (the caller cuts units; this module does not), keeping
 * `acceptedAt`, `acceptedBy`, `history` and `held`. Entries whose file changed
 * keep their old fields and are classified as usual; newly watched paths are the
 * caller's to add as first-run entries. `recompute` may return null to leave an
 * entry as it is. Returns the unsigned document and the keys recomputed.
 */
export function upgradeStore(
  doc: UnsignedStoreDoc | StoreDoc,
  currentSha: (key: string, entry: StoreEntry) => string | null | undefined,
  recompute: (key: string, entry: StoreEntry) => DerivedFields | null,
): { doc: UnsignedStoreDoc; recomputed: string[] } {
  const { mac: _old, ...rest } = doc as StoreDoc;
  const entries: Record<string, StoreEntry> = {};
  const recomputed: string[] = [];
  for (const [key, entry] of Object.entries(rest.entries)) {
    const derived = entry.state === "file" && entry.sha256 !== null && currentSha(key, entry) === entry.sha256 ? recompute(key, entry) : null;
    if (derived) {
      entries[key] = { ...entry, units: derived.units, cat: derived.cat, tok: derived.tok, nexusHooks: derived.nexusHooks };
      recomputed.push(key);
    } else {
      entries[key] = entry;
    }
  }
  return { doc: { ...rest, v: INTEGRITY_SCHEMA, watchedSetVersion: WATCHED_SET_VERSION, entries }, recomputed };
}

// ── Config and the disabled marker ──────────────────────────────────────────

export type StoredConfig = Omit<IntegrityConfig, "enabled">;

const STORED_DEFAULTS: StoredConfig = {
  instructionGate: CONFIG_DEFAULTS.instructionGate,
  memoryGate: CONFIG_DEFAULTS.memoryGate,
  agentWindowEscalation: CONFIG_DEFAULTS.agentWindowEscalation,
  withholdMcp: CONFIG_DEFAULTS.withholdMcp,
  quoteFlaggedLines: CONFIG_DEFAULTS.quoteFlaggedLines,
};

/** Known keys with valid values; anything else is its default (unknown keys are ignored). */
function configValues(raw: Record<string, unknown>): StoredConfig {
  return {
    instructionGate: raw.instructionGate === "always" || raw.instructionGate === "risky" ? raw.instructionGate : STORED_DEFAULTS.instructionGate,
    memoryGate: raw.memoryGate === "tainted-only" || raw.memoryGate === "novel-tokens" || raw.memoryGate === "exposed"
      ? raw.memoryGate : STORED_DEFAULTS.memoryGate,
    agentWindowEscalation: typeof raw.agentWindowEscalation === "boolean" ? raw.agentWindowEscalation : STORED_DEFAULTS.agentWindowEscalation,
    withholdMcp: raw.withholdMcp === "off" || raw.withholdMcp === "suspect" || raw.withholdMcp === "unreviewed"
      ? raw.withholdMcp : STORED_DEFAULTS.withholdMcp,
    quoteFlaggedLines: typeof raw.quoteFlaggedLines === "boolean" ? raw.quoteFlaggedLines : STORED_DEFAULTS.quoteFlaggedLines,
  };
}

/**
 * `config.json`: `missing` and `unverified` both give the defaults. Only the
 * human-gated CLI writes it, and a config that does not verify is TAMPER, so a
 * forged file can never loosen a setting. It verifies only with its signed
 * `kind: "config"`, so the `.disabled` marker (signed with the same subkey)
 * copied over it does not pass as a config.
 */
export function readConfig(paths: IntegrityPaths, signer: Signer | null): { state: SignedRead<unknown>["state"]; config: StoredConfig } {
  const read = readSigned(paths.config, MAX_SMALL_DOC_BYTES, "config", signer, (raw) => (isRecord(raw) && raw.v === 1 && raw.kind === "config" ? raw : null));
  return { state: read.state, config: read.state === "ok" ? configValues(read.doc) : { ...STORED_DEFAULTS } };
}

export function writeConfig(paths: IntegrityPaths, signer: Signer, config: StoredConfig): void {
  const doc = signer.sign<ConfigDoc>("config", { v: 1, kind: "config", ...configValues(config) });
  atomicWriteFile(paths.config, JSON.stringify(doc), WRITE);
}

/**
 * Is the `.disabled` marker present and signed, as a marker (`kind: "disabled"`)?
 * An unsigned or malformed marker, or a signed config document copied over it,
 * is ignored (integrity stays on).
 */
function readDisabled(paths: IntegrityPaths, signer: Signer | null): boolean {
  if (!signer || !existsSync(paths.disabled)) return false;
  const read = readPrivateJson(paths.disabled, MAX_SMALL_DOC_BYTES);
  if (read.state !== "ok") return false;
  const v = read.value;
  return isRecord(v) && v.v === 1 && v.kind === "disabled" && typeof v.at === "string" && (v.by === "cli" || v.by === "install")
    && signer.verify("config", v);
}

/** `readDisabled` for callers without a signer: absent marker → false without touching the key. */
export function isIntegrityDisabled(paths: IntegrityPaths): boolean {
  if (!existsSync(paths.disabled)) return false;
  const key = readKeyFile(paths.key);
  return key.state === "ok" && readDisabled(paths, signerFor(key.key));
}

export function writeDisabled(paths: IntegrityPaths, signer: Signer, by: DisabledMarker["by"], now: Date): void {
  const marker = signer.sign<DisabledMarker>("config", { v: 1, kind: "disabled", at: now.toISOString(), by });
  atomicWriteFile(paths.disabled, JSON.stringify(marker), WRITE);
}

export function removeDisabled(paths: IntegrityPaths): void {
  try {
    unlinkSync(paths.disabled);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

// ── watch-prefixes.json ─────────────────────────────────────────────────────

/** The lists: one scope's, or every scope's together (the Codex lists absent in a scope written before them). */
export type PrefixData = Pick<WatchPrefixes, "memoryDirs" | "configDirs" | "importTargets" | "hookScripts" | "codexDirs" | "codexDocs">;

/**
 * A scope's name (enumerate.ts `prefixScopes`): `config-`, `codex-`,
 * `project-` or `memory-` and a hash, a project's with its cwd's; or
 * LEGACY_SCOPE.
 */
const PREFIX_SCOPE = /^(?:(?:config|codex|project|memory)-[0-9a-f]{16}(?:-[0-9a-f]{16})?|legacy)$/;
/**
 * The scope that keeps the lists a file written before scopes holds at its top
 * level (one set, the last session's, as the previous release wrote it), seen
 * when that file was written: a session that release started keeps its asks
 * after the first SessionStart of this one, until the scope ages out.
 */
const LEGACY_SCOPE = "legacy";
/** Scopes kept at most, the most recently seen: the file is read whole on every watched write. */
const MAX_PREFIX_SCOPES = 128;
/**
 * A scope whose lists did not change is marked seen again at most this often,
 * so that a SessionStart with nothing new does not rewrite the file.
 */
const PREFIX_SEEN_REFRESH_MS = 24 * 60 * 60 * 1000;

const pathList = (v: unknown): string[] =>
  (Array.isArray(v) ? v.filter((s): s is string => typeof s === "string" && s !== "") : []).slice(0, MAX_PREFIX_ITEMS);

function parseScope(v: unknown): WatchPrefixScope | null {
  if (!isRecord(v) || typeof v.seen !== "string") return null;
  return {
    memoryDirs: pathList(v.memoryDirs), configDirs: pathList(v.configDirs), importTargets: pathList(v.importTargets), hookScripts: pathList(v.hookScripts),
    ...(v.codexDirs !== undefined ? { codexDirs: pathList(v.codexDirs) } : {}), ...(v.codexDocs !== undefined ? { codexDocs: pathList(v.codexDocs) } : {}),
    seen: v.seen,
  };
}

/**
 * The unsigned prefix lists — every scope's together, as the hooks read them —
 * and the scopes, the top-level lists of a file written before scopes as
 * LEGACY_SCOPE; or null when the file is missing or malformed. A forged file
 * can only add asks.
 */
export function readWatchPrefixes(paths: IntegrityPaths): WatchPrefixes | null {
  const read = readPrivateJson(paths.watchPrefixes, MAX_PREFIX_BYTES);
  if (read.state !== "ok") return null;
  const lists = prefixListsOf(read.value);
  if (!lists) return null;
  const raw = read.value as Record<string, unknown>;
  const updatedAt = typeof raw.updatedAt === "string" ? raw.updatedAt : EPOCH;
  const stores: Record<string, WatchPrefixScope> = {};
  if (isRecord(raw.stores)) {
    for (const [id, v] of Object.entries(raw.stores)) {
      const scope = PREFIX_SCOPE.test(id) ? parseScope(v) : null;
      if (scope) stores[id] = scope;
    }
  }
  const legacy = parseScope({ ...raw, seen: updatedAt });
  if (legacy && !stores[LEGACY_SCOPE] && PREFIX_LISTS.some((name) => (legacy[name]?.length ?? 0) > 0)) stores[LEGACY_SCOPE] = legacy;
  return { v: 1, ...lists, updatedAt, stores };
}

/** `watch-prefixes.json` holding `stores` (`nextWatchPrefixScopes`). Call it under `withStoreLock`. */
export function writeWatchPrefixScopes(paths: IntegrityPaths, stores: Readonly<Record<string, WatchPrefixScope>>, now: Date): void {
  atomicWriteFile(paths.watchPrefixes, JSON.stringify({ v: 1, updatedAt: now.toISOString(), stores }), WRITE);
}

/** A scope's lists as written: each capped, a Codex list written only when it has paths (a scope without one reads the same). */
function pickLists(data: PrefixData): PrefixData {
  const codexDirs = (data.codexDirs ?? []).slice(0, MAX_PREFIX_ITEMS);
  const codexDocs = (data.codexDocs ?? []).slice(0, MAX_PREFIX_ITEMS);
  return {
    memoryDirs: [...data.memoryDirs].slice(0, MAX_PREFIX_ITEMS),
    configDirs: [...data.configDirs].slice(0, MAX_PREFIX_ITEMS),
    importTargets: [...data.importTargets].slice(0, MAX_PREFIX_ITEMS),
    hookScripts: [...data.hookScripts].slice(0, MAX_PREFIX_ITEMS),
    ...(codexDirs.length ? { codexDirs } : {}),
    ...(codexDocs.length ? { codexDocs } : {}),
  };
}

function sameLists(a: PrefixData, b: PrefixData): boolean {
  const same = (x: readonly string[] = [], y: readonly string[] = []) => x.length === y.length && x.every((v, i) => v === y[i]);
  return same(a.memoryDirs, b.memoryDirs) && same(a.configDirs, b.configDirs)
    && same(a.importTargets, b.importTargets) && same(a.hookScripts, b.hookScripts)
    && same(a.codexDirs, b.codexDirs) && same(a.codexDocs, b.codexDocs);
}

/**
 * The scopes `watch-prefixes.json` holds once a SessionStart found `scopes`, or
 * null when the file (`current`) already holds them and nothing aged out. Each
 * of `scopes` replaces its earlier lists, and is marked seen now when they
 * changed or were last marked a day ago or more; every other scope is kept
 * until it has not been seen for RETENTION_MS (a project not worked in for 30
 * days), at most MAX_PREFIX_SCOPES in all, the ones just found first, then the
 * most recently seen. Lists outside any scope (a file written before scopes)
 * are kept so, as LEGACY_SCOPE (`readWatchPrefixes`).
 */
export function nextWatchPrefixScopes(
  current: WatchPrefixes | null, scopes: Readonly<Record<string, PrefixData>>, now: Date,
): Record<string, WatchPrefixScope> | null {
  const nowMs = now.getTime();
  const before = current?.stores ?? {};
  let changed = current === null;
  const found: [string, WatchPrefixScope][] = [];
  for (const [id, lists] of Object.entries(scopes)) {
    const old = before[id];
    const seen = old ? Date.parse(old.seen) : NaN;
    if (old && sameLists(old, lists) && seen > nowMs - PREFIX_SEEN_REFRESH_MS) {
      found.push([id, old]);
    } else {
      found.push([id, { ...pickLists(lists), seen: now.toISOString() }]);
      changed = true;
    }
  }
  const others: [string, WatchPrefixScope, number][] = [];
  for (const [id, scope] of Object.entries(before)) {
    if (id in scopes) continue;
    const seen = Date.parse(scope.seen);
    if (seen >= nowMs - RETENTION_MS) others.push([id, scope, seen]);
    else changed = true; // not seen for the retention window (or no valid time): dropped
  }
  others.sort((a, b) => b[2] - a[2]);
  const room = Math.max(0, MAX_PREFIX_SCOPES - found.length);
  if (others.length > room) changed = true;
  if (!changed) return null;
  return Object.fromEntries([...found, ...others.slice(0, room).map(([id, scope]) => [id, scope] as const)]);
}

// ── log.jsonl ───────────────────────────────────────────────────────────────

const LOG_EVENTS: ReadonlySet<string> = new Set<LogEvent>([
  "advance", "notice", "hold", "suspect", "cleared-revert", "accept", "first-run", "tamper", "reset",
]);

/**
 * Append `entries` (one JSON object per line, in one write), then cap the file:
 * once it holds LOG_MAX_LINES (1,200) lines it is rewritten atomically to the
 * last LOG_KEEP_LINES (1,000). Call it under `withStoreLock`. Throws, without
 * blocking, when something other than a regular file (a symlink, a FIFO) is
 * planted at the log path.
 */
export function appendLog(paths: IntegrityPaths, entries: readonly LogEntry[]): void {
  if (entries.length === 0) return;
  const text = entries.map((e) => JSON.stringify(e)).join("\n") + "\n";
  appendPrivateText(paths.log, text);
  const read = readPrivateText(paths.log, MAX_LOG_BYTES);
  if (read.state === "invalid") {
    // An oversized or planted log: start over with what was just appended.
    atomicWriteFile(paths.log, text, WRITE);
    return;
  }
  if (read.state !== "ok") return;
  const lines = read.text.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  if (lines.length >= LOG_MAX_LINES) atomicWriteFile(paths.log, lines.slice(-LOG_KEEP_LINES).join("\n") + "\n", WRITE);
}

/** The last `limit` well-formed log entries, oldest first. Malformed lines are skipped. */
export function readLog(paths: IntegrityPaths, limit = 50): LogEntry[] {
  const read = readPrivateText(paths.log, MAX_LOG_BYTES);
  if (read.state !== "ok") return [];
  const out: LogEntry[] = [];
  const lines = read.text.split("\n");
  for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
    if (lines[i] === "") continue;
    try {
      const v = JSON.parse(lines[i]) as unknown;
      if (isRecord(v) && typeof v.at === "string" && typeof v.event === "string" && LOG_EVENTS.has(v.event)) out.push(v as LogEntry);
    } catch {
      // skipped
    }
  }
  return out.reverse();
}

// ── Lock ────────────────────────────────────────────────────────────────────

/** `busy`: another writer holds the lock (or it is not provably stale); `unavailable`: it could not be created at all. */
export type LockResult<T> = { ok: true; value: T } | { ok: false; reason: "busy" | "unavailable"; error: Error };

/**
 * Run `fn` holding `integrity/.lock` (O_EXCL; a dead owner's lock is taken over
 * after 30 s). SessionStart waits LOCK_WAIT_SESSION_START_MS (1 s) and persists
 * nothing on failure; the CLI waits LOCK_WAIT_CLI_MS (5 s). Failing to take the
 * lock is a result, never an exception; an exception thrown by `fn` propagates.
 */
export function withStoreLock<T>(paths: IntegrityPaths, fn: () => T, waitMs: number): LockResult<T> {
  let entered = false;
  try {
    const value = withExclusiveLock(paths.lock, () => {
      entered = true;
      return fn();
    }, { waitMs, staleMs: LOCK_STALE_MS });
    return { ok: true, value };
  } catch (error) {
    if (entered) throw error;
    const err = error instanceof Error ? error : new Error(String(error));
    return { ok: false, reason: error instanceof LockBusyError ? "busy" : "unavailable", error: err };
  }
}

// ── Loading and TAMPER detection (§5.6) ─────────────────────────────────────

/** The §5.6 message fragment for each TAMPER reason. */
export const TAMPER_FRAGMENTS: Readonly<Record<TamperReason, string>> = {
  permission: "Nexus may not read its fingerprint store (permission denied); check who owns it",
  mac: "signature mismatch",
  "missing-store": "a registered fingerprint is missing",
  rollback: "an older fingerprint was restored",
  "store-deleted": "the fingerprint store was deleted",
  key: "the integrity key is unreadable or was replaced",
  redirect:
    "NEXUS_DATA points to an empty store while ~/.nexus has one; if you set NEXUS_DATA on purpose, run nexus guard integrity baseline with it set",
};

/** Store-wide reasons, most significant first. */
const GLOBAL_ORDER: readonly TamperReason[] = ["permission", "redirect", "store-deleted", "key", "mac"];

export type LoadDeps = {
  /** D. */
  dataDir: string;
  /** The home directory (for the `redirect` check against `~/.nexus`). */
  homedir: string;
  platform: NodeJS.Platform;
};

export type StoreLoad = {
  id: string;
  /** The verified document; otherwise a best-effort parse of the file (unverified, for showing old lines only), or null. */
  doc: StoreDoc | null;
  verified: boolean;
  /** The registry lists this store. */
  registered: boolean;
  /**
   * A store file that does not verify and that a trusted (or absent) registry
   * does not list — a leftover from a lost key or an interrupted reset, which
   * no writer without the key could make matter. It loads as absent (a first
   * run for that store) and the next commit overwrites it.
   */
  orphan: boolean;
  /** The TAMPER reason that applies to this store (a store-wide one first), or null. */
  tamper: TamperReason | null;
};

export type IntegrityState = {
  paths: IntegrityPaths;
  /** The key as read; never created or replaced by loading. */
  key: KeyFileRead;
  signer: Signer | null;
  anchor: AnchorRead;
  /**
   * No anchor and no redirect, and either no key (the machine's first run) or a
   * trusted key, a missing or verified empty registry and nothing in `stores/`
   * (a first run cut short before its anchor): `initIntegrity`, then load
   * again. The stores, config and marker were not read.
   */
  machineFirstRun: boolean;
  /** TAMPER reasons that apply to every store, most significant first. */
  tamper: TamperReason[];
  /** With TAMPER `permission`: the first of D, `integrity/`, the anchor and the key Nexus may not read. */
  unreadable: string | null;
  /** The registry (best-effort when not verified), or null when missing. */
  registry: RegistryDoc | null;
  registryVerified: boolean;
  /** The §8 config (defaults unless it verified); `enabled` reflects the marker. */
  config: IntegrityConfig;
  disabled: boolean;
  stores: Record<string, StoreLoad>;
};

/** A directory, or a symlink to one (a moved store still verifies by its contents). */
function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

/** §5.6 `redirect`: D is not `~/.nexus`, `~/.nexus` holds an anchor, and D does not. */
function redirected(deps: LoadDeps, anchor: AnchorRead): boolean {
  if (anchor.state !== "missing") return false;
  const home = resolve(deps.homedir, ".nexus");
  const data = resolve(deps.dataDir);
  const same = deps.platform === "win32" ? data.toLowerCase() === home.toLowerCase() : data === home;
  return !same && existsSync(join(home, ANCHOR_FILE));
}

/**
 * Load and verify the key, anchor, registry, config, marker and the stores
 * `storeIds` (the context's global, project and memory stores), and report
 * TAMPER exactly as §5.6 defines it:
 *
 * - `redirect`: D !== resolve(homedir, ".nexus"), `~/.nexus/.integrity-anchor`
 *   exists, and `D/.integrity-anchor` does not;
 * - `store-deleted`: the anchor exists but `integrity/`, the registry or the key
 *   is missing; or the anchor is missing while a trusted key remains and a store
 *   was committed (`storesCommitted`), which §5.6 does not name: a deleted
 *   anchor is not a first run;
 * - `key`: the key is untrusted, or it does not match the anchor's keyId (or the anchor is malformed);
 * - `mac`: the registry or config does not verify (store-wide), or a store does (that store);
 * - `missing-store`: the registry lists a store whose file is missing;
 * - `rollback`: a store's gen is below the registry's.
 *
 * Read-only: nothing is created, replaced or repaired.
 */
export function loadIntegrity(deps: LoadDeps, storeIds: readonly string[]): IntegrityState {
  const paths = integrityPaths(resolve(deps.dataDir));
  const anchor = readAnchor(paths);
  const dirExists = isDirectory(paths.dir);
  const key: KeyFileRead = dirExists ? readKeyFile(paths.key) : { state: "missing" };
  const signer = key.state === "ok" ? signerFor(key.key) : null;
  const reasons = new Set<TamperReason>();
  const anchorExists = anchor.state !== "missing";

  if (redirected(deps, anchor)) reasons.add("redirect");
  const registryRead = readRegistry(paths, signer);
  const anchorLost = !anchorExists && key.state === "ok" && storesCommitted(paths, registryRead);
  const machineFirstRun =
    !anchorExists &&
    !reasons.has("redirect") &&
    (key.state === "missing" || (key.state === "ok" && !anchorLost && registryRead.state !== "unverified"));
  const stores: Record<string, StoreLoad> = {};
  const absent = (id: string, orphan = false, tamper: TamperReason | null = null): StoreLoad =>
    ({ id, doc: null, verified: false, registered: false, orphan, tamper });

  if (machineFirstRun) {
    for (const id of storeIds) stores[id] = absent(id);
    return {
      paths, key, signer, anchor, machineFirstRun, tamper: [], unreadable: null, registry: null, registryVerified: false,
      config: { ...STORED_DEFAULTS, enabled: true }, disabled: false, stores,
    };
  }

  if (anchorExists && (!dirExists || key.state === "missing" || !existsSync(paths.registry))) reasons.add("store-deleted");
  if (anchorLost) reasons.add("store-deleted");
  if (key.state === "untrusted") reasons.add("key");
  if (signer && anchorExists && (anchor.state !== "ok" || !timingSafeEqualHex(anchor.anchor.keyId, signer.keyId))) reasons.add("key");

  if (signer && registryRead.state === "unverified") reasons.add("mac");
  const registry = registryRead.state === "missing" ? null : registryRead.doc;
  const registryVerified = registryRead.state === "ok";
  // A missing registry with no anchor claims nothing; with an anchor it is already `store-deleted`.
  const registryTrusted = registryVerified || registryRead.state === "missing";

  const config = readConfig(paths, signer);
  if (signer && config.state === "unverified") reasons.add("mac");
  const disabled = readDisabled(paths, signer);

  // A store another account owns (`sudo nexus guard install` keeping HOME), or one Nexus may not
  // read, looks deleted or its key replaced: say which it is, and that only its owner can fix it.
  const unreadable = reasons.has("store-deleted") || reasons.has("key") || anchor.state === "malformed" ? accessProblem(paths) : null;
  if (unreadable) {
    for (const r of ["store-deleted", "key", "mac"] as const) reasons.delete(r);
    reasons.add("permission");
  }

  const tamper = GLOBAL_ORDER.filter((r) => reasons.has(r));
  for (const id of storeIds) {
    const listed = registry?.stores[id];
    const read = readStore(paths, id, signer);
    let own: TamperReason | null = null;
    let orphan = false;
    if (read.state === "missing") {
      if (listed) own = "missing-store";
    } else if (read.state === "unverified") {
      if (signer && registryTrusted && !listed) orphan = true;
      else if (signer) own = "mac";
    } else if (listed && registryVerified && read.doc.gen < listed.gen) {
      own = "rollback";
    }
    const reason = tamper[0] ?? own;
    stores[id] = orphan
      ? absent(id, true, reason)
      : {
          id,
          doc: read.state === "missing" ? null : read.doc,
          verified: read.state === "ok",
          registered: !!listed,
          orphan: false,
          tamper: reason,
        };
  }

  return {
    paths, key, signer, anchor, machineFirstRun, tamper, unreadable, registry, registryVerified,
    config: { ...config.config, enabled: !disabled }, disabled, stores,
  };
}

const DENIED: ReadonlySet<string> = new Set(["EACCES", "EPERM"]);
const errorCode = (error: unknown) => String((error as NodeJS.ErrnoException).code ?? "");

/**
 * The first of D and `integrity/` that belongs to another account, or of them,
 * the anchor and the key, that Nexus is denied (EACCES, EPERM) listing or
 * opening; null when there is none. Asked only once the store already looks
 * deleted or its key replaced. Nothing is read beyond an open. A key alone
 * owned by someone else, in a store that is the user's, stays `key`.
 */
function accessProblem(paths: IntegrityPaths): string | null {
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  const checks: [string, boolean][] = [[paths.dataDir, true], [paths.dir, true], [paths.anchor, false], [paths.key, false]];
  for (const [path, isDir] of checks) {
    let owner: number;
    try {
      owner = lstatSync(path).uid;
    } catch (error) {
      if (DENIED.has(errorCode(error))) return path;
      continue; // missing: the reason stands
    }
    if (isDir && uid !== null && owner !== uid) return path;
    try {
      if (isDir) opendirSync(path).closeSync();
      else closeSync(openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0)));
    } catch (error) {
      if (DENIED.has(errorCode(error))) return path;
    }
  }
  return null;
}

// ── Retention ───────────────────────────────────────────────────────────────

const DAY_MS = 24 * 60 * 60 * 1000;
const DAY_DIR = /^(\d{4})(\d{2})(\d{2})$/;
/** A ledger record's file name, `<epochMs>-<sid8>-<rand6>.json` (ledger.ts writes and reads them). */
export const LEDGER_RECORD_NAME = /^(\d{1,16})-([0-9a-z]{8})-[0-9a-f]{6}\.json$/;
/** sessions/<sid16>.log|json, and the temp files an interrupted atomic write leaves. */
const SESSION_FILE = /^[0-9a-f]{16}\.(?:log|json)(?:\.\d{1,10}\.[0-9a-f]{12}\.tmp)?$/;
/** Directory entries looked at per directory per run. */
const GC_SCAN_LIMIT = 20_000;

/** `ledger/<YYYYMMDD>` (UTC) for an epoch-ms time. */
export function ledgerDayName(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10).replace(/-/g, "");
}

/** Start (UTC epoch ms) of a ledger day directory name, or null when it is not one. */
export function ledgerDayStart(name: string): number | null {
  const m = DAY_DIR.exec(name);
  if (!m) return null;
  const t = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  return Number.isFinite(t) && ledgerDayName(t) === name ? t : null;
}

export type GcOptions = {
  /** Epoch ms the retention window is measured from. */
  now: number;
  /** Stop before any deletion once `clock() >= deadline` (default: no deadline). */
  deadline?: number;
  /** Current epoch ms (default: `now`, i.e. a fixed clock). */
  clock?: () => number;
  maxDeletions?: number;
  retentionMs?: number;
};

/** `path` itself is a directory (lstat: a symlink to one is not), so retention never deletes outside the store. */
function isRealDirectory(path: string): boolean {
  try {
    return lstatSync(path).isDirectory();
  } catch {
    return false;
  }
}

const NOTHING_LISTED = { names: [] as string[], more: false };

/**
 * Remove ledger day directories whose whole day is older than the retention
 * window (30 days), oldest first, then session `.log` / `.json` files (and
 * stale temp files) last modified before it, then pending-confirm markers
 * older than a day (an ask the user rejected is never confirmed). Each unlinked file or removed
 * directory counts as one deletion; at most MAX_GC_DELETIONS (500) per call,
 * and nothing more once the deadline passes. `complete` is false when anything
 * may be left for the next run. Never throws. Only regular files with a ledger
 * record's or a session file's name are unlinked, in real directories: a
 * symlinked `ledger/`, day or `sessions/` directory is never followed, and
 * unrecognised names are left alone (keeping their day directory).
 */
export function collectGarbage(paths: IntegrityPaths, opts: GcOptions): { deleted: number; complete: boolean } {
  const { now, deadline = Number.POSITIVE_INFINITY, maxDeletions = MAX_GC_DELETIONS, retentionMs = RETENTION_MS } = opts;
  const clock = opts.clock ?? (() => now);
  const cutoff = now - retentionMs;
  let deleted = 0;
  const mayDelete = () => deleted < maxDeletions && clock() < deadline;
  const tryRemove = (remove: () => void): void => {
    try {
      remove();
      deleted++;
    } catch {
      // gone already, or not ours to remove
    }
  };

  const days = isRealDirectory(paths.ledgerDir) ? listDir(paths.ledgerDir, GC_SCAN_LIMIT) : NOTHING_LISTED;
  let complete = !days.more;
  const old = days.names
    .map((name) => ({ name, start: ledgerDayStart(name) }))
    .filter((d): d is { name: string; start: number } => d.start !== null && d.start + DAY_MS <= cutoff)
    .sort((a, b) => a.start - b.start);
  for (const { name } of old) {
    const dir = join(paths.ledgerDir, name);
    if (!isRealDirectory(dir)) continue;
    const files = listDir(dir, maxDeletions);
    for (const file of files.names) {
      if (!LEDGER_RECORD_NAME.test(file)) continue;
      const path = join(dir, file);
      try {
        if (!lstatSync(path).isFile()) continue;
      } catch {
        continue;
      }
      if (!mayDelete()) return { deleted, complete: false };
      tryRemove(() => unlinkSync(path));
    }
    if (!mayDelete()) return { deleted, complete: false };
    tryRemove(() => rmdirSync(dir));
    if (files.more) complete = false;
  }

  const sessions = isRealDirectory(paths.sessionsDir) ? listDir(paths.sessionsDir, GC_SCAN_LIMIT) : NOTHING_LISTED;
  if (sessions.more) complete = false;
  for (const name of sessions.names) {
    if (!SESSION_FILE.test(name)) continue;
    const path = join(paths.sessionsDir, name);
    let mtimeMs: number;
    try {
      const st = lstatSync(path);
      if (!st.isFile()) continue;
      mtimeMs = st.mtimeMs;
    } catch {
      continue;
    }
    if (mtimeMs >= cutoff) continue;
    if (!mayDelete()) return { deleted, complete: false };
    tryRemove(() => unlinkSync(path));
  }

  const pending = isRealDirectory(paths.pendingDir) ? listDir(paths.pendingDir, GC_SCAN_LIMIT) : NOTHING_LISTED;
  if (pending.more) complete = false;
  for (const name of pending.names) {
    if (!PENDING_MARKER.test(name)) continue;
    const path = join(paths.pendingDir, name);
    try {
      const st = lstatSync(path);
      if (!st.isFile() || st.mtimeMs >= now - DAY_MS) continue;
    } catch {
      continue;
    }
    if (!mayDelete()) return { deleted, complete: false };
    tryRemove(() => unlinkSync(path));
  }
  return { deleted, complete };
}

/** A pending-confirm marker's name (pending.ts). */
const PENDING_MARKER = /^[0-9a-f]{32}$/;

