/**
 * Crash-safe file primitives shared by the memory engine and the integrity
 * store: atomic replace, single-write appends, private directories, and an
 * O_EXCL lock file with dead-owner recovery. Synchronous `node:fs` only.
 */

import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { randomBytes, randomUUID } from "node:crypto";

/** Block the thread for `ms` (no event-loop turn; callers are synchronous). */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// ── Atomic replace ──────────────────────────────────────────────────────────

const RENAME_RETRIES = 3;
const RENAME_RETRY_MS = 20;

/**
 * `renameSync`, retried on win32 when the target is briefly held open (EBUSY /
 * EPERM from an antivirus scan or an indexer): 3 retries, 20 ms apart. Anything
 * else, and any error on other platforms, is thrown at once. `platform` and
 * `rename` are injectable for tests.
 */
export function renameWithRetry(
  from: string,
  to: string,
  platform: NodeJS.Platform = process.platform,
  rename: (from: string, to: string) => void = renameSync,
): void {
  for (let attempt = 0; ; attempt++) {
    try {
      rename(from, to);
      return;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (platform !== "win32" || (code !== "EBUSY" && code !== "EPERM") || attempt >= RENAME_RETRIES) throw error;
      sleepSync(RENAME_RETRY_MS);
    }
  }
}

export type AtomicWriteOptions = {
  /** Mode of a newly written file (default 0600). */
  mode?: number;
  /** fsync the data before the rename (default true). Bulk writers that can
   *  afford to lose the last write on power loss may turn it off. */
  fsync?: boolean;
};

/**
 * Replace `path` with `data` so a reader sees the old file or the new one, never
 * a torn write: the data goes to a fresh `wx` temp file beside the target, which
 * is renamed over it. The temp file is removed on any failure.
 */
export function atomicWriteFile(path: string, data: string | Uint8Array, opts: AtomicWriteOptions = {}): void {
  const { mode = 0o600, fsync = true } = opts;
  const tempPath = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  let fd: number | undefined;
  let created = false;
  let renamed = false;
  try {
    fd = openSync(tempPath, "wx", mode);
    created = true;
    writeFileSync(fd, data);
    if (fsync) fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameWithRetry(tempPath, path);
    renamed = true;
  } finally {
    if (fd !== undefined) closeSync(fd);
    if (created && !renamed) {
      try { unlinkSync(tempPath); } catch { /* already gone */ }
    }
  }
}

// ── Appends and directories ─────────────────────────────────────────────────

/**
 * Append `line` and a newline with ONE write() on an O_APPEND descriptor, so
 * lines from concurrent writers land whole rather than interleaved. CR/LF inside
 * `line` become spaces: one call is always exactly one line. Creates the file
 * with `mode` when it is missing.
 */
export function appendLine(path: string, line: string, mode = 0o600): void {
  const fd = openSync(path, "a", mode);
  try {
    writeSync(fd, `${line.replace(/[\r\n]/g, " ")}\n`);
  } finally {
    closeSync(fd);
  }
}

/** Create `path` and any missing parents 0700. An existing directory is left as it is. */
export function ensurePrivateDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
}

// ── Exclusive lock ──────────────────────────────────────────────────────────

export type LockOptions = {
  /** How long to keep retrying a busy lock before giving up (default 0: fail fast). */
  waitMs?: number;
  /** Age after which a well-formed lock whose owner process is dead may be
   *  taken over (default 30 s). Age alone is never enough. */
  staleMs?: number;
  /** Age after which a lock with no readable owner record (a crash between
   *  creating it and writing the record) may be taken over (default 10 × staleMs). */
  malformedStaleMs?: number;
};

/** The lock is held by an owner that is alive, or not provably dead. */
export class LockBusyError extends Error {
  readonly lockPath: string;
  /** Set when stale-lock recovery itself was busy: the `.recovery` lock's path,
   *  and whether that lock looks abandoned (needs a manual check and removal). */
  readonly recovery: { path: string; stale: boolean } | null;

  constructor(lockPath: string, recovery: { path: string; stale: boolean } | null = null) {
    super(
      `Lock already held: ${lockPath}` +
        (recovery?.stale
          ? `. Stale recovery lock detected at ${recovery.path}; after verifying no Nexus process holds the lock, remove that file and retry.`
          : ""),
    );
    this.name = "LockBusyError";
    this.lockPath = lockPath;
    this.recovery = recovery;
  }
}

type LockRecord = { pid: number; token: string; createdAt: string };
type HeldLock = { fd: number; token: string };

const LOCK_POLL_MS = 25;

function readLock(path: string): LockRecord | null {
  try {
    const value = JSON.parse(readFileSync(path, "utf-8")) as Partial<LockRecord>;
    if (!Number.isSafeInteger(value.pid) || typeof value.token !== "string" || typeof value.createdAt !== "string") {
      return null;
    }
    return value as LockRecord;
  } catch {
    return null;
  }
}

/** Milliseconds since `path` was last written; 0 if it is gone. */
function lockAgeMs(path: string): number {
  try {
    return Date.now() - statSync(path).mtimeMs;
  } catch {
    return 0;
  }
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means the process exists but belongs to a security context that
    // does not permit signaling it. Treat that as alive and never steal.
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

function removeLockIfOwned(path: string, token: string): void {
  if (readLock(path)?.token === token && existsSync(path)) unlinkSync(path);
}

function createLock(path: string): HeldLock {
  const token = randomUUID();
  const fd = openSync(path, "wx", 0o600);
  try {
    writeFileSync(fd, JSON.stringify({ pid: process.pid, token, createdAt: new Date().toISOString() }), "utf-8");
    return { fd, token };
  } catch (error) {
    closeSync(fd);
    if (existsSync(path)) unlinkSync(path);
    throw error;
  }
}

/** One attempt at the lock: take it, or take over a stale one, or throw LockBusyError. */
function tryAcquire(lockPath: string, staleMs: number, malformedStaleMs: number): HeldLock {
  try {
    return createLock(lockPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }

  // Serialize stale-lock recovery separately. A lock is recoverable only when
  // it is old, well-formed, and its owner process is confirmed dead. Age alone
  // is never grounds for stealing a live writer's lock.
  const recoveryPath = `${lockPath}.recovery`;
  let recovery: HeldLock;
  try {
    recovery = createLock(recoveryPath);
  } catch {
    const owner = readLock(recoveryPath);
    const ageMs = lockAgeMs(recoveryPath);
    const stale = owner ? ageMs > staleMs && !processIsAlive(owner.pid) : ageMs > malformedStaleMs;
    throw new LockBusyError(lockPath, { path: recoveryPath, stale });
  }

  try {
    const existing = readLock(lockPath);
    const ageMs = lockAgeMs(lockPath);
    if (existing && (ageMs <= staleMs || processIsAlive(existing.pid))) throw new LockBusyError(lockPath);

    if (existing) {
      // The dead owner cannot replace the file. A second recovery process is
      // excluded by the recovery lock, so deleting this exact token is safe.
      removeLockIfOwned(lockPath, existing.token);
    } else {
      // An empty/partial lock can be left by a crash between exclusive creation
      // and the tiny owner-record write. Reclaim it only after a much more
      // conservative age while recovery is serialized.
      if (ageMs <= malformedStaleMs) throw new LockBusyError(lockPath);
      if (readLock(lockPath) === null && existsSync(lockPath)) unlinkSync(lockPath);
    }
  } finally {
    closeSync(recovery.fd);
    removeLockIfOwned(recoveryPath, recovery.token);
  }

  // Another normal contender may win the tiny window after stale removal. In
  // that case createLock fails safely; we never delete it.
  try {
    return createLock(lockPath);
  } catch {
    throw new LockBusyError(lockPath);
  }
}

/**
 * Run `fn` while holding the O_EXCL lock file `lockPath`, which records
 * `{pid, token, createdAt}`. A busy lock is retried for up to `waitMs`, then
 * LockBusyError is thrown; a stale one (see LockOptions) is taken over. The lock
 * is released when `fn` returns or throws — `fn` must be synchronous.
 */
export function withExclusiveLock<T>(lockPath: string, fn: () => T, opts: LockOptions = {}): T {
  const { waitMs = 0, staleMs = 30_000 } = opts;
  const malformedStaleMs = opts.malformedStaleMs ?? staleMs * 10;
  const deadline = Date.now() + waitMs;
  let lock: HeldLock | undefined;
  while (!lock) {
    try {
      lock = tryAcquire(lockPath, staleMs, malformedStaleMs);
    } catch (error) {
      const remaining = deadline - Date.now();
      if (!(error instanceof LockBusyError) || remaining <= 0) throw error;
      sleepSync(Math.min(LOCK_POLL_MS, remaining));
    }
  }
  try {
    return fn();
  } finally {
    closeSync(lock.fd);
    removeLockIfOwned(lockPath, lock.token);
  }
}
