/**
 * Private key files (the memory engine's `.sanitation-key`, the integrity
 * store's `.integrity-key`): one trusted read path and two writers.
 *
 * The read path opens ONE descriptor and checks that same descriptor, so the
 * ownership/permission check and the read see the same file (no check-then-open
 * race on the path). A key is trusted only when it is a regular file owned by
 * this user and not group/world-accessible (POSIX; win32 has no mode or uid to
 * check), reached without following a symlink (O_NOFOLLOW, where supported), and
 * in the expected format. Reading never creates or replaces a key: the caller
 * decides what a missing or untrusted key means.
 */

import { closeSync, constants, fstatSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";

export type KeyFileRead =
  | { state: "ok"; key: Buffer }
  | { state: "missing" }
  | { state: "untrusted"; why: string };

/** Decodes a key file's text to the key, or null when it is malformed. */
export type KeyFormat = (text: string) => Buffer | null;

/** 64 hex characters, at most one trailing newline (the integrity key). */
export const HEX64_KEY: KeyFormat = (text) =>
  /^[0-9a-f]{64}\n?$/i.test(text) ? Buffer.from(text.slice(0, 64), "hex") : null;

/** Read and verify the key at `path`. Never throws, never writes. */
export function readKeyFile(path: string, format: KeyFormat = HEX64_KEY): KeyFileRead {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0), 0o600);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { state: "missing" };
    // ELOOP is O_NOFOLLOW refusing a symlink at the key path.
    return { state: "untrusted", why: code === "ELOOP" ? "is a symlink" : `cannot be opened (${code ?? "error"})` };
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { state: "untrusted", why: "is not a regular file" };
    if (process.platform !== "win32") {
      if ((st.mode & 0o077) !== 0) {
        return { state: "untrusted", why: `is group/world-accessible (mode ${(st.mode & 0o777).toString(8)})` };
      }
      if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
        return { state: "untrusted", why: "is owned by another user" };
      }
    }
    const key = format(readFileSync(fd, "utf-8"));
    return key ? { state: "ok", key } : { state: "untrusted", why: "is malformed" };
  } catch (error) {
    return { state: "untrusted", why: `cannot be read (${(error as NodeJS.ErrnoException).code ?? "error"})` };
  } finally {
    closeSync(fd);
  }
}

/**
 * Create a fresh 0600 key at `path` with O_EXCL. If a key already exists (or
 * another process created one since the caller's read), the existing file is
 * read instead, with the same checks as `readKeyFile`. Throws when the file can
 * be neither created nor found (e.g. its directory is missing or unwritable).
 */
export function createKeyFile(path: string, format: KeyFormat = HEX64_KEY): KeyFileRead {
  const key = randomBytes(32);
  let fd: number;
  try {
    fd = openSync(path, "wx", 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    return readKeyFile(path, format);
  }
  try {
    writeFileSync(fd, key.toString("hex"), "utf-8");
    fsyncSync(fd);
  } catch (error) {
    // A half-written key would read as untrusted forever; it is ours to remove.
    closeSync(fd);
    try { unlinkSync(path); } catch { /* already gone */ }
    throw error;
  }
  closeSync(fd);
  return { state: "ok", key };
}

/**
 * Replace whatever is at `path` with a fresh 0600 key: written to a temp file
 * beside it, then renamed into place. Used when the existing key is not trusted
 * — replacing it, rather than only re-tightening its mode, means a key that may
 * have been read or planted can never validate anything again. The rename
 * replaces a symlink at `path` itself, never its target. Throws on failure
 * (e.g. a directory at `path`), leaving no temp file behind.
 */
export function replaceKeyFile(path: string): Buffer {
  const key = randomBytes(32);
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    const fd = openSync(tmp, "wx", 0o600);
    try {
      writeFileSync(fd, key.toString("hex"), "utf-8");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
    return key;
  } catch (error) {
    try { unlinkSync(tmp); } catch { /* never created */ }
    throw error;
  }
}
