/**
 * Instruction-file integrity — reading Nexus's own private files (store
 * documents, ledger records, session files) and listing their directories,
 * defensively: one non-blocking descriptor, no symlink at the final component
 * (where the platform supports O_NOFOLLOW), regular files only, bounded sizes
 * and listings. Something planted in the store — a FIFO, a symlink, a huge file
 * — then reads as `invalid` instead of hanging or exhausting a hook. The one
 * writer here, `appendPrivateText`, refuses the same planted paths.
 */

import { closeSync, constants, fstatSync, opendirSync, openSync, readSync, writeSync, type Dir } from "node:fs";

export type PrivateRead =
  | { state: "ok"; text: string }
  | { state: "missing" }
  | { state: "invalid"; why: "not-a-file" | "too-large" | "unreadable" };

const CHUNK_BYTES = 1 << 20;

/** Read the UTF-8 text at `path`, refusing anything that is not a regular file of at most `maxBytes`. */
export function readPrivateText(path: string, maxBytes: number): PrivateRead {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return { state: "missing" };
    return { state: "invalid", why: code === "ELOOP" || code === "EISDIR" ? "not-a-file" : "unreadable" };
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { state: "invalid", why: "not-a-file" };
    if (st.size > maxBytes) return { state: "invalid", why: "too-large" };
    // Read to EOF (the file may have grown since fstat), never past maxBytes + 1.
    const buf = Buffer.allocUnsafe(Math.min(maxBytes + 1, CHUNK_BYTES + 1, Math.max(st.size + 1, 4096)));
    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      total += n;
      if (total > maxBytes) return { state: "invalid", why: "too-large" };
      chunks.push(Buffer.from(buf.subarray(0, n)));
    }
    return { state: "ok", text: Buffer.concat(chunks, total).toString("utf-8") };
  } catch {
    return { state: "invalid", why: "unreadable" };
  } finally {
    closeSync(fd);
  }
}

/** `readPrivateText` + `JSON.parse`: the parsed value, `missing`, or `invalid` (unreadable, oversize or not JSON). */
export function readPrivateJson(path: string, maxBytes: number): { state: "ok"; value: unknown } | { state: "missing" } | { state: "invalid" } {
  const read = readPrivateText(path, maxBytes);
  if (read.state === "missing") return read;
  if (read.state === "invalid") return { state: "invalid" };
  try {
    return { state: "ok", value: JSON.parse(read.text) as unknown };
  } catch {
    return { state: "invalid" };
  }
}

/**
 * Up to `limit` entry names of `dir`, in directory order (empty when it cannot
 * be read); `more` when it holds others. A directory with millions of entries
 * costs no more than `limit` reads.
 */
export function listDir(dir: string, limit: number): { names: string[]; more: boolean } {
  const names: string[] = [];
  let handle: Dir;
  try {
    handle = opendirSync(dir);
  } catch {
    return { names, more: false };
  }
  try {
    for (let d = handle.readSync(); d !== null; d = handle.readSync()) {
      if (names.length >= limit) return { names, more: true };
      names.push(d.name);
    }
  } catch {
    // a directory that vanished or cannot be read further: what was listed stands
  } finally {
    handle.closeSync();
  }
  return { names, more: false };
}

/**
 * O_APPEND, creating the file 0600 if needed; O_NOFOLLOW: never through a symlink
 * at the final component (ELOOP); O_NONBLOCK: a FIFO with no reader fails at once
 * (ENXIO) instead of blocking the hook forever. O_NONBLOCK changes nothing for
 * the regular file a log must be.
 */
const APPEND_FLAGS =
  constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);

/**
 * Append `text` to the regular file at `path` with ONE write(), so concurrent
 * appenders never tear each other's lines. Throws, writing nothing, for a
 * symlink (ELOOP), a FIFO without a reader (ENXIO), or anything else that is
 * not a regular file — a FIFO with a reader included.
 */
export function appendPrivateText(path: string, text: string): void {
  const fd = openSync(path, APPEND_FLAGS, 0o600);
  try {
    if (!fstatSync(fd).isFile()) throw new Error(`not a regular file: ${path}`);
    writeSync(fd, text);
  } finally {
    closeSync(fd);
  }
}
