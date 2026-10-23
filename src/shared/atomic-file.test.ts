import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { appendLine, atomicWriteFile, ensurePrivateDir, LockBusyError, renameWithRetry, withExclusiveLock } from "./atomic-file.js";

const POSIX = process.platform !== "win32";
const DEAD_PID = 99_999_999;
const TSX = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;
const MODULE_URL = pathToFileURL(fileURLToPath(new URL("./atomic-file.ts", import.meta.url))).href;

const errno = (code: string) => Object.assign(new Error(code), { code });

describe("atomicWriteFile", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "nexus-atomic-")); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("writes and replaces the file 0600, leaving no temp file behind", () => {
    const target = join(dir, "store.json");
    atomicWriteFile(target, '{"v":1}');
    assert.equal(readFileSync(target, "utf-8"), '{"v":1}');
    atomicWriteFile(target, Buffer.from('{"v":2}'), { fsync: false });
    assert.equal(readFileSync(target, "utf-8"), '{"v":2}');
    if (POSIX) assert.equal(statSync(target).mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(dir), ["store.json"]);
  });

  it("honours a requested mode for a new file", { skip: !POSIX }, () => {
    const target = join(dir, "public.txt");
    atomicWriteFile(target, "x", { mode: 0o640 });
    assert.equal(statSync(target).mode & 0o777, 0o640);
  });

  it("leaves no temp file and the old target intact when the rename fails", () => {
    const target = join(dir, "busy");
    mkdirSync(target);
    writeFileSync(join(target, "inside"), "keep"); // a non-empty directory cannot be renamed over
    assert.throws(() => atomicWriteFile(target, "new"));
    assert.deepEqual(readdirSync(dir), ["busy"]);
    assert.equal(readFileSync(join(target, "inside"), "utf-8"), "keep");
  });

  it("throws, creating nothing, when the directory is missing", () => {
    assert.throws(() => atomicWriteFile(join(dir, "missing", "f.json"), "x"), { code: "ENOENT" });
    assert.deepEqual(readdirSync(dir), []);
  });
});

describe("renameWithRetry", () => {
  /** A rename that fails with `codes` in order, then succeeds. */
  function flaky(codes: string[]) {
    const calls: string[] = [];
    const rename = (from: string, to: string) => {
      calls.push(`${from}->${to}`);
      const code = codes[calls.length - 1];
      if (code) throw errno(code);
    };
    return { calls, rename };
  }

  it("retries EBUSY and EPERM on win32, 3 times", () => {
    const busy = flaky(["EBUSY", "EPERM"]);
    renameWithRetry("a", "b", "win32", busy.rename);
    assert.equal(busy.calls.length, 3);

    const stuck = flaky(["EBUSY", "EBUSY", "EBUSY", "EBUSY", "EBUSY"]);
    const started = Date.now();
    assert.throws(() => renameWithRetry("a", "b", "win32", stuck.rename), { code: "EBUSY" });
    assert.equal(stuck.calls.length, 4);
    assert.ok(Date.now() - started >= 50, "the retries are spaced out");
  });

  it("does not retry other errors, or on other platforms", () => {
    const missing = flaky(["ENOENT"]);
    assert.throws(() => renameWithRetry("a", "b", "win32", missing.rename), { code: "ENOENT" });
    assert.equal(missing.calls.length, 1);
    const posix = flaky(["EBUSY"]);
    assert.throws(() => renameWithRetry("a", "b", "linux", posix.rename), { code: "EBUSY" });
    assert.equal(posix.calls.length, 1);
  });
});

describe("appendLine and ensurePrivateDir", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "nexus-append-")); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("appends exactly one line per call, creating the file 0600", () => {
    const log = join(dir, "s.log");
    appendLine(log, "s\t1\tstartup\t42");
    appendLine(log, "a\t2\tBash\r\ninjected\nline");
    assert.equal(readFileSync(log, "utf-8"), "s\t1\tstartup\t42\na\t2\tBash  injected line\n");
    if (POSIX) assert.equal(statSync(log).mode & 0o777, 0o600);
  });

  it("creates missing directories 0700 and leaves an existing one alone", { skip: !POSIX }, () => {
    const nested = join(dir, "data", "integrity");
    ensurePrivateDir(nested);
    assert.equal(statSync(nested).mode & 0o777, 0o700);
    assert.equal(statSync(join(dir, "data")).mode & 0o777, 0o700);
    ensurePrivateDir(nested); // idempotent
    const open = join(dir, "shared");
    mkdirSync(open, { mode: 0o755 });
    const before = statSync(open).mode;
    ensurePrivateDir(open);
    assert.equal(statSync(open).mode, before);
  });

  it("refuses a path that is a file", () => {
    writeFileSync(join(dir, "file"), "x");
    assert.throws(() => ensurePrivateDir(join(dir, "file")));
  });
});

describe("withExclusiveLock", () => {
  let dir: string;
  let lockPath: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "nexus-lock-"));
    lockPath = join(dir, ".lock");
  });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  const plantLock = (record: unknown, ageMs: number) => {
    writeFileSync(lockPath, typeof record === "string" ? record : JSON.stringify(record));
    const at = new Date(Date.now() - ageMs);
    utimesSync(lockPath, at, at);
  };
  const owner = (pid: number) => ({ pid, token: "planted", createdAt: new Date(0).toISOString() });

  it("holds an owner record while fn runs, returns its value and releases", () => {
    const value = withExclusiveLock(lockPath, () => {
      const record = JSON.parse(readFileSync(lockPath, "utf-8"));
      assert.equal(record.pid, process.pid);
      assert.equal(typeof record.token, "string");
      assert.ok(!Number.isNaN(Date.parse(record.createdAt)));
      return 42;
    });
    assert.equal(value, 42);
    assert.equal(existsSync(lockPath), false);
  });

  it("releases when fn throws", () => {
    assert.throws(() => withExclusiveLock(lockPath, () => { throw new Error("boom"); }), /boom/);
    assert.equal(existsSync(lockPath), false);
    assert.equal(withExclusiveLock(lockPath, () => "again"), "again");
  });

  it("fails fast by default on a lock held by a live process, and never touches it", () => {
    plantLock(owner(process.pid), 0);
    let ran = false;
    assert.throws(() => withExclusiveLock(lockPath, () => { ran = true; }), (error: unknown) =>
      error instanceof LockBusyError && error.lockPath === lockPath && error.recovery === null);
    assert.equal(ran, false);
    assert.equal(JSON.parse(readFileSync(lockPath, "utf-8")).token, "planted");
    assert.deepEqual(readdirSync(dir), [".lock"]);
  });

  it("waits up to waitMs for a busy lock, then gives up", () => {
    plantLock(owner(process.pid), 0);
    const started = Date.now();
    assert.throws(() => withExclusiveLock(lockPath, () => {}, { waitMs: 150 }), LockBusyError);
    assert.ok(Date.now() - started >= 150);
    assert.equal(JSON.parse(readFileSync(lockPath, "utf-8")).token, "planted");
  });

  it("never steals an old lock from a live process, nor a fresh one from a dead process", () => {
    plantLock(owner(process.pid), 120_000);
    assert.throws(() => withExclusiveLock(lockPath, () => {}, { staleMs: 1000 }), LockBusyError);
    plantLock(owner(DEAD_PID), 0);
    assert.throws(() => withExclusiveLock(lockPath, () => {}, { staleMs: 60_000 }), LockBusyError);
    assert.equal(JSON.parse(readFileSync(lockPath, "utf-8")).token, "planted");
  });

  it("takes over a stale lock once its owner is confirmed dead", () => {
    plantLock(owner(DEAD_PID), 5_000);
    assert.equal(withExclusiveLock(lockPath, () => JSON.parse(readFileSync(lockPath, "utf-8")).pid, { staleMs: 1000 }), process.pid);
    assert.deepEqual(readdirSync(dir), []);
  });

  it("takes over a malformed lock only after the longer malformed age", () => {
    plantLock("", 5_000);
    assert.throws(() => withExclusiveLock(lockPath, () => {}, { staleMs: 1000 }), LockBusyError); // < 10 × staleMs
    plantLock("", 11_000);
    assert.equal(withExclusiveLock(lockPath, () => "ok", { staleMs: 1000 }), "ok");
    plantLock("{", 5_000);
    assert.equal(withExclusiveLock(lockPath, () => "ok", { staleMs: 1000, malformedStaleMs: 2000 }), "ok");
    assert.deepEqual(readdirSync(dir), []);
  });

  it("reports an abandoned recovery lock for manual repair instead of removing it", () => {
    plantLock(owner(DEAD_PID), 120_000);
    const recovery = `${lockPath}.recovery`;
    writeFileSync(recovery, JSON.stringify(owner(DEAD_PID)));
    const old = new Date(Date.now() - 120_000);
    utimesSync(recovery, old, old);
    assert.throws(() => withExclusiveLock(lockPath, () => {}, { staleMs: 1000 }), (error: unknown) =>
      error instanceof LockBusyError &&
      error.recovery?.path === recovery && error.recovery.stale &&
      /Stale recovery lock detected at .*remove that file/.test(error.message));
    assert.equal(existsSync(recovery), true);
    assert.equal(existsSync(lockPath), true);
  });

  it("serializes with another process: a waiter gets the lock once the holder releases", async () => {
    const ready = join(dir, "ready");
    const home = join(dir, "home");
    mkdirSync(home);
    const holder = spawn(process.execPath, [
      "--import", TSX, "--input-type=module", "-e",
      `const { withExclusiveLock } = await import(${JSON.stringify(MODULE_URL)});
       const { writeFileSync } = await import("node:fs");
       withExclusiveLock(${JSON.stringify(lockPath)}, () => {
         writeFileSync(${JSON.stringify(ready)}, "1");
         Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 400);
       });`,
    ], {
      stdio: "ignore",
      env: { ...process.env, HOME: home, USERPROFILE: home, NEXUS_DATA: join(dir, "data"), CLAUDE_CONFIG_DIR: join(home, ".claude") },
    });
    const exited = new Promise<number | null>((done) => holder.on("exit", done));
    try {
      const deadline = Date.now() + 15_000;
      while (!existsSync(ready)) {
        assert.ok(Date.now() < deadline, "holder never took the lock");
        await new Promise((r) => setTimeout(r, 20));
      }
      assert.throws(() => withExclusiveLock(lockPath, () => {}), LockBusyError);
      const value = withExclusiveLock(lockPath, () => JSON.parse(readFileSync(lockPath, "utf-8")).pid, { waitMs: 10_000 });
      assert.equal(value, process.pid);
      assert.equal(await exited, 0);
    } finally {
      holder.kill();
    }
    assert.equal(existsSync(lockPath), false);
  });
});
