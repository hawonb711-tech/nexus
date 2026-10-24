import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync, constants, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, readSync, readdirSync, rmSync, statSync, symlinkSync, utimesSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  activityWindows, activityWindowsSince, appendSessionEvents, inWindows, integrityDirExists, normalizeMcpServerName, readSessionLog,
  readSessionState, sessionLevel, sid16, tailMsFor, writeSessionState, type SessionEvent,
} from "./session-log.js";
import { INTEGRITY_DIR, MAX_INDICATORS, SESSIONS_DIR, type SessionStateDoc } from "./types.js";

const POSIX = process.platform !== "win32";
const TSX = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;
const MODULE_URL = pathToFileURL(fileURLToPath(new URL("./session-log.ts", import.meta.url))).href;
const T = 1_761_200_000_000;

describe("session log", () => {
  let base: string;
  let data: string;
  const SID = sid16("session-abc");
  const logPath = () => join(data, INTEGRITY_DIR, SESSIONS_DIR, `${SID}.log`);

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), "nexus-session-"));
    data = join(base, "data");
  });
  afterEach(() => { rmSync(base, { recursive: true, force: true }); });

  const enable = () => mkdirSync(join(data, INTEGRITY_DIR), { recursive: true, mode: 0o700 });
  const append = (...events: SessionEvent[]) => appendSessionEvents(data, SID, events);

  it("names sessions by sha256(session_id)[:16]", () => {
    assert.equal(SID, createHash("sha256").update("session-abc").digest("hex").slice(0, 16));
    assert.match(sid16("../../etc/passwd"), /^[0-9a-f]{16}$/);
  });

  it("writes nothing at all while integrity was never enabled", () => {
    assert.equal(integrityDirExists(data), false);
    assert.equal(append({ kind: "x", t: T, tool: "WebFetch" }), false);
    assert.equal(writeSessionState(data, { v: 1, sid: SID, at: "now", indicators: [], withheldMcp: [], shown: [] }), false);
    assert.equal(existsSync(data), false);
  });

  it("appends tab-separated lines, creating sessions/ 0700 and the log 0600", () => {
    enable();
    assert.equal(append({ kind: "s", t: T, source: "startup", pid: 42 }), true);
    assert.equal(append({ kind: "a", t: T + 1, tool: "Bash", tailMs: 150_000 }, { kind: "x", t: T + 1, tool: "Bash" }), true);
    append({ kind: "f", t: T + 2, tool: "WebFetch", rule: "prompt-injection" }, { kind: "t", t: T + 3, heldId: "h_0123456789ab" });
    assert.equal(readFileSync(logPath(), "utf-8"), [
      `s\t${T}\tstartup\t42`,
      `a\t${T + 1}\tBash\t150000`,
      `x\t${T + 1}\tBash`,
      `f\t${T + 2}\tWebFetch\tprompt-injection`,
      `t\t${T + 3}\tsession-start\th_0123456789ab`,
      "",
    ].join("\n"));
    if (POSIX) {
      assert.equal(statSync(logPath()).mode & 0o777, 0o600);
      assert.equal(statSync(join(data, INTEGRITY_DIR, SESSIONS_DIR)).mode & 0o777, 0o700);
    }
    // an `s` line records the Claude Code process (the parent) when known; one without it still reads
    append({ kind: "s", t: T + 4, source: "resume", pid: 43, ppid: 40 });
    assert.ok(readFileSync(logPath(), "utf-8").endsWith(`s\t${T + 4}\tresume\t43\t40\n`));
    assert.deepEqual(readSessionLog(data, SID).events.filter((e) => e.kind === "s"), [
      { kind: "s", t: T, source: "startup", pid: 42 },
      { kind: "s", t: T + 4, source: "resume", pid: 43, ppid: 40 },
    ]);
  });

  it("sanitises fields and keeps every line under 1 KB with its fields intact", () => {
    enable();
    append(
      { kind: "a", t: T, tool: "mcp__evil\t__x\r\ny", tailMs: 30_000 },
      { kind: "f", t: T, tool: "工具".repeat(400), rule: "\u{1F600}".repeat(400) },
      { kind: "s", t: T, source: "x".repeat(5000), pid: 7 },
    );
    const lines = readFileSync(logPath(), "utf-8").split("\n").filter((l) => l !== "");
    assert.equal(lines.length, 3);
    assert.equal(lines[0], `a\t${T}\tmcp__evil __x  y\t30000`);
    for (const line of lines) assert.ok(Buffer.byteLength(`${line}\n`) <= 1024, `${Buffer.byteLength(line)} bytes`);
    const log = readSessionLog(data, SID);
    assert.deepEqual([log.events.length, log.malformed], [3, 0]);
    assert.deepEqual(log.events[2], { kind: "s", t: T, source: "x".repeat(160), pid: 7 });
  });

  it("computes tails per §4.6", () => {
    assert.equal(tailMsFor("Bash", {}), 150_000);
    assert.equal(tailMsFor("Bash", { timeout: 5000 }), 35_000);
    assert.equal(tailMsFor("PowerShell", { timeout: 9_999_999 }), 630_000);
    assert.equal(tailMsFor("Bash", { timeout: "soon" }), 150_000);
    assert.equal(tailMsFor("Bash", { run_in_background: true, timeout: 1000 }), 7_200_000);
    assert.equal(tailMsFor("Edit", { timeout: 1000 }), 30_000);
    assert.equal(tailMsFor("mcp__srv__tool", null), 30_000);
  });

  it("derives the level: clean, exposed, tainted", () => {
    enable();
    const level = () => sessionLevel(readSessionLog(data, SID));
    assert.equal(level(), "clean", "a missing log is clean");
    append({ kind: "s", t: T, source: "startup", pid: 1 }, { kind: "a", t: T, tool: "Bash", tailMs: 1 });
    assert.equal(level(), "clean");
    append({ kind: "x", t: T, tool: "WebFetch" });
    assert.equal(level(), "exposed");
    append({ kind: "f", t: T, tool: "WebFetch", rule: "r" });
    assert.equal(level(), "tainted");

    rmSync(logPath());
    append({ kind: "t", t: T, heldId: "h_1" });
    assert.equal(level(), "tainted", "a delivered SUSPECT item taints on its own");
  });

  it("skips malformed lines but keeps reading", () => {
    enable();
    append({ kind: "a", t: T, tool: "Bash", tailMs: 1000 });
    writeFileSync(logPath(), readFileSync(logPath(), "utf-8") + [
      "garbage",
      `q\t${T}\tBash`,              // unknown kind
      `a\t${T}\tBash`,              // missing tail
      `a\tsoon\tBash\t5`,           // non-numeric time
      `a\t${T}\tBash\t9999999999`,  // tail beyond any tool's
      `x\t${T}\tWebFetch\textra`,   // extra field
      `s\t${T}\tstartup\t-1`,
      "",
      `x\t${T + 5}\tWebFetch\r`,    // CRLF is tolerated
      `f\t${T + 6}\tmcp__a__b\tr`,
    ].join("\n") + "\n");
    const log = readSessionLog(data, SID);
    assert.equal(log.malformed, 7);
    assert.deepEqual(log.events.map((e) => e.kind), ["a", "x", "f"]);
    assert.equal(sessionLevel(log), "tainted");
  });

  it("reads an inflated or replaced log as tainted (lines only raise the level)", { skip: !POSIX }, () => {
    enable();
    mkdirSync(logPath(), { recursive: true }); // not a file
    const log = readSessionLog(data, SID);
    assert.equal(log.unreadable, true);
    assert.equal(sessionLevel(log), "tainted");
  });

  it("never appends through a symlink planted at the log path", { skip: !POSIX }, () => {
    enable();
    mkdirSync(join(data, INTEGRITY_DIR, SESSIONS_DIR));
    const victim = join(base, "victim.txt");
    writeFileSync(victim, "keep\n");
    try {
      symlinkSync(victim, logPath());
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    assert.equal(append({ kind: "x", t: T, tool: "WebFetch" }), false);
    assert.equal(readFileSync(victim, "utf-8"), "keep\n");
  });

  it("never blocks on, or appends to, a FIFO planted at the log path", { skip: !POSIX }, (t) => {
    enable();
    mkdirSync(join(data, INTEGRITY_DIR, SESSIONS_DIR));
    if (spawnSync("mkfifo", [logPath()]).status !== 0) return t.skip("mkfifo is unavailable");
    // No reader: a blocking open() would wait forever, so the append runs in a child with a timeout.
    const child = spawnSync(process.execPath, [
      "--import", TSX, "--input-type=module", "-e",
      `const { appendSessionEvents } = await import(${JSON.stringify(MODULE_URL)});
       process.stdout.write(String(appendSessionEvents(${JSON.stringify(data)}, ${JSON.stringify(SID)}, [{ kind: "x", t: ${T}, tool: "WebFetch" }])));`,
    ], { encoding: "utf-8", timeout: 15_000, env: { ...process.env, HOME: base, USERPROFILE: base, NEXUS_DATA: data, CLAUDE_CONFIG_DIR: join(base, ".claude") } });
    assert.equal(child.signal, null, "the append hung on the FIFO");
    assert.equal(child.stdout, "false");
    // A reader present: the open succeeds, but a FIFO is still not a log.
    const reader = openSync(logPath(), constants.O_RDONLY | constants.O_NONBLOCK);
    try {
      assert.equal(append({ kind: "x", t: T, tool: "WebFetch" }), false);
      assert.equal(readSync(reader, Buffer.alloc(64), 0, 64, null), 0, "nothing was written into the FIFO");
    } finally {
      closeSync(reader);
    }
  });

  it("builds activity windows from `a` lines and from `x` lines of mcp__ tools only", () => {
    const events: SessionEvent[] = [
      { kind: "a", t: T, tool: "Bash", tailMs: 150_000 },
      { kind: "x", t: T + 1_000_000, tool: "mcp__github__get_file" },
      { kind: "x", t: T + 5_000_000, tool: "WebFetch" },
      { kind: "s", t: T + 6_000_000, source: "startup", pid: 1 },
      { kind: "a", t: T + 100_000, tool: "Edit", tailMs: 30_000 }, // overlaps the first
    ];
    const windows = activityWindows(events);
    assert.deepEqual(windows, [[T - 2000, T + 150_000], [T + 1_000_000 - 120_000, T + 1_000_000 + 2000]]);
    assert.equal(inWindows(windows, T - 2000), true);
    assert.equal(inWindows(windows, T - 2001), false);
    assert.equal(inWindows(windows, T + 150_000), true);
    assert.equal(inWindows(windows, T + 150_001), false);
    assert.equal(inWindows(windows, T + 900_000), true, "MCP tools may write before their result is seen");
    assert.equal(inWindows(windows, T + 1_002_001), false);
    assert.equal(inWindows(windows, T + 5_000_000), false, "WebFetch exposure is not activity");
    assert.equal(inWindows([], T), false);
  });

  it("reads windows lazily: only logs modified at or after `since`, across sessions", () => {
    enable();
    const other = sid16("another-session");
    append({ kind: "a", t: T, tool: "Bash", tailMs: 1000 });
    appendSessionEvents(data, other, [{ kind: "a", t: T + 50_000, tool: "Edit", tailMs: 30_000 }]);
    const sessions = join(data, INTEGRITY_DIR, SESSIONS_DIR);
    writeFileSync(join(sessions, "notes.txt"), `a\t${T + 90_000_000}\tBash\t1000\n`);
    const old = new Date(T - 3_600_000);
    utimesSync(join(sessions, `${other}.log`), old, old);

    const recent = activityWindowsSince(data, T - 1000);
    assert.deepEqual(recent.windows, [[T - 2000, T + 1000]]);
    assert.deepEqual([recent.scanned, recent.partial], [1, false]);

    const all = activityWindowsSince(data, 0);
    assert.deepEqual(all.windows, [[T - 2000, T + 1000], [T + 48_000, T + 80_000]]);
    assert.equal(all.scanned, 2);

    const capped = activityWindowsSince(data, 0, { maxLogs: 1 });
    assert.deepEqual([capped.scanned, capped.partial], [1, true]);
    assert.deepEqual(activityWindowsSince(join(base, "nowhere"), 0), { windows: [], scanned: 0, bytes: 0, partial: false });
  });

  it("bounds the windows scan by bytes read and by a deadline; past either the result is partial", () => {
    enable();
    const other = sid16("another-session");
    append(...Array.from({ length: 40 }, (_, i) => ({ kind: "a" as const, t: T + i * 1000, tool: "Bash", tailMs: 1000 })));
    appendSessionEvents(data, other, Array.from({ length: 40 }, (_, i) => ({ kind: "a" as const, t: T + 3_600_000 + i * 1000, tool: "Edit", tailMs: 1000 })));
    const sizes = [SID, other].map((sid) => statSync(join(data, INTEGRITY_DIR, SESSIONS_DIR, `${sid}.log`)).size);
    const full = activityWindowsSince(data, 0);
    assert.deepEqual([full.scanned, full.bytes, full.partial], [2, sizes[0] + sizes[1], false]);

    const budget = activityWindowsSince(data, 0, { maxBytes: Math.max(...sizes) + 10 });
    assert.deepEqual([budget.scanned, budget.partial], [1, true]);
    assert.ok(budget.bytes <= Math.max(...sizes) + 10);
    assert.ok(budget.windows.length > 0, "what was read is kept");

    let now = 1000;
    const late = activityWindowsSince(data, 0, { deadline: 1000, clock: () => now });
    assert.deepEqual([late.scanned, late.partial, late.windows], [0, true, []]);
    // the deadline passing between logs stops the scan there
    now = 0;
    const clock = () => (now += 600);
    const cut = activityWindowsSince(data, 0, { deadline: 1000, clock });
    assert.deepEqual([cut.scanned, cut.partial], [1, true]);
  });

  it("keeps whole lines when two processes append at once", async () => {
    enable();
    const go = join(base, "go");
    const N = 400;
    const child = (tag: string) => spawn(process.execPath, [
      "--import", TSX, "--input-type=module", "-e",
      `const { appendSessionEvents } = await import(${JSON.stringify(MODULE_URL)});
       const { existsSync } = await import("node:fs");
       while (!existsSync(${JSON.stringify(go)})) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
       const tool = "mcp__" + ${JSON.stringify(tag)}.repeat(150);
       for (let i = 0; i < ${N}; i++) {
         if (!appendSessionEvents(${JSON.stringify(data)}, ${JSON.stringify(SID)}, [{ kind: "a", t: ${T} + i, tool, tailMs: 2000 }, { kind: "x", t: ${T} + i, tool }])) process.exit(2);
       }`,
    ], { stdio: "ignore", env: { ...process.env, HOME: base, USERPROFILE: base, NEXUS_DATA: data, CLAUDE_CONFIG_DIR: join(base, ".claude") } });
    const exits = [child("A"), child("B")].map((p) => new Promise<number | null>((done) => p.on("exit", done)));
    writeFileSync(go, "1");
    assert.deepEqual(await Promise.all(exits), [0, 0]);
    const log = readSessionLog(data, SID);
    assert.equal(log.malformed, 0);
    assert.equal(log.events.length, 4 * N);
    for (const tag of ["A", "B"]) {
      assert.equal(log.events.filter((e) => e.kind === "a" && e.tool === `mcp__${tag.repeat(150)}`).length, N, tag);
    }
  });

  describe("sessions/<sid16>.json", () => {
    const state = (over: Partial<SessionStateDoc> = {}): SessionStateDoc => ({
      v: 1,
      sid: SID,
      at: "2026-10-23T10:00:00.000Z",
      indicators: [{ t: "setup.example.net", file: "CLAUDE.md", tier: "SUSPECT" }],
      withheldMcp: [{ name: "helper", reason: "MCP server command matches pipe-to-shell" }],
      shown: ["h_3f9c0a1b2c3d"],
      ...over,
    });

    it("round-trips atomically, 0600, without a temp file", () => {
      enable();
      assert.equal(readSessionState(data, SID), null);
      assert.equal(writeSessionState(data, state()), true);
      assert.deepEqual(readSessionState(data, SID), state());
      const dir = join(data, INTEGRITY_DIR, SESSIONS_DIR);
      assert.deepEqual(readdirSync(dir), [`${SID}.json`]);
      if (POSIX) assert.equal(statSync(join(dir, `${SID}.json`)).mode & 0o777, 0o600);
    });

    it("keeps at most MAX_INDICATORS (32) indicators of at least 6 characters, lower-cased and deduplicated", () => {
      enable();
      const indicators = [
        { t: "short", file: "a", tier: "HOLD" as const },
        { t: "Setup.Example.NET", file: "a", tier: "SUSPECT" as const },
        { t: "setup.example.net", file: "b", tier: "HOLD" as const },
        ...Array.from({ length: 40 }, (_, i) => ({ t: `token-${i}.example.org`, file: "c", tier: "HOLD" as const })),
      ];
      writeSessionState(data, state({ indicators }));
      const read = readSessionState(data, SID);
      assert.equal(MAX_INDICATORS, 32);
      assert.equal(read?.indicators.length, MAX_INDICATORS);
      assert.deepEqual(read?.indicators[0], { t: "setup.example.net", file: "a", tier: "SUSPECT" });
      assert.ok(read?.indicators.every((i) => i.t.length >= 6 && i.t === i.t.toLowerCase()));
    });

    it("drops malformed items and rejects a document for another session", () => {
      enable();
      const path = join(data, INTEGRITY_DIR, SESSIONS_DIR, `${SID}.json`);
      mkdirSync(join(data, INTEGRITY_DIR, SESSIONS_DIR), { recursive: true });
      writeFileSync(path, JSON.stringify({
        ...state(),
        indicators: [{ t: 42 }, { t: "valid-token", file: "x", tier: "NOTICE" }, { t: "valid-token", file: "x", tier: "HOLD" }],
        withheldMcp: [{ name: "" , reason: "r" }, { name: "ok", reason: "r" }, "junk"],
        shown: ["h_1", 2],
      }));
      assert.deepEqual(readSessionState(data, SID), state({
        indicators: [{ t: "valid-token", file: "x", tier: "HOLD" }], withheldMcp: [{ name: "ok", reason: "r" }], shown: ["h_1"],
      }));
      writeFileSync(path, JSON.stringify(state({ sid: sid16("someone-else") })));
      assert.equal(readSessionState(data, SID), null);
      writeFileSync(path, "{");
      assert.equal(readSessionState(data, SID), null);
      assert.throws(() => writeSessionState(data, state({ sid: "../x" })), TypeError);
    });
  });
});

describe("MCP server names in tool names (amendment A9)", () => {
  it("replaces every character outside [A-Za-z0-9_-] with _, and tidies claude.ai connector names", () => {
    assert.equal(normalizeMcpServerName("docs"), "docs");
    assert.equal(normalizeMcpServerName("my-server_2"), "my-server_2");
    assert.equal(normalizeMcpServerName("evil helper"), "evil_helper");
    assert.equal(normalizeMcpServerName("a.b  c"), "a_b__c", "only claude.ai names collapse runs");
    assert.equal(normalizeMcpServerName("claude.ai Google Drive"), "claude_ai_Google_Drive");
    assert.equal(normalizeMcpServerName("claude.ai  Notes (beta)!"), "claude_ai_Notes_beta");
    assert.equal(normalizeMcpServerName("☃"), "_");
  });
});
