import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { canonicalJson } from "../../shared/sign.js";
import {
  appendConfirmRecord, appendNexusRecord, appendWriteRecord, expectedShaOf, landedRecords, readLedger, simulateWrite,
  type LedgerQuery, type WriteRecordInput,
} from "./ledger.js";
import { initIntegrity, integrityPaths, signerFor, type IntegrityPaths, type Signer } from "./store.js";

const POSIX = process.platform !== "win32";
const NOW = Date.UTC(2026, 9, 23, 10, 0, 0);
const DAY = 24 * 60 * 60 * 1000;
const SID = "5f3e9a1c2b4d6e8f";
const PATH = "/home/u/app/CLAUDE.md";

function writeInput(over: Partial<WriteRecordInput> = {}): WriteRecordInput {
  return {
    sid: SID,
    tu: "toolu_01AbC",
    tool: "Edit",
    path: PATH,
    added: ["a1b2c3d4e5f60718#1"],
    removed: [],
    expectedSha: "e".repeat(64),
    approx: false,
    decision: "ask",
    mode: "default",
    level: "clean",
    novel: false,
    screen: null,
    ...over,
  };
}

describe("integrity ledger", () => {
  let base: string;
  let paths: IntegrityPaths;
  let signer: Signer;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), "nexus-ledger-"));
    paths = integrityPaths(join(base, "data"));
    const init = initIntegrity(paths, new Date(NOW));
    assert.ok(init.ok);
    signer = init.signer;
  });
  afterEach(() => { rmSync(base, { recursive: true, force: true }); });

  const query = (over: Partial<LedgerQuery> = {}): LedgerQuery => ({ keys: new Set([PATH]), since: NOW - DAY, now: NOW + DAY, ...over });
  const fileOf = (rel: string) => join(paths.ledgerDir, ...rel.split("/"));

  describe("writing", () => {
    it("writes one signed 0600 file per event under its UTC day, named <epochMs>-<sid8>-<rand6>", () => {
      const rel = appendWriteRecord(paths, signer, writeInput(), { now: NOW, rand: () => "0a1b2c" });
      assert.equal(rel, `20261023/${NOW}-5f3e9a1c-0a1b2c.json`);
      const record = JSON.parse(readFileSync(fileOf(rel), "utf-8"));
      assert.deepEqual(Object.keys(record), [
        "v", "kind", "t", "sid", "tu", "tool", "path", "added", "removed", "expectedSha", "approx", "decision", "mode", "level", "novel", "screen", "mac",
      ]);
      assert.equal(record.t, new Date(NOW).toISOString());
      assert.equal(record.kind, "write");
      assert.equal(signer.verify("ledger", record), true);
      // independently: "v1:" + HMAC(K("ledger"), canonicalJson(record without mac))
      const key = Buffer.from(readFileSync(paths.key, "utf-8"), "hex");
      const sub = createHmac("sha256", key).update("nexus/integrity/v1/ledger").digest();
      const { mac, ...rest } = record;
      assert.equal(mac, `v1:${createHmac("sha256", sub).update(canonicalJson(rest)).digest("hex")}`);
      if (POSIX) {
        assert.equal(statSync(fileOf(rel)).mode & 0o777, 0o600);
        assert.equal(statSync(join(paths.ledgerDir, "20261023")).mode & 0o777, 0o700);
      }
    });

    it("never overwrites: a name collision takes a fresh random suffix", () => {
      const suffixes = ["aaaaaa", "aaaaaa", "aaaaaa", "bbbbbb"];
      const rand = () => suffixes.shift()!;
      const first = appendWriteRecord(paths, signer, writeInput({ tu: "first" }), { now: NOW, rand });
      const second = appendWriteRecord(paths, signer, writeInput({ tu: "second" }), { now: NOW, rand });
      assert.notEqual(first, second);
      assert.match(second, /-bbbbbb\.json$/);
      assert.equal(JSON.parse(readFileSync(fileOf(first), "utf-8")).tu, "first");
      assert.equal(JSON.parse(readFileSync(fileOf(second), "utf-8")).tu, "second");
      // and gives up rather than loop forever when every suffix collides
      assert.throws(() => appendWriteRecord(paths, signer, writeInput(), { now: NOW, rand: () => "aaaaaa" }), { code: "EEXIST" });
      assert.equal(readdirSync(join(paths.ledgerDir, "20261023")).length, 2);
    });

    it("gives every record of a burst its own file", () => {
      const names = new Set<string>();
      for (let i = 0; i < 200; i++) names.add(appendWriteRecord(paths, signer, writeInput({ tu: String(i) }), { now: NOW }));
      assert.equal(names.size, 200);
      assert.equal(readLedger(paths, signer, query()).records.length, 200);
    });

    it("records nexus install/uninstall under sid8 nexus000", () => {
      const rel = appendNexusRecord(paths, signer, {
        action: "install", path: "/home/u/.claude/settings.json", added: ["u1#1"], removed: [], nexusHooks: ["PostToolUse", "PreToolUse", "SessionStart"],
      }, { now: NOW, rand: () => "00ff00" });
      assert.equal(rel, `20261023/${NOW}-nexus000-00ff00.json`);
      const { records } = readLedger(paths, signer, query({ keys: new Set(["/home/u/.claude/settings.json"]) }));
      assert.equal(records.length, 1);
      assert.equal(records[0].kind, "nexus");
      assert.deepEqual(records[0].kind === "nexus" && records[0].nexusHooks, ["PostToolUse", "PreToolUse", "SessionStart"]);
    });

    it("copies a subagent's agent_id and agent_type when present (A5), and omits them otherwise", () => {
      const withAgent = appendWriteRecord(paths, signer, writeInput({ agentId: "agent-7", agentType: "general-purpose" }), { now: NOW });
      const without = appendWriteRecord(paths, signer, writeInput({ agentId: "", agentType: undefined }), { now: NOW + 1 });
      const a = JSON.parse(readFileSync(fileOf(withAgent), "utf-8"));
      const b = JSON.parse(readFileSync(fileOf(without), "utf-8"));
      assert.deepEqual([a.agentId, a.agentType], ["agent-7", "general-purpose"]);
      assert.equal("agentId" in b || "agentType" in b, false);
      const { records } = readLedger(paths, signer, query());
      assert.deepEqual(records.map((r) => r.kind === "write" && r.agentId), ["agent-7", undefined]);
    });

    it("refuses a sid that is not 16 hex characters", () => {
      assert.throws(() => appendWriteRecord(paths, signer, writeInput({ sid: "../../etc" }), { now: NOW }), TypeError);
      assert.equal(existsSync(paths.ledgerDir), false);
    });
  });

  describe("reading", () => {
    it("returns verified records for the requested keys after `since`, sorted by t", () => {
      appendWriteRecord(paths, signer, writeInput({ tu: "c" }), { now: NOW + 3000 });
      appendWriteRecord(paths, signer, writeInput({ tu: "a" }), { now: NOW + 1000 });
      appendWriteRecord(paths, signer, writeInput({ tu: "other", path: "/home/u/app/AGENTS.md" }), { now: NOW + 1500 });
      appendWriteRecord(paths, signer, writeInput({ tu: "b" }), { now: NOW + DAY }); // next UTC day
      appendWriteRecord(paths, signer, writeInput({ tu: "old" }), { now: NOW - 1000 });
      const read = readLedger(paths, signer, query({ since: NOW }));
      assert.deepEqual(read.records.map((r) => r.kind === "write" && r.tu), ["a", "c", "b"]);
      assert.deepEqual([read.invalid, read.truncated], [0, false]);
      assert.match(read.records[0].file, /^20261023\/\d{13}-5f3e9a1c-[0-9a-f]{6}\.json$/);
      assert.match(read.records[2].file, /^20261024\//);
      // `since` is exclusive
      assert.deepEqual(readLedger(paths, signer, query({ since: NOW + 1000 })).records.map((r) => r.kind === "write" && r.tu), ["c", "b"]);
      // keys: null reads every path (ledger-learned paths)
      assert.equal(readLedger(paths, signer, query({ keys: null, since: NOW })).records.length, 4);
    });

    it("ignores and counts malformed records and records that do not verify", () => {
      const good = appendWriteRecord(paths, signer, writeInput({ tu: "good" }), { now: NOW });
      const day = join(paths.ledgerDir, "20261023");
      const plant = (name: string, body: unknown) => writeFileSync(join(day, name), typeof body === "string" ? body : JSON.stringify(body));
      const valid = JSON.parse(readFileSync(fileOf(good), "utf-8"));
      plant(`${NOW + 1}-5f3e9a1c-000001.json`, "{not json");
      plant(`${NOW + 2}-5f3e9a1c-000002.json`, { ...valid, tu: "flipped" }); // MAC no longer matches
      const forged = { ...valid, tu: "forged" };
      const otherSub = createHmac("sha256", randomBytes(32)).update("nexus/integrity/v1/ledger").digest();
      const { mac: _m, ...unsigned } = forged;
      forged.mac = `v1:${createHmac("sha256", otherSub).update(canonicalJson(unsigned)).digest("hex")}`;
      plant(`${NOW + 3}-5f3e9a1c-000003.json`, forged); // signed with another key
      plant(`${NOW + 4}-5f3e9a1c-000004.json`, signerFor(Buffer.from(readFileSync(paths.key, "utf-8"), "hex"))
        .sign("ledger", { ...unsigned, decision: "deny" })); // validly signed, but not a recordable shape
      plant(`${NOW + 5}-5f3e9a1c-000005.json`, { ...valid, mac: undefined });
      plant(`${NOW + 6}-5f3e9a1c-000006.json`, []);
      plant("stray.tmp", "x");
      mkdirSync(join(day, `${NOW + 7}-5f3e9a1c-000007.json`)); // not a file
      const read = readLedger(paths, signer, query());
      assert.deepEqual(read.records.map((r) => r.kind === "write" && r.tu), ["good"]);
      assert.equal(read.invalid, 8);
    });

    it("stops at maxFiles and says so, keeping the newest records (the expectedSha fast path needs the latest)", () => {
      for (let i = 0; i < 5; i++) appendWriteRecord(paths, signer, writeInput({ tu: String(i) }), { now: NOW + i });
      appendWriteRecord(paths, signer, writeInput({ tu: "later" }), { now: NOW + DAY / 2 + 1000 });
      const read = readLedger(paths, signer, query({ maxFiles: 3 }));
      assert.deepEqual(read.records.map((r) => r.kind === "write" && r.tu), ["3", "4", "later"], "sorted by t, the oldest cut");
      assert.equal(read.truncated, true);
      assert.equal(readLedger(paths, signer, query({ maxFiles: 6 })).truncated, false);
    });

    it("stops once expired() says so (asked every 64 files), keeping the newest read so far", () => {
      for (let i = 0; i < 70; i++) appendWriteRecord(paths, signer, writeInput({ tu: String(i) }), { now: NOW + i });
      let checks = 0;
      const read = readLedger(paths, signer, query({ maxFiles: Number.POSITIVE_INFINITY, expired: () => ++checks > 1 }));
      assert.equal(checks, 2, "before the first file, then after 64");
      assert.deepEqual([read.records.length, read.records[0].kind === "write" && read.records[0].tu, read.truncated], [64, "6", true]);
      const all = readLedger(paths, signer, query({ expired: () => false }));
      assert.deepEqual([all.records.length, all.truncated], [70, false]);
    });

    it("reads no day directory or record dated more than a day after now", () => {
      appendWriteRecord(paths, signer, writeInput({ tu: "a" }), { now: NOW - 2000 });
      appendWriteRecord(paths, signer, writeInput({ tu: "b" }), { now: NOW - 1000 });
      appendWriteRecord(paths, signer, writeInput({ tu: "skewed" }), { now: NOW + 60_000 }); // a clock a minute ahead
      // validly signed records under future-dated names: they must not take the budget from the newest real ones
      for (let i = 0; i < 4; i++) appendWriteRecord(paths, signer, writeInput({ tu: `future${i}` }), { now: NOW + 3 * DAY + i });
      const today = join(paths.ledgerDir, "20261023");
      writeFileSync(join(today, `${NOW + 5 * DAY}-5f3e9a1c-0000ff.json`), "{ planted");
      const read = readLedger(paths, signer, query({ since: NOW - DAY, now: NOW, maxFiles: 2 }));
      assert.deepEqual(read.records.map((r) => r.kind === "write" && r.tu), ["b", "skewed"]);
      assert.deepEqual([read.invalid, read.truncated], [0, true]);
      // read from later on, the same records are in range
      assert.deepEqual(readLedger(paths, signer, query({ since: NOW - DAY, now: NOW + 3 * DAY, maxFiles: 2 })).records.map((r) => r.kind === "write" && r.tu), ["future2", "future3"]);
    });

    it("does not read day directories outside the retention window or before `since`", () => {
      appendWriteRecord(paths, signer, writeInput({ tu: "ancient" }), { now: NOW - 40 * DAY });
      appendWriteRecord(paths, signer, writeInput({ tu: "recent" }), { now: NOW - 2 * DAY });
      // a corrupt file in an out-of-range day is never opened, so it is not counted
      const ancientDay = join(paths.ledgerDir, new Date(NOW - 40 * DAY).toISOString().slice(0, 10).replace(/-/g, ""));
      writeFileSync(join(ancientDay, `${NOW - 40 * DAY + 5}-5f3e9a1c-0000aa.json`), "{");
      const all = readLedger(paths, signer, query({ since: 0, now: NOW }));
      assert.deepEqual(all.records.map((r) => r.kind === "write" && r.tu), ["recent"]);
      assert.equal(all.invalid, 0);
      assert.deepEqual(readLedger(paths, signer, query({ since: NOW - DAY, now: NOW })).records, []);
    });

    it("reads nothing, without failing, when there is no ledger yet", () => {
      assert.deepEqual(readLedger(paths, signer, query()), { records: [], confirmed: new Set(), invalid: 0, truncated: false });
    });

    it("landedRecords keeps the write records PostToolUse confirmed, and every Nexus record", () => {
      appendWriteRecord(paths, signer, writeInput({ tu: "toolu_approved" }), { now: NOW + 1000 });
      appendWriteRecord(paths, signer, writeInput({ tu: "toolu_rejected" }), { now: NOW + 2000 });
      appendWriteRecord(paths, signer, writeInput({ tu: "" }), { now: NOW + 3000 });
      appendNexusRecord(paths, signer, { action: "install", path: PATH, added: ["u1#1"], removed: [], nexusHooks: ["SessionStart"] }, { now: NOW + 4000 });
      appendConfirmRecord(paths, signer, { sid: SID, tu: "toolu_approved", path: PATH }, { now: NOW + 5000 });
      // a confirmation of another session, path or tool use confirms nothing here
      appendConfirmRecord(paths, signer, { sid: "0123456789abcdef", tu: "toolu_rejected", path: PATH }, { now: NOW + 5001 });
      appendConfirmRecord(paths, signer, { sid: SID, tu: "toolu_rejected", path: "/home/u/app/AGENTS.md" }, { now: NOW + 5002 });
      // nor does one that does not verify
      const forged = appendConfirmRecord(paths, signer, { sid: SID, tu: "toolu_forged", path: PATH }, { now: NOW + 5003 });
      writeFileSync(fileOf(forged), readFileSync(fileOf(forged), "utf-8").replace("toolu_forged", "toolu_rejected"));
      const read = readLedger(paths, signer, query({ keys: null }));
      assert.deepEqual(read.records.map((r) => (r.kind === "write" ? r.tu : r.kind)), ["toolu_approved", "toolu_rejected", "", "nexus"], "read returns every write record");
      assert.equal(read.invalid, 1);
      assert.deepEqual(landedRecords(read).map((r) => (r.kind === "write" ? r.tu : r.kind)), ["toolu_approved", "nexus"]);
      assert.throws(() => appendConfirmRecord(paths, signer, { sid: SID, tu: "", path: PATH }, { now: NOW }), TypeError);
      assert.throws(() => appendConfirmRecord(paths, signer, { sid: "nope", tu: "toolu_x", path: PATH }, { now: NOW }), TypeError);
    });
  });

  describe("simulateWrite", () => {
    it("Write: the content", () => {
      assert.deepEqual(simulateWrite("Write", { file_path: PATH, content: "# New\n" }, "# Old\n"), { text: "# New\n", approx: false });
      assert.deepEqual(simulateWrite("Write", { file_path: PATH, content: "x" }, null), { text: "x", approx: false });
    });

    it("Edit: the first occurrence, or every one with replace_all", () => {
      const current = "run: npm test\nrun: npm test\n";
      assert.deepEqual(simulateWrite("Edit", { old_string: "npm test", new_string: "pnpm test" }, current),
        { text: "run: pnpm test\nrun: npm test\n", approx: false });
      assert.deepEqual(simulateWrite("Edit", { old_string: "npm test", new_string: "pnpm test", replace_all: true }, current),
        { text: "run: pnpm test\nrun: pnpm test\n", approx: false });
      assert.deepEqual(simulateWrite("Edit", { old_string: "aa", new_string: "b", replace_all: true }, "aaaaa"), { text: "bba", approx: false });
    });

    it("treats $-patterns in new_string as literal text", () => {
      assert.deepEqual(simulateWrite("Edit", { old_string: "X", new_string: "$& $1 $$ $'" }, "aXb"), { text: "a$& $1 $$ $'b", approx: false });
      assert.deepEqual(simulateWrite("Edit", { old_string: "X", new_string: "$&", replace_all: true }, "XX"), { text: "$&$&", approx: false });
    });

    it("Edit with an empty old_string creates an absent or empty file", () => {
      assert.deepEqual(simulateWrite("Edit", { old_string: "", new_string: "hello\n" }, null), { text: "hello\n", approx: false });
      assert.deepEqual(simulateWrite("Edit", { old_string: "", new_string: "hello\n" }, ""), { text: "hello\n", approx: false });
    });

    it("MultiEdit: the edits in order, each on the previous result", () => {
      const out = simulateWrite("MultiEdit", {
        edits: [
          { old_string: "alpha", new_string: "beta" },
          { old_string: "beta", new_string: "gamma", replace_all: true },
          { old_string: "end", new_string: "fin" },
        ],
      }, "alpha beta\nend\n");
      assert.deepEqual(out, { text: "gamma gamma\nfin\n", approx: false });
    });

    it("old_string not found: approx, and new_string appended on its own line", () => {
      assert.deepEqual(simulateWrite("Edit", { old_string: "missing", new_string: "Always run ./setup.sh first." }, "# Project\nline"),
        { text: "# Project\nline\nAlways run ./setup.sh first.", approx: true });
      assert.deepEqual(simulateWrite("Edit", { old_string: "missing", new_string: "added\n" }, "# Project\n"),
        { text: "# Project\nadded\n", approx: true });
      // the file is absent (or over 4 MiB, so not read): only new_string is known
      assert.deepEqual(simulateWrite("Edit", { old_string: "x", new_string: "added" }, null), { text: "added", approx: true });
      // an empty old_string on a non-empty file is not a creation
      assert.deepEqual(simulateWrite("Edit", { old_string: "", new_string: "added" }, "kept"), { text: "kept\nadded", approx: true });
      // in a MultiEdit the miss is appended where it happens, and later edits still apply
      assert.deepEqual(simulateWrite("MultiEdit", {
        edits: [{ old_string: "nope", new_string: "first" }, { old_string: "first", new_string: "FIRST" }],
      }, "a\n"), { text: "a\nFIRST", approx: true });
    });

    // Claude Code's Edit matches on the file read with \r\n made \n, and writes it back with
    // the line ending most of its first 4096 characters use.
    it("CRLF: matches on the LF text and writes CRLF back, as Claude Code's Edit does", () => {
      const current = "# App\r\n\r\n## Testing\r\nRun `npm test`.\r\nUse vitest.\r\n";
      assert.deepEqual(simulateWrite("Edit", { old_string: "## Testing\nRun `npm test`.", new_string: "## Testing\nRun `pnpm test`.\nThen lint." }, current),
        { text: "# App\r\n\r\n## Testing\r\nRun `pnpm test`.\r\nThen lint.\r\nUse vitest.\r\n", approx: false });
      assert.deepEqual(simulateWrite("MultiEdit", {
        edits: [{ old_string: "Use vitest.\n", new_string: "" }, { old_string: "# App\n", new_string: "# App\nSee docs.\n" }],
      }, current), { text: "# App\r\nSee docs.\r\n\r\n## Testing\r\nRun `npm test`.\r\n", approx: false });
      // mostly LF: the few CRLF lines come back LF
      assert.deepEqual(simulateWrite("Edit", { old_string: "b", new_string: "B" }, "a\r\nb\nc\nd\n"), { text: "a\nB\nc\nd\n", approx: false });
    });

    it("typographic quotes: old_string matched with straight quotes takes the file's text, and new_string the file's quote style", () => {
      assert.deepEqual(simulateWrite("Edit", {
        old_string: "Don't commit secrets.", new_string: "Don't commit secrets or API keys; see 'vault' docs.",
      }, "# App\n\nDon’t commit secrets.\n"), { text: "# App\n\nDon’t commit secrets or API keys; see ‘vault’ docs.\n", approx: false });
      assert.deepEqual(simulateWrite("Edit", { old_string: 'Say "hi".', new_string: 'Say "hello" ("hi" is old).' }, "Say “hi”.\n"),
        { text: "Say “hello” (“hi” is old).\n", approx: false });
      // an exact match keeps new_string as written
      assert.deepEqual(simulateWrite("Edit", { old_string: "it's", new_string: "it's 'x'" }, "it's ’y’\n"), { text: "it's 'x' ’y’\n", approx: false });
    });

    it("an empty new_string deletes the line break after old_string; an empty old_string fills a blank file, keeping its BOM", () => {
      assert.deepEqual(simulateWrite("Edit", { old_string: "Use vitest.", new_string: "" }, "a\nUse vitest.\nb\n"), { text: "a\nb\n", approx: false });
      assert.deepEqual(simulateWrite("Edit", { old_string: "", new_string: "# New\n" }, "\n  \n"), { text: "# New\n", approx: false });
      assert.deepEqual(simulateWrite("Edit", { old_string: "", new_string: "# New\n" }, "\uFEFF"), { text: "\uFEFF# New\n", approx: false });
      assert.deepEqual(simulateWrite("Write", { file_path: PATH, content: "# New\n" }, "\uFEFF# Old\r\n"), { text: "\uFEFF# New\n", approx: false });
      assert.deepEqual(simulateWrite("Write", { file_path: PATH, content: "" }, "\uFEFF# Old\n"), { text: "", approx: false });
    });

    it("approximates a replace_all whose result would be oversized instead of building it", () => {
      const current = "a".repeat(1 << 20);
      const out = simulateWrite("Edit", { old_string: "a", new_string: "b".repeat(64), replace_all: true }, current);
      assert.equal(out?.approx, true);
      assert.equal(out?.text.length, current.length + 1 + 64);
    });

    it("returns null for NotebookEdit, other tools and malformed input", () => {
      assert.equal(simulateWrite("NotebookEdit", { notebook_path: "/n.ipynb", new_source: "x" }, null), null);
      assert.equal(simulateWrite("Bash", { command: "echo" }, null), null);
      assert.equal(simulateWrite("Write", { file_path: PATH }, null), null);
      assert.equal(simulateWrite("Edit", { old_string: 1, new_string: "x" }, "1"), null);
      assert.equal(simulateWrite("MultiEdit", { edits: [{ old_string: "a", new_string: "b" }, null] }, "a"), null);
      assert.equal(simulateWrite("MultiEdit", { edits: "nope" }, "a"), null);
      assert.equal(simulateWrite("Edit", null, "a"), null);
    });

    it("bounds a whole MultiEdit: once its work budget is spent, the remaining edits are appended", () => {
      // ~4 MiB with 1.4 M matches per edit: each exact edit scans and rebuilds all of it
      const current = "ab\n".repeat(1_400_000);
      const edits = Array.from({ length: 40 }, (_, i) =>
        i % 2 === 0 ? { old_string: "a", new_string: "c", replace_all: true } : { old_string: "c", new_string: "a", replace_all: true });
      const started = performance.now();
      const out = simulateWrite("MultiEdit", { edits }, current);
      const ms = performance.now() - started;
      assert.ok(out);
      assert.equal(out.approx, true);
      // the first `exact` edits applied exactly, then each later new_string on a line of its own
      const tail = out.text.slice(current.length);
      const exact = edits.length - tail.split("\n").length;
      assert.ok(exact >= 1 && exact < edits.length, `${exact} exact edits`);
      assert.equal(out.text.slice(0, current.length) === (exact % 2 === 0 ? current : current.replaceAll("a", "c")), true);
      assert.equal(tail, edits.slice(exact).map((e) => e.new_string).join("\n"));
      assert.ok(ms < 2000, `${ms.toFixed(0)}ms`);
    });

    it("keeps ordinary MultiEdits exact", () => {
      const current = Array.from({ length: 500 }, (_, i) => `rule ${i}: keep\n`).join("");
      const edits = Array.from({ length: 500 }, (_, i) => ({ old_string: `rule ${i}: keep`, new_string: `rule ${i}: kept` }));
      assert.deepEqual(simulateWrite("MultiEdit", { edits }, current), { text: current.replaceAll("keep", "kept"), approx: false });
    });

    it("is linear on large inputs", () => {
      const current = "line of text\n".repeat(300_000);
      const started = performance.now();
      const out = simulateWrite("Edit", { old_string: "text", new_string: "prose", replace_all: true }, current);
      assert.equal(out?.approx, false);
      assert.ok(performance.now() - started < 2000);
    });

    it("expectedSha is the sha256 of the file the write leaves", () => {
      const file = join(base, "CLAUDE.md");
      const current = "﻿# Proj\r\nUse pnpm.\r\n";
      writeFileSync(file, current);
      const sim = simulateWrite("Edit", { old_string: "pnpm", new_string: "npm ✓" }, readFileSync(file, "utf-8"));
      assert.ok(sim);
      // apply the same edit the way the tool would, then hash the bytes on disk
      writeFileSync(file, current.replace("pnpm", "npm ✓"));
      assert.equal(expectedShaOf(sim.text), createHash("sha256").update(readFileSync(file)).digest("hex"));
      assert.match(expectedShaOf(""), /^e3b0c442/);
    });
  });
});
