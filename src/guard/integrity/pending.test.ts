/**
 * Pending-confirm markers (pending.ts): the names, when the hook entry may
 * skip a file tool's PostToolUse, and their garbage collection. The marker's
 * lifecycle through PreToolUse and the confirm is in pre-tool.test.ts, and
 * through the hook entry process in hook-entry.test.ts.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { clearPending, markPending, nothingToConfirm, pendingMarkerPath } from "./pending.js";
import { collectGarbage, integrityPaths } from "./store.js";
import { INTEGRITY_DIR, PENDING_DIR } from "./types.js";

const DAY = 24 * 60 * 60 * 1000;

function withData(fn: (data: string) => void): void {
  const data = mkdtempSync(join(tmpdir(), "nexus-pending-"));
  try {
    fn(data);
  } finally {
    rmSync(data, { recursive: true, force: true });
  }
}

const postFile = (over: Record<string, unknown> = {}) => ({
  hook_event_name: "PostToolUse", session_id: "s-1", tool_name: "Edit", tool_use_id: "toolu_1",
  tool_input: { file_path: "/repo/src/a.ts" }, tool_response: {}, ...over,
});

describe("pending-confirm markers", () => {
  it("live where integrityPaths says, named by the session and tool use", () => {
    withData((data) => {
      const p = pendingMarkerPath(data, "s-1", "toolu_1");
      assert.equal(dirname(p), integrityPaths(data).pendingDir);
      assert.equal(dirname(p), join(data, INTEGRITY_DIR, PENDING_DIR));
      assert.match(basename(p), /^[0-9a-f]{32}$/);
      assert.notEqual(p, pendingMarkerPath(data, "s-1", "toolu_2"));
      assert.notEqual(p, pendingMarkerPath(data, "s-2", "toolu_1"));
      // the separator keeps ("ab", "c") and ("a", "bc") apart
      assert.notEqual(pendingMarkerPath(data, "ab", "c"), pendingMarkerPath(data, "a", "bc"));
    });
  });

  it("a file tool's PostToolUse has nothing to confirm until a marker exists, and again once it is cleared", () => {
    withData((data) => {
      const d = () => data;
      assert.equal(nothingToConfirm(postFile(), d), true);
      markPending(data, "s-1", "toolu_1");
      assert.equal(nothingToConfirm(postFile(), d), false);
      assert.equal(nothingToConfirm(postFile({ tool_use_id: "toolu_2" }), d), true, "another tool use");
      for (const tool of ["Write", "MultiEdit", "NotebookEdit"]) assert.equal(nothingToConfirm(postFile({ tool_name: tool, tool_use_id: "toolu_9" }), d), true, tool);
      clearPending(data, "s-1", "toolu_1");
      assert.equal(nothingToConfirm(postFile(), d), true);
      clearPending(data, "s-1", "toolu_1"); // gone already: no throw
      // the confirm needs a session and a tool use id; without them there is nothing to do
      assert.equal(nothingToConfirm(postFile({ tool_use_id: "" }), d), true);
      assert.equal(nothingToConfirm(postFile({ session_id: undefined }), d), true);
    });
  });

  it("never skips anything but a file tool's PostToolUse", () => {
    withData((data) => {
      const d = () => data;
      for (const payload of [
        postFile({ hook_event_name: "PreToolUse" }),
        postFile({ tool_name: "WebFetch" }),
        postFile({ tool_name: "Bash" }),
        postFile({ tool_name: "mcp__fs__write_file" }),
        { hook_event_name: "SessionStart", session_id: "s-1" },
        null, [], "Edit", 42,
      ]) assert.equal(nothingToConfirm(payload, d), false, JSON.stringify(payload));
      assert.equal(nothingToConfirm(postFile(), () => { throw new Error("no data dir"); }), false, "an error means: run the handler");
    });
  });

  it("markPending never throws: a data dir that cannot hold it leaves the write unconfirmed", () => {
    withData((data) => {
      const file = join(data, "not-a-dir");
      writeFileSync(file, "x");
      markPending(file, "s-1", "toolu_1");
      assert.equal(nothingToConfirm(postFile(), () => file), true);
    });
  });

  it("garbage collection removes markers older than a day, and nothing else there", () => {
    withData((data) => {
      const paths = integrityPaths(data);
      const now = Date.now();
      markPending(data, "s-1", "toolu_old");
      markPending(data, "s-1", "toolu_new");
      const old = pendingMarkerPath(data, "s-1", "toolu_old");
      const stale = new Date(now - 2 * DAY);
      utimesSync(old, stale, stale);
      const other = join(paths.pendingDir, "notes.txt");
      writeFileSync(other, "x");
      utimesSync(other, stale, stale);
      mkdirSync(join(paths.pendingDir, "0123456789abcdef0123456789abcdef"));
      assert.deepEqual(collectGarbage(paths, { now }), { deleted: 1, complete: true });
      assert.equal(existsSync(old), false);
      assert.equal(existsSync(pendingMarkerPath(data, "s-1", "toolu_new")), true);
      assert.deepEqual(readdirSync(paths.pendingDir).length, 3);
    });
  });
});
