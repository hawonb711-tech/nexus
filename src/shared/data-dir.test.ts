/**
 * `NEXUS_DATA` as every entry point reads it (`dataDirFrom`): empty is unset,
 * `~/` is the home directory, anything else that is not absolute is ignored for
 * ~/.nexus. The hook runs in the user's repository, so a value that resolved
 * against its cwd would put the integrity key and stores there.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { join, win32 } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dataDirFrom, nexusDataDir } from "./data-dir.js";

const TSX = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;
const HOOK_SRC = fileURLToPath(new URL("../guard/hook.ts", import.meta.url));

describe("dataDirFrom", () => {
  it("reads an unset or empty value as ~/.nexus, and expands a leading ~/", () => {
    const home = "/home/u";
    for (const value of [undefined, ""]) assert.deepEqual(dataDirFrom(value, home, "linux"), { dir: "/home/u/.nexus", ignored: null }, String(value));
    assert.deepEqual(dataDirFrom("~/.nexus-work", home, "linux"), { dir: "/home/u/.nexus-work", ignored: null });
    assert.deepEqual(dataDirFrom("~", home, "linux"), { dir: "/home/u", ignored: null });
    assert.deepEqual(dataDirFrom("~//srv/x", home, "linux"), { dir: "/home/u/srv/x", ignored: null });
    assert.deepEqual(dataDirFrom("/srv/nexus/../data", home, "linux"), { dir: "/srv/data", ignored: null });
    // `~\` is a home path only on Windows; elsewhere it is a relative name like any other
    assert.deepEqual(dataDirFrom("~\\data", home, "linux"), { dir: "/home/u/.nexus", ignored: "~\\data" });
  });

  it("ignores a relative value for ~/.nexus and reports it", () => {
    for (const value of ["data", "./data", "../data", "~user/data", " "]) {
      assert.deepEqual(dataDirFrom(value, "/home/u", "linux"), { dir: "/home/u/.nexus", ignored: value }, value);
    }
  });

  it("reads Windows paths with Windows rules", () => {
    const home = "C:\\Users\\u";
    assert.deepEqual(dataDirFrom("~\\nexus", home, "win32"), { dir: "C:\\Users\\u\\nexus", ignored: null });
    assert.deepEqual(dataDirFrom("~/nexus", home, "win32"), { dir: "C:\\Users\\u\\nexus", ignored: null });
    assert.deepEqual(dataDirFrom("~\\\\nexus", home, "win32"), { dir: "C:\\Users\\u\\nexus", ignored: null });
    assert.deepEqual(dataDirFrom("D:\\nexus", home, "win32"), { dir: "D:\\nexus", ignored: null });
    assert.deepEqual(dataDirFrom("nexus", home, "win32"), { dir: "C:\\Users\\u\\.nexus", ignored: "nexus" });
    assert.equal(dataDirFrom(undefined, home, "win32").dir, win32.join(home, ".nexus"));
  });

  it("nexusDataDir reads NEXUS_DATA from the process the same way", () => {
    const saved = process.env.NEXUS_DATA;
    try {
      for (const value of ["", "relative/dir"]) {
        process.env.NEXUS_DATA = value;
        assert.equal(nexusDataDir(), join(homedir(), ".nexus"), `${JSON.stringify(value)}: ~/.nexus, never resolved against the cwd`);
      }
      process.env.NEXUS_DATA = "~/.nexus-work";
      assert.equal(nexusDataDir(), join(homedir(), ".nexus-work"));
    } finally {
      if (saved === undefined) delete process.env.NEXUS_DATA;
      else process.env.NEXUS_DATA = saved;
    }
  });
});

describe("the hook with an empty, relative or ~/ NEXUS_DATA", () => {
  it("never writes into the session's repository: the store goes to ~/.nexus (or the expanded ~/ path)", () => {
    const root = realpathSync.native(mkdtempSync(join(tmpdir(), "nexus-data-dir-")));
    try {
      // a home each: a second data dir beside a ~/.nexus that has a store is a §5.6 redirect, where nothing is created
      const cases: [value: string, store: string][] = [["", ".nexus"], ["nexus-data", ".nexus"], ["~/.nexus-work", ".nexus-work"]];
      for (const [i, [value, name]] of cases.entries()) {
        const home = join(root, `home-${i}`);
        const config = join(home, ".claude");
        const store = join(home, name);
        mkdirSync(config, { recursive: true });
        const repo = join(root, `repo-${i}`);
        mkdirSync(join(repo, ".git"), { recursive: true });
        writeFileSync(join(repo, "CLAUDE.md"), "# rules\n");
        const payload = { hook_event_name: "SessionStart", session_id: `s${i}`, cwd: repo, source: "startup", transcript_path: join(config, "projects", "x", `s${i}.jsonl`) };
        // the hook runs in the repository, as Claude Code starts it
        const r = spawnSync(process.execPath, ["--import", TSX, HOOK_SRC], {
          cwd: repo,
          env: { ...process.env, HOME: home, USERPROFILE: home, CLAUDE_CONFIG_DIR: config, NEXUS_DATA: value },
          input: JSON.stringify(payload),
          encoding: "utf8",
          timeout: 60_000,
        });
        assert.equal(r.status, 0, r.stderr);
        assert.deepEqual(readdirSync(repo).sort(), [".git", "CLAUDE.md"], `NEXUS_DATA=${JSON.stringify(value)}: nothing new in the repository`);
        assert.ok(existsSync(join(store, "integrity", ".integrity-key")), `NEXUS_DATA=${JSON.stringify(value)}: the store is in ${store}`);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
