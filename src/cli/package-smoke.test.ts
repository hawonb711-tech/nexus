/**
 * `npm run smoke:package` runs the packed CLI, and `guard install` writes the
 * settings file CLAUDE_CONFIG_DIR names and the integrity store in NEXUS_DATA.
 * Run from a developer's shell with either set, the smoke must still keep every
 * nexus process in its own throwaway dirs. npm is replaced by a stand-in
 * (`npm_execpath`) that "installs" this checkout's build by linking it, so the
 * check needs no network; the smoke's own checks then run as usual.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const REPO = resolve(".");

/** Answers the npm commands the smoke runs: pack, install (a link to REPO), ls and audit. */
const FAKE_NPM = `
import { mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const [command, ...rest] = process.argv.slice(2);
const repo = process.env.NEXUS_SMOKE_TEST_REPO;
if (command === "pack") {
  writeFileSync(join(rest[rest.indexOf("--pack-destination") + 1], "nexus.tgz"), "");
  console.log(JSON.stringify([{ filename: "nexus.tgz", files: [{ path: "dist/guard/hook.js" }] }]));
} else if (command === "install") {
  mkdirSync(join("node_modules", "@hawon"), { recursive: true });
  symlinkSync(repo, join("node_modules", "@hawon", "nexus"), "junction");
  symlinkSync(join(repo, "node_modules", "@modelcontextprotocol"), join("node_modules", "@modelcontextprotocol"), "junction");
} else if (command === "ls") {
  const v = (version) => ({ version });
  console.log(JSON.stringify({ dependencies: {
    "@hono/node-server": v("2.0.12"), "@modelcontextprotocol/sdk": v("1.31.0"), "body-parser": v("2.3.0"),
    "fast-uri": v("3.1.8"), hono: v("4.13.7"), "ip-address": v("10.7.1"),
  } }));
} else if (command === "audit") {
  console.log(JSON.stringify({ metadata: { vulnerabilities: { total: 0 } } }));
} else {
  process.exit(2);
}
`;

const listing = (dir: string): string[] =>
  existsSync(dir) ? readdirSync(dir, { recursive: true }).map(String).sort() : [];

test("the package smoke never writes the CLAUDE_CONFIG_DIR or NEXUS_DATA it was started with", (t) => {
  if (!existsSync(join(REPO, "dist", "cli", "index.js")) || !existsSync(join(REPO, "dist", "guard", "hook.js"))) {
    t.skip("dist/ not built — run `npm run build` first");
    return;
  }
  const root = mkdtempSync(join(tmpdir(), "nexus-smoke-env-"));
  try {
    // The developer's own dirs: a working settings file and an empty store.
    const home = join(root, "home");
    const config = join(root, "claude-config");
    const data = join(root, "nexus-data");
    const smokeTmp = join(root, "tmp");
    for (const d of [home, config, data, smokeTmp]) mkdirSync(d);
    const settings = join(config, "settings.json");
    const own = JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "my-lint" }] }] } });
    writeFileSync(settings, own);
    const npm = join(root, "fake-npm.mjs");
    writeFileSync(npm, FAKE_NPM);

    const r = spawnSync(process.execPath, [join(REPO, "scripts", "package-smoke.mjs")], {
      cwd: REPO,
      env: {
        ...process.env, HOME: home, USERPROFILE: home, CLAUDE_CONFIG_DIR: config, NEXUS_DATA: data,
        TMPDIR: smokeTmp, TMP: smokeTmp, TEMP: smokeTmp,
        CLAUDECODE: "1", CLAUDE_CODE_SESSION_ID: "smoke-test-session", CLAUDE_CODE_CHILD_SESSION: "1",
        CODEX_THREAD_ID: "smoke-test-thread", CODEX_SANDBOX: "seatbelt", CODEX_SANDBOX_NETWORK_DISABLED: "1",
        npm_execpath: npm, NEXUS_SMOKE_TEST_REPO: REPO,
      },
      encoding: "utf8",
      timeout: 120_000,
    });
    assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
    assert.match(r.stdout, /package smoke: .* OK/);
    assert.equal(readFileSync(settings, "utf-8"), own, "the developer's settings are byte-identical");
    assert.deepEqual(listing(config), ["settings.json"]);
    assert.deepEqual(listing(data), [], "nothing lands in the developer's store");
    assert.deepEqual(listing(home), []);
    assert.deepEqual(listing(smokeTmp), [], "the smoke removes its own dirs");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
