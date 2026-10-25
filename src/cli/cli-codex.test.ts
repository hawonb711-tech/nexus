/**
 * `nexus guard install|uninstall|status --codex` and the Codex part of
 * `nexus guard integrity status`, run as the CLI (from source) with every
 * directory a throwaway one: HOME, CODEX_HOME, NEXUS_DATA and CLAUDE_CONFIG_DIR.
 * The gated forms (`--trust`, `--no-integrity`, a narrowing install) refuse from
 * a pipe and from any agent's environment; on a pseudo-terminal outside an
 * agent `--trust` writes Nexus's trust (the gate's own tests do the same).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { AGENT_ENV, HUMAN_GATE_MESSAGE } from "./integrity.js";
import { CODEX_PRE_MATCHER } from "../guard/codex/install.js";
import { hookStates, scanToml } from "../guard/codex/trust.js";

const TSX = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;
const CLI_SRC = resolve("src/cli/index.ts");

type Dirs = { root: string; home: string; codex: string; data: string; claude: string; project: string; env: NodeJS.ProcessEnv };

function withDirs(run: (d: Dirs) => void): void {
  const root = mkdtempSync(join(tmpdir(), "nexus-cli-codex-"));
  const d = { root, home: join(root, "home"), codex: join(root, "codex"), data: join(root, "data"), claude: join(root, "claude"), project: join(root, "project") };
  for (const dir of [d.home, d.codex, d.project]) mkdirSync(dir);
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: d.home, USERPROFILE: d.home, CODEX_HOME: d.codex, NEXUS_DATA: d.data, CLAUDE_CONFIG_DIR: d.claude, NO_COLOR: "1" };
  for (const name of AGENT_ENV) delete env[name];
  try {
    run({ ...d, env });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

/** `nexus <args>` from source, on pipes (never a terminal). */
function nexus(d: Dirs, args: string[], env: Record<string, string> = {}) {
  const r = spawnSync(process.execPath, ["--import", TSX, CLI_SRC, ...args], { cwd: d.project, env: { ...d.env, ...env }, encoding: "utf8", timeout: 60_000 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

// util-linux `script` runs the CLI on a pseudo-terminal, past the gate's terminal check
const hasScript = process.platform === "linux" && spawnSync("script", ["--version"]).status === 0;
const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
function onTerminal(d: Dirs, args: string[], env: Record<string, string> = {}) {
  const cmd = [process.execPath, "--import", TSX, CLI_SRC, ...args].map(q).join(" ");
  const r = spawnSync("script", ["-qec", cmd, "/dev/null"], { cwd: d.project, env: { ...d.env, ...env }, encoding: "utf8", timeout: 60_000, input: "" });
  return { status: r.status, stdout: r.stdout };
}

const hooksOf = (d: Dirs): any => JSON.parse(readFileSync(join(d.codex, "hooks.json"), "utf-8"));
const plain = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

test("guard install --codex writes hooks.json in CODEX_HOME and says how to trust the hooks; --agent codex is the same", () => {
  withDirs((d) => {
    const r = nexus(d, ["guard", "install", "--codex"]);
    assert.equal(r.status, 0, r.stderr);
    const out = plain(r.stdout);
    assert.match(out, /Codex hooks installed → .*hooks\.json/);
    assert.match(out, /Not trusted: +SessionStart, PreToolUse, PostToolUse MCP, PostToolUse apply_patch\. Codex runs a hook only once you trust it, and `codex exec` skips an untrusted one without a word\./);
    assert.match(out, /choose "Trust all and continue" in its "Hooks need review" prompt/);
    assert.match(out, /run in your own terminal: nexus guard install --codex --trust/);
    assert.equal(hooksOf(d).hooks.PreToolUse[0].matcher, CODEX_PRE_MATCHER);
    assert.ok(hooksOf(d).hooks.PreToolUse[0].hooks[0].command.endsWith(" --agent codex"));
    assert.equal(existsSync(join(d.codex, "config.toml")), false, "no trust without --trust");
    assert.equal(existsSync(join(d.claude, "settings.json")), false, "Claude Code's settings are not touched");

    const again = nexus(d, ["guard", "install", "--agent", "codex"]);
    assert.equal(again.status, 0, again.stderr);
    assert.match(plain(again.stdout), /Codex hooks already installed and up to date/);
  });
});

test("guard status --codex reports each hook live and untrusted, as JSON too; uninstall --codex takes them out", () => {
  withDirs((d) => {
    assert.equal(nexus(d, ["guard", "status", "--codex"]).stdout.includes("Run `nexus guard install --codex`"), true, "nothing installed yet");
    nexus(d, ["guard", "install", "--codex"]);
    const json = nexus(d, ["guard", "status", "--codex", "--json"]);
    assert.equal(json.status, 0);
    const s = JSON.parse(json.stdout);
    assert.deepEqual(s.groups.map((g: any) => [g.label, g.installed, g.live, g.trusted]), [
      ["SessionStart", true, true, false], ["PreToolUse", true, true, false], ["PostToolUse MCP", true, true, false], ["PostToolUse apply_patch", true, true, false],
    ]);
    assert.deepEqual([s.outdated, s.missing, s.hooksOff], [[], [], null]);
    const human = plain(nexus(d, ["guard", "status", "--codex"]).stdout);
    assert.match(human, /SessionStart +#0\.0 +live, not trusted \(Codex skips it\)/);
    assert.match(human, /SessionStart hook is not trusted: Codex skips it \(codex exec says nothing\)/);

    const u = nexus(d, ["guard", "uninstall", "--codex"]);
    assert.match(plain(u.stdout), /Removed Nexus's Codex hooks \(4 hooks\)/);
    assert.deepEqual(hooksOf(d), {});
    assert.match(plain(nexus(d, ["guard", "uninstall", "--codex"]).stdout), /No Nexus hooks found/);
  });
});

test("--trust, --no-integrity and a narrowing Codex install run only for the human", () => {
  withDirs((d) => {
    const trust = nexus(d, ["guard", "install", "--codex", "--trust"]);
    assert.equal(trust.status, 1);
    assert.equal(trust.stderr, `Trusting hooks is Codex's own security check, so Nexus writes that trust only when you ask in your own terminal.\n${HUMAN_GATE_MESSAGE}\n`);
    assert.equal(existsSync(join(d.codex, "hooks.json")), false, "refused before anything is written");
    const off = nexus(d, ["guard", "install", "--codex", "--no-integrity"]);
    assert.deepEqual([off.status, off.stderr], [1, `${HUMAN_GATE_MESSAGE}\n`]);
    writeFileSync(join(d.codex, "hooks.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "nexus guard check --agent codex" }] }] } }));
    const narrow = nexus(d, ["guard", "install", "--codex"]);
    assert.deepEqual([narrow.status, narrow.stderr], [1, `This install would stop guarding *.\n${HUMAN_GATE_MESSAGE}\n`]);
  });
});

test("on a terminal outside any agent, --trust writes Nexus's trust; inside one it refuses", { skip: !hasScript && "needs util-linux script" }, () => {
  withDirs((d) => {
    for (const name of AGENT_ENV) {
      const r = onTerminal(d, ["guard", "install", "--codex", "--trust"], { [name]: "1" });
      assert.equal(r.status, 1, name);
      assert.match(r.stdout, /an agent cannot approve its own changes/, name);
    }
    assert.equal(existsSync(join(d.codex, "config.toml")), false);
    const r = onTerminal(d, ["guard", "install", "--codex", "--trust"]);
    assert.equal(r.status, 0, r.stdout);
    assert.match(plain(r.stdout), /Trust: +trusted in .*config\.toml \(4 entries written\)/);
    assert.equal(hookStates(scanToml(readFileSync(join(d.codex, "config.toml"), "utf-8"))).size, 4);
    const status = JSON.parse(nexus(d, ["guard", "status", "--codex", "--json"]).stdout);
    assert.ok(status.groups.every((g: any) => g.runs));
    const u = nexus(d, ["guard", "uninstall", "--codex"]);
    assert.match(plain(u.stdout), /and 4 trust entries from config\.toml/);
    assert.equal(readFileSync(join(d.codex, "config.toml"), "utf-8"), "");

    // --no-integrity past the gate: integrity status names the Codex install as off, and needs nothing
    const off = onTerminal(d, ["guard", "install", "--codex", "--no-integrity"]);
    assert.equal(off.status, 0, off.stdout);
    assert.match(plain(off.stdout), /Integrity: +off \(--no-integrity\) — one switch for Claude Code and Codex/);
    const s = nexus(d, ["guard", "integrity", "status"]);
    assert.match(s.stdout, /Codex: +integrity is off \(.*hooks\.json\)/);
  });
});

test("Codex options that do not fit are usage errors", () => {
  withDirs((d) => {
    for (const [args, message] of [
      [["guard", "install", "--trust"], /--trust is for the Codex install: nexus guard install --codex --trust/],
      [["guard", "install", "--codex", "--project"], /--project and --tools are for Claude Code/],
      [["guard", "status", "--codex", "--tools", "Bash"], /--project and --tools are for Claude Code/],
      [["guard", "install", "--agent", "cursor"], /--agent must be claude or codex \(got "cursor"\)/],
      [["guard", "install", "--codex", "--agent", "claude"], /--codex and --agent claude contradict each other/],
    ] as const) {
      const r = nexus(d, [...args]);
      assert.equal(r.status, 1, args.join(" "));
      assert.match(r.stderr, message, args.join(" "));
    }
    assert.equal(existsSync(join(d.codex, "hooks.json")), false);
  });
});

test("install and status --codex say loudly when config.toml turns Codex's hooks off", () => {
  withDirs((d) => {
    writeFileSync(join(d.codex, "config.toml"), "[features]\nhooks = false\n");
    const r = nexus(d, ["guard", "install", "--codex"]);
    assert.match(plain(r.stdout), /Warning: +.*config\.toml turns Codex's hooks off \(features\.hooks = false \(line 2\)\): Codex runs none of these hooks until you remove that setting/);
    const s = plain(nexus(d, ["guard", "status", "--codex"]).stdout);
    assert.match(s, /Hooks: +off in .*config\.toml \(features\.hooks = false \(line 2\)\): Codex runs no hook/);
  });
});

test("guard integrity status reports a Codex install (exit 3 while untrusted) and nothing without one", () => {
  withDirs((d) => {
    const before = nexus(d, ["guard", "integrity", "status", "--json"]);
    assert.equal(JSON.parse(before.stdout).hook.codex, null);
    assert.doesNotMatch(nexus(d, ["guard", "integrity", "status"]).stdout, /Codex:/);
    nexus(d, ["guard", "install"]); // Claude Code's hooks, so only Codex's can need attention
    assert.equal(nexus(d, ["guard", "integrity", "status"]).status, 0);
    nexus(d, ["guard", "install", "--codex"]);
    const r = nexus(d, ["guard", "integrity", "status"]);
    assert.equal(r.status, 3);
    assert.match(r.stdout, /Codex: +not working \(.*hooks\.json\): SessionStart hook is not trusted: Codex skips it/);
    assert.match(r.stdout, /Next: +nexus guard status --codex/);
    const json = JSON.parse(nexus(d, ["guard", "integrity", "status", "--json"]).stdout);
    assert.deepEqual([json.hook.live, json.hook.codex.live, json.hook.codex.sessionStartTrust], [true, false, "untrusted"]);
  });
});

test("help documents --codex, --trust and CODEX_HOME", () => {
  withDirs((d) => {
    const help = plain(nexus(d, ["--help"]).stdout);
    for (const want of ["--codex", "--trust", "CODEX_HOME", "nexus guard install --codex"]) assert.ok(help.includes(want), want);
  });
});
