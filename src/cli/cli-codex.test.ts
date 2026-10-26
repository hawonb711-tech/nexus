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
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { AGENT_ENV, HUMAN_GATE_MESSAGE } from "./integrity.js";
import { CODEX_CONFIRM_MATCHER, CODEX_CONTENT_MATCHER, CODEX_CONTEXT_LIMIT, CODEX_PRE_MATCHER, installCodex } from "../guard/codex/install.js";
import { installGuard } from "../guard/install.js";
import { hookStates, scanToml, trustHash, trustKey } from "../guard/codex/trust.js";

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
    // a Claude Code status here names Codex's install rather than a missing hook
    const claude = plain(nexus(d, ["guard", "status"]).stdout);
    assert.match(claude, /Installed: +no\n +Integrity: +not installed for Claude Code\n +Codex: +installed \(.*hooks\.json\); nexus guard status --codex checks it\n/);
    assert.match(claude, /Run `nexus guard install` to protect Claude Code too\./);
    assert.doesNotMatch(claude, /hook missing/);
    assert.match(out, /Not trusted: +SessionStart, PreToolUse, PostToolUse MCP, PostToolUse apply_patch\. Codex runs a hook only once you trust it, and `codex exec` skips an untrusted one without a word\./);
    assert.match(out, /choose "Trust all and continue" in its "Hooks need review" prompt/);
    assert.match(out, /run in your own terminal: nexus guard install --codex --trust \(trusts Nexus's hooks only, recorded as Nexus's own change\), or/);
    assert.ok(out.indexOf("--codex --trust") < out.indexOf("Trust all and continue"), "--trust first");
    assert.equal(hooksOf(d).hooks.PreToolUse[0].matcher, CODEX_PRE_MATCHER);
    assert.ok(hooksOf(d).hooks.PreToolUse[0].hooks[0].command.endsWith(" --agent codex"));
    assert.equal(existsSync(join(d.codex, "config.toml")), false, "no trust without --trust");
    assert.equal(existsSync(join(d.claude, "settings.json")), false, "Claude Code's settings are not touched");

    const again = nexus(d, ["guard", "install", "--agent", "codex"]);
    assert.equal(again.status, 0, again.stderr);
    assert.match(plain(again.stdout), /Codex hooks already installed and up to date/);

    writeFileSync(join(d.codex, "hooks.json"), `\ufeff${readFileSync(join(d.codex, "hooks.json"), "utf-8")}`);
    const bom = nexus(d, ["guard", "install", "--codex"]);
    assert.equal(bom.status, 0, bom.stderr);
    assert.match(plain(bom.stdout), /Codex hooks updated → .*hooks\.json \(removed the byte-order mark Codex could not read\)/);
    assert.notEqual(readFileSync(join(d.codex, "hooks.json"), "utf-8").charCodeAt(0), 0xfeff);
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

/**
 * hooks.json and config.toml as `install --codex --trust` from another copy of Nexus at
 * `<root>/pkgC` leaves them (npx's cache, another Node version's global install): its
 * hook entry there, every hook trusted.
 */
function trustedFromAnotherCopy(d: Dirs): { hooks: string; config: string } {
  const entry = join(d.root, "pkgC", "dist", "guard", "hook.js");
  mkdirSync(join(d.root, "pkgC", "dist", "guard"), { recursive: true });
  writeFileSync(entry, "");
  const handler = { type: "command", command: `node ${JSON.stringify(entry)} --agent codex`, timeout: 30 };
  const doc = {
    hooks: {
      SessionStart: [{ hooks: [{ ...handler, additionalContextLimit: CODEX_CONTEXT_LIMIT }] }],
      PreToolUse: [{ matcher: CODEX_PRE_MATCHER, hooks: [handler] }],
      PostToolUse: [{ matcher: CODEX_CONTENT_MATCHER, hooks: [handler] }, { matcher: CODEX_CONFIRM_MATCHER, hooks: [handler] }],
    },
  };
  const path = join(realpathSync(d.codex), "hooks.json");
  const tables = Object.entries(doc.hooks).flatMap(([event, groups]) => (groups as any[]).map((g, gi) =>
    `[hooks.state.${JSON.stringify(trustKey(path, event, gi, 0))}]\ntrusted_hash = "${trustHash(event, g.matcher, g.hooks[0])}"\n`));
  const hooks = JSON.stringify(doc, null, 2) + "\n";
  const config = `model = "gpt-5.5"\n\n${tables.join("\n")}`;
  writeFileSync(join(d.codex, "hooks.json"), hooks);
  writeFileSync(join(d.codex, "config.toml"), config);
  return { hooks, config };
}

const STOPS_TRUSTED = "This install would change Nexus's Codex hooks that Codex trusts now (SessionStart, PreToolUse, PostToolUse MCP, PostToolUse apply_patch): " +
  "Codex would skip them until you trust them again. To update and trust them: nexus guard install --codex --trust";

test("a re-install that would make Codex skip Nexus's trusted hooks runs only for the human; their trust goes with the old hooks", () => {
  withDirs((d) => {
    const before = trustedFromAnotherCopy(d);
    assert.ok(JSON.parse(nexus(d, ["guard", "status", "--codex", "--json"]).stdout).groups.every((g: any) => g.runs), "running before");
    // status names the update that keeps them trusted, which a plain re-install would not
    const status = plain(nexus(d, ["guard", "status", "--codex"]).stdout);
    assert.match(status, /Outdated install:/);
    assert.match(status, /Run `nexus guard install --codex --trust` in your own terminal to update it: Codex trusts these hooks now, and would skip the new ones until they are trusted\./);
    const files = () => ({ hooks: readFileSync(join(d.codex, "hooks.json"), "utf-8"), config: readFileSync(join(d.codex, "config.toml"), "utf-8") });
    for (const args of [["guard", "install", "--codex"], ["guard", "install", "--agent", "codex"]]) {
      const r = nexus(d, args);
      assert.deepEqual([r.status, r.stderr], [1, `${STOPS_TRUSTED}\n${HUMAN_GATE_MESSAGE}\n`], args.join(" "));
      assert.deepEqual(files(), before, "nothing written");
    }
    if (hasScript) {
      const agent = onTerminal(d, ["guard", "install", "--codex"], { CODEX_THREAD_ID: "t-1" });
      assert.equal(agent.status, 1, agent.stdout);
      assert.match(plain(agent.stdout), /This install would change Nexus's Codex hooks that Codex trusts now/);
      assert.deepEqual(files(), before, "an agent's terminal is refused too");

      const human = onTerminal(d, ["guard", "install", "--codex"]);
      const out = plain(human.stdout);
      assert.equal(human.status, 0, out);
      assert.match(out, /Codex hooks updated → .*hooks\.json \(replaced 4 earlier Nexus hooks; removed 4 trust entries of earlier Nexus hooks from config\.toml\)/);
      assert.match(out, /Not trusted: +SessionStart, PreToolUse, PostToolUse MCP, PostToolUse apply_patch\./);
      assert.equal(files().config, 'model = "gpt-5.5"\n', "the old hooks' trust went with them");
      const u = nexus(d, ["guard", "uninstall", "--codex"]);
      assert.match(plain(u.stdout), /Removed Nexus's Codex hooks \(4 hooks\) from .*hooks\.json\n/);
      assert.equal(files().config, 'model = "gpt-5.5"\n');
    }
  });
});

test("a Codex install that would move the user's own trusted hook runs only for the human; one that adds a group moves none", () => {
  withDirs((d) => {
    const path = join(realpathSync(d.codex), "hooks.json");
    const user = { type: "command", command: "node /opt/audit.mjs", timeout: 10 };
    const trustUser = (gi: number) => {
      const g = hooksOf(d).hooks.PostToolUse[gi];
      writeFileSync(join(d.codex, "config.toml"), `[hooks.state.${JSON.stringify(trustKey(path, "PostToolUse", gi, 0))}]\ntrusted_hash = "${trustHash("PostToolUse", g.matcher, g.hooks[0])}"\n`);
    };
    // --no-integrity, then the user's own PostToolUse hook after Nexus's group, trusted: turning integrity back on adds a group, after it
    if (hasScript) {
      assert.equal(onTerminal(d, ["guard", "install", "--codex", "--no-integrity"]).status, 0);
      const doc = hooksOf(d);
      doc.hooks.PostToolUse.push({ matcher: "apply_patch|Bash", hooks: [user] });
      writeFileSync(join(d.codex, "hooks.json"), JSON.stringify(doc, null, 2) + "\n");
      trustUser(1);
      const r = nexus(d, ["guard", "install", "--codex"]);
      assert.equal(r.status, 0, r.stderr);
      assert.doesNotMatch(plain(r.stdout), /moved/);
      assert.deepEqual(hooksOf(d).hooks.PostToolUse.map((g: any) => g.matcher), [CODEX_CONTENT_MATCHER, "apply_patch|Bash", CODEX_CONFIRM_MATCHER]);
    }
    // a duplicate Nexus group before the user's: taking it out moves theirs
    assert.equal(nexus(d, ["guard", "install", "--codex"]).status, 0);
    const doc = hooksOf(d);
    doc.hooks.PostToolUse = [doc.hooks.PostToolUse[0], structuredClone(doc.hooks.PostToolUse[0]), { matcher: "apply_patch|Bash", hooks: [user] }, doc.hooks.PostToolUse.at(-1)];
    writeFileSync(join(d.codex, "hooks.json"), JSON.stringify(doc, null, 2) + "\n");
    trustUser(2);
    const files = () => [readFileSync(join(d.codex, "hooks.json"), "utf-8"), readFileSync(join(d.codex, "config.toml"), "utf-8")];
    const before = files();
    const r = nexus(d, ["guard", "install", "--codex"]);
    assert.equal(r.status, 1, r.stdout);
    assert.equal(r.stderr, "This install would move your own Codex hook that Codex runs now (PostToolUse `node /opt/audit.mjs` (group 2 → 1)). " +
      `Codex keeps trust by position, so it would skip it until you trust it again in codex's "Hooks need review".\n${HUMAN_GATE_MESSAGE}\n`);
    assert.deepEqual(files(), before, "nothing written");
    if (hasScript) {
      const human = onTerminal(d, ["guard", "install", "--codex"]);
      assert.equal(human.status, 0, human.stdout);
      assert.match(plain(human.stdout), /Warning: +1 of your own Codex hook moved in hooks\.json, and Codex keeps trust by position: it will ask about it again \(PostToolUse `node \/opt\/audit\.mjs` \(group 2 → 1\)\)/);
    }
  });
});

test("install --codex --trust says which of Nexus's hooks config.toml turns off", { skip: !hasScript && "needs util-linux script" }, () => {
  withDirs((d) => {
    assert.equal(onTerminal(d, ["guard", "install", "--codex", "--trust"]).status, 0);
    const config = join(d.codex, "config.toml");
    const header = `[hooks.state.${JSON.stringify(trustKey(join(realpathSync(d.codex), "hooks.json"), "PreToolUse", 0, 0))}]\n`;
    writeFileSync(config, readFileSync(config, "utf-8").replace(header, `${header}enabled = false\n`));
    const r = onTerminal(d, ["guard", "install", "--codex", "--trust"]);
    const out = plain(r.stdout);
    assert.equal(r.status, 0, out);
    assert.match(out, /Codex hooks already installed and up to date/);
    assert.match(out, /Turned off: +PreToolUse: .*config\.toml turns it off \(enabled = false\), so Codex does not run it until you remove that setting/);
    assert.match(plain(nexus(d, ["guard", "status", "--codex"]).stdout), /PreToolUse +#0\.0 +live, turned off in config\.toml/);
  });
});

test("--trust that config.toml does not let Nexus write exits 1, and offers only Codex's own review", { skip: !hasScript && "needs util-linux script" }, () => {
  withDirs((d) => {
    const config = '[hooks]\nstate = { "elsewhere" = { trusted_hash = "sha256:x" } }\n';
    writeFileSync(join(d.codex, "config.toml"), config);
    const r = onTerminal(d, ["guard", "install", "--codex", "--trust"]);
    const out = plain(r.stdout);
    assert.equal(r.status, 1, out);
    assert.match(out, /Codex hooks installed → /);
    assert.match(out, /Not trusted: +SessionStart, PreToolUse, PostToolUse MCP, PostToolUse apply_patch\. .* To trust them:\s+- start codex in your terminal and choose "Trust all and continue"/);
    assert.doesNotMatch(out, /nexus guard install --codex --trust/, "re-running --trust would be refused the same way");
    assert.match(out, /Error: --trust: Nexus did not change .*config\.toml: line 2 sets hook state with a dotted key or an inline table\. The hooks are installed/);
    assert.equal(readFileSync(join(d.codex, "config.toml"), "utf-8"), config);
    assert.equal(hooksOf(d).hooks.PreToolUse[0].matcher, CODEX_PRE_MATCHER);
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

test("--codex and --agent mean the same on every guard command, with the same errors; elsewhere they are refused", () => {
  withDirs((d) => {
    writeFileSync(join(d.codex, "AGENTS.md"), "Be helpful.\n");
    // guard integrity: --codex is Codex's view, as --agent codex is
    const view = (args: string[]) => plain(nexus(d, ["guard", "integrity", "status", ...args]).stdout);
    for (const flag of [["--codex"], ["--agent", "codex"], ["--agent=CODEX"]]) {
      assert.match(view(flag), /Hook: +Codex's hooks are checked by nexus guard status --codex/, flag.join(" "));
      assert.match(view(flag), /Watching: .*\(Codex \d+, project \d+\)/, flag.join(" "));
    }
    assert.doesNotMatch(view([]), /Codex's hooks are checked/);
    for (const [args, message] of [
      [["guard", "integrity", "status", "--agent", "codx"], /--agent must be claude or codex \(got "codx"\)/],
      [["guard", "status", "--agent", "codx"], /--agent must be claude or codex \(got "codx"\)/],
      [["guard", "integrity", "diff", "--codex", "--agent", "claude"], /--codex and --agent claude contradict each other/],
      [["guard", "demo", "--codex"], /--codex and --agent are for nexus guard install, uninstall, status, check and integrity/],
      [["scan", "hello", "--agent", "codex"], /--codex and --agent are for nexus guard install, uninstall, status, check and integrity/],
    ] as const) {
      const r = nexus(d, [...args]);
      assert.equal(r.status, 1, args.join(" "));
      assert.match(r.stderr, message, args.join(" "));
    }
    // guard check, a hook, fails open: --codex answers in Codex's format, and so does a value that names neither agent
    const payload = JSON.stringify({
      session_id: "s", turn_id: "t", cwd: d.project, hook_event_name: "PreToolUse", permission_mode: "default",
      tool_name: "Bash", tool_input: { command: "chmod 777 build" }, tool_use_id: "c1",
    });
    const check = (args: string[]) => spawnSync(process.execPath, ["--import", TSX, CLI_SRC, "guard", "check", ...args], {
      cwd: d.project, env: d.env, encoding: "utf8", input: payload, timeout: 60_000,
    });
    assert.match(check([]).stdout, /"permissionDecision":"ask"/);
    for (const flag of [["--codex"], ["--agent", "codex"], ["--agent", "codx"], ["--codex", "--agent", "claude"]]) {
      const r = check(flag);
      assert.deepEqual([r.status, r.stderr], [0, ""], flag.join(" "));
      assert.match(r.stdout, /"permissionDecision":"deny"/, flag.join(" "));
      assert.match(r.stdout, /Codex hooks cannot ask for confirmation/, flag.join(" "));
    }
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

test("with only a Codex install, guard integrity status reports Claude Code as not installed, and points at Codex alone", () => {
  withDirs((d) => {
    // trusted as `--trust` would (the CLI's --trust needs a terminal)
    installCodex({ trust: true }, { env: { CODEX_HOME: d.codex }, homedir: d.home, dataDir: d.data, cwd: d.project, managedDir: join(d.root, "managed") });
    const ok = nexus(d, ["guard", "integrity", "status"]);
    assert.equal(ok.status, 0, ok.stdout);
    assert.match(ok.stdout, /Hook: +Claude Code: not installed \(nexus guard install adds its hooks\)/);
    assert.match(ok.stdout, /Codex: +SessionStart installed and trusted \(.*hooks\.json\)/);
    assert.doesNotMatch(ok.stdout, /SessionStart hook missing|Next:/);
    assert.equal(nexus(d, ["guard", "integrity", "status", "--json"]).status, 0);

    writeFileSync(join(d.codex, "config.toml"), ""); // the trust gone
    const r = nexus(d, ["guard", "integrity", "status"]);
    assert.equal(r.status, 3);
    assert.match(r.stdout, /Hook: +Claude Code: not installed/);
    assert.match(r.stdout, /Codex: +not working \(.*hooks\.json\): SessionStart hook is not trusted/);
    assert.match(r.stdout, /Next: +nexus guard status --codex/);

    // a Claude Code install that is there but broken is Claude Code's problem again, and comes first
    mkdirSync(d.claude, { recursive: true });
    writeFileSync(join(d.claude, "settings.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "nexus guard check" }] }] } }));
    const both = nexus(d, ["guard", "integrity", "status"]);
    assert.equal(both.status, 3);
    assert.match(both.stdout, /Hook: +not working \(user settings\)/);
    assert.match(both.stdout, /Next: +nexus guard install\n/);
  });
});

test("an install that turns integrity's one switch back on says so, naming the other agent's install that lacks its hooks; status says why", () => {
  // each agent's --no-integrity install from the library (the CLI's needs a terminal), then the other's plain install from the CLI
  const depsOf = (d: Dirs) => ({ env: { CLAUDE_CONFIG_DIR: d.claude, CODEX_HOME: d.codex }, homedir: d.home, dataDir: d.data, cwd: d.project });
  withDirs((d) => {
    assert.equal(installGuard({ integrity: false }, depsOf(d)).integrity.reenabled, false);
    const r = nexus(d, ["guard", "install", "--codex"]);
    assert.equal(r.status, 0, r.stderr);
    const out = plain(r.stdout);
    assert.match(out, /Note: +integrity was off \(--no-integrity; one switch for Claude Code and Codex\) and is on again, for both agents\n/);
    assert.match(out, /Note: +Claude Code's install has no integrity hooks: nexus guard install adds them, or in your own terminal nexus guard install --codex --no-integrity turns integrity off again for both\n/);
    assert.doesNotMatch(plain(nexus(d, ["guard", "install", "--codex"]).stdout), /Note:/, "once: the switch is on now");
    const status = nexus(d, ["guard", "integrity", "status"]);
    assert.equal(status.status, 3, "integrity is on, and Claude Code's sessions are not fingerprinted");
    assert.match(plain(status.stdout), /Hook: +left out \(user settings\): installed without integrity's SessionStart and PostToolUse Write\|Edit\|MultiEdit hooks \(by --no-integrity, or a Nexus version before them\), while integrity is on: one switch for Claude Code and Codex\n/);
    assert.match(plain(status.stdout), /Next: +nexus guard install, or in your own terminal nexus guard install --no-integrity to keep integrity off for both agents\n/);
    const guard = plain(nexus(d, ["guard", "status"]).stdout);
    assert.match(guard, /Integrity: +left out \(user settings\)/);
    assert.match(guard, /Run `nexus guard install` to update it, or `nexus guard install --no-integrity` in your own terminal to keep integrity off for both agents\./);
  });
  withDirs((d) => {
    assert.equal(installCodex({ integrity: false }, depsOf(d)).integrity.reenabled, false);
    const r = nexus(d, ["guard", "install"]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(plain(r.stdout), /Note: +Codex's install has no integrity hooks: nexus guard install --codex adds them, or in your own terminal nexus guard install --no-integrity turns integrity off again for both\n/);
    const codex = plain(nexus(d, ["guard", "status", "--codex"]).stdout);
    assert.match(codex, /- installed without integrity's SessionStart and PostToolUse apply_patch hooks \(by --no-integrity, or a Nexus version before them\)/);
    assert.match(codex, /Run `nexus guard install --codex` to update it, or `nexus guard install --codex --no-integrity` in your own terminal to keep integrity off for both agents\./);
    assert.match(plain(nexus(d, ["guard", "integrity", "status"]).stdout), /Codex: +left out \(.*hooks\.json\): installed without integrity's SessionStart and PostToolUse apply_patch hooks/);
  });
});

test("a relative CODEX_HOME is read as integrity reads it: not taken, so install and uninstall refuse, and status says so", () => {
  withDirs((d) => {
    mkdirSync(join(d.project, "codex-rel"));
    const env = { CODEX_HOME: "codex-rel" };
    for (const action of ["install", "uninstall"]) {
      const r = nexus(d, ["guard", action, "--codex"], env);
      assert.equal(r.status, 1, action);
      assert.match(r.stderr, /CODEX_HOME="codex-rel" is not an absolute path, so Nexus does not use it \(Codex reads it against the directory it starts in\): set it to an absolute path/);
    }
    assert.equal(existsSync(join(d.project, "codex-rel", "hooks.json")), false);
    assert.match(plain(nexus(d, ["guard", "status", "--codex"], env).stdout), /Warning: +CODEX_HOME="codex-rel" is not an absolute path, so Nexus does not use it .*, and reads ~\/\.codex/);
    assert.match(plain(nexus(d, ["guard", "integrity", "status", "--agent", "codex"], env).stdout), /Warning: +CODEX_HOME="codex-rel" is not an absolute path, so Nexus ignores it and uses ~\/\.codex/);
  });
});

test("help documents --codex, --trust and CODEX_HOME", () => {
  withDirs((d) => {
    const help = plain(nexus(d, ["--help"]).stdout);
    for (const want of ["--codex", "--trust", "CODEX_HOME", "nexus guard install --codex"]) assert.ok(help.includes(want), want);
  });
});
