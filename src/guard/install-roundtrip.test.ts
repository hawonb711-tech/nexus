import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  installGuard, uninstallGuard, guardStatus, guardCommand, isNexusGuardCommand, settingsPath, staleDefaultSettings, droppedTools,
  checkNexusHooks, DEFAULT_HOOK_TIMEOUT, DEFAULT_FILE_TOOLS, runsCliGuardCheck, scriptPathOf, withoutAgentFlag, type HookLayers, type InstallDeps,
} from "./install.js";
import { classify, type ClassifyResult, type StoreInput } from "./integrity/classify.js";
import { contextFromHook } from "./integrity/context.js";
import { enumerateWatched } from "./integrity/enumerate.js";
import { readLedger } from "./integrity/ledger.js";
import { canonicalPath, storeKey } from "./integrity/paths.js";
import { renderSessionStart } from "./integrity/render.js";
import {
  initIntegrity, integrityPaths, isIntegrityDisabled, loadIntegrity, readIntegrityKey, signerFor, TAMPER_FRAGMENTS,
} from "./integrity/store.js";
import type { StoreDoc } from "./integrity/types.js";
import { unitHasher } from "./integrity/units.js";

const POSIX = process.platform !== "win32";

/** Everything install reads from the process, pointed into `dir`: never the real ~/.claude or ~/.nexus. */
function depsIn(dir: string, over: InstallDeps = {}): InstallDeps {
  return {
    homedir: join(dir, "home"), env: {}, cwd: join(dir, "project"), dataDir: join(dir, "data"), managedDir: join(dir, "managed"),
    ...over,
  };
}

// Every test targets an explicit settings file in a temp dir — never ~/.claude —
// and a temp data dir — never ~/.nexus.
function withSettings(initial: unknown, run: (path: string, deps: InstallDeps) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "nexus-install-"));
  const path = join(dir, "settings.json");
  if (initial !== undefined) writeFileSync(path, JSON.stringify(initial, null, 2) + "\n");
  try {
    run(path, depsIn(dir));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The SessionStart group install writes: no `matcher` key, so it runs for every source. */
const OUR_SESSION_START = () => ({ hooks: [{ type: "command", command: guardCommand(), timeout: DEFAULT_HOOK_TIMEOUT }] });

const read = (path: string): any => JSON.parse(readFileSync(path, "utf-8"));
const nexusEntries = (list: any[] = []) =>
  list.filter((m) => (m.hooks ?? []).some((h: any) => isNexusGuardCommand(h.command)));
/** Integrity's PostToolUse group: exact tool names (never TodoWrite), after the content guard's. */
const CONFIRM = "Write|Edit|MultiEdit";
const CONFIRM_MISSING = "PostToolUse Write|Edit|MultiEdit hook is missing (instruction-file integrity: approved edits would show as unexplained changes)";
const contentEntries = (list: any[] = []) => nexusEntries(list).filter((m) => m.matcher !== CONFIRM);

const USER_SETTINGS = {
  model: "opus",
  permissions: { allow: ["Bash(npm test)"] },
  hooks: {
    PostToolUse: [{ matcher: "Edit", hooks: [{ type: "command", command: "echo hi" }] }],
    PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "my-lint --staged", timeout: 5 }] }],
    SessionStart: [{ hooks: [{ type: "command", command: "echo start" }] }],
  },
};

test("install → status → reinstall with other tools → uninstall keeps exactly one Nexus entry and the user's settings", () => {
  withSettings(USER_SETTINGS, (path, deps) => {
    const original = readFileSync(path, "utf-8");
    const r = installGuard({ path }, deps);
    assert.equal(r.alreadyInstalled, false);
    assert.equal(r.replaced, 0);

    const s = guardStatus({ path }, deps);
    assert.equal(s.installed, true);
    assert.deepEqual(s.outdated, [], "a fresh install is current");
    // Default content-guard coverage is web + ALL MCP tools (`mcp__.*` is a Claude
    // Code matcher regex matched against tool_name, so it guards every MCP tool).
    assert.deepEqual(s.contentTools, ["WebFetch", "WebSearch", "mcp__.*"]);
    assert.deepEqual(s.commandTools, ["Bash", "PowerShell", ...DEFAULT_FILE_TOOLS]);
    assert.ok(s.commandTools.includes("MultiEdit"), "MultiEdit writes are guarded");

    let after = read(path);
    for (const event of ["PostToolUse", "PreToolUse", "SessionStart"]) {
      const ours = contentEntries(after.hooks[event]);
      assert.equal(ours.length, 1, `one Nexus ${event} entry`);
      assert.deepEqual(ours[0].hooks, [{ type: "command", command: guardCommand(), timeout: DEFAULT_HOOK_TIMEOUT }]);
    }
    assert.deepEqual(nexusEntries(after.hooks.PostToolUse).map((m) => m.matcher), ["WebFetch|WebSearch|mcp__.*", CONFIRM]);
    // Instruction-file integrity: one SessionStart group with no matcher, after the user's own.
    assert.deepEqual(after.hooks.SessionStart, [USER_SETTINGS.hooks.SessionStart[0], OUR_SESSION_START()]);
    assert.equal("matcher" in after.hooks.SessionStart[1], false);
    assert.equal(DEFAULT_HOOK_TIMEOUT, 30, "Claude Code reads hook timeouts in seconds");

    // Same install again: nothing to change, file left byte-for-byte.
    const before = readFileSync(path, "utf-8");
    const r2 = installGuard({ path }, deps);
    assert.equal(r2.alreadyInstalled, true);
    assert.equal(readFileSync(path, "utf-8"), before);

    // Widening --tools replaces our entries instead of appending duplicates.
    const r3 = installGuard({ path, tools: ["WebFetch", "WebSearch", "Read"], timeout: 45 }, deps);
    assert.equal(r3.alreadyInstalled, false);
    assert.equal(r3.replaced, 4, "PostToolUse's two entries, PreToolUse's and SessionStart's");
    after = read(path);
    const post = contentEntries(after.hooks.PostToolUse);
    const pre = nexusEntries(after.hooks.PreToolUse);
    assert.equal(post.length, 1);
    assert.equal(pre.length, 1);
    assert.equal(post[0].matcher, "WebFetch|WebSearch|Read");
    assert.equal(post[0].hooks[0].timeout, 45);
    assert.equal(pre[0].hooks[0].timeout, 45);
    assert.deepEqual(after.hooks.SessionStart[1], { hooks: [{ type: "command", command: guardCommand(), timeout: 45 }] }, "replaced in place");
    assert.deepEqual(guardStatus({ path }, deps).contentTools, ["WebFetch", "WebSearch", "Read"]);

    const u = uninstallGuard({ path }, deps);
    assert.equal(u.removed, 4);
    assert.equal(guardStatus({ path }, deps).installed, false);
    assert.equal(readFileSync(path, "utf-8"), original, "unrelated hooks and settings are exactly as they were, byte for byte");

    // Nothing of ours left: a second uninstall doesn't touch the file.
    assert.equal(uninstallGuard({ path }, deps).removed, 0);
    assert.equal(readFileSync(path, "utf-8"), original);
  });
});

test("install into a missing settings file creates it; uninstall leaves no empty hook lists", () => {
  withSettings(undefined, (path, deps) => {
    const r = installGuard({ path }, deps);
    assert.equal(r.created, true);
    assert.ok(existsSync(path));
    assert.deepEqual(read(path).hooks.SessionStart, [OUR_SESSION_START()]);
    assert.equal(uninstallGuard({ path }, deps).removed, 4);
    assert.deepEqual(read(path), {});
  });
});

test("migrates hooks written by older versions: ms timeout, stale CLI path, duplicates, missing MultiEdit", () => {
  const legacy = (command: string) => ({ type: "command", command, timeout: 15000 });
  const staleCli = 'node "/x/dist/cli/index.js" guard check';
  withSettings({
    model: "opus",
    hooks: {
      PostToolUse: [
        { matcher: "Edit", hooks: [{ type: "command", command: "echo hi" }] },
        { matcher: "WebFetch|WebSearch", hooks: [legacy("nexus guard check")] },
        // The pre-fix --tools re-install appended a second entry instead of replacing.
        { matcher: "WebFetch|WebSearch|Read", hooks: [legacy(staleCli)] },
      ],
      PreToolUse: [
        { matcher: "Bash|PowerShell|Write|Edit|NotebookEdit", hooks: [legacy(staleCli)] },
      ],
    },
  }, (path, deps) => {
    const before = readFileSync(path, "utf-8");
    const s = guardStatus({ path }, deps);
    assert.equal(s.installed, true, "legacy entries are recognised as installed");
    assert.deepEqual(s.contentTools, ["WebFetch", "WebSearch", "Read"]);
    const reasons = s.outdated.join("\n");
    assert.match(reasons, /timeout is 15000/);
    assert.match(reasons, /no longer exists: \/x\/dist\/cli\/index\.js/);
    assert.match(reasons, /2 duplicate PostToolUse hooks/);
    assert.match(reasons, /does not cover MultiEdit/);
    assert.ok(s.outdated.includes("SessionStart hook is missing (instruction-file integrity)"), reasons);
    assert.equal(readFileSync(path, "utf-8"), before, "status never writes");

    // Three earlier Nexus hooks replaced; no Nexus version before integrity wrote a SessionStart one.
    const r = installGuard({ path }, deps);
    assert.equal(r.replaced, 3);
    const after = read(path);
    assert.equal(after.model, "opus");
    assert.deepEqual(after.hooks.PostToolUse[0], { matcher: "Edit", hooks: [{ type: "command", command: "echo hi" }] });
    const post = contentEntries(after.hooks.PostToolUse);
    const pre = nexusEntries(after.hooks.PreToolUse);
    assert.equal(post.length, 1);
    assert.equal(pre.length, 1);
    for (const entry of [...post, ...pre]) {
      assert.deepEqual(entry.hooks, [{ type: "command", command: guardCommand(), timeout: DEFAULT_HOOK_TIMEOUT }]);
    }
    assert.ok(pre[0].matcher.split("|").includes("MultiEdit"));
    assert.deepEqual(after.hooks.SessionStart, [OUR_SESSION_START()]);
    assert.deepEqual(guardStatus({ path }, deps).outdated, []);
  });
});

test("a matcher entry shared with the user's own hook keeps that hook", () => {
  withSettings({
    hooks: {
      PreToolUse: [{
        matcher: "Bash",
        hooks: [
          { type: "command", command: "my-audit-log" },
          { type: "command", command: "nexus guard check", timeout: 15000 },
        ],
      }],
    },
  }, (path, deps) => {
    assert.equal(uninstallGuard({ path }, deps).removed, 1);
    assert.deepEqual(read(path).hooks.PreToolUse, [{ matcher: "Bash", hooks: [{ type: "command", command: "my-audit-log" }] }]);
  });
});

test("refuses to rewrite settings it cannot safely merge", () => {
  withSettings({ hooks: { PreToolUse: { matcher: "Bash" } } }, (path, deps) => {
    const before = readFileSync(path, "utf-8");
    assert.throws(() => installGuard({ path }, deps), /not an array/);
    assert.throws(() => uninstallGuard({ path }, deps), /not an array/);
    assert.match(guardStatus({ path }, deps).error ?? "", /not an array/);
    assert.equal(readFileSync(path, "utf-8"), before);
    assert.equal(existsSync(deps.dataDir!), false, "a refused install prepares no integrity store");
  });
  withSettings({ hooks: { SessionStart: { hooks: [] } } }, (path, deps) => {
    const before = readFileSync(path, "utf-8");
    assert.throws(() => installGuard({ path }, deps), /hooks\.SessionStart is not an array/);
    assert.throws(() => uninstallGuard({ path }, deps), /hooks\.SessionStart is not an array/);
    assert.equal(readFileSync(path, "utf-8"), before);
  });
});

test("isNexusGuardCommand recognises every command form Nexus has installed", () => {
  const ours = [
    "nexus guard check",
    "  nexus   guard check  ",
    "/usr/local/bin/nexus guard check",
    "npx -y @hawon/nexus guard check",
    "npx @hawon/nexus@0.7.4 guard check",
    'node "/home/me/.npm/_npx/1a2b/node_modules/@hawon/nexus/dist/cli/index.js" guard check',
    'node "/Users/me/My Project/nexus/dist/cli/index.js" guard check',
    'node "/Users/me/My%20Project/nexus/dist/cli/index.js" guard check', // <= 0.6 used URL.pathname
    // JSON.stringify of a Windows path, as guardCommand() writes it there.
    `node ${JSON.stringify("C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\@hawon\\nexus\\dist\\cli\\index.js")} guard check`,
    "node dist/cli/index.js guard check",
    // The dedicated hook entry guardCommand() writes now (no `guard check` args).
    'node "/home/me/.npm/_npx/1a2b/node_modules/@hawon/nexus/dist/guard/hook.js"',
    'node "/Users/me/My Project/nexus/dist/guard/hook.js"',
    `node ${JSON.stringify("C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\@hawon\\nexus\\dist\\guard\\hook.js")}`,
    "/usr/local/bin/node /opt/nexus/dist/guard/hook.js",
    "node dist/guard/hook.js",
    // The repo's own compatibility wrapper (runs `guard check` internally).
    "bash scripts/scan-tool-result.sh",
    "/home/me/nexus/scripts/scan-tool-result.sh",
  ];
  for (const command of ours) assert.equal(isNexusGuardCommand(command), true, command);

  const notOurs = [
    "echo hi",
    "nexus guard install",
    "nexus guard check --verbose",
    "other-tool guard check",
    'node "/x/dist/server.js" guard check',
    'node "/x/dist/guard/hook.js" --verbose',
    'node "/x/dist/guard/install.js"',
    "python3 /x/dist/guard/hook.js",
    "cat dist/guard/hook.js",
    "npx nexus guard check", // the unrelated unscoped "nexus" npm package
    "",
    undefined,
    42,
  ];
  for (const command of notOurs) assert.equal(isNexusGuardCommand(command), false, String(command));
});

test("the hook-command recognisers stay linear on a long whitespace run, as guard status reads every settings layer", () => {
  // `guard status` and `guard integrity status` run these on every hook command of
  // every layer, a cloned repository's .claude/settings.json included. A pattern
  // for the `--agent` flag unanchored on the left (`\s+--agent…$`) retried the
  // whitespace run from each of its starts: 12 s for a 120 KB command.
  const slack = Math.max(1, Number(process.env.NEXUS_PERF_SLACK) || 1);
  const run = " ".repeat(100_000);
  const commands = [
    `echo${run}done`,
    `node "/p/dist/guard/hook.js"${run}--agent${run}x1`,
    `nexus guard check${" --agent".repeat(12_500)}`,
    `a${run}--agent`,
    `node${run}"/p/dist/guard/hook.js"${run}guard${run}check${run}--agent=codex`,
  ];
  for (const command of commands) {
    const t0 = performance.now();
    isNexusGuardCommand(command);
    runsCliGuardCheck(command);
    scriptPathOf(command);
    withoutAgentFlag(command);
    const ms = performance.now() - t0;
    assert.ok(ms < 1000 * slack, `${JSON.stringify(command.slice(0, 32))}…: ${ms.toFixed(0)} ms`);
  }

  // end to end: checkNexusHooks, which both status commands run, over a project layer holding one such hook
  const dir = mkdtempSync(join(tmpdir(), "nexus-install-"));
  try {
    const project = join(dir, "project");
    mkdirSync(join(project, ".claude"), { recursive: true });
    writeFileSync(join(project, ".claude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: commands[0] }] }] } }));
    const t0 = performance.now();
    const check = checkNexusHooks({ user: join(dir, "home", "settings.json"), projectDirs: [project], managedDir: join(dir, "managed"), homedir: join(dir, "home"), platform: process.platform });
    const ms = performance.now() - t0;
    assert.equal(check.layers.length, 0, "not a Nexus hook");
    assert.ok(ms < 1000 * slack, `checkNexusHooks: ${ms.toFixed(0)} ms`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  // what the flag's removal keeps and drops
  assert.equal(withoutAgentFlag(' node "/p/dist/guard/hook.js"   --agent \t codex  '), 'node "/p/dist/guard/hook.js"');
  assert.equal(withoutAgentFlag("nexus guard check --agent=codex"), "nexus guard check");
  for (const kept of ["--agent codex", "x--agent codex", "nexus guard check --agent", "nexus guard check --agent codex2", "nexus guard check --agent codex extra"]) {
    assert.equal(withoutAgentFlag(kept), kept, kept);
  }
});

test("a plain re-install keeps a custom --tools list instead of narrowing to defaults", () => {
  withSettings(USER_SETTINGS, (path, deps) => {
    installGuard({ path, tools: ["WebFetch", "WebSearch", "mcp__.*"] }, deps);
    assert.deepEqual(guardStatus({ path }, deps).contentTools, ["WebFetch", "WebSearch", "mcp__.*"]);

    // The documented upgrade step is a bare `guard install`; it must not drop
    // the MCP matcher the user set earlier.
    const r = installGuard({ path }, deps);
    assert.equal(r.alreadyInstalled, true, "nothing changed, so no rewrite");
    assert.equal(r.replaced, 0, "a no-op install replaced nothing");
    assert.deepEqual(guardStatus({ path }, deps).contentTools, ["WebFetch", "WebSearch", "mcp__.*"]);
  });
});

test("hooks that is not an object is refused rather than silently mis-installing", () => {
  withSettings({ hooks: [] }, (path, deps) => {
    assert.throws(() => installGuard({ path }, deps), /hooks is not an object/);
  });
  withSettings({ hooks: "oops" }, (path, deps) => {
    assert.throws(() => installGuard({ path }, deps), /hooks is not an object/);
  });
});

// Under tsx there is no built hook.js next to src/guard/install.ts, so
// guardCommand() falls back to `nexus guard check`; the built module returns the
// absolute `node "<pkg>/dist/guard/hook.js"` an installed package writes. The
// tests below therefore drive the BUILT install module.
type InstallModule = typeof import("./install.js");
async function builtInstall(t: { skip(message: string): void }): Promise<InstallModule | null> {
  const built = resolve("dist/guard/install.js");
  if (!existsSync(built) || !existsSync(resolve("dist/guard/hook.js"))) {
    t.skip("dist/ not built — run `npm run build` first");
    return null;
  }
  const dist = (await import(pathToFileURL(built).href)) as InstallModule;
  if (!Array.isArray(dist.LIFECYCLE_EVENTS)) {
    t.skip("dist/ is older than this source — run `npm run build` first");
    return null;
  }
  return dist;
}

/** What Nexus <= 0.7.4 wrote from an installed package: the whole CLI's `guard check`. */
const OLD_CLI_FORM = `node ${JSON.stringify(resolve("dist/cli/index.js"))} guard check`;

test("the command the built package installs is the hook entry, and recognised as ours (v0.6.0–0.7.4 regression)", async (t) => {
  const dist = await builtInstall(t);
  if (!dist) return;
  const command = dist.guardCommand(); // pure: resolves a path, writes nothing
  assert.match(command, /^node ".*dist[\\/]+guard[\\/]+hook\.js"$/);
  assert.ok(existsSync(JSON.parse(command.slice("node ".length))), "the hook entry it names exists");
  assert.equal(isNexusGuardCommand(command), true);
  assert.equal(dist.isNexusGuardCommand(command), true);
  assert.equal(isNexusGuardCommand(guardCommand()), true);
  assert.equal(dist.isNexusGuardCommand(OLD_CLI_FORM), true, "the old full-CLI form is still ours");
});

test("built install → status → reinstall → uninstall round-trips with the hook entry", async (t) => {
  const dist = await builtInstall(t);
  if (!dist) return;
  withSettings(USER_SETTINGS, (path, deps) => {
    const original = readFileSync(path, "utf-8");
    assert.equal(dist.installGuard({ path }, deps).alreadyInstalled, false);
    const after = read(path);
    for (const event of ["PostToolUse", "PreToolUse", "SessionStart"]) {
      const ours = contentEntries(after.hooks[event]);
      assert.equal(ours.length, 1, `one Nexus ${event} entry`);
      assert.deepEqual(ours[0].hooks, [{ type: "command", command: dist.guardCommand(), timeout: DEFAULT_HOOK_TIMEOUT }]);
    }
    assert.deepEqual(nexusEntries(after.hooks.PostToolUse).map((m) => m.matcher), ["WebFetch|WebSearch|mcp__.*", CONFIRM]);
    assert.deepEqual(after.hooks.SessionStart, [USER_SETTINGS.hooks.SessionStart[0], { hooks: [{ type: "command", command: dist.guardCommand(), timeout: 30 }] }]);
    assert.deepEqual(dist.guardStatus({ path }, deps).outdated, [], "a fresh hook-entry install is current");

    const before = readFileSync(path, "utf-8");
    assert.equal(dist.installGuard({ path }, deps).alreadyInstalled, true);
    assert.equal(readFileSync(path, "utf-8"), before, "a no-op reinstall leaves the file byte-for-byte");

    assert.equal(dist.uninstallGuard({ path }, deps).removed, 4);
    assert.equal(readFileSync(path, "utf-8"), original);
  });
});

test("built status flags the old full-CLI command as outdated; a plain install migrates it in place", async (t) => {
  const dist = await builtInstall(t);
  if (!dist) return;
  const userPost = { matcher: "Edit", hooks: [{ type: "command", command: "echo hi" }] };
  const userPre = { matcher: "Bash", hooks: [{ type: "command", command: "my-lint --staged", timeout: 5 }] };
  withSettings({
    model: "opus",
    hooks: {
      // Timeout and matchers already current: the command form is the only thing out of date.
      PostToolUse: [userPost, { matcher: "WebFetch|WebSearch|mcp__.*", hooks: [{ type: "command", command: OLD_CLI_FORM, timeout: 30 }] }],
      PreToolUse: [
        { matcher: "Bash|PowerShell|Write|Edit|NotebookEdit|MultiEdit", hooks: [{ type: "command", command: "nexus guard check", timeout: 30 }] },
        userPre,
      ],
    },
  }, (path, deps) => {
    const before = readFileSync(path, "utf-8");
    const s = dist.guardStatus({ path }, deps);
    assert.equal(s.installed, true);
    assert.equal(s.outdated.length, 4, s.outdated.join("\n"));
    for (const [reason, old] of [[s.outdated[0], OLD_CLI_FORM], [s.outdated[1], "nexus guard check"]]) {
      assert.ok(reason.includes(`hook runs the full CLI (\`${old}\`)`), reason);
      assert.ok(reason.includes(`dedicated hook entry (\`${dist.guardCommand()}\`)`), reason);
    }
    assert.equal(s.outdated[2], "SessionStart hook is missing (instruction-file integrity)");
    assert.equal(s.outdated[3], CONFIRM_MISSING);
    assert.equal(readFileSync(path, "utf-8"), before, "status never writes");

    const r = dist.installGuard({ path }, deps);
    assert.equal(r.alreadyInstalled, false);
    assert.equal(r.replaced, 2);
    const after = read(path);
    const ours = { type: "command", command: dist.guardCommand(), timeout: DEFAULT_HOOK_TIMEOUT };
    // Replaced where the old entries sat; the user's hooks keep their places.
    assert.deepEqual(after.hooks.PostToolUse, [userPost, { matcher: "WebFetch|WebSearch|mcp__.*", hooks: [ours] }, { matcher: CONFIRM, hooks: [ours] }]);
    assert.deepEqual(after.hooks.PreToolUse, [{ matcher: "Bash|PowerShell|Write|Edit|NotebookEdit|MultiEdit", hooks: [ours] }, userPre]);
    assert.deepEqual(after.hooks.SessionStart, [{ hooks: [ours] }]);
    assert.equal(after.model, "opus");
    assert.deepEqual(dist.guardStatus({ path }, deps).outdated, []);
    assert.equal(dist.installGuard({ path }, deps).alreadyInstalled, true, "the migration does not repeat");
  });
});

test("built uninstall removes old full-CLI and hook-entry duplicates alike", async (t) => {
  const dist = await builtInstall(t);
  if (!dist) return;
  const hook = (command: string, timeout = 30) => ({ type: "command", command, timeout });
  withSettings({
    hooks: {
      PostToolUse: [
        { matcher: "WebFetch|WebSearch", hooks: [hook(OLD_CLI_FORM, 15000)] },
        { matcher: "WebFetch|WebSearch|mcp__.*", hooks: [hook(dist.guardCommand())] },
      ],
      PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "my-audit-log" }, hook("nexus guard check"), hook(dist.guardCommand())] }],
    },
  }, (path, deps) => {
    assert.match(dist.guardStatus({ path }, deps).outdated.join("\n"), /2 duplicate PostToolUse hooks/);
    assert.equal(dist.uninstallGuard({ path }, deps).removed, 4);
    assert.deepEqual(read(path), { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "my-audit-log" }] }] } });
  });
});

// ── Instruction-file integrity (spec §6.1, §7 "Changes to existing commands") ──

test("the SessionStart group goes after the user's own and keeps its place on reinstall", () => {
  withSettings(USER_SETTINGS, (path, deps) => {
    installGuard({ path }, deps);
    // The user adds a group of their own after ours.
    const later = { hooks: [{ type: "command", command: "echo later" }] };
    const edited = read(path);
    edited.hooks.SessionStart.push(later);
    writeFileSync(path, JSON.stringify(edited, null, 2) + "\n");

    const r = installGuard({ path, timeout: 45 }, deps);
    assert.equal(r.replaced, 4);
    const ours45 = { hooks: [{ type: "command", command: guardCommand(), timeout: 45 }] };
    assert.deepEqual(read(path).hooks.SessionStart, [USER_SETTINGS.hooks.SessionStart[0], ours45, later], "replaced where it was");
    installGuard({ path }, deps);
    assert.deepEqual(read(path).hooks.SessionStart, [USER_SETTINGS.hooks.SessionStart[0], OUR_SESSION_START(), later]);

    // A matcher someone added to our group is dropped: it must run for every source.
    const narrowed = read(path);
    narrowed.hooks.SessionStart[1] = { matcher: "startup", ...narrowed.hooks.SessionStart[1] };
    writeFileSync(path, JSON.stringify(narrowed, null, 2) + "\n");
    assert.equal(installGuard({ path }, deps).alreadyInstalled, false);
    assert.deepEqual(read(path).hooks.SessionStart[1], OUR_SESSION_START());
  });
});

test("install creates the integrity key and anchor once, and turns integrity back on", () => {
  withSettings(USER_SETTINGS, (path, deps) => {
    const paths = integrityPaths(deps.dataDir!);
    const r = installGuard({ path }, deps);
    assert.deepEqual(r.integrity, { enabled: true, recorded: true, problem: null });
    for (const file of [paths.key, paths.anchor, paths.registry]) assert.ok(existsSync(file), file);
    if (POSIX) {
      for (const dir of [paths.dataDir, paths.dir]) assert.equal(statSync(dir).mode & 0o777, 0o700, dir);
      for (const file of [paths.key, paths.anchor]) assert.equal(statSync(file).mode & 0o777, 0o600, file);
    }
    const key = readFileSync(paths.key, "utf-8");
    const anchor = readFileSync(paths.anchor, "utf-8");

    // Turned off (as `nexus guard integrity config enabled false` would): a plain install removes the marker.
    installGuard({ path, integrity: false }, deps);
    assert.equal(isIntegrityDisabled(paths), true);
    const back = installGuard({ path }, deps);
    assert.equal(back.integrity.enabled, true);
    assert.equal(existsSync(paths.disabled), false);
    assert.equal(readFileSync(paths.key, "utf-8"), key, "the key is kept");
    assert.equal(readFileSync(paths.anchor, "utf-8"), anchor, "the anchor is kept");

    // An unsigned marker never counted, and install leaves it be.
    writeFileSync(paths.disabled, JSON.stringify({ v: 1, kind: "disabled", at: "2026-10-23T09:00:00.000Z", by: "cli", mac: "v1:forged" }));
    assert.equal(installGuard({ path }, deps).alreadyInstalled, true);
    assert.equal(existsSync(paths.disabled), true);
    assert.equal(guardStatus({ path }, deps).integrity.disabled, false);
  });
});

test("integrity: false (--no-integrity) writes no SessionStart group and a signed .disabled marker", () => {
  withSettings(USER_SETTINGS, (path, deps) => {
    const paths = integrityPaths(deps.dataDir!);
    const r = installGuard({ path, integrity: false }, deps);
    assert.equal(r.integrity.enabled, false);
    assert.equal(r.integrity.problem, null);
    const after = read(path);
    assert.deepEqual(after.hooks.SessionStart, USER_SETTINGS.hooks.SessionStart, "only the user's own group");
    assert.equal(nexusEntries(after.hooks.PostToolUse).length, 1);
    assert.equal(nexusEntries(after.hooks.PreToolUse).length, 1);
    assert.equal(isIntegrityDisabled(paths), true);
    const marker = JSON.parse(readFileSync(paths.disabled, "utf-8"));
    assert.deepEqual([marker.kind, marker.by], ["disabled", "install"]);
    const s = guardStatus({ path }, deps);
    assert.deepEqual([s.integrity.sessionStartHook, s.integrity.disabled, s.integrity.disableAllHooksIn], [false, true, []]);
    assert.deepEqual(s.outdated, [], "a missing SessionStart hook is not outdated while integrity is off");

    // Again: nothing changes, the marker included.
    const before = readFileSync(path, "utf-8");
    const markerBefore = readFileSync(paths.disabled, "utf-8");
    assert.equal(installGuard({ path, integrity: false }, deps).alreadyInstalled, true);
    assert.equal(readFileSync(path, "utf-8"), before);
    assert.equal(readFileSync(paths.disabled, "utf-8"), markerBefore);

    // Over an install with integrity on, it removes Nexus's SessionStart group and PostToolUse
    // confirmation (the content entry is put back as it was) and nothing else.
    installGuard({ path }, deps);
    assert.equal(isIntegrityDisabled(paths), false);
    const off = installGuard({ path, integrity: false }, deps);
    assert.equal(off.alreadyInstalled, false);
    assert.equal(off.replaced, 2);
    assert.equal(readFileSync(path, "utf-8"), before);
    assert.equal(isIntegrityDisabled(paths), true);
  });
  withSettings(undefined, (path, deps) => {
    installGuard({ path, integrity: false }, deps);
    assert.equal("SessionStart" in read(path).hooks, false);
    assert.equal(uninstallGuard({ path }, deps).removed, 2);
  });
});

test("settingsPath('user') honours an absolute CLAUDE_CONFIG_DIR, and install writes there", () => {
  const dir = mkdtempSync(join(tmpdir(), "nexus-config-dir-"));
  try {
    const home = join(dir, "home");
    const config = join(dir, "claude-config");
    assert.equal(settingsPath("user", { homedir: home, env: {} }), join(home, ".claude", "settings.json"));
    assert.equal(settingsPath("user", { homedir: home, env: { CLAUDE_CONFIG_DIR: config } }), join(config, "settings.json"));
    assert.equal(settingsPath("user", { homedir: home, env: { CLAUDE_CONFIG_DIR: "relative/dir" } }), join(home, ".claude", "settings.json"), "a relative one is ignored");
    assert.equal(settingsPath("project", { cwd: join(dir, "proj"), env: { CLAUDE_CONFIG_DIR: config } }), join(dir, "proj", ".claude", "settings.json"));

    const deps = depsIn(dir, { env: { CLAUDE_CONFIG_DIR: config } });
    const r = installGuard({ scope: "user" }, deps);
    assert.equal(r.path, join(config, "settings.json"));
    assert.equal(guardStatus({ scope: "user" }, deps).installed, true);
    assert.equal(existsSync(join(home, ".claude")), false, "~/.claude is not touched");
    assert.equal(uninstallGuard({ scope: "user" }, deps).removed, 4);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("guardStatus names ~/.claude/settings.json while it keeps Nexus hooks and CLAUDE_CONFIG_DIR points elsewhere", () => {
  const dir = mkdtempSync(join(tmpdir(), "nexus-stale-config-"));
  try {
    const home = join(dir, "home");
    const other = join(dir, "other");
    const stale = join(home, ".claude", "settings.json");
    mkdirSync(other);
    const at = (env: Record<string, string>) => depsIn(dir, { env });
    // Installed while Claude Code read ~/.claude, then pointed elsewhere.
    installGuard({ scope: "user" }, at({}));
    const before = readFileSync(stale, "utf-8");
    assert.equal(guardStatus({ scope: "user" }, at({})).staleDefaultSettings, null, "no CLAUDE_CONFIG_DIR: it is the file Claude Code reads");
    const s = guardStatus({ scope: "user" }, at({ CLAUDE_CONFIG_DIR: other }));
    assert.deepEqual([s.path, s.installed, s.staleDefaultSettings], [join(other, "settings.json"), false, stale]);
    assert.equal(staleDefaultSettings({ homedir: home, env: { CLAUDE_CONFIG_DIR: other } }), stale);
    // ~/.claude itself, however it is spelled, and a relative value (which Claude Code ignores) are not elsewhere.
    for (const value of [join(home, ".claude"), join(home, ".claude") + "/", `${home}/x/../.claude`, "relative/dir"]) {
      assert.equal(staleDefaultSettings({ homedir: home, env: { CLAUDE_CONFIG_DIR: value } }), null, value);
    }
    if (POSIX) {
      symlinkSync(join(home, ".claude"), join(dir, "link"));
      assert.equal(staleDefaultSettings({ homedir: home, env: { CLAUDE_CONFIG_DIR: join(dir, "link") } }), null, "a symlink to ~/.claude");
    }
    // Only a Nexus hook counts, in any event.
    writeFileSync(stale, JSON.stringify(USER_SETTINGS));
    assert.equal(staleDefaultSettings({ homedir: home, env: { CLAUDE_CONFIG_DIR: other } }), null, "the user's own hooks");
    writeFileSync(stale, JSON.stringify({ hooks: { SessionStart: [OUR_SESSION_START()], Stop: "not a list" } }));
    assert.equal(staleDefaultSettings({ homedir: home, env: { CLAUDE_CONFIG_DIR: other } }), stale);
    writeFileSync(stale, "{ not json");
    assert.equal(guardStatus({ scope: "user" }, at({ CLAUDE_CONFIG_DIR: other })).staleDefaultSettings, null, "an unreadable file");
    rmSync(stale);
    assert.equal(staleDefaultSettings({ homedir: home, env: { CLAUDE_CONFIG_DIR: other } }), null);
    writeFileSync(stale, before);
    guardStatus({ scope: "user" }, at({ CLAUDE_CONFIG_DIR: other }));
    assert.equal(readFileSync(stale, "utf-8"), before, "read-only");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("guardStatus reports the SessionStart hook, the disabled marker, every event's hooks and disableAllHooks layers", () => {
  const MISSING = "SessionStart hook is missing (instruction-file integrity)";
  withSettings(USER_SETTINGS, (path, deps) => {
    // Hooks from before instruction-file integrity: outdated until reinstalled, unless it is off.
    installGuard({ path, integrity: false }, deps);
    const paths = integrityPaths(deps.dataDir!);
    rmSync(paths.disabled);
    let s = guardStatus({ path }, deps);
    assert.deepEqual([s.installed, s.outdated, s.integrity.sessionStartHook, s.integrity.disabled], [true, [MISSING, CONFIRM_MISSING], false, false]);
    installGuard({ path }, deps);
    s = guardStatus({ path }, deps);
    assert.deepEqual([s.outdated, s.integrity.sessionStartHook], [[], true]);
  });

  // Only the SessionStart hook: installed (every event counts), and the tool hooks are missing.
  withSettings({ hooks: { SessionStart: [OUR_SESSION_START()] } }, (path, deps) => {
    const s = guardStatus({ path }, deps);
    assert.equal(s.installed, true);
    assert.equal(s.integrity.sessionStartHook, true);
    assert.deepEqual(s.outdated, ["PostToolUse hook is missing", "PreToolUse hook is missing", CONFIRM_MISSING]);
  });
  withSettings({ hooks: { SessionStart: [OUR_SESSION_START(), { hooks: [{ type: "command", command: "nexus guard check", timeout: 15000 }] }] } }, (path, deps) => {
    const reasons = guardStatus({ path }, deps).outdated.join("\n");
    assert.match(reasons, /2 duplicate SessionStart hooks/);
    assert.match(reasons, /timeout is 15000/);
  });
  withSettings({ verbose: true }, (path, deps) => {
    const s = guardStatus({ path }, deps);
    assert.deepEqual([s.installed, s.outdated, s.integrity.sessionStartHook], [false, [], false]);
  });

  // disableAllHooks: true in any layer Claude Code reads means no Nexus hook runs.
  withSettings({ disableAllHooks: true }, (path, deps) => {
    const managed = deps.managedDir!;
    const cwd = deps.cwd!;
    const config = join(deps.homedir!, "config");
    const layer = (file: string, doc: unknown) => {
      mkdirSync(resolve(file, ".."), { recursive: true });
      writeFileSync(file, JSON.stringify(doc));
    };
    layer(join(managed, "managed-settings.json"), { disableAllHooks: true });
    layer(join(managed, "managed-settings.d", "20-b.json"), { disableAllHooks: true });
    layer(join(managed, "managed-settings.d", "10-a.json"), { disableAllHooks: false });
    layer(join(managed, "managed-settings.d", "30-c.txt"), { disableAllHooks: true });
    layer(join(config, "settings.json"), { disableAllHooks: true });
    layer(join(cwd, ".claude", "settings.json"), { disableAllHooks: "true" });
    layer(join(cwd, ".claude", "settings.local.json"), { disableAllHooks: true });
    const status = guardStatus({ path }, { ...deps, env: { CLAUDE_CONFIG_DIR: config } });
    assert.deepEqual(status.integrity.disableAllHooksIn, [
      join(managed, "managed-settings.json"),
      join(managed, "managed-settings.d", "20-b.json"),
      join(config, "settings.json"),
      join(cwd, ".claude", "settings.local.json"),
      resolve(path),
    ]);
    // The target is listed once even when it is also a layer.
    const asUser = guardStatus({ scope: "user" }, { ...deps, env: { CLAUDE_CONFIG_DIR: config } });
    assert.equal(asUser.integrity.disableAllHooksIn.filter((p) => p === join(config, "settings.json")).length, 1);
  });
});

test("install and uninstall each leave a signed nexus ledger record, so the next SessionStart is silent about them", () => {
  // Real paths: canonical store keys resolve symlinked temp dirs (macOS /var → /private/var).
  const dir = realpathSync.native(mkdtempSync(join(tmpdir(), "nexus-install-ledger-")));
  try {
    const home = join(dir, "home");
    const repo = join(dir, "repo");
    const data = join(dir, "data");
    mkdirSync(join(home, ".claude"), { recursive: true });
    mkdirSync(join(repo, ".git"), { recursive: true });
    const user = join(home, ".claude", "settings.json");
    // Written compactly: install rewrites it indented, so after uninstall it is not a
    // version seen before (an exact revert would be silent through history alone).
    writeFileSync(user, JSON.stringify(USER_SETTINGS));
    const ctxDeps = { platform: process.platform, homedir: home, env: {}, dataDir: data, managedDir: join(dir, "managed") };
    const deps = (now: string): InstallDeps => ({ ...ctxDeps, cwd: repo, now: new Date(now) });
    const paths = integrityPaths(data);

    // The machine's first SessionStart, before the install, takes the baseline.
    const T0 = "2026-10-20T09:00:00.000Z";
    assert.ok(initIntegrity(paths, new Date(T0)).ok);
    const keyRead = readIntegrityKey(paths);
    assert.equal(keyRead.state, "ok");
    const integrityKey = keyRead.state === "ok" ? keyRead.key : Buffer.alloc(0);
    const signer = signerFor(integrityKey);
    const hashers = { unit: unitHasher(integrityKey), nonce: (t: string) => signer.hmac16("nonce", t) };
    type Stores = { global: StoreInput; project: StoreInput; memory: StoreInput | null };
    const none: Stores = { global: { doc: null, tamper: null }, project: { doc: null, tamper: null }, memory: { doc: null, tamper: null } };
    const sessionStart = (now: string, stores: Stores, ledger = true): ClassifyResult => {
      const ctx = contextFromHook({ cwd: repo }, ctxDeps);
      assert.ok(ctx);
      const records = ledger ? readLedger(paths, signer, { keys: null, since: 0, now: Date.parse(now) }).records : [];
      return classify({
        stores, snapshot: enumerateWatched(ctx), ledger: records, windows: () => [], config: { agentWindowEscalation: true },
        now: new Date(now), hashers, home, platform: process.platform,
      });
    };
    const committed = (r: ClassifyResult): Stores => {
      const doc = (d: ClassifyResult["stores"]["global"]["next"]) => (d ? (JSON.parse(JSON.stringify(d)) as StoreDoc) : null);
      return {
        global: { doc: doc(r.stores.global.next), tamper: null },
        project: { doc: doc(r.stores.project.next), tamper: null },
        memory: r.stores.memory ? { doc: doc(r.stores.memory.next), tamper: null } : null,
      };
    };
    const silent = (r: ClassifyResult) =>
      renderSessionStart({ result: r, display: { root: repo, home, platform: process.platform }, nonce: hashers.nonce }).output;
    const userKey = storeKey(canonicalPath(user), process.platform);
    const itemFor = (r: ClassifyResult) => {
      const found = r.items.filter((i) => i.key === userKey);
      assert.equal(found.length, 1, JSON.stringify(r.items.map((i) => [i.path, i.tier, i.rules])));
      return found[0];
    };
    const base = committed(sessionStart(T0, none));

    // Install: one record for the settings file it changed.
    const installed = installGuard({ scope: "user" }, deps("2026-10-21T09:00:00.000Z"));
    assert.deepEqual(installed.integrity, { enabled: true, recorded: true, problem: null });
    let records = readLedger(paths, signer, { keys: null, since: 0, now: Date.parse("2026-10-22T09:00:00.000Z") }).records;
    assert.equal(records.length, 1);
    assert.deepEqual([records[0].kind, records[0].kind === "nexus" && records[0].action, records[0].path, records[0].t],
      ["nexus", "install", userKey, "2026-10-21T09:00:00.000Z"]);
    assert.deepEqual(records[0].kind === "nexus" && records[0].nexusHooks, ["PostToolUse", "PreToolUse", "SessionStart"]);
    assert.equal(records[0].added.length, 4, "four hooks added (PostToolUse: the content guard and integrity's confirmation)");
    assert.equal(records[0].removed.length, 0);
    assert.match(records[0].file, /^20261021\/\d+-nexus000-[0-9a-f]{6}\.json$/);
    // A reinstall that changes nothing records nothing.
    assert.equal(installGuard({ scope: "user" }, deps("2026-10-21T10:00:00.000Z")).integrity.recorded, false);

    // The next SessionStart attributes the new hooks to Nexus: silent, and the baseline advances.
    const T2 = "2026-10-22T09:00:00.000Z";
    const after = sessionStart(T2, base);
    const i = itemFor(after);
    assert.deepEqual([i.tier, i.rule, i.next?.acceptedBy, i.next?.nexusHooks], ["SILENT", "Z", "nexus", ["PostToolUse", "PreToolUse", "SessionStart"]]);
    assert.deepEqual(after.items.filter((x) => x.tier !== "SILENT").map((x) => x.path), []);
    assert.equal(silent(after), null);
    // Without the record, the same change is a hook nobody approved.
    assert.equal(itemFor(sessionStart(T2, base, false)).tier, "HOLD");

    // Uninstall: an uninstall record, so the removed Nexus hooks are not reported (S3) either.
    const settled = committed(after);
    const u = uninstallGuard({ scope: "user" }, deps("2026-10-23T09:00:00.000Z"));
    assert.deepEqual([u.removed, u.recorded], [4, true]);
    records = readLedger(paths, signer, { keys: null, since: 0, now: Date.parse("2026-10-24T09:00:00.000Z") }).records;
    assert.equal(records.length, 2);
    assert.deepEqual([records[1].kind === "nexus" && records[1].action, records[1].kind === "nexus" && records[1].nexusHooks, records[1].added.length, records[1].removed.length],
      ["uninstall", [], 0, 4]);
    assert.deepEqual(JSON.parse(readFileSync(user, "utf-8")), USER_SETTINGS);
    const T4 = "2026-10-24T09:00:00.000Z";
    const gone = sessionStart(T4, settled);
    const g = itemFor(gone);
    assert.deepEqual([g.tier, g.rule, g.next?.acceptedBy, g.removedNexusHooks], ["SILENT", "Z", "nexus", []]);
    assert.equal(silent(gone), null);
    const unrecorded = itemFor(sessionStart(T4, settled, false));
    assert.deepEqual([unrecorded.tier, unrecorded.rule], ["SUSPECT", "S3"]);
    assert.ok(existsSync(paths.registry), "uninstall leaves the store in place");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("turning integrity off is recorded as Nexus removing its own hook, and uninstall without a store records nothing", () => {
  withSettings(USER_SETTINGS, (path, deps) => {
    const paths = integrityPaths(deps.dataDir!);
    installGuard({ path }, deps);
    const off = installGuard({ path, integrity: false }, deps);
    assert.equal(off.integrity.recorded, true);
    const key = readIntegrityKey(paths);
    assert.equal(key.state, "ok");
    const records = readLedger(paths, signerFor(key.state === "ok" ? key.key : Buffer.alloc(0)), { keys: null, since: 0, now: Date.now() }).records;
    assert.deepEqual(records.map((r) => r.kind === "nexus" && [r.action, r.nexusHooks]), [
      ["install", ["PostToolUse", "PreToolUse", "SessionStart"]],
      ["uninstall", ["PostToolUse", "PreToolUse"]],
    ]);
  });
  withSettings(USER_SETTINGS, (path, deps) => {
    // Hooks written by hand (or an older Nexus); no integrity store under this data dir.
    const hand = read(path);
    hand.hooks.PreToolUse.push({ matcher: "Bash", hooks: [{ type: "command", command: "nexus guard check", timeout: 30 }] });
    writeFileSync(path, JSON.stringify(hand, null, 2) + "\n");
    assert.deepEqual(uninstallGuard({ path }, deps), { path, removed: 1, recorded: false });
    assert.equal(existsSync(deps.dataDir!), false, "uninstall never creates the store");
  });
});

test("an integrity key that is not trusted does not stop the install, and is reported", { skip: !POSIX }, () => {
  withSettings(USER_SETTINGS, (path, deps) => {
    const paths = integrityPaths(deps.dataDir!);
    mkdirSync(paths.dir, { recursive: true, mode: 0o700 });
    writeFileSync(paths.key, "0".repeat(64), { mode: 0o644 });
    const r = installGuard({ path }, deps);
    assert.equal(r.alreadyInstalled, false);
    assert.equal(nexusEntries(read(path).hooks.SessionStart).length, 1);
    assert.equal(r.integrity.recorded, false);
    assert.match(r.integrity.problem ?? "", /^the integrity key is group\/world-accessible/);
    assert.equal(readFileSync(paths.key, "utf-8"), "0".repeat(64), "install never replaces a key");
  });
});

test("install under a NEXUS_DATA redirect leaves the redirect TAMPER for the gated baseline (§5.6)", () => {
  withSettings(USER_SETTINGS, (path, deps) => {
    // ~/.nexus holds the user's store; the session's NEXUS_DATA points at an empty one.
    const home = deps.homedir!;
    const nexusHome = integrityPaths(join(home, ".nexus"));
    assert.ok(initIntegrity(nexusHome, new Date("2026-10-01T00:00:00.000Z")).ok);
    const homeAnchor = readFileSync(nexusHome.anchor, "utf-8");
    const redirected = join(resolve(path, ".."), "repo", ".cache", "nx");
    const env = { NEXUS_DATA: redirected };
    const over: InstallDeps = { ...deps, env, dataDir: undefined };
    const tamper = () => loadIntegrity({ dataDir: redirected, homedir: home, platform: process.platform }, ["global"]).tamper;
    assert.deepEqual(tamper(), ["redirect"]);

    // A plain install is not gated, so it must not clear what only `baseline` may.
    const r = installGuard({ path }, over);
    assert.equal(r.alreadyInstalled, false, "the hooks are still installed");
    assert.equal(nexusEntries(read(path).hooks.SessionStart).length, 1);
    assert.deepEqual(r.integrity, { enabled: true, recorded: false, problem: TAMPER_FRAGMENTS.redirect });
    assert.deepEqual(tamper(), ["redirect"]);
    assert.equal(existsSync(redirected), false, "no key, anchor or registry in the redirected store");

    const off = installGuard({ path, integrity: false }, over);
    assert.deepEqual(off.integrity, { enabled: false, recorded: false, problem: `the .disabled marker was not written: ${TAMPER_FRAGMENTS.redirect}` });
    assert.equal(nexusEntries(read(path).hooks.SessionStart).length, 0);
    assert.equal(uninstallGuard({ path }, over).recorded, false);
    assert.deepEqual(tamper(), ["redirect"]);
    assert.equal(existsSync(redirected), false);
    assert.equal(readFileSync(nexusHome.anchor, "utf-8"), homeAnchor, "~/.nexus is left as it was");

    // Once the redirected store has its own anchor (as baseline gives it), install prepares it as usual.
    assert.ok(initIntegrity(integrityPaths(redirected), new Date("2026-10-02T00:00:00.000Z")).ok);
    assert.deepEqual(installGuard({ path }, over).integrity, { enabled: true, recorded: true, problem: null });
    assert.deepEqual(tamper(), []);
  });
});

test("droppedTools names what an install's tool lists would stop guarding; keeping or widening drops nothing", () => {
  withSettings(USER_SETTINGS, (path, deps) => {
    assert.deepEqual(droppedTools({ path, tools: ["TodoWrite"] }, deps), [], "nothing is guarded yet");
    installGuard({ path }, deps);
    const before = readFileSync(path, "utf-8");
    assert.deepEqual(droppedTools({ path }, deps), [], "a plain re-install keeps the list");
    assert.deepEqual(droppedTools({ path, tools: ["WebFetch", "WebSearch", "mcp__.*", "Read"] }, deps), []);
    assert.deepEqual(droppedTools({ path, tools: ["mcp__.*", "WebSearch", "WebFetch"] }, deps), [], "order does not matter");
    assert.deepEqual(droppedTools({ path, tools: ["TodoWrite"] }, deps), ["WebFetch", "WebSearch", "mcp__.*"]);
    assert.deepEqual(droppedTools({ path, tools: ["WebFetch", "mcp__github.*"] }, deps), ["WebSearch", "mcp__.*"], "a narrower regex is a drop");
    assert.deepEqual(droppedTools({ path, commandTools: ["Bash"] }, deps), ["PowerShell"]);
    assert.deepEqual(droppedTools({ path, commandTools: ["Bash", "PowerShell", "Task"] }, deps), []);
    // a list written as the matcher it becomes keeps every tool in it
    assert.deepEqual(droppedTools({ path, tools: ["WebFetch|WebSearch|mcp__.*"] }, deps), []);
    assert.deepEqual(droppedTools({ path, tools: ["WebFetch|mcp__.*"], commandTools: ["Bash|PowerShell"] }, deps), ["WebSearch"]);
    assert.equal(readFileSync(path, "utf-8"), before, "read-only");

    // a hand-written Nexus group with no matcher runs for every tool: anything narrower drops it
    const all = read(path);
    all.hooks.PreToolUse = all.hooks.PreToolUse.map((m: any) => (nexusEntries([m]).length ? { hooks: m.hooks } : m));
    writeFileSync(path, JSON.stringify(all));
    assert.deepEqual(droppedTools({ path }, deps), ["*"]);
  });
});

test("install and guardStatus read NEXUS_DATA as every entry point does: an empty or relative value means ~/.nexus", () => {
  withSettings(USER_SETTINGS, (path, deps) => {
    const home = deps.homedir!;
    const cwd = deps.cwd!;
    mkdirSync(cwd, { recursive: true });
    for (const value of ["", "nexus-data", "./nexus-data"]) {
      const over: InstallDeps = { ...deps, env: { NEXUS_DATA: value }, dataDir: undefined };
      installGuard({ path }, over);
      assert.deepEqual(readdirSync(cwd), [], `NEXUS_DATA=${JSON.stringify(value)}: nothing in the cwd`);
      assert.ok(existsSync(join(home, ".nexus", "integrity", ".integrity-key")));
      assert.deepEqual(guardStatus({ path }, over).dataDir, { dir: join(home, ".nexus"), ignored: value === "" ? null : value });
    }
    const tilde: InstallDeps = { ...deps, env: { NEXUS_DATA: "~/.nexus" }, dataDir: undefined };
    assert.deepEqual(guardStatus({ path }, tilde).dataDir, { dir: join(home, ".nexus"), ignored: null });
  });
});

/** Settings with every Nexus hook a full install writes, each running `command`. */
function nexusSettings(command: string, drop: "SessionStart" | "PreToolUse" | "confirm" | null = null): unknown {
  const hook = () => [{ type: "command", command, timeout: 30 }];
  return {
    hooks: {
      PostToolUse: [
        { matcher: "WebFetch|WebSearch|mcp__.*", hooks: hook() },
        ...(drop === "confirm" ? [] : [{ matcher: "Write|Edit|MultiEdit", hooks: hook() }]),
      ],
      ...(drop === "PreToolUse" ? {} : { PreToolUse: [{ matcher: "Bash|PowerShell|Write|Edit|NotebookEdit|MultiEdit", hooks: hook() }] }),
      ...(drop === "SessionStart" ? {} : { SessionStart: [{ hooks: hook() }] }),
    },
  };
}

test("checkNexusHooks: integrity's hooks are live only when all three are present and the script they name exists, in any layer", () => {
  const dir = realpathSync.native(mkdtempSync(join(tmpdir(), "nexus-hook-check-")));
  try {
    const script = join(dir, "pkg", "dist", "guard", "hook.js");
    mkdirSync(resolve(script, ".."), { recursive: true });
    writeFileSync(script, "");
    const live = `node ${JSON.stringify(script)}`;
    const gone = `node ${JSON.stringify(join(dir, "old", "dist", "guard", "hook.js"))}`;
    const project = join(dir, "project");
    const l: HookLayers = {
      user: join(dir, "config", "settings.json"), projectDirs: [project], managedDir: join(dir, "managed"), homedir: join(dir, "home"), platform: process.platform,
    };
    const put = (file: string, doc: unknown) => {
      mkdirSync(resolve(file, ".."), { recursive: true });
      writeFileSync(file, JSON.stringify(doc));
    };
    const clear = () => {
      for (const d of ["config", "project", "managed"]) rmSync(join(dir, d), { recursive: true, force: true });
    };
    const layers = {
      user: l.user,
      project: join(project, ".claude", "settings.json"),
      local: join(project, ".claude", "settings.local.json"),
      managed: join(l.managedDir, "managed-settings.json"),
    } as const;

    const none = checkNexusHooks(l);
    assert.deepEqual([none.live, none.sessionStart, none.scope, none.layers], [false, false, null, []]);
    assert.equal(none.problems.length, 3);

    for (const [scope, file] of Object.entries(layers)) {
      clear();
      put(file, nexusSettings(live));
      const c = checkNexusHooks(l);
      assert.deepEqual([c.live, c.sessionStart, c.scope, c.path, c.problems], [true, true, scope, file, []], scope);
    }
    // a managed drop-in counts as the managed layer
    clear();
    put(join(l.managedDir, "managed-settings.d", "50-nexus.json"), nexusSettings(live));
    assert.deepEqual([checkNexusHooks(l).live, checkNexusHooks(l).scope], [true, "managed"]);

    // the script is gone (an nvm switch, a moved global prefix): one problem for the hooks that run it
    clear();
    put(layers.user, nexusSettings(gone));
    let c = checkNexusHooks(l);
    assert.deepEqual([c.live, c.sessionStart, c.scope], [false, true, "user"]);
    assert.deepEqual(c.problems, [`SessionStart, PreToolUse and PostToolUse Write|Edit|MultiEdit hooks run a hook entry that no longer exists: ${join(dir, "old", "dist", "guard", "hook.js")}`]);
    // ... unless a live copy runs in another layer (Claude Code merges them)
    put(layers.project, nexusSettings(live));
    c = checkNexusHooks(l);
    assert.deepEqual([c.live, c.scope, c.layers.map((x) => x.scope)], [true, "project", ["user", "project"]]);

    // a group missing
    for (const drop of ["SessionStart", "PreToolUse", "confirm"] as const) {
      clear();
      put(layers.user, nexusSettings(live, drop));
      c = checkNexusHooks(l);
      assert.equal(c.live, false, drop);
      assert.equal(c.scope, "user", drop);
      assert.equal(c.problems.length, 1, drop);
      assert.match(c.problems[0], drop === "confirm" ? /^PostToolUse Write\|Edit\|MultiEdit hook is missing/ : new RegExp(`^${drop} hook is missing`));
    }

    // a command that names no script (`nexus guard check`) is taken to run; a single-quoted path is read without its quotes
    clear();
    put(layers.user, nexusSettings("nexus guard check"));
    assert.equal(checkNexusHooks(l).live, true);
    put(layers.user, nexusSettings(`node '${script}'`));
    assert.equal(checkNexusHooks(l).live, true, "node '<path>', as guardCommand writes a path holding $");

    // disableAllHooks is reported per layer; the user's own hooks are not ours. The hooks get the NEXUS_DATA of the layer
    // that wins (managed over local over project over user), so a relative value a higher layer overrides is not reported
    clear();
    put(layers.user, { ...(nexusSettings(live) as object), env: { NEXUS_DATA: "nexus-data" } });
    put(layers.local, { disableAllHooks: true, env: { NEXUS_DATA: "~/.nexus-work" }, hooks: USER_SETTINGS.hooks });
    // a byte-order mark, as some editors save settings, and an empty NEXUS_DATA (unset, not ignored)
    writeFileSync(layers.project, `\ufeff${JSON.stringify({ ...(nexusSettings(live) as object), env: { NEXUS_DATA: "" } })}`);
    c = checkNexusHooks(l);
    assert.deepEqual(c.disableAllHooksIn, [layers.local]);
    assert.deepEqual(c.ignoredDataDir, [], "local's ~/.nexus-work reaches the hooks");
    assert.deepEqual(c.layers, [{ scope: "user", path: layers.user }, { scope: "project", path: layers.project }]);
    assert.equal(c.live, true, "disableAllHooks is reported apart");
    put(layers.local, { env: { EDITOR: "vi" } });
    assert.deepEqual(checkNexusHooks(l).ignoredDataDir, [], "project's \"\" overrides the user's value: unset, ~/.nexus");
    put(layers.project, nexusSettings(live));
    assert.deepEqual(checkNexusHooks(l).ignoredDataDir, [{ scope: "user", path: layers.user, value: "nexus-data" }], "only the user's is set");
    put(layers.managed, { env: { NEXUS_DATA: "policy-data" } });
    put(layers.local, { env: { NEXUS_DATA: "/srv/nexus" } });
    assert.deepEqual(checkNexusHooks(l).ignoredDataDir, [{ scope: "managed", path: layers.managed, value: "policy-data" }], "managed wins over local");
    // within the managed layer a drop-in wins over the base file, a later one over an earlier one
    put(join(l.managedDir, "managed-settings.d", "10-a.json"), { env: { NEXUS_DATA: "drop-a" } });
    put(join(l.managedDir, "managed-settings.d", "20-b.json"), { env: { NEXUS_DATA: "/srv/nexus-b" } });
    assert.deepEqual(checkNexusHooks(l).ignoredDataDir, []);
    put(join(l.managedDir, "managed-settings.d", "20-b.json"), { env: { NEXUS_DATA: "drop-b" } });
    assert.deepEqual(checkNexusHooks(l).ignoredDataDir.map((x) => x.value), ["drop-b"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("guardStatus judges integrity's hooks across the layers for its cwd, a --project install included", () => {
  withSettings(undefined, (path, deps) => {
    const cwd = deps.cwd!;
    mkdirSync(join(cwd, ".git"), { recursive: true });
    const sub = join(cwd, "src");
    mkdirSync(sub);
    installGuard({ scope: "project" }, deps);
    for (const at of [cwd, sub]) {
      const s = guardStatus({ scope: "user" }, { ...deps, cwd: at });
      assert.equal(s.installed, false, "the user settings hold no Nexus hook");
      assert.deepEqual([s.integrity.hooks.live, s.integrity.hooks.scope], [true, "project"], at);
      assert.deepEqual(s.integrity.hooks.layers.map((l) => l.scope), ["project"]);
    }
    const project = guardStatus({ scope: "project" }, deps);
    assert.deepEqual([project.installed, project.integrity.hooks.live, project.integrity.hooks.scope], [true, true, "project"]);
  });
});
