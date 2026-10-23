import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  installGuard, uninstallGuard, guardStatus, guardCommand, isNexusGuardCommand,
  DEFAULT_HOOK_TIMEOUT, DEFAULT_FILE_TOOLS,
} from "./install.js";

// Every test targets an explicit settings file in a temp dir — never ~/.claude.
function withSettings(initial: unknown, run: (path: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "nexus-install-"));
  const path = join(dir, "settings.json");
  if (initial !== undefined) writeFileSync(path, JSON.stringify(initial, null, 2) + "\n");
  try {
    run(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const read = (path: string): any => JSON.parse(readFileSync(path, "utf-8"));
const nexusEntries = (list: any[] = []) =>
  list.filter((m) => (m.hooks ?? []).some((h: any) => isNexusGuardCommand(h.command)));

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
  withSettings(USER_SETTINGS, (path) => {
    const r = installGuard({ path });
    assert.equal(r.alreadyInstalled, false);
    assert.equal(r.replaced, 0);

    const s = guardStatus({ path });
    assert.equal(s.installed, true);
    assert.deepEqual(s.outdated, [], "a fresh install is current");
    // Default content-guard coverage is web + ALL MCP tools (`mcp__.*` is a Claude
    // Code matcher regex matched against tool_name, so it guards every MCP tool).
    assert.deepEqual(s.contentTools, ["WebFetch", "WebSearch", "mcp__.*"]);
    assert.deepEqual(s.commandTools, ["Bash", "PowerShell", ...DEFAULT_FILE_TOOLS]);
    assert.ok(s.commandTools.includes("MultiEdit"), "MultiEdit writes are guarded");

    let after = read(path);
    for (const event of ["PostToolUse", "PreToolUse"]) {
      const ours = nexusEntries(after.hooks[event]);
      assert.equal(ours.length, 1, `one Nexus ${event} entry`);
      assert.deepEqual(ours[0].hooks, [{ type: "command", command: guardCommand(), timeout: DEFAULT_HOOK_TIMEOUT }]);
    }
    assert.equal(DEFAULT_HOOK_TIMEOUT, 30, "Claude Code reads hook timeouts in seconds");

    // Same install again: nothing to change, file left byte-for-byte.
    const before = readFileSync(path, "utf-8");
    const r2 = installGuard({ path });
    assert.equal(r2.alreadyInstalled, true);
    assert.equal(readFileSync(path, "utf-8"), before);

    // Widening --tools replaces our entries instead of appending duplicates.
    const r3 = installGuard({ path, tools: ["WebFetch", "WebSearch", "Read"], timeout: 45 });
    assert.equal(r3.alreadyInstalled, false);
    assert.equal(r3.replaced, 2);
    after = read(path);
    const post = nexusEntries(after.hooks.PostToolUse);
    const pre = nexusEntries(after.hooks.PreToolUse);
    assert.equal(post.length, 1);
    assert.equal(pre.length, 1);
    assert.equal(post[0].matcher, "WebFetch|WebSearch|Read");
    assert.equal(post[0].hooks[0].timeout, 45);
    assert.equal(pre[0].hooks[0].timeout, 45);
    assert.deepEqual(guardStatus({ path }).contentTools, ["WebFetch", "WebSearch", "Read"]);

    const u = uninstallGuard({ path });
    assert.equal(u.removed, 2);
    assert.equal(guardStatus({ path }).installed, false);
    assert.deepEqual(read(path), USER_SETTINGS, "unrelated hooks and settings are exactly as they were");

    // Nothing of ours left: a second uninstall doesn't touch the file.
    const final = readFileSync(path, "utf-8");
    assert.equal(uninstallGuard({ path }).removed, 0);
    assert.equal(readFileSync(path, "utf-8"), final);
  });
});

test("install into a missing settings file creates it; uninstall leaves no empty hook lists", () => {
  withSettings(undefined, (path) => {
    const r = installGuard({ path });
    assert.equal(r.created, true);
    assert.ok(existsSync(path));
    assert.equal(uninstallGuard({ path }).removed, 2);
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
  }, (path) => {
    const before = readFileSync(path, "utf-8");
    const s = guardStatus({ path });
    assert.equal(s.installed, true, "legacy entries are recognised as installed");
    assert.deepEqual(s.contentTools, ["WebFetch", "WebSearch", "Read"]);
    const reasons = s.outdated.join("\n");
    assert.match(reasons, /timeout is 15000/);
    assert.match(reasons, /no longer exists: \/x\/dist\/cli\/index\.js/);
    assert.match(reasons, /2 duplicate PostToolUse hooks/);
    assert.match(reasons, /does not cover MultiEdit/);
    assert.equal(readFileSync(path, "utf-8"), before, "status never writes");

    const r = installGuard({ path });
    assert.equal(r.replaced, 3);
    const after = read(path);
    assert.equal(after.model, "opus");
    assert.deepEqual(after.hooks.PostToolUse[0], { matcher: "Edit", hooks: [{ type: "command", command: "echo hi" }] });
    const post = nexusEntries(after.hooks.PostToolUse);
    const pre = nexusEntries(after.hooks.PreToolUse);
    assert.equal(post.length, 1);
    assert.equal(pre.length, 1);
    for (const entry of [...post, ...pre]) {
      assert.deepEqual(entry.hooks, [{ type: "command", command: guardCommand(), timeout: DEFAULT_HOOK_TIMEOUT }]);
    }
    assert.ok(pre[0].matcher.split("|").includes("MultiEdit"));
    assert.deepEqual(guardStatus({ path }).outdated, []);
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
  }, (path) => {
    assert.equal(uninstallGuard({ path }).removed, 1);
    assert.deepEqual(read(path).hooks.PreToolUse, [{ matcher: "Bash", hooks: [{ type: "command", command: "my-audit-log" }] }]);
  });
});

test("refuses to rewrite settings it cannot safely merge", () => {
  withSettings({ hooks: { PreToolUse: { matcher: "Bash" } } }, (path) => {
    const before = readFileSync(path, "utf-8");
    assert.throws(() => installGuard({ path }), /not an array/);
    assert.throws(() => uninstallGuard({ path }), /not an array/);
    assert.match(guardStatus({ path }).error ?? "", /not an array/);
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

test("a plain re-install keeps a custom --tools list instead of narrowing to defaults", () => {
  withSettings(USER_SETTINGS, (path) => {
    installGuard({ path, tools: ["WebFetch", "WebSearch", "mcp__.*"] });
    assert.deepEqual(guardStatus({ path }).contentTools, ["WebFetch", "WebSearch", "mcp__.*"]);

    // The documented upgrade step is a bare `guard install`; it must not drop
    // the MCP matcher the user set earlier.
    const r = installGuard({ path });
    assert.equal(r.alreadyInstalled, true, "nothing changed, so no rewrite");
    assert.equal(r.replaced, 0, "a no-op install replaced nothing");
    assert.deepEqual(guardStatus({ path }).contentTools, ["WebFetch", "WebSearch", "mcp__.*"]);
  });
});

test("hooks that is not an object is refused rather than silently mis-installing", () => {
  withSettings({ hooks: [] }, (path) => {
    assert.throws(() => installGuard({ path }), /hooks is not an object/);
  });
  withSettings({ hooks: "oops" }, (path) => {
    assert.throws(() => installGuard({ path }), /hooks is not an object/);
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
  return import(pathToFileURL(built).href) as Promise<InstallModule>;
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
  withSettings(USER_SETTINGS, (path) => {
    assert.equal(dist.installGuard({ path }).alreadyInstalled, false);
    const after = read(path);
    for (const event of ["PostToolUse", "PreToolUse"]) {
      const ours = nexusEntries(after.hooks[event]);
      assert.equal(ours.length, 1, `one Nexus ${event} entry`);
      assert.deepEqual(ours[0].hooks, [{ type: "command", command: dist.guardCommand(), timeout: DEFAULT_HOOK_TIMEOUT }]);
    }
    assert.deepEqual(dist.guardStatus({ path }).outdated, [], "a fresh hook-entry install is current");

    const before = readFileSync(path, "utf-8");
    assert.equal(dist.installGuard({ path }).alreadyInstalled, true);
    assert.equal(readFileSync(path, "utf-8"), before, "a no-op reinstall leaves the file byte-for-byte");

    assert.equal(dist.uninstallGuard({ path }).removed, 2);
    assert.deepEqual(read(path), USER_SETTINGS);
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
  }, (path) => {
    const before = readFileSync(path, "utf-8");
    const s = dist.guardStatus({ path });
    assert.equal(s.installed, true);
    assert.equal(s.outdated.length, 2, s.outdated.join("\n"));
    for (const [reason, old] of [[s.outdated[0], OLD_CLI_FORM], [s.outdated[1], "nexus guard check"]]) {
      assert.ok(reason.includes(`hook runs the full CLI (\`${old}\`)`), reason);
      assert.ok(reason.includes(`dedicated hook entry (\`${dist.guardCommand()}\`)`), reason);
    }
    assert.equal(readFileSync(path, "utf-8"), before, "status never writes");

    const r = dist.installGuard({ path });
    assert.equal(r.alreadyInstalled, false);
    assert.equal(r.replaced, 2);
    const after = read(path);
    const ours = { type: "command", command: dist.guardCommand(), timeout: DEFAULT_HOOK_TIMEOUT };
    // Replaced where the old entries sat; the user's hooks keep their places.
    assert.deepEqual(after.hooks.PostToolUse, [userPost, { matcher: "WebFetch|WebSearch|mcp__.*", hooks: [ours] }]);
    assert.deepEqual(after.hooks.PreToolUse, [{ matcher: "Bash|PowerShell|Write|Edit|NotebookEdit|MultiEdit", hooks: [ours] }, userPre]);
    assert.equal(after.model, "opus");
    assert.deepEqual(dist.guardStatus({ path }).outdated, []);
    assert.equal(dist.installGuard({ path }).alreadyInstalled, true, "the migration does not repeat");
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
  }, (path) => {
    assert.match(dist.guardStatus({ path }).outdated.join("\n"), /2 duplicate PostToolUse hooks/);
    assert.equal(dist.uninstallGuard({ path }).removed, 4);
    assert.deepEqual(read(path), { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "my-audit-log" }] }] } });
  });
});
