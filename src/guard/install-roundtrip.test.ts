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
    assert.deepEqual(s.contentTools, ["WebFetch", "WebSearch"]);
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
  ];
  for (const command of ours) assert.equal(isNexusGuardCommand(command), true, command);

  const notOurs = [
    "echo hi",
    "nexus guard install",
    "nexus guard check --verbose",
    "other-tool guard check",
    'node "/x/dist/server.js" guard check',
    "npx nexus guard check", // the unrelated unscoped "nexus" npm package
    "",
    undefined,
    42,
  ];
  for (const command of notOurs) assert.equal(isNexusGuardCommand(command), false, String(command));
});

test("the command the built CLI installs is recognised as ours (v0.6.0–0.7.4 regression)", async (t) => {
  // Under tsx there is no dist/cli/index.js next to src/, so guardCommand() falls
  // back to `nexus guard check`; the built module returns the absolute
  // `node "<pkg>/dist/cli/index.js" guard check` an installed package writes.
  const built = resolve("dist/guard/install.js");
  if (!existsSync(built)) {
    t.skip("dist/ not built — run `npm run build` first");
    return;
  }
  const dist = await import(pathToFileURL(built).href);
  const command: string = dist.guardCommand(); // pure: resolves a path, writes nothing
  assert.match(command, /^node ".*dist[\\/]+cli[\\/]+index\.js" guard check$/);
  assert.equal(isNexusGuardCommand(command), true);
  assert.equal(isNexusGuardCommand(guardCommand()), true);
});
