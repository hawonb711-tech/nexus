/**
 * Default content-guard coverage = web + ALL MCP tools. A plain `nexus guard
 * install` guards WebFetch, WebSearch AND every MCP tool (`mcp__.*`), the
 * documented re-install upgrades a stock web-only install forward to gain MCP
 * coverage, and a user's explicit custom `--tools` list is never clobbered.
 *
 * Every test targets an explicit settings file in a temp dir, except the one that
 * exercises the user-scope path, which points HOME at a throwaway dir — never the
 * real ~/.claude.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  installGuard, guardStatus, guardCommand, isNexusGuardCommand, settingsPath,
  DEFAULT_GUARDED_TOOLS, OLD_STOCK_GUARDED_TOOLS, DEFAULT_HOOK_TIMEOUT,
} from "./install.js";

function withTempDir(run: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "nexus-mcp-"));
  try {
    run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const read = (path: string): any => JSON.parse(readFileSync(path, "utf-8"));
const postMatcher = (path: string): string | undefined =>
  read(path).hooks.PostToolUse.find((m: any) => (m.hooks ?? []).some((h: any) => isNexusGuardCommand(h.command)))?.matcher;

test("the default guarded set is web + all MCP tools", () => {
  assert.deepEqual(DEFAULT_GUARDED_TOOLS, ["WebFetch", "WebSearch", "mcp__.*"]);
  assert.deepEqual(OLD_STOCK_GUARDED_TOOLS, ["WebFetch", "WebSearch"]);
});

test("a fresh install writes the matcher WebFetch|WebSearch|mcp__.* (explicit path)", () => {
  withTempDir((dir) => {
    const path = join(dir, "settings.json");
    const r = installGuard({ path });
    assert.equal(r.created, true);
    assert.deepEqual(r.contentTools, ["WebFetch", "WebSearch", "mcp__.*"]);
    assert.equal(postMatcher(path), "WebFetch|WebSearch|mcp__.*");
    assert.deepEqual(guardStatus({ path }).contentTools, ["WebFetch", "WebSearch", "mcp__.*"]);
  });
});

test("a fresh user-scope install under a temp HOME writes WebFetch|WebSearch|mcp__.*", () => {
  withTempDir((home) => {
    const savedHome = process.env.HOME;
    const savedProfile = process.env.USERPROFILE;
    process.env.HOME = home;
    process.env.USERPROFILE = home; // Windows
    try {
      const path = settingsPath("user");
      assert.ok(path.startsWith(home), "the user settings path resolves under the temp HOME");
      const r = installGuard({ scope: "user" });
      assert.equal(r.path, path);
      assert.equal(postMatcher(path), "WebFetch|WebSearch|mcp__.*");
      assert.deepEqual(guardStatus({ scope: "user" }).contentTools, ["WebFetch", "WebSearch", "mcp__.*"]);
    } finally {
      if (savedHome === undefined) delete process.env.HOME; else process.env.HOME = savedHome;
      if (savedProfile === undefined) delete process.env.USERPROFILE; else process.env.USERPROFILE = savedProfile;
    }
  });
});

test("a stock web-only install (Nexus <= 0.7.4) is UPGRADED to include mcp__.* on a plain re-install", () => {
  withTempDir((dir) => {
    const path = join(dir, "settings.json");
    // Simulate a <= 0.7.4 install: the PostToolUse hook guards exactly the old
    // stock default. (An explicit --tools install reproduces that stored state.)
    installGuard({ path, tools: [...OLD_STOCK_GUARDED_TOOLS] });
    assert.equal(postMatcher(path), "WebFetch|WebSearch");
    assert.deepEqual(guardStatus({ path }).contentTools, ["WebFetch", "WebSearch"]);

    // The documented upgrade step is a bare `guard install`: a user who never set
    // --tools gets the wider default (MCP coverage added).
    const up = installGuard({ path });
    assert.equal(up.alreadyInstalled, false, "the stock default moves forward, so the file changes");
    assert.deepEqual(up.contentTools, ["WebFetch", "WebSearch", "mcp__.*"]);
    assert.equal(postMatcher(path), "WebFetch|WebSearch|mcp__.*");

    // Idempotent afterward: a second plain re-install changes nothing.
    const again = installGuard({ path });
    assert.equal(again.alreadyInstalled, true);
    assert.equal(postMatcher(path), "WebFetch|WebSearch|mcp__.*");
  });
});

test("a custom --tools list is preserved verbatim on a plain re-install (never clobbered or widened)", () => {
  withTempDir((dir) => {
    const path = join(dir, "settings.json");
    // A user who scoped coverage to one MCP server.
    installGuard({ path, tools: ["WebFetch", "mcp__github__.*"] });
    assert.equal(postMatcher(path), "WebFetch|mcp__github__.*");

    const r = installGuard({ path });
    assert.equal(r.alreadyInstalled, true, "a custom set is left exactly as it was");
    assert.deepEqual(r.contentTools, ["WebFetch", "mcp__github__.*"]);
    assert.equal(postMatcher(path), "WebFetch|mcp__github__.*");
  });
});

test("an install already on the new default does not re-migrate (no loop)", () => {
  withTempDir((dir) => {
    const path = join(dir, "settings.json");
    installGuard({ path, tools: [...DEFAULT_GUARDED_TOOLS] });
    const r = installGuard({ path });
    assert.equal(r.alreadyInstalled, true);
    assert.equal(postMatcher(path), "WebFetch|WebSearch|mcp__.*");
  });
});

test("a user who dropped WebSearch keeps their narrowed list (differs from the stock default)", () => {
  withTempDir((dir) => {
    const path = join(dir, "settings.json");
    installGuard({ path, tools: ["WebFetch"] });
    const r = installGuard({ path });
    assert.equal(r.alreadyInstalled, true);
    assert.deepEqual(r.contentTools, ["WebFetch"]);
  });
});

test("explicit --tools always wins, even over the migration of the stock default", () => {
  withTempDir((dir) => {
    const path = join(dir, "settings.json");
    installGuard({ path }); // fresh → new default
    // Passing an explicit list narrows to exactly it (opts.tools short-circuits
    // the keep/upgrade logic).
    const r = installGuard({ path, tools: ["WebFetch", "WebSearch"] });
    assert.deepEqual(r.contentTools, ["WebFetch", "WebSearch"]);
    assert.equal(postMatcher(path), "WebFetch|WebSearch");
    const after = read(path);
    const ours = after.hooks.PostToolUse.filter((m: any) => (m.hooks ?? []).some((h: any) => isNexusGuardCommand(h.command)));
    assert.equal(ours.length, 1, "no duplicate Nexus PostToolUse entry");
    assert.deepEqual(ours[0].hooks, [{ type: "command", command: guardCommand(), timeout: DEFAULT_HOOK_TIMEOUT }]);
  });
});

test("a stock web-only install in the old full-CLI form gains mcp__.* AND the hook entry on a plain re-install (built)", async (t) => {
  // Under tsx guardCommand() falls back to `nexus guard check`; the built module
  // writes the dedicated `node "<pkg>/dist/guard/hook.js"` entry, as an installed package does.
  const built = resolve("dist/guard/install.js");
  if (!existsSync(built) || !existsSync(resolve("dist/guard/hook.js"))) {
    t.skip("dist/ not built — run `npm run build` first");
    return;
  }
  const dist = (await import(pathToFileURL(built).href)) as typeof import("./install.js");
  const oldCli = `node ${JSON.stringify(resolve("dist/cli/index.js"))} guard check`;
  withTempDir((dir) => {
    const path = join(dir, "settings.json");
    // Exactly what Nexus <= 0.7.4 wrote from an installed package (ms timeout included).
    writeFileSync(path, JSON.stringify({
      hooks: {
        PostToolUse: [{ matcher: "WebFetch|WebSearch", hooks: [{ type: "command", command: oldCli, timeout: 15000 }] }],
        PreToolUse: [{ matcher: "Bash|PowerShell|Write|Edit|NotebookEdit", hooks: [{ type: "command", command: oldCli, timeout: 15000 }] }],
      },
    }, null, 2));
    const status = dist.guardStatus({ path });
    assert.deepEqual(status.contentTools, ["WebFetch", "WebSearch"]);
    assert.match(status.outdated.join("\n"), /hook runs the full CLI/);

    const r = dist.installGuard({ path });
    assert.deepEqual(r.contentTools, ["WebFetch", "WebSearch", "mcp__.*"]);
    assert.equal(r.replaced, 2);
    assert.equal(postMatcher(path), "WebFetch|WebSearch|mcp__.*");
    for (const event of ["PostToolUse", "PreToolUse"]) {
      const ours = read(path).hooks[event].filter((m: any) => (m.hooks ?? []).some((h: any) => isNexusGuardCommand(h.command)));
      assert.equal(ours.length, 1, `one Nexus ${event} entry`);
      assert.deepEqual(ours[0].hooks, [{ type: "command", command: dist.guardCommand(), timeout: DEFAULT_HOOK_TIMEOUT }]);
    }
    assert.deepEqual(dist.guardStatus({ path }).outdated, []);
    assert.equal(dist.installGuard({ path }).alreadyInstalled, true, "idempotent afterward");
  });
});
