import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import {
  canonicalPath, classOf, isUnder, labelOf, memoryStoreId, projectStoreId, storeKey, watchedRoleOf, type PrefixLists, type RoleContext,
} from "./paths.js";
import { WATCHED_ROLES } from "./types.js";

const NO_PREFIXES: PrefixLists = { memoryDirs: [], configDirs: [], importTargets: [], hookScripts: [] };

describe("store keys and canonical paths", () => {
  let dir: string;
  beforeEach(() => { dir = realpathSync(mkdtempSync(join(tmpdir(), "nexus-paths-"))); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("store keys use forward slashes and are lower-cased on win32 only", () => {
    assert.equal(storeKey("C:\\Users\\Me\\Proj\\CLAUDE.md", "win32"), "c:/users/me/proj/claude.md");
    assert.equal(storeKey("/home/Me/CLAUDE.md", "linux"), "/home/Me/CLAUDE.md");
    assert.equal(storeKey("/Users/Me/CLAUDE.md", "darwin"), "/Users/Me/CLAUDE.md");
  });

  it("store ids hash the root's key", () => {
    assert.match(projectStoreId("/home/u/app", "linux"), /^project-[0-9a-f]{16}$/);
    assert.equal(projectStoreId("C:\\App", "win32"), projectStoreId("c:/app", "win32"));
    assert.notEqual(projectStoreId("/a", "linux"), projectStoreId("/b", "linux"));
    assert.match(memoryStoreId("/home/u/.claude/projects/-a/memory", "linux"), /^memory-[0-9a-f]{16}$/);
  });

  it("isUnder compares whole components", () => {
    assert.equal(isUnder("/home/u/app/x", "/home/u/app", "linux"), true);
    assert.equal(isUnder("/home/u/app", "/home/u/app", "linux"), true);
    assert.equal(isUnder("/home/u/application", "/home/u/app", "linux"), false);
    assert.equal(isUnder("/anything", "/", "linux"), true);
    assert.equal(isUnder("C:\\Users\\ME\\x", "c:/users/me", "win32"), true);
    assert.equal(isUnder("/home/U/app/x", "/home/u/app", "linux"), false);
  });

  it("canonical paths resolve the directory but keep the file's own name", () => {
    mkdirSync(join(dir, "real"));
    writeFileSync(join(dir, "real", "AGENTS.md"), "x");
    assert.equal(canonicalPath(join(dir, "real", "..", "real", "AGENTS.md")), join(dir, "real", "AGENTS.md"));
    assert.equal(canonicalPath(join(dir, "real", "missing.md")), join(dir, "real", "missing.md"));
    assert.equal(canonicalPath(join(dir, "no", "such", "dir", "x.md")), join(dir, "no", "such", "dir", "x.md"));
    try {
      symlinkSync(join(dir, "real"), join(dir, "alias"));
      symlinkSync(join(dir, "real", "AGENTS.md"), join(dir, "real", "CLAUDE.md"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    assert.equal(canonicalPath(join(dir, "alias", "AGENTS.md")), join(dir, "real", "AGENTS.md"));
    assert.equal(canonicalPath(join(dir, "alias", "CLAUDE.md")), join(dir, "real", "CLAUDE.md"), "a symlinked file keeps its own entry");
  });

  it("a missing directory resolves from its deepest existing ancestor, through links, at any depth", () => {
    // what canonicalPath computed one failed realpath per missing level: the reference
    const reference = (p: string): string => {
      const parent = dirname(p);
      if (parent === p) return p;
      let real: string | null = null;
      try { real = realpathSync.native(parent); } catch { /* missing */ }
      return join(real ?? reference(parent), basename(p));
    };
    mkdirSync(join(dir, "real", "sub"), { recursive: true });
    writeFileSync(join(dir, "real", "file.txt"), "x");
    const deep = join(dir, ..."a/".repeat(240).split("/").filter(Boolean), "x.md");
    const cases = [
      deep,
      join(dir, "real", "sub", "no", "such", "x.md"),
      join(dir, "real", "file.txt", "under", "a-file.md"),
    ];
    let links = true;
    try {
      symlinkSync(join(dir, "real"), join(dir, "alias"));
      symlinkSync(join(dir, "nowhere"), join(dir, "real", "dangling"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EPERM") throw error;
      links = false;
    }
    if (links) {
      cases.push(join(dir, "alias", "sub", "missing", "x.md"), join(dir, "real", "dangling", "missing", "x.md"));
      assert.equal(canonicalPath(join(dir, "alias", "sub", "missing", "x.md")), join(dir, "real", "sub", "missing", "x.md"));
    }
    for (const p of cases) assert.equal(canonicalPath(p), reference(p), p);
    assert.equal(canonicalPath(deep), deep);
  });
});

describe("watchedRoleOf", () => {
  const ctx: RoleContext = {
    platform: "linux",
    configDir: "/home/u/.claude",
    managedDir: "/etc/claude-code",
    root: "/home/u/app",
    autoMemoryDir: "/home/u/.claude/projects/-home-u-app/memory",
    appState: ["/home/u/.claude.json"],
  };
  const role = (p: string, c: RoleContext = ctx, prefixes: PrefixLists | null | (() => PrefixLists | null) = null) => watchedRoleOf(p, c, prefixes);

  it("recognises every static pattern, with user roles under U", () => {
    const cases: [string, string | null][] = [
      ["/home/u/app/CLAUDE.md", "ancestor-claude-md"],
      ["/home/u/app/src/api/CLAUDE.md", "ancestor-claude-md"],
      ["/home/u/app/.claude/CLAUDE.md", "ancestor-claude-md"],
      ["/home/u/CLAUDE.local.md", "ancestor-local-md"],
      ["/home/u/app/AGENTS.md", "ancestor-agents-md"],
      ["/home/u/app/.claude/settings.json", "project-settings"],
      ["/home/u/app/.claude/settings.local.json", "local-settings"],
      ["/home/u/app/.mcp.json", "project-mcp"],
      ["/srv/other/.claude.json", "claude-json"],
      ["/home/u/app/.claude/hooks/pre.sh", "hook-script"],
      ["/home/u/app/.claude/rules/style/ts.md", "project-rules"],
      ["/home/u/app/.claude/agents/reviewer.md", "project-agent"],
      ["/home/u/app/.claude/commands/ship.md", "project-command"],
      ["/home/u/app/.claude/skills/pdf/SKILL.md", "project-skill"],
      ["/home/u/app/.claude/skills/pdf/scripts/run.py", "project-skill-file"],
      ["/home/u/app/.claude/agent-memory/reviewer/MEMORY.md", "project-agent-memory"],
      ["/home/u/app/.claude/agent-memory-local/reviewer/notes.md", "project-agent-memory"],
      ["/opt/x/.claude/projects/-opt-x/memory/MEMORY.md", "auto-memory-index"],
      ["/opt/x/.claude/projects/-opt-x/memory/topic.md", "auto-memory-topic"],
      ["/opt/x/.claude/projects/-opt-x/memory/data.json", null],
      ["/srv/policy/managed-settings.json", "managed-settings"],
      ["/srv/policy/managed-settings.d/10-x.json", "managed-settings"],
      ["/srv/policy/managed-mcp.json", "managed-mcp"],
      ["/home/u/.claude/CLAUDE.md", "user-claude-md"],
      ["/home/u/.claude/settings.json", "user-settings"],
      ["/home/u/.claude/rules/a.md", "user-rules"],
      ["/home/u/.claude/agents/a.md", "user-agent"],
      ["/home/u/.claude/commands/a/b.md", "user-command"],
      ["/home/u/.claude/skills/s/SKILL.md", "user-skill"],
      ["/home/u/.claude/skills/s/x.sh", "user-skill-file"],
      ["/home/u/.claude/agent-memory/r/MEMORY.md", "user-agent-memory"],
      ["/home/u/.claude/hooks/notify.sh", "hook-script"],
      ["/home/u/.claude.json", "claude-json"],
      ["/etc/claude-code/CLAUDE.md", "managed-claude-md"],
      ["/etc/claude-code/managed-settings.d/a.json", "managed-settings"],
      ["/home/u/.claude/projects/-home-u-app/memory/MEMORY.md", "auto-memory-index"],
      ["/home/u/.claude/projects/-home-u-app/memory/prefs.md", "auto-memory-topic"],
      ["/home/u/app/src/index.ts", null],
      ["/home/u/app/README.md", null],
      ["/home/u/app/.claude/launch.json", null],
      ["/home/u/app/docs/CLAUDE.md.bak", null],
    ];
    for (const [path, expected] of cases) assert.equal(role(path), expected, path);
  });

  it("matches Windows paths, backslashes and case", () => {
    const win: RoleContext = { platform: "win32", configDir: "C:\\Users\\Me\\.claude", root: "C:\\Users\\Me\\proj" };
    assert.equal(role("C:\\Users\\me\\proj\\CLAUDE.md", win), "ancestor-claude-md");
    assert.equal(role("C:\\Users\\me\\proj\\.claude\\settings.local.json", win), "local-settings");
    assert.equal(role("c:\\users\\me\\.claude\\settings.json", win), "user-settings");
    assert.equal(role("C:\\Users\\me\\proj\\.Claude\\Rules\\x.md", win), "project-rules");
    assert.equal(role("C:/Users/me/proj/agents.md", win), "ancestor-agents-md");
  });

  it("refines by the context: a config dir not named .claude, an auto-memory override, the managed dir", () => {
    const custom: RoleContext = { platform: "linux", configDir: "/cfg/claude-alt", managedDir: "/opt/managed", autoMemoryDir: "/notes/mem" };
    assert.equal(role("/cfg/claude-alt/CLAUDE.md", custom), "user-claude-md");
    assert.equal(role("/cfg/claude-alt/settings.json", custom), "user-settings");
    assert.equal(role("/cfg/claude-alt/rules/x.md", custom), "user-rules");
    assert.equal(role("/opt/managed/CLAUDE.md", custom), "managed-claude-md");
    assert.equal(role("/notes/mem/MEMORY.md", custom), "auto-memory-index");
    assert.equal(role("/notes/mem/x.md", custom), "auto-memory-topic");
    assert.equal(role("/notes/mem/sub/x.md", custom), null);
    assert.equal(role("/notes/mem/x.txt", custom), null);
  });

  it("falls back to the watch prefixes, read only when the patterns miss", () => {
    let reads = 0;
    const prefixes = {
      memoryDirs: ["/notes/mem", "/cfg/alt/agent-memory", "/srv/proj/.x/agent-memory-local"],
      configDirs: ["/cfg/alt"],
      importTargets: ["/home/u/app/docs/style.md", "/srv/shared/team.md"],
      hookScripts: ["/home/u/app/scripts/guard.sh"],
    };
    const lazy = () => { reads++; return prefixes; };
    const bare: RoleContext = { platform: "linux", root: "/home/u/app", configDir: "/cfg/alt" };
    assert.equal(role("/home/u/app/CLAUDE.md", bare, lazy), "ancestor-claude-md");
    assert.equal(reads, 0, "a static hit never reads watch-prefixes.json");
    const noU: RoleContext = { platform: "linux", root: "/home/u/app" };
    assert.equal(role("/cfg/alt/settings.json", noU, lazy), "user-settings");
    assert.equal(role("/notes/mem/MEMORY.md", noU, lazy), "auto-memory-index");
    assert.equal(role("/cfg/alt/agent-memory/r/MEMORY.md", bare, lazy), "user-agent-memory");
    assert.equal(role("/srv/proj/.x/agent-memory-local/r/a.md", bare, lazy), "project-agent-memory");
    assert.equal(role("/home/u/app/scripts/guard.sh", noU, lazy), "hook-script");
    assert.equal(role("/home/u/app/docs/style.md", noU, lazy), "import");
    assert.equal(role("/srv/shared/team.md", noU, lazy), "external-import");
    assert.equal(role("/home/u/app/docs/other.md", noU, lazy), null);
    assert.equal(role("/home/u/app/docs/other.md", noU, () => null), null);
    assert.equal(role("/home/u/app/docs/style.md", noU, NO_PREFIXES), null);
    assert.ok(reads > 0);
  });

  it("matches the prefix lists as store keys on win32", () => {
    const win: RoleContext = { platform: "win32" };
    const prefixes = { ...NO_PREFIXES, hookScripts: ["C:\\Users\\Me\\proj\\scripts\\guard.ps1"] };
    assert.equal(role("c:/users/me/PROJ/scripts/GUARD.ps1", win, prefixes), "hook-script");
  });
});

describe("labels and classes", () => {
  const SPEC_LABELS = new Set([
    "project instructions", "personal project instructions", "user instructions", "a rules file", "a subagent definition",
    "a slash command", "a skill", "a hook script", "Claude Code settings", "MCP server config",
  ]);

  it("every notice/exec/import role uses a §6.6 label; memory roles say which memory", () => {
    for (const r of WATCHED_ROLES) {
      if (classOf(r) === "memory") assert.match(labelOf(r), /memory$/, r);
      else assert.ok(SPEC_LABELS.has(labelOf(r)), `${r}: ${labelOf(r)}`);
    }
    assert.equal(labelOf("ancestor-local-md"), "personal project instructions");
    assert.equal(labelOf("user-claude-md"), "user instructions");
    assert.equal(labelOf("project-mcp"), "MCP server config");
  });

  it("classes follow §3.6", () => {
    assert.equal(classOf("hook-script"), "exec");
    assert.equal(classOf("project-skill-file"), "exec");
    assert.equal(classOf("auto-memory-topic"), "memory");
    assert.equal(classOf("import"), "import-silent");
    assert.equal(classOf("external-import"), "notice");
    assert.equal(classOf("claude-json-project"), "notice");
  });
});
