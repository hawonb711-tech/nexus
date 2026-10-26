import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import {
  canonicalPath, codexHomeEnv, codexHomeFrom, isCodexRole, isUnder, labelOf, memoryStoreId, onDiskPath, prefixListsOf, projectStoreId, SKILL_DOC_NAME,
  storeKey, watchedRoleOf, type PrefixLists, type RoleContext,
} from "./paths.js";
import { ROLE_CLASS, WATCHED_ROLES } from "./types.js";

const NO_PREFIXES: PrefixLists = { memoryDirs: [], configDirs: [], importTargets: [], hookScripts: [] };

describe("store keys and canonical paths", () => {
  let dir: string;
  beforeEach(() => { dir = realpathSync.native(mkdtempSync(join(tmpdir(), "nexus-paths-"))); });
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

  it("onDiskPath spells a win32 store key as the file is on disk; elsewhere it is the key as is", () => {
    mkdirSync(join(dir, "Src", "Api"), { recursive: true });
    writeFileSync(join(dir, "Src", "Api", "CLAUDE.md"), "x");
    // a win32 key is lower-cased: the directory and the name come back in their real case
    // (the directory through realpath, which keeps case where the file system does)
    const lower = join(realpathSync.native(join(dir, "Src", "Api")), "claude.md");
    assert.equal(onDiskPath(lower, "win32"), join(dir, "Src", "Api", "CLAUDE.md"));
    assert.equal(onDiskPath(join(dir, "Src", "Api", "gone.md"), "win32"), join(dir, "Src", "Api", "gone.md"));
    assert.equal(onDiskPath(join(dir, "missing-dir", "x.md"), "win32"), join(dir, "missing-dir", "x.md"));
    assert.equal(onDiskPath(lower, "linux"), lower);
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

describe("CODEX_HOME, read one way by the Codex install and the integrity layer", () => {
  it("an absolute value by its real path, as Codex keys it; a relative one is not taken; unset, ~/.codex", () => {
    const dir = realpathSync.native(mkdtempSync(join(tmpdir(), "nexus-codex-home-")));
    try {
      mkdirSync(join(dir, "real"));
      symlinkSync(join(dir, "real"), join(dir, "link"));
      assert.deepEqual(codexHomeEnv({ CODEX_HOME: join(dir, "link") }), { dir: join(dir, "real"), ignored: null }, "through the link");
      assert.deepEqual(codexHomeEnv({ CODEX_HOME: join(dir, "not-yet") }), { dir: join(dir, "not-yet"), ignored: null }, "as written while missing");
      assert.deepEqual(codexHomeEnv({ CODEX_HOME: "codex-rel" }), { dir: null, ignored: "codex-rel" });
      assert.deepEqual(codexHomeEnv({ CODEX_HOME: "" }), { dir: null, ignored: null });
      assert.deepEqual(codexHomeEnv({}), { dir: null, ignored: null });
      const deps = (env: Record<string, string>) => ({ env, homedir: "/home/u" });
      assert.deepEqual(codexHomeFrom(undefined, deps({ CODEX_HOME: "codex-rel" })), { dir: join("/home/u", ".codex"), source: "home" });
      assert.deepEqual(codexHomeFrom(undefined, deps({ CODEX_HOME: join(dir, "link") })), { dir: join(dir, "real"), source: "env" });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
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
      ["/home/u/app/.claude/skills/pdf/reference.md", "project-skill-doc"],
      ["/home/u/app/.claude/skills/pdf/docs/forms.txt", "project-skill-doc"],
      ["/home/u/app/.claude/skills/pdf/assets/logo.png", "project-skill-file"],
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
      ["/home/u/.claude/skills/s/notes/REFERENCE.MD", "user-skill-doc"],
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

  it("gives a skill's file the document role exactly when enumeration reads it as one (SKILL_DOC_NAME)", () => {
    for (const name of ["a.md", "a.MARKDOWN", "a.mdx", "a.txt", "a.text", "a.rst", "a.sh", "a.py", "a.json", "a.md.bak", "md", "a.png"]) {
      const doc = SKILL_DOC_NAME.test(name);
      assert.equal(role(`/home/u/app/.claude/skills/pdf/docs/${name}`), doc ? "project-skill-doc" : "project-skill-file", name);
      assert.equal(role(`/home/u/.claude/skills/pdf/${name}`), doc ? "user-skill-doc" : "user-skill-file", name);
    }
  });

  it("matches Windows paths, backslashes and case", () => {
    const win: RoleContext = { platform: "win32", configDir: "C:\\Users\\Me\\.claude", root: "C:\\Users\\Me\\proj" };
    assert.equal(role("C:\\Users\\me\\proj\\CLAUDE.md", win), "ancestor-claude-md");
    assert.equal(role("C:\\Users\\me\\proj\\.claude\\settings.local.json", win), "local-settings");
    assert.equal(role("c:\\users\\me\\.claude\\settings.json", win), "user-settings");
    assert.equal(role("C:\\Users\\me\\proj\\.Claude\\Rules\\x.md", win), "project-rules");
    assert.equal(role("C:/Users/me/proj/agents.md", win), "ancestor-agents-md");
  });

  it("matches names in any case only where the file systems fold case (win32, darwin); elsewhere exactly", () => {
    const mac: RoleContext = { ...ctx, platform: "darwin" };
    const cases: [string, string, string | null][] = [
      ["/home/u/app/docs/claude.md", "ancestor-claude-md", null],
      ["/home/u/app/docs/agents.md", "ancestor-agents-md", null],
      ["/home/u/app/docs/Agents.md", "ancestor-agents-md", null],
      ["/home/u/notes/claude.md", "ancestor-claude-md", null],
      ["/home/u/app/claude.local.md", "ancestor-local-md", null],
      ["/home/u/app/.Claude/settings.json", "project-settings", null],
      ["/home/u/app/.claude/skills/pdf/skill.md", "project-skill", "project-skill-doc"],
      ["/home/u/app/agents.override.md", "codex-project-md", null],
      ["/home/u/.claude/Settings.json", "user-settings", null],
      ["/home/u/.codex/agents.md", "ancestor-agents-md", null],
    ];
    const codex: RoleContext = { ...ctx, codexHome: "/home/u/.codex" };
    for (const [path, folded, exact] of cases) {
      assert.equal(role(path, { ...mac, codexHome: "/home/u/.codex" }), path.endsWith("/.codex/agents.md") ? "codex-user-instructions" : folded, `darwin: ${path}`);
      assert.equal(role(path, codex), exact, `linux: ${path}`);
    }
    // the exact names, and a skill document's extension in any case (enumeration reads it so everywhere)
    assert.equal(role("/home/u/app/docs/CLAUDE.md"), "ancestor-claude-md");
    assert.equal(role("/home/u/app/docs/AGENTS.md"), "ancestor-agents-md");
    assert.equal(role("/home/u/.claude/skills/s/notes/REFERENCE.MD"), "user-skill-doc");
    assert.equal(role("/home/u/app/.agents/skills/a/Guide.TXT"), "codex-project-skill-doc");
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

  it("reads every scope's lists of watch-prefixes.json together, and any outside a scope", () => {
    const scope = (hookScripts: unknown) => ({ memoryDirs: [], configDirs: [], importTargets: [], hookScripts, seen: "2026-10-23T09:00:00.000Z" });
    const lists = prefixListsOf({
      v: 1, hookScripts: ["/top.sh"],
      stores: { "project-aaaaaaaaaaaaaaaa": scope(["/a.sh", 7, ""]), "project-bbbbbbbbbbbbbbbb": scope(["/b.sh"]), junk: "x" },
    });
    assert.deepEqual(lists?.hookScripts, ["/top.sh", "/a.sh", "/b.sh"]);
    assert.equal(prefixListsOf({ v: 2, stores: {} }), null);
  });

  it("matches the prefix lists as store keys on win32", () => {
    const win: RoleContext = { platform: "win32" };
    const prefixes = { ...NO_PREFIXES, hookScripts: ["C:\\Users\\Me\\proj\\scripts\\guard.ps1"] };
    assert.equal(role("c:/users/me/PROJ/scripts/GUARD.ps1", win, prefixes), "hook-script");
  });
});

describe("watchedRoleOf, Codex's files", () => {
  const ctx: RoleContext = {
    platform: "linux", configDir: "/home/u/.claude", managedDir: "/etc/claude-code", root: "/home/u/app",
    codexHome: "/home/u/.codex", codexSystemDir: "/etc/codex", home: "/home/u",
  };
  const role = (p: string, c: RoleContext = ctx, prefixes: PrefixLists | null | (() => PrefixLists | null) = null) => watchedRoleOf(p, c, prefixes);

  it("under C, S and ~/.agents/skills: Codex's user-level roles", () => {
    const cases: [string, string | null][] = [
      ["/home/u/.codex/AGENTS.md", "codex-user-instructions"],
      ["/home/u/.codex/AGENTS.override.md", "codex-user-instructions"],
      ["/home/u/.codex/config.toml", "codex-user-config"],
      ["/home/u/.codex/work.config.toml", "codex-user-config"],
      ["/home/u/.codex/hooks.json", "codex-user-hooks"],
      ["/home/u/.codex/rules/default.rules", "codex-user-rules"],
      ["/home/u/.codex/rules/notes.txt", null],
      ["/home/u/.codex/skills/deploy/SKILL.md", "codex-user-skill"],
      ["/home/u/.codex/skills/ns/deploy/SKILL.md", "codex-user-skill"],
      ["/home/u/.codex/skills/deploy/references/api.md", "codex-user-skill-doc"],
      ["/home/u/.codex/skills/deploy/scripts/run.py", "codex-user-skill-file"],
      ["/home/u/.codex/skills/.system/imagegen/scripts/x.py", "codex-user-skill-file"],
      ["/home/u/.codex/memories/memory_summary.md", "codex-memory"],
      ["/home/u/.codex/memories_v2/MEMORY.md", "codex-memory"],
      ["/home/u/.codex/memories/rollout_summaries/x.md", null],
      ["/home/u/.codex/sessions/2026/10/25/rollout-x.jsonl", null],
      ["/home/u/.codex/history.jsonl", null],
      ["/etc/codex/config.toml", "codex-managed-config"],
      ["/etc/codex/requirements.toml", "codex-managed-config"],
      ["/etc/codex/managed_config.toml", "codex-managed-config"],
      ["/etc/codex/other.toml", null],
      ["/home/u/.agents/skills/notes/SKILL.md", "codex-user-skill"],
      ["/home/u/.agents/skills/notes/run.sh", "codex-user-skill-file"],
    ];
    for (const [path, expected] of cases) assert.equal(role(path), expected, path);
  });

  it("a project's Codex files, and context-free ones when C is not known", () => {
    const cases: [string, string | null][] = [
      ["/home/u/app/AGENTS.override.md", "codex-project-md"],
      ["/home/u/app/src/AGENTS.override.md", "codex-project-md"],
      ["/home/u/app/.codex/config.toml", "codex-project-config"],
      ["/home/u/app/.codex/hooks.json", "codex-project-hooks"],
      ["/home/u/app/.codex/rules/team.rules", "codex-project-rules"],
      ["/home/u/app/.codex/skills/a/SKILL.md", "codex-project-skill"],
      ["/home/u/app/.agents/skills/a/SKILL.md", "codex-project-skill"],
      ["/home/u/app/pkg/.agents/skills/a/doc.md", "codex-project-skill-doc"],
      ["/home/u/app/.agents/skills/a/bin", "codex-project-skill-file"],
      ["/home/u/app/.codex/other.json", null],
      ["/home/u/app/config.toml", null],
      ["/home/u/app/.agents/notes.md", null],
    ];
    for (const [path, expected] of cases) assert.equal(role(path), expected, path);
    const bare: RoleContext = { platform: "linux" };
    assert.equal(role("/x/.codex/config.toml", bare), "codex-project-config");
    assert.equal(role("/x/.codex/memories/memory_summary.md", bare), "codex-memory");
    assert.equal(role("/etc/codex/requirements.toml", bare), "codex-managed-config");
    assert.equal(role("/srv/etc/codex/config.toml", bare), null, "only the system's own /etc/codex");
  });

  it("a CODEX_HOME not named .codex and the fallback names come from the watch prefixes", () => {
    const bare: RoleContext = { platform: "linux" };
    const lists: PrefixLists = { ...NO_PREFIXES, codexDirs: ["/opt/codex-home"], codexDocs: ["/home/u/app/GUIDE.md"] };
    assert.equal(role("/opt/codex-home/config.toml", bare, lists), "codex-user-config");
    assert.equal(role("/opt/codex-home/hooks.json", bare, lists), "codex-user-hooks");
    // AGENTS.md and AGENTS.override.md there are that home's own, not a project's, though their patterns match anywhere
    assert.equal(role("/opt/codex-home/AGENTS.md", bare, lists), "codex-user-instructions");
    assert.equal(role("/opt/codex-home/AGENTS.override.md", bare, lists), "codex-user-instructions");
    assert.equal(role("/opt/codex-home/skills/x/AGENTS.md", bare, lists), "codex-user-skill-doc");
    assert.equal(role("/opt/codex-home/AGENTS.md", bare, NO_PREFIXES), "ancestor-agents-md", "without the lists, still watched by its pattern");
    assert.equal(role("/home/u/app/AGENTS.md", bare, lists), "ancestor-agents-md");
    assert.equal(role("/home/u/app/AGENTS.override.md", bare, lists), "codex-project-md");
    assert.equal(role("/opt/codex-home/AGENTS.md", { ...bare, codexHome: "/opt/codex-home" }), "codex-user-instructions");
    assert.equal(role("/home/u/app/GUIDE.md", bare, lists), "codex-project-md");
    assert.equal(role("/home/u/app/OTHER.md", bare, lists), null);
    assert.equal(role("/opt/codex-home/config.toml", bare, NO_PREFIXES), null);
    const parsed = prefixListsOf({ v: 1, stores: { "codex-aaaaaaaaaaaaaaaa": { memoryDirs: [], configDirs: [], importTargets: [], hookScripts: [], codexDirs: ["/opt/codex-home"], seen: "x" } } });
    assert.deepEqual(parsed?.codexDirs, ["/opt/codex-home"]);
    assert.equal(parsed?.codexDocs, undefined, "a list no scope has stays absent");
  });

  it("an import a Codex config names under C is an `import`", () => {
    const lists: PrefixLists = { ...NO_PREFIXES, importTargets: ["/home/u/.codex/prompts/model.md", "/srv/prompts/model.md"] };
    assert.equal(role("/home/u/.codex/prompts/model.md", ctx, lists), "import");
    assert.equal(role("/srv/prompts/model.md", ctx, lists), "external-import");
  });
});

describe("labels and classes", () => {
  const SPEC_LABELS = new Set([
    "project instructions", "personal project instructions", "user instructions", "a rules file", "a subagent definition",
    "a slash command", "a skill", "a hook script", "Claude Code settings", "MCP server config",
  ]);

  /** Codex's files: what reasons call them (Codex's own words for its config, hooks and rules). */
  const CODEX_LABELS = new Set([
    "project instructions", "Codex user instructions", "Codex config", "managed Codex config", "Codex project config", "Codex hooks",
    "Codex exec-policy rules", "a Codex skill",
  ]);

  it("every notice/exec/import role uses a §6.6 label (a Codex file, a Codex label); memory roles say which memory", () => {
    for (const r of WATCHED_ROLES) {
      if (ROLE_CLASS[r] === "memory") assert.match(labelOf(r), /memory$/, r);
      else if (isCodexRole(r)) assert.ok(CODEX_LABELS.has(labelOf(r)), `${r}: ${labelOf(r)}`);
      else assert.ok(SPEC_LABELS.has(labelOf(r)), `${r}: ${labelOf(r)}`);
    }
    assert.equal(labelOf("ancestor-local-md"), "personal project instructions");
    assert.equal(labelOf("user-claude-md"), "user instructions");
    assert.equal(labelOf("project-mcp"), "MCP server config");
  });

  it("classes follow §3.6", () => {
    assert.equal(ROLE_CLASS["hook-script"], "exec");
    assert.equal(ROLE_CLASS["project-skill-file"], "exec");
    assert.equal(ROLE_CLASS["project-skill-doc"], "notice");
    assert.equal(ROLE_CLASS["auto-memory-topic"], "memory");
    assert.equal(ROLE_CLASS["import"], "import-silent");
    assert.equal(ROLE_CLASS["external-import"], "notice");
    assert.equal(ROLE_CLASS["claude-json-project"], "notice");
  });
});
