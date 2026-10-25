import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import {
  autoMemoryFromProjects, configDirFrom, contextFromCli, contextFromHook, managedDirFor, projectSlug, type ContextDeps,
} from "./context.js";

/** Create a symlink, or report false where the OS refuses (Windows without the privilege). */
function trySymlink(target: string, path: string): boolean {
  try {
    symlinkSync(target, path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EPERM") return false;
    throw error;
  }
}

describe("context resolution", () => {
  let dir: string;
  let home: string;
  let managed: string;
  let deps: ContextDeps;
  beforeEach(() => {
    dir = realpathSync.native(mkdtempSync(join(tmpdir(), "nexus-context-")));
    home = join(dir, "home");
    managed = join(dir, "managed");
    mkdirSync(join(home, ".claude"), { recursive: true });
    deps = { platform: process.platform, homedir: home, env: {}, dataDir: join(dir, "data"), managedDir: managed };
  });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  const write = (path: string, text: string) => {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text);
  };
  const mkdir = (path: string) => { mkdirSync(path, { recursive: true }); return path; };
  const settings = (path: string, doc: unknown) => write(path, JSON.stringify(doc));

  it("managed directory per platform", () => {
    assert.equal(managedDirFor("linux", {}), "/etc/claude-code");
    assert.equal(managedDirFor("darwin", {}), "/Library/Application Support/ClaudeCode");
    assert.equal(managedDirFor("win32", {}), "C:\\Program Files\\ClaudeCode");
    assert.equal(managedDirFor("win32", { ProgramFiles: "D:\\Apps" }), "D:\\Apps\\ClaudeCode");
    assert.equal(managedDirFor("freebsd", {}), "/etc/claude-code");
  });

  it("U: the transcript layout first, then an absolute CLAUDE_CONFIG_DIR, then ~/.claude", () => {
    const d = { homedir: "/h", env: { CLAUDE_CONFIG_DIR: "/cfg" } };
    assert.deepEqual(configDirFrom("/x/conf/projects/-repo/5f3e.jsonl", d), { dir: resolve("/x/conf"), source: "transcript" });
    assert.deepEqual(configDirFrom("/x/conf/sessions/-repo/5f3e.jsonl", d), { dir: resolve("/cfg"), source: "env" });
    assert.deepEqual(configDirFrom("relative/projects/-repo/a.jsonl", d), { dir: resolve("/cfg"), source: "env" });
    assert.deepEqual(configDirFrom(undefined, { homedir: "/h", env: { CLAUDE_CONFIG_DIR: "rel/cfg" } }), { dir: join("/h", ".claude"), source: "home" });
    assert.deepEqual(configDirFrom(undefined, { homedir: "/h", env: {} }), { dir: join("/h", ".claude"), source: "home" });
  });

  it("resolves from the payload's cwd, never the process cwd, and rejects bad payloads", () => {
    const repo = mkdir(join(dir, "repo"));
    mkdir(join(repo, ".git"));
    const sub = mkdir(join(repo, "pkg", "web"));
    const ctx = contextFromHook({ cwd: sub, transcript_path: join(home, ".claude", "projects", "-x", "s.jsonl") }, deps)!;
    assert.equal(ctx.cwd, sub);
    assert.equal(ctx.root, repo);
    assert.equal(ctx.canonicalRoot, repo);
    assert.equal(ctx.configDir, join(home, ".claude"));
    assert.equal(ctx.configDirSource, "transcript");
    assert.equal(ctx.managedDir, managed);
    assert.equal(ctx.dataDir, join(dir, "data"));
    assert.equal(ctx.home, home);
    assert.notEqual(ctx.cwd, process.cwd());
    for (const bad of [null, [], "x", {}, { cwd: 42 }, { cwd: "relative/dir" }, { cwd: join(dir, "missing") }, { cwd: sub, transcript_path: {} }]) {
      assert.equal(contextFromHook(bad, deps), null, JSON.stringify(bad));
    }
    write(join(dir, "file"), "x");
    assert.equal(contextFromHook({ cwd: join(dir, "file") }, deps), null);
  });

  it("R is the nearest ancestor with .git (a directory or a file); without one it is cwd", () => {
    const outer = mkdir(join(dir, "outer"));
    mkdir(join(outer, ".git"));
    const inner = mkdir(join(outer, "vendor", "inner"));
    write(join(inner, ".git"), "gitdir: ../../.git/modules/inner\n");
    const deep = mkdir(join(inner, "src"));
    assert.equal(contextFromHook({ cwd: deep }, deps)!.root, inner);
    const plain = mkdir(join(dir, "plain", "a"));
    const ctx = contextFromHook({ cwd: plain }, deps)!;
    assert.equal(ctx.root, plain);
    assert.equal(ctx.canonicalRoot, plain);
  });

  it("A4: a linked worktree's memory lives under the main worktree's slug", () => {
    const main = mkdir(join(dir, "main"));
    mkdir(join(main, ".git", "worktrees", "feature"));
    write(join(main, ".git", "worktrees", "feature", "commondir"), "../..\n");
    const wt = mkdir(join(dir, "wt", "feature"));
    write(join(wt, ".git"), `gitdir: ${join(main, ".git", "worktrees", "feature")}\n`);
    const ctx = contextFromHook({ cwd: wt, transcript_path: join(home, ".claude", "projects", projectSlug(wt), "s.jsonl") }, deps)!;
    assert.equal(ctx.root, wt);
    assert.equal(ctx.canonicalRoot, main);
    assert.equal(ctx.autoMemoryDir, join(home, ".claude", "projects", projectSlug(main), "memory"));
    assert.equal(ctx.autoMemorySource, "projects");

    // a relative gitdir resolves from R
    const wt2 = mkdir(join(dir, "wt2"));
    write(join(wt2, ".git"), "gitdir: ../main/.git/worktrees/feature\n");
    assert.equal(contextFromHook({ cwd: wt2 }, deps)!.canonicalRoot, main);

    // a submodule's gitdir has no commondir and is not named .git: R itself
    mkdir(join(main, ".git", "modules", "sub"));
    const sub = mkdir(join(main, "sub"));
    write(join(sub, ".git"), "gitdir: ../.git/modules/sub\n");
    assert.equal(contextFromHook({ cwd: sub }, deps)!.canonicalRoot, sub);
  });

  it("A4: a slug over 200 characters is found by its unique 200-character prefix", () => {
    const deepRoot = mkdir(join(dir, "r".repeat(120), "s".repeat(120)));
    const slug = projectSlug(deepRoot);
    assert.ok(slug.length > 200);
    const projects = join(home, ".claude", "projects");
    assert.equal(autoMemoryFromProjects(join(home, ".claude"), deepRoot), null, "no directory yet");
    mkdir(join(projects, `${slug.slice(0, 200)}-1a2b3c`));
    mkdir(join(projects, `${slug.slice(0, 199)}x-other`));
    assert.equal(contextFromHook({ cwd: deepRoot }, deps)!.autoMemoryDir, join(projects, `${slug.slice(0, 200)}-1a2b3c`, "memory"));
    mkdir(join(projects, `${slug.slice(0, 200)}-9z9z9z`));
    const ctx = contextFromHook({ cwd: deepRoot }, deps)!;
    assert.equal(ctx.autoMemoryDir, null, "two candidates: auto memory not located");
    assert.equal(ctx.autoMemorySource, null);
  });

  it("A: autoMemoryDirectory from the highest layer that sets it: managed > local > project > user", () => {
    const repo = mkdir(join(dir, "repo"));
    mkdir(join(repo, ".git"));
    const at = (name: string) => join(dir, "mem", name);
    const resolveA = () => contextFromHook({ cwd: repo }, deps)!;
    assert.equal(resolveA().autoMemoryDir, join(home, ".claude", "projects", projectSlug(repo), "memory"));

    settings(join(home, ".claude", "settings.json"), { autoMemoryDirectory: "~/notes/user" });
    assert.equal(resolveA().autoMemoryDir, join(home, "notes", "user"));
    assert.equal(resolveA().autoMemorySource, "user");
    settings(join(repo, ".claude", "settings.json"), { autoMemoryDirectory: at("project") });
    assert.deepEqual([resolveA().autoMemoryDir, resolveA().autoMemorySource], [at("project"), "project"]);
    settings(join(repo, ".claude", "settings.local.json"), { autoMemoryDirectory: at("local") });
    assert.deepEqual([resolveA().autoMemoryDir, resolveA().autoMemorySource], [at("local"), "local"]);
    settings(join(managed, "managed-settings.json"), { autoMemoryDirectory: at("managed") });
    assert.deepEqual([resolveA().autoMemoryDir, resolveA().autoMemorySource], [at("managed"), "managed"]);
    settings(join(managed, "managed-settings.d", "10-a.json"), { autoMemoryDirectory: at("drop-a") });
    settings(join(managed, "managed-settings.d", "20-b.json"), { autoMemoryDirectory: at("drop-b") });
    assert.equal(resolveA().autoMemoryDir, at("drop-b"), "the later drop-in wins");

    // a relative value, a non-string and unparseable JSON are not honoured
    rmSync(managed, { recursive: true });
    settings(join(repo, ".claude", "settings.local.json"), { autoMemoryDirectory: "relative/mem" });
    write(join(repo, ".claude", "settings.json"), "{ not json");
    assert.deepEqual([resolveA().autoMemoryDir, resolveA().autoMemorySource], [join(home, "notes", "user"), "user"]);
  });

  it("J: the existing ~/.claude.json and U/.claude.json, deduplicated by real path", () => {
    const cfg = mkdir(join(dir, "cfg"));
    const cwd = mkdir(join(dir, "w"));
    const withEnv = { ...deps, env: { CLAUDE_CONFIG_DIR: cfg } };
    assert.deepEqual(contextFromHook({ cwd }, withEnv)!.appState, []);
    write(join(home, ".claude.json"), "{}");
    assert.deepEqual(contextFromHook({ cwd }, withEnv)!.appState, [join(home, ".claude.json")]);
    write(join(cfg, ".claude.json"), "{}");
    assert.deepEqual(contextFromHook({ cwd }, withEnv)!.appState, [join(home, ".claude.json"), join(cfg, ".claude.json")]);
    rmSync(join(cfg, ".claude.json"));
    if (!trySymlink(join(home, ".claude.json"), join(cfg, ".claude.json"))) return;
    assert.deepEqual(contextFromHook({ cwd }, withEnv)!.appState, [join(home, ".claude.json")]);
    assert.equal(contextFromHook({ cwd }, withEnv)!.configDirSource, "env");
  });

  it("the CLI resolves from the directory it is given, with U from the environment", () => {
    const cfg = mkdir(join(dir, "cfg"));
    const cwd = mkdir(join(dir, "cli"));
    const ctx = contextFromCli(cwd, { ...deps, env: { CLAUDE_CONFIG_DIR: cfg } })!;
    assert.equal(ctx.cwd, cwd);
    assert.equal(ctx.configDir, cfg);
    assert.equal(ctx.configDirSource, "env");
    assert.equal(contextFromCli(join(dir, "nope"), deps), null);
  });
});
