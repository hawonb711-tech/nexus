/**
 * Instruction-file integrity — where the watched files are (spec §3.1, with
 * amendments A4 and A6).
 *
 * The hook resolves everything from its payload and never from `process.cwd()`;
 * the CLI passes its own cwd. Environment, home directory, platform and data
 * dir come in through `ContextDeps`, read once at the edge by
 * `defaultContextDeps()`. Resolution only reads the filesystem (stat, realpath,
 * small reads of `.git`, `commondir` and settings files); it never runs git.
 *
 * Symbols, as the spec names them:
 * - `cwd`: the session's directory (real path);
 * - R `root`: the nearest ancestor of cwd (or cwd) holding `.git`, else cwd;
 * - U `configDir`: `<X>` of a `<X>/projects/<slug>/<file>` transcript path, else
 *   an absolute `$CLAUDE_CONFIG_DIR`, else `~/.claude`;
 * - J `appState`: the existing `~/.claude.json` and `U/.claude.json`, deduped by real path;
 * - A `autoMemoryDir`: `autoMemoryDirectory` from the highest settings layer that
 *   sets it (managed > local > project > user), else
 *   `U/projects/<slug(canonical git root)>/memory`;
 * - M `managedDir`: the platform's managed-policy directory;
 * - D `dataDir`: the Nexus data directory.
 */

import { closeSync, constants, fstatSync, opendirSync, openSync, readSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { nexusDataDir } from "../../shared/data-dir.js";
import { canonicalDir, canonicalPath, configDirFrom, managedDirFor, realPathOrNull, type ConfigDirSource } from "./paths.js";
import { MAX_FILE_BYTES } from "./types.js";

export type ContextDeps = {
  platform: NodeJS.Platform;
  homedir: string;
  /** Only `CLAUDE_CONFIG_DIR` and `ProgramFiles` are read. */
  env: Readonly<Record<string, string | undefined>>;
  /** D, as `nexusDataDir()` resolves it. */
  dataDir: string;
  /** Overrides M (tests); otherwise `managedDirFor(platform, env)`. */
  managedDir?: string;
};

/** The real process's deps, read once. Logic below never reads `process.*` itself. */
export function defaultContextDeps(): ContextDeps {
  return { platform: process.platform, homedir: homedir(), env: process.env, dataDir: nexusDataDir() };
}

/** Which settings layer set `autoMemoryDirectory`, or `projects` for the derived default. */
export type AutoMemorySource = "managed" | "local" | "project" | "user" | "projects";

export type IntegrityContext = {
  platform: NodeJS.Platform;
  /** The home directory as given (used for `~` expansion). */
  home: string;
  cwd: string;
  /** R. */
  root: string;
  /** The main worktree's root when R is a linked worktree (A4); R otherwise, cwd without git. */
  canonicalRoot: string;
  /** U. */
  configDir: string;
  configDirSource: ConfigDirSource;
  /** J: canonical paths. */
  appState: string[];
  /** A; null when auto memory was not located. */
  autoMemoryDir: string | null;
  autoMemorySource: AutoMemorySource | null;
  /** M. */
  managedDir: string;
  /** D. */
  dataDir: string;
};

/** Bytes read from a `.git` file or `commondir` (each is one short line). */
const GIT_POINTER_BYTES = 4096;
/** Entries of `U/projects/` scanned for a long slug's hashed directory (A4). */
const PROJECTS_SCAN_LIMIT = 2000;
/** Claude Code shortens a project slug past this length and appends a hash. */
const SLUG_MAX = 200;

// U and M are worked out in paths.ts, which the PreToolUse overlay loads without this module.
export { configDirFrom, managedDirFor, type ConfigDirSource };

/** Claude Code's project directory name: every character outside `[a-zA-Z0-9]` becomes `-`. */
export function projectSlug(path: string): string {
  return path.replace(/[^a-zA-Z0-9]/g, "-");
}

/** Up to `max` bytes of a regular file as UTF-8, or null. Opened non-blocking so a FIFO never hangs the hook. */
function readSmall(path: string, max: number): string | null {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch {
    return null;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return null;
    const buf = Buffer.alloc(Math.min(st.size, max));
    let n = 0;
    while (n < buf.length) {
      const r = readSync(fd, buf, n, buf.length - n, null);
      if (r === 0) break;
      n += r;
    }
    return buf.subarray(0, n).toString("utf-8");
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

/** A settings file parsed as a JSON object, or null (missing, too large, unparseable, not an object). */
function readJsonObject(path: string, max = MAX_FILE_BYTES): Record<string, unknown> | null {
  try {
    const st = statSync(path, { throwIfNoEntry: false });
    if (!st?.isFile() || st.size > max) return null;
  } catch {
    return null;
  }
  const text = readSmall(path, max);
  if (text === null) return null;
  try {
    const parsed: unknown = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** R: the nearest ancestor of `cwd` (or `cwd`) with `.git` as a directory or a file. */
function findProjectRoot(cwd: string): { root: string; git: "dir" | "file" | null } {
  for (let dir = cwd; ; dir = dirname(dir)) {
    try {
      const st = statSync(join(dir, ".git"), { throwIfNoEntry: false });
      if (st?.isDirectory()) return { root: dir, git: "dir" };
      if (st?.isFile()) return { root: dir, git: "file" };
    } catch { /* unreadable: keep walking */ }
    if (dirname(dir) === dir) return { root: cwd, git: null };
  }
}

/**
 * The repository's main worktree root (A4): R itself when `.git` is a directory;
 * for a `.git` file `gitdir: X`, the parent of the common dir (`X/commondir`,
 * else X) when that is named `.git`, otherwise R (a submodule); cwd without git.
 */
function canonicalRootOf(root: string, git: "dir" | "file" | null, cwd: string): string {
  if (git === null) return cwd;
  if (git === "dir") return root;
  const pointer = readSmall(join(root, ".git"), GIT_POINTER_BYTES);
  const first = pointer?.split("\n", 1)[0].trim() ?? "";
  if (!first.startsWith("gitdir:")) return root;
  const gitdir = resolve(root, first.slice("gitdir:".length).trim());
  const commondir = readSmall(join(gitdir, "commondir"), GIT_POINTER_BYTES)?.split("\n", 1)[0].trim();
  const common = commondir ? resolve(gitdir, commondir) : gitdir;
  const real = realPathOrNull(common) ?? common;
  return basename(real) === ".git" ? dirname(real) : root;
}

/**
 * `U/projects/<slug>/memory` for the canonical root. A slug over 200 characters
 * carries a hash Nexus cannot reproduce, so the one directory whose name starts
 * with the first 200 characters plus `-` is used; none or several → null.
 */
export function autoMemoryFromProjects(configDir: string, canonicalRoot: string): string | null {
  const slug = projectSlug(canonicalRoot);
  const projects = join(configDir, "projects");
  if (slug.length <= SLUG_MAX) return join(projects, slug, "memory");
  const prefix = `${slug.slice(0, SLUG_MAX)}-`;
  const hits: string[] = [];
  try {
    const dir = opendirSync(projects);
    try {
      for (let i = 0; i < PROJECTS_SCAN_LIMIT; i++) {
        const entry = dir.readSync();
        if (!entry) break;
        if (entry.isDirectory() && entry.name.startsWith(prefix)) hits.push(entry.name);
      }
    } finally {
      dir.closeSync();
    }
  } catch {
    return null;
  }
  return hits.length === 1 ? join(projects, hits[0], "memory") : null;
}

/** An `autoMemoryDirectory` value Claude Code honours: absolute, or `~/…`. */
function memoryDirSetting(value: unknown, home: string): string | null {
  if (typeof value !== "string" || value === "") return null;
  if (value.startsWith("~/")) return join(home, value.slice(2));
  return isAbsolute(value) ? resolve(value) : null;
}

/** The managed layer's files, highest precedence first: drop-ins (later names win), then the base file. */
function managedSettingsFiles(managedDir: string): string[] {
  const dropIns: string[] = [];
  try {
    const dir = opendirSync(join(managedDir, "managed-settings.d"));
    try {
      for (let i = 0; i < PROJECTS_SCAN_LIMIT; i++) {
        const entry = dir.readSync();
        if (!entry) break;
        if (entry.name.toLowerCase().endsWith(".json")) dropIns.push(entry.name);
      }
    } finally {
      dir.closeSync();
    }
  } catch { /* no drop-in directory */ }
  dropIns.sort().reverse();
  return [...dropIns.map((n) => join(managedDir, "managed-settings.d", n)), join(managedDir, "managed-settings.json")];
}

/** A, by precedence managed > local > project > user (the `--settings` layer is invisible to hooks), then the derived default. */
function resolveAutoMemory(
  ctx: Pick<IntegrityContext, "managedDir" | "cwd" | "root" | "configDir" | "canonicalRoot" | "home">,
): { dir: string | null; source: AutoMemorySource | null } {
  const xs = ctx.cwd === ctx.root ? [ctx.cwd] : [ctx.cwd, ctx.root];
  const layers: [AutoMemorySource, string[]][] = [
    ["managed", managedSettingsFiles(ctx.managedDir)],
    ["local", xs.map((x) => join(x, ".claude", "settings.local.json"))],
    ["project", xs.map((x) => join(x, ".claude", "settings.json"))],
    ["user", [join(ctx.configDir, "settings.json")]],
  ];
  for (const [source, files] of layers) {
    for (const file of files) {
      const dir = memoryDirSetting(readJsonObject(file)?.autoMemoryDirectory, ctx.home);
      if (dir) return { dir: canonicalDir(dir), source };
    }
  }
  const derived = autoMemoryFromProjects(ctx.configDir, ctx.canonicalRoot);
  return derived ? { dir: canonicalDir(derived), source: "projects" } : { dir: null, source: null };
}

/** J: the existing `~/.claude.json` and `U/.claude.json`, deduplicated by real path. */
function appStateFiles(home: string, configDir: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const candidate of [join(home, ".claude.json"), join(configDir, ".claude.json")]) {
    try {
      if (!statSync(candidate, { throwIfNoEntry: false })?.isFile()) continue;
    } catch {
      continue;
    }
    const real = realPathOrNull(candidate);
    if (!real || seen.has(real)) continue;
    seen.add(real);
    out.push(canonicalPath(candidate));
  }
  return out;
}

function build(cwd: string, transcriptPath: string | undefined, deps: ContextDeps): IntegrityContext {
  const u = configDirFrom(transcriptPath, deps);
  const configDir = canonicalDir(u.dir);
  const { root, git } = findProjectRoot(cwd);
  const canonicalRoot = canonicalRootOf(root, git, cwd);
  const managedDir = canonicalDir(deps.managedDir ?? managedDirFor(deps.platform, deps.env));
  const base = { platform: deps.platform, home: deps.homedir, cwd, root, canonicalRoot, configDir, managedDir };
  const auto = resolveAutoMemory(base);
  return {
    ...base,
    configDirSource: u.source,
    appState: appStateFiles(deps.homedir, configDir),
    autoMemoryDir: auto.dir,
    autoMemorySource: auto.source,
    dataDir: deps.dataDir,
  };
}

/** The real path of an existing directory, or null. */
function realDir(path: string): string | null {
  const real = realPathOrNull(path);
  if (!real) return null;
  try {
    return statSync(real).isDirectory() ? real : null;
  } catch {
    return null;
  }
}

/**
 * Context from a hook payload. Null (the hook then says nothing) unless `cwd` is
 * an absolute path to an existing directory and `transcript_path`, when present,
 * is a string.
 */
export function contextFromHook(payload: unknown, deps: ContextDeps): IntegrityContext | null {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const { cwd, transcript_path: transcript } = payload as Record<string, unknown>;
  if (typeof cwd !== "string" || !isAbsolute(cwd)) return null;
  if (transcript !== undefined && typeof transcript !== "string") return null;
  const real = realDir(cwd);
  return real ? build(real, transcript, deps) : null;
}

/** Context for the CLI, from its own cwd (no transcript: U comes from the environment or home). */
export function contextFromCli(cwd: string, deps: ContextDeps): IntegrityContext | null {
  const real = realDir(resolve(cwd));
  return real ? build(real, undefined, deps) : null;
}
