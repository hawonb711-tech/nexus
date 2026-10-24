/**
 * Instruction-file integrity — path vocabulary: the canonical form and store key
 * of a watched path, store ids, the Claude config (U) and managed-policy (M)
 * directories, and which watched role (if any) a path an agent writes to has,
 * with the label that role carries.
 *
 * `watchedRoleOf` is pure: static patterns first, then the resolved context's
 * directories, then the `watch-prefixes.json` lists (read lazily, only when the
 * patterns miss). Only `canonicalPath` / `canonicalDir` / `realPathOrNull` /
 * `linkedWrite` ask the filesystem.
 *
 * The PreToolUse overlay loads this module for every file-tool call while
 * integrity is on, so it loads no runtime code from other integrity modules but
 * private-file.ts (types.ts included: only its types).
 */

import { createHash } from "node:crypto";
import { lstatSync, readlinkSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, parse, posix, resolve, sep, win32 } from "node:path";
import { readPrivateJson } from "./private-file.js";
import type { StoreId, WatchPrefixes, WatchedRole } from "./types.js";

// ── Canonical paths, keys and store ids ─────────────────────────────────────

/** `realpathSync.native(p)`, or null when it cannot be resolved (missing, dangling, unreadable). */
export function realPathOrNull(p: string): string | null {
  try {
    return realpathSync.native(p);
  } catch {
    return null;
  }
}

/**
 * The path a watched entry is known by: the real path of its directory plus its
 * own name. The last component is deliberately NOT resolved, so a symlinked
 * CLAUDE.md keeps its own entry (with the link text recorded and the target
 * hashed) and a retargeted link reads as a change to that entry; ledger records
 * for a write through the link land on the same key. A missing directory is
 * resolved as far up as it exists.
 */
export function canonicalPath(p: string): string {
  const abs = resolve(p);
  const parent = dirname(abs);
  if (parent === abs) return realPathOrNull(abs) ?? abs;
  return join(realPathOrNull(parent) ?? unresolvedDir(parent), basename(abs));
}

/** Does anything (a dangling link included) sit at `p`? No exception for a miss. */
function lexists(p: string): boolean {
  try {
    return lstatSync(p, { throwIfNoEntry: false }) !== undefined;
  } catch {
    return false; // ENOTDIR, EACCES, ENAMETOOLONG: nothing reachable there
  }
}

/**
 * `canonicalPath` of a directory that does not resolve: the real path of its
 * deepest ancestor that does, plus the rest as written. That ancestor is found
 * walking down from the root (one `lstat` per existing component; the first
 * missing one ends the walk), so a path hundreds of missing levels deep costs
 * what a shallow one does instead of one failed `realpath` per level.
 */
function unresolvedDir(dir: string): string {
  const { root } = parse(dir);
  const parts = dir.slice(root.length).split(sep).filter((s) => s !== "");
  let n = 0;
  for (let cur = root; n < parts.length; n++) {
    cur = join(cur, parts[n]);
    if (!lexists(cur)) break;
  }
  // the deepest existing component may still not resolve (a dangling link): step up
  for (let k = n; k >= 0; k--) {
    const real = realPathOrNull(join(root, ...parts.slice(0, k)));
    if (real !== null) return join(real, ...parts.slice(k));
  }
  return dir;
}

/** A directory's real path when it exists, else `canonicalPath` (its nearest existing ancestor resolved). */
export function canonicalDir(p: string): string {
  return realPathOrNull(p) ?? canonicalPath(p);
}

/** Store key: the canonical path with forward slashes, lower-cased on win32. */
export function storeKey(path: string, platform: NodeJS.Platform): string {
  const slashed = path.replace(/\\/g, "/");
  return platform === "win32" ? slashed.toLowerCase() : slashed;
}

/** Is `path` `dir` itself or inside it? Compared as store keys. */
export function isUnder(path: string, dir: string, platform: NodeJS.Platform): boolean {
  const p = storeKey(path, platform);
  const d = storeKey(dir, platform);
  const prefix = d.endsWith("/") ? d : `${d}/`;
  return p === d || p.startsWith(prefix);
}

const h16 = (text: string) => createHash("sha256").update(text).digest("hex").slice(0, 16);

/** `project-<h16>`, where h16 = sha256(storeKey(R))[:16]. */
export function projectStoreId(root: string, platform: NodeJS.Platform): StoreId {
  return `project-${h16(storeKey(root, platform))}`;
}

/** `memory-<h16>` for an auto-memory directory (worktrees of one repo share it). */
export function memoryStoreId(dir: string, platform: NodeJS.Platform): StoreId {
  return `memory-${h16(storeKey(dir, platform))}`;
}

// ── The config and managed-policy directories ──────────────────────────────

/** M: linux and WSL `/etc/claude-code`; darwin `/Library/Application Support/ClaudeCode`; win32 `%ProgramFiles%\ClaudeCode`. */
export function managedDirFor(platform: NodeJS.Platform, env: Readonly<Record<string, string | undefined>>): string {
  if (platform === "win32") return win32.join(env.ProgramFiles ?? "C:\\Program Files", "ClaudeCode");
  if (platform === "darwin") return "/Library/Application Support/ClaudeCode";
  return "/etc/claude-code";
}

/** Where U was found: the transcript path's layout, `$CLAUDE_CONFIG_DIR`, or `~/.claude`. */
export type ConfigDirSource = "transcript" | "env" | "home";

/** U and where it came from (A6): the transcript layout, then an absolute `CLAUDE_CONFIG_DIR`, then `~/.claude`. */
export function configDirFrom(
  transcriptPath: string | undefined,
  deps: { env: Readonly<Record<string, string | undefined>>; homedir: string },
): { dir: string; source: ConfigDirSource } {
  if (transcriptPath && isAbsolute(transcriptPath)) {
    const file = resolve(transcriptPath);
    const slugDir = dirname(file);
    const projects = dirname(slugDir);
    const x = dirname(projects);
    if (basename(projects) === "projects" && slugDir !== projects && projects !== x) {
      return { dir: x, source: "transcript" };
    }
  }
  const env = deps.env.CLAUDE_CONFIG_DIR;
  if (env && isAbsolute(env)) return { dir: resolve(env), source: "env" };
  return { dir: join(deps.homedir, ".claude"), source: "home" };
}

// ── Roles of written paths ──────────────────────────────────────────────────

/** The parts of the resolved context `watchedRoleOf` uses; all optional, so the
 *  PreToolUse hot path can pass only what it has without touching the disk. */
export type RoleContext = {
  platform: NodeJS.Platform;
  /** U: the Claude Code config directory. */
  configDir?: string;
  /** M: the managed-policy directory. */
  managedDir?: string;
  /** R: the project root. */
  root?: string;
  /** A: the auto-memory directory. */
  autoMemoryDir?: string | null;
  /** J: the `.claude.json` app-state files. */
  appState?: readonly string[];
};

export type PrefixLists = Pick<WatchPrefixes, "memoryDirs" | "configDirs" | "importTargets" | "hookScripts">;

const PREFIX_LISTS = ["memoryDirs", "configDirs", "importTargets", "hookScripts"] as const;
/** Paths kept per `watch-prefixes.json` list. */
const MAX_PREFIX_ITEMS = 10_000;

/**
 * The four lists of a parsed `watch-prefixes.json` (non-empty strings, at most
 * 10,000 each), or null unless it is a version-1 object. The file is unsigned:
 * whatever it lists only ever adds asks.
 */
export function prefixListsOf(raw: unknown): PrefixLists | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw) || (raw as { v?: unknown }).v !== 1) return null;
  const doc = raw as Record<string, unknown>;
  const lists = {} as PrefixLists;
  for (const name of PREFIX_LISTS) {
    const v = doc[name];
    lists[name] = (Array.isArray(v) ? v.filter((s): s is string => typeof s === "string" && s !== "") : []).slice(0, MAX_PREFIX_ITEMS);
  }
  return lists;
}

/**
 * Context-free patterns (forward-slash paths, case-insensitive), most specific
 * first. They mirror the `SENSITIVE_PATHS` write rules plus the auto-memory and
 * agent-memory locations; a path under `~/.claude` is refined to its user role by
 * the context check that runs before these.
 */
const STATIC_ROLES: readonly [RegExp, WatchedRole][] = [
  [/(?:^|\/)\.claude\/projects\/[^/]{1,255}\/memory\/MEMORY\.md$/i, "auto-memory-index"],
  [/(?:^|\/)\.claude\/projects\/[^/]{1,255}\/memory\/[^/]{1,255}\.md$/i, "auto-memory-topic"],
  [/(?:^|\/)\.claude\/agent-memory(?:-local)?\//i, "project-agent-memory"],
  [/(?:^|\/)managed-settings\.json$|(?:^|\/)managed-settings\.d\/[^/]{1,255}\.json$/i, "managed-settings"],
  [/(?:^|\/)managed-mcp\.json$/i, "managed-mcp"],
  [/(?:^|\/)\.claude\/settings\.json$/i, "project-settings"],
  [/(?:^|\/)\.claude\/settings\.local\.json$/i, "local-settings"],
  [/(?:^|\/)\.mcp\.json$/i, "project-mcp"],
  [/(?:^|\/)\.claude\.json$/i, "claude-json"],
  [/(?:^|\/)\.claude\/hooks\//i, "hook-script"],
  [/(?:^|\/)\.claude\/rules\//i, "project-rules"],
  [/(?:^|\/)\.claude\/agents\//i, "project-agent"],
  [/(?:^|\/)\.claude\/commands\//i, "project-command"],
  [/(?:^|\/)\.claude\/skills\/[^/]{1,255}\/SKILL\.md$/i, "project-skill"],
  [/(?:^|\/)\.claude\/skills\//i, "project-skill-file"],
  [/(?:^|\/)CLAUDE\.local\.md$/i, "ancestor-local-md"],
  [/(?:^|\/)CLAUDE\.md$/i, "ancestor-claude-md"],
  [/(?:^|\/)AGENTS\.md$/i, "ancestor-agents-md"],
];

/** Roles of a path relative to the config directory U (or a `configDirs` prefix). */
const CONFIG_DIR_ROLES: readonly [RegExp, WatchedRole][] = [
  [/^CLAUDE\.md$/i, "user-claude-md"],
  [/^settings\.json$/i, "user-settings"],
  [/^\.claude\.json$/i, "claude-json"],
  [/^rules\//i, "user-rules"],
  [/^agents\//i, "user-agent"],
  [/^commands\//i, "user-command"],
  [/^skills\/[^/]{1,255}\/SKILL\.md$/i, "user-skill"],
  [/^skills\//i, "user-skill-file"],
  [/^agent-memory(?:-local)?\//i, "user-agent-memory"],
  [/^hooks\//i, "hook-script"],
  [/^projects\/[^/]{1,255}\/memory\/MEMORY\.md$/i, "auto-memory-index"],
  [/^projects\/[^/]{1,255}\/memory\/[^/]{1,255}\.md$/i, "auto-memory-topic"],
];

/** Roles of a path relative to the managed directory M. */
const MANAGED_DIR_ROLES: readonly [RegExp, WatchedRole][] = [
  [/^CLAUDE\.md$/i, "managed-claude-md"],
  [/^managed-settings\.json$|^managed-settings\.d\/[^/]{1,255}\.json$/i, "managed-settings"],
  [/^managed-mcp\.json$/i, "managed-mcp"],
];

const AGENT_MEMORY_DIR = /(?:^|\/)agent-memory(?:-local)?$/i;

/** `path` relative to `dir` as a store-key fragment (forward slashes; lower-cased on
 *  win32, which the case-insensitive role tables allow), or null when it is not
 *  strictly inside. */
function relativeKey(path: string, dir: string | null | undefined, platform: NodeJS.Platform): string | null {
  if (!dir) return null;
  const p = storeKey(path, platform);
  const d = storeKey(dir, platform);
  const prefix = d.endsWith("/") ? d : `${d}/`;
  return p.startsWith(prefix) && p.length > prefix.length ? p.slice(prefix.length) : null;
}

function firstMatch(rel: string | null, table: readonly [RegExp, WatchedRole][]): WatchedRole | null {
  if (rel === null) return null;
  for (const [re, role] of table) if (re.test(rel)) return role;
  return null;
}

/** An auto-memory file directly inside a memory directory. */
function memoryFileRole(rel: string | null): WatchedRole | null {
  if (rel === null || rel.includes("/") || !/\.md$/i.test(rel)) return null;
  return rel.toLowerCase() === "memory.md" ? "auto-memory-index" : "auto-memory-topic";
}

/**
 * The watched role of `abs` (an absolute path an agent tool is about to write),
 * or null when nothing watches it. Static patterns and the context's own
 * directories are checked first; `prefixes` (the `watch-prefixes.json` lists, or
 * a function that reads them) is consulted only when those miss.
 */
export function watchedRoleOf(
  abs: string,
  ctx: RoleContext,
  prefixes?: PrefixLists | null | (() => PrefixLists | null),
): WatchedRole | null {
  const { platform } = ctx;
  const slashed = abs.replace(/\\/g, "/");
  const key = storeKey(abs, platform);

  if (ctx.appState?.some((j) => storeKey(j, platform) === key)) return "claude-json";
  const managed = firstMatch(relativeKey(abs, ctx.managedDir, platform), MANAGED_DIR_ROLES);
  if (managed) return managed;
  const user = firstMatch(relativeKey(abs, ctx.configDir, platform), CONFIG_DIR_ROLES);
  if (user) return user;
  const memory = memoryFileRole(relativeKey(abs, ctx.autoMemoryDir, platform));
  if (memory) return memory;
  for (const [re, role] of STATIC_ROLES) if (re.test(slashed)) return role;

  const lists = typeof prefixes === "function" ? prefixes() : prefixes;
  if (!lists) return null;
  for (const dir of lists.configDirs) {
    const role = firstMatch(relativeKey(abs, dir, platform), CONFIG_DIR_ROLES);
    if (role) return role;
  }
  for (const dir of lists.memoryDirs) {
    const rel = relativeKey(abs, dir, platform);
    if (rel === null) continue;
    if (AGENT_MEMORY_DIR.test(dir.replace(/\\/g, "/"))) {
      return ctx.configDir && isUnder(dir, ctx.configDir, platform) ? "user-agent-memory" : "project-agent-memory";
    }
    const role = memoryFileRole(rel);
    if (role) return role;
  }
  if (lists.hookScripts.some((p) => storeKey(p, platform) === key)) return "hook-script";
  if (lists.importTargets.some((p) => storeKey(p, platform) === key)) {
    const inside = (dir: string | null | undefined) => !!dir && isUnder(abs, dir, platform);
    return inside(ctx.root) || inside(ctx.configDir) ? "import" : "external-import";
  }
  return null;
}

// ── The role of a path an agent tool writes (PreToolUse, §6.6 step 2) ───────

/** `watch-prefixes.json` is read at most this large. */
const MAX_PREFIX_BYTES = 4 * 1024 * 1024;
/** types.ts's INTEGRITY_DIR and WATCH_PREFIXES_FILE (repeated: this module loads no runtime code from types.ts). */
const PREFIXES_FILE = ["integrity", "watch-prefixes.json"] as const;

/** What `writeRoleOf` reads from the hook's deps. */
export type RoleDeps = {
  dataDir: string;
  homedir: string;
  platform: NodeJS.Platform;
  env: Readonly<Record<string, string | undefined>>;
  managedDir?: string;
};

/** The `watch-prefixes.json` lists, or null when missing or malformed. */
export function readPrefixLists(dataDir: string): PrefixLists | null {
  const read = readPrivateJson(join(dataDir, ...PREFIXES_FILE), MAX_PREFIX_BYTES);
  return read.state === "ok" ? prefixListsOf(read.value) : null;
}

/**
 * The watched role of `abs`, or null: §6.6 step 2 without touching the disk
 * for a path the patterns (or the payload's config dir U, the managed dir M and
 * the `.claude.json` app-state files) recognise; otherwise the prefix lists,
 * read once; otherwise all of that again for the path through its real
 * directory, when that differs.
 */
export function writeRoleOf(abs: string, transcriptPath: unknown, deps: RoleDeps): WatchedRole | null {
  const p = deps.platform === "win32" ? win32 : posix;
  const configDir = configDirFrom(typeof transcriptPath === "string" ? transcriptPath : undefined, deps).dir;
  const ctx: RoleContext = {
    platform: deps.platform,
    configDir,
    managedDir: deps.managedDir ?? managedDirFor(deps.platform, deps.env),
    appState: [p.join(deps.homedir, ".claude.json"), p.join(configDir, ".claude.json")],
  };
  let lists: PrefixLists | null | undefined;
  const prefixes = () => (lists === undefined ? (lists = readPrefixLists(deps.dataDir)) : lists);
  const role = watchedRoleOf(abs, ctx, prefixes);
  if (role) return role;
  const real = canonicalPath(abs);
  return real === abs ? null : watchedRoleOf(real, ctx, prefixes);
}

/** The file a symlink at `abs` reaches: its real path, or for a dangling link its target (one level), which a write creates. */
function linkTargetOf(abs: string): string | null {
  const real = realPathOrNull(abs);
  if (real !== null) return real;
  try {
    if (!lstatSync(abs).isSymbolicLink()) return null;
    return canonicalPath(resolve(dirname(abs), readlinkSync(abs)));
  } catch {
    return null;
  }
}

/** A watched file a write lands in under another store key than the path it names. */
export type LinkedWrite = { path: string; key: string; role: WatchedRole };

/**
 * The other watched entry a write to `abs` changes, or null: when `abs` is a
 * symlink (CLAUDE.md linked to AGENTS.md), the file it reaches — its store key
 * differs from `canonicalPath(abs)`'s, which keeps the link's own name — if that
 * file has a watched role too. Both entries see the write, so PreToolUse records
 * it, and PostToolUse confirms it, under both keys.
 */
export function linkedWrite(abs: string, transcriptPath: unknown, deps: RoleDeps): LinkedWrite | null {
  const target = linkTargetOf(abs);
  if (target === null) return null;
  const key = storeKey(target, deps.platform);
  if (key === storeKey(canonicalPath(abs), deps.platform)) return null;
  const role = writeRoleOf(target, transcriptPath, deps);
  return role ? { path: target, key, role } : null;
}

// ── Labels ──────────────────────────────────────────────────────────────────

const LABELS: Readonly<Record<WatchedRole, string>> = {
  "managed-claude-md": "user instructions",
  "managed-settings": "Claude Code settings",
  "managed-mcp": "MCP server config",
  "user-claude-md": "user instructions",
  "user-rules": "a rules file",
  "user-settings": "Claude Code settings",
  "user-agent": "a subagent definition",
  "user-command": "a slash command",
  "user-skill": "a skill",
  "user-skill-file": "a skill",
  "user-agent-memory": "subagent memory",
  "claude-json": "MCP server config",
  "hook-script": "a hook script",
  "ancestor-claude-md": "project instructions",
  "ancestor-local-md": "personal project instructions",
  "ancestor-agents-md": "project instructions",
  "project-settings": "Claude Code settings",
  "local-settings": "Claude Code settings",
  "project-mcp": "MCP server config",
  "project-rules": "a rules file",
  "project-agent": "a subagent definition",
  "project-command": "a slash command",
  "project-skill": "a skill",
  "project-skill-file": "a skill",
  "project-agent-memory": "subagent memory",
  "claude-json-project": "MCP server config",
  "import": "project instructions",
  "external-import": "project instructions",
  "ledger-learned": "project instructions",
  "auto-memory-index": "auto memory",
  "auto-memory-topic": "auto memory",
};

/** The short noun phrase PreToolUse messages use for a role ("project instructions", "a hook script", …). */
export function labelOf(role: WatchedRole): string {
  return LABELS[role];
}

