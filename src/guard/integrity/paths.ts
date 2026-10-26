/**
 * Instruction-file integrity — path vocabulary: the canonical form and store key
 * of a watched path, store ids, the Claude config (U) and managed-policy (M)
 * directories, Codex's home (C) and system (S) directories, and which watched
 * role (if any) a path an agent writes to has, with the label that role
 * carries.
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
import { lstatSync, readdirSync, readlinkSync, realpathSync } from "node:fs";
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
 * The path a store key names, spelled as it is on disk. On win32 a key is
 * lower-cased (`storeKey`), so a path learned from a ledger record would
 * otherwise be shown and recorded in lower case: the directory comes back from
 * `realPathOrNull` in its real case, and the name from one listing of that
 * directory. Elsewhere, and whenever that fails, the key is returned as is.
 */
export function onDiskPath(key: string, platform: NodeJS.Platform): string {
  if (platform !== "win32") return key;
  const dir = realPathOrNull(dirname(key));
  if (!dir) return key;
  const name = basename(key).toLowerCase();
  try {
    const found = readdirSync(dir).find((e) => e.toLowerCase() === name);
    return join(dir, found ?? basename(key));
  } catch {
    return join(dir, basename(key));
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

/** The first 16 hex digits of a sha256: store ids and watch-prefix scope names. */
export const h16 = (text: string) => createHash("sha256").update(text).digest("hex").slice(0, 16);

/** `project-<h16>`, where h16 = sha256(storeKey(R))[:16]. */
export function projectStoreId(root: string, platform: NodeJS.Platform): StoreId {
  return `project-${h16(storeKey(root, platform))}`;
}

/** `memory-<h16>` for an auto-memory directory (worktrees of one repo share it). */
export function memoryStoreId(dir: string, platform: NodeJS.Platform): StoreId {
  return `memory-${h16(storeKey(dir, platform))}`;
}

/** Which agent's session it is: its user-level files are the ones checked (Claude Code's `global` store, or Codex's `codex`). */
export type Agent = "claude" | "codex";

/** The user-level store of an agent's sessions. */
export function userStoreId(agent: Agent): StoreId {
  return agent === "codex" ? "codex" : "global";
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

/**
 * S: the directory of Codex's system layer — `/etc/codex` (its config.toml,
 * requirements.toml and the legacy managed_config.toml), or on win32
 * `%ProgramData%\OpenAI\Codex`.
 */
export function codexSystemDirFor(platform: NodeJS.Platform, env: Readonly<Record<string, string | undefined>>): string {
  if (platform === "win32") return win32.join(env.ProgramData ?? "C:\\ProgramData", "OpenAI", "Codex");
  return "/etc/codex";
}

/** Where C was found: a Codex transcript's layout, `$CODEX_HOME`, or `~/.codex`. */
export type CodexHomeSource = "transcript" | "env" | "home";

/** A Codex transcript: `<C>/sessions/YYYY/MM/DD/rollout-<…>.jsonl`. */
const CODEX_TRANSCRIPT = /^rollout-[^/\\]{1,255}\.jsonl$/;
const TWO_DIGITS = /^\d{2}$/;

/**
 * C, Codex's home, and where it came from: the directory a Codex transcript
 * path lives under (`<C>/sessions/YYYY/MM/DD/rollout-….jsonl`, as Codex sends
 * it in every hook payload), then an absolute `$CODEX_HOME`, then `~/.codex`.
 */
export function codexHomeFrom(
  transcriptPath: string | undefined,
  deps: { env: Readonly<Record<string, string | undefined>>; homedir: string },
): { dir: string; source: CodexHomeSource } {
  const home = codexTranscriptHome(transcriptPath);
  if (home) return { dir: home, source: "transcript" };
  const env = deps.env.CODEX_HOME;
  if (env && isAbsolute(env)) return { dir: resolve(env), source: "env" };
  return { dir: join(deps.homedir, ".codex"), source: "home" };
}

/** C when `transcriptPath` is laid out as a Codex transcript (see `codexHomeFrom`), else null. */
export function codexTranscriptHome(transcriptPath: string | undefined): string | null {
  // the file name first, without resolving anything: Claude Code's transcripts (every hook call's) fail here
  const name = transcriptPath ? Math.max(transcriptPath.lastIndexOf("/"), transcriptPath.lastIndexOf("\\")) + 1 : 0;
  if (!transcriptPath || !transcriptPath.startsWith("rollout-", name) || !isAbsolute(transcriptPath)) return null;
  const file = resolve(transcriptPath);
  if (!CODEX_TRANSCRIPT.test(basename(file))) return null;
  const day = dirname(file);
  const month = dirname(day);
  const year = dirname(month);
  const sessions = dirname(year);
  if (!TWO_DIGITS.test(basename(day)) || !TWO_DIGITS.test(basename(month)) || !/^\d{4}$/.test(basename(year))) return null;
  return basename(sessions) === "sessions" && dirname(sessions) !== sessions ? dirname(sessions) : null;
}

// ── Roles of written paths ──────────────────────────────────────────────────

/**
 * A skill file named as a text document (Markdown, plain text): its own role
 * (`*-skill-doc`), cut into lines and reported like an instruction file. A
 * skill's other files — scripts, binaries — are code it runs, watched by sha;
 * so is a document that turns out not to be text, or to start with `#!`, and
 * one too long to compare line by line (enumerate.ts reads it).
 */
export const SKILL_DOC_NAME = /\.(?:md|markdown|mdx|txt|text|rst)$/i;
/**
 * SKILL_DOC_NAME's extensions in either case, whatever a role table's case mode
 * (`foldsCase`): enumeration tells a skill's documents from its scripts by them
 * on every platform.
 */
const DOC_EXT = SKILL_DOC_NAME.source.replace(/[a-z]/g, (c) => `[${c}${c.toUpperCase()}]`);
/** A skill's document below `skills/<name>/` (up to 8 directories further): the `*-skill-doc` role patterns, named as SKILL_DOC_NAME says. */
const SKILL_DOC_PATH = `skills/[^/]{1,255}/(?:[^/]{1,255}/){0,8}[^/]{1,255}${DOC_EXT}`;
/**
 * A Codex skill's SKILL.md below a skills root: Codex finds them at any depth
 * (up to 6), a skill's own folder or a namespace's; its other files below the
 * root (`*-skill-doc`, `*-skill-file`) are watched as Claude Code's skills' are.
 */
const CODEX_SKILL_MD = "skills/(?:[^/]{1,255}/){0,8}SKILL\\.md$";
const CODEX_SKILL_DOC = `skills/(?:[^/]{1,255}/){0,8}[^/]{1,255}${DOC_EXT}`;

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
  /** C: Codex's home. */
  codexHome?: string;
  /** S: Codex's system directory. */
  codexSystemDir?: string;
  /** The home directory: `~/.agents/skills` holds user-level Codex skills. */
  home?: string;
};

/** The lists the hooks match against; the Codex ones absent when no scope has any. */
export type PrefixLists = Pick<WatchPrefixes, "memoryDirs" | "configDirs" | "importTargets" | "hookScripts" | "codexDirs" | "codexDocs">;

export const PREFIX_LISTS = ["memoryDirs", "configDirs", "importTargets", "hookScripts", "codexDirs", "codexDocs"] as const;
/** Paths kept per `watch-prefixes.json` list. */
const MAX_PREFIX_ITEMS = 10_000;

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/**
 * The lists of a parsed `watch-prefixes.json` (non-empty strings, at most
 * 10,000 each; a list a file does not have is empty, and a Codex list absent),
 * or null unless it is a version-1 object: every scope's lists
 * (`stores`) together, and any at the top level. The file is unsigned: whatever
 * it lists only ever adds asks, so a path twice costs nothing but a compare.
 */
export function prefixListsOf(raw: unknown): PrefixLists | null {
  if (!isObject(raw) || raw.v !== 1) return null;
  const sources = [raw, ...(isObject(raw.stores) ? Object.values(raw.stores).filter(isObject) : [])];
  const lists = {} as PrefixLists;
  for (const name of PREFIX_LISTS) {
    const out: string[] = [];
    for (const source of sources) {
      const v = source[name];
      if (!Array.isArray(v)) continue;
      for (const s of v) {
        if (out.length >= MAX_PREFIX_ITEMS) break;
        if (typeof s === "string" && s !== "") out.push(s);
      }
    }
    if (out.length || (name !== "codexDirs" && name !== "codexDocs")) lists[name] = out;
  }
  return lists;
}

/**
 * Do the platform's default file systems compare names case-insensitively
 * (win32's and darwin's)? There a write to `claude.md` lands in `CLAUDE.md`, and
 * the role tables match in any case; elsewhere neither agent loads `claude.md`
 * or `docs/agents.md`, and they match exactly. Store keys are lower-cased on
 * win32 only either way (`storeKey`).
 */
export function foldsCase(platform: NodeJS.Platform): boolean {
  return platform === "win32" || platform === "darwin";
}

type RoleTable = readonly [RegExp, WatchedRole][];
/** A role table in both case modes: as written (case-insensitive) where names fold case, exact elsewhere (`foldsCase`). */
type RoleTables = { folded: RoleTable; exact: RoleTable };
const bothCases = (folded: RoleTable): RoleTables =>
  ({ folded, exact: folded.map(([re, role]) => [new RegExp(re.source, re.flags.replace("i", "")), role] as const) });

/**
 * Context-free patterns (forward-slash paths, `bothCases`), most specific
 * first. They mirror the `SENSITIVE_PATHS` write rules plus the auto-memory and
 * agent-memory locations; a path under `~/.claude` is refined to its user role by
 * the context check that runs before these.
 */
const STATIC_ROLES = bothCases([
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
  [new RegExp(`(?:^|/)\\.claude/${SKILL_DOC_PATH}`, "i"), "project-skill-doc"],
  [/(?:^|\/)\.claude\/skills\//i, "project-skill-file"],
  [/(?:^|\/)CLAUDE\.local\.md$/i, "ancestor-local-md"],
  [/(?:^|\/)CLAUDE\.md$/i, "ancestor-claude-md"],
  [/(?:^|\/)AGENTS\.md$/i, "ancestor-agents-md"],
]);

/**
 * Codex's context-free patterns: a project's `.codex/` and `.agents/skills/`,
 * AGENTS.override.md, the default system directory, and `~/.codex` itself
 * when C is not known. Tried only for a path CODEXISH finds a Codex name in, so
 * that a write elsewhere costs one test, not one per pattern.
 */
const CODEXISH = /(?:^|\/)(?:\.codex\/|\.agents\/skills\/|AGENTS\.override\.md$)|^\/etc\/codex\//i;
const CODEX_STATIC_ROLES = bothCases([
  [/(?:^|\/)AGENTS\.override\.md$/i, "codex-project-md"],
  [/^\/etc\/codex\/(?:config|requirements|managed_config)\.toml$/i, "codex-managed-config"],
  [/(?:^|\/)\.codex\/memories(?:_v2)?\/(?:memory_summary|MEMORY)\.md$/i, "codex-memory"],
  [/(?:^|\/)\.codex\/config\.toml$/i, "codex-project-config"],
  [/(?:^|\/)\.codex\/hooks\.json$/i, "codex-project-hooks"],
  [/(?:^|\/)\.codex\/rules\/[^/]{1,255}\.rules$/i, "codex-project-rules"],
  [new RegExp(`(?:^|/)\\.(?:codex|agents)/${CODEX_SKILL_MD}`, "i"), "codex-project-skill"],
  [new RegExp(`(?:^|/)\\.(?:codex|agents)/${CODEX_SKILL_DOC}`, "i"), "codex-project-skill-doc"],
  [/(?:^|\/)\.(?:codex|agents)\/skills\//i, "codex-project-skill-file"],
]);

/**
 * Roles of a path relative to Codex's home C (or a `codexDirs` prefix): its
 * instructions, config and profiles (`<name>.config.toml`), hooks, exec-policy
 * rules, skills and memories. `skills/.system`, the skills Codex itself
 * rewrites on install and upgrade, is not fingerprinted (enumerate.ts), but a
 * write there still has its role.
 */
const CODEX_HOME_ROLES = bothCases([
  [/^AGENTS(?:\.override)?\.md$/i, "codex-user-instructions"],
  [/^(?:[^/]{1,255}\.)?config\.toml$/i, "codex-user-config"],
  [/^hooks\.json$/i, "codex-user-hooks"],
  [/^rules\/[^/]{1,255}\.rules$/i, "codex-user-rules"],
  [new RegExp(`^${CODEX_SKILL_MD}`, "i"), "codex-user-skill"],
  [new RegExp(`^${CODEX_SKILL_DOC}`, "i"), "codex-user-skill-doc"],
  [/^skills\//i, "codex-user-skill-file"],
  [/^memories(?:_v2)?\/(?:memory_summary|MEMORY)\.md$/i, "codex-memory"],
]);

/** Roles of a path relative to Codex's system directory S. */
const CODEX_SYSTEM_ROLES = bothCases([
  [/^(?:config|requirements|managed_config)\.toml$/i, "codex-managed-config"],
]);

/** Roles of a path relative to the home directory: user-level Codex skills. */
const HOME_ROLES = bothCases([
  [new RegExp(`^\\.agents/${CODEX_SKILL_MD}`, "i"), "codex-user-skill"],
  [new RegExp(`^\\.agents/${CODEX_SKILL_DOC}`, "i"), "codex-user-skill-doc"],
  [/^\.agents\/skills\//i, "codex-user-skill-file"],
]);

/** Roles of a path relative to the config directory U (or a `configDirs` prefix). */
const CONFIG_DIR_ROLES = bothCases([
  [/^CLAUDE\.md$/i, "user-claude-md"],
  [/^settings\.json$/i, "user-settings"],
  [/^\.claude\.json$/i, "claude-json"],
  [/^rules\//i, "user-rules"],
  [/^agents\//i, "user-agent"],
  [/^commands\//i, "user-command"],
  [/^skills\/[^/]{1,255}\/SKILL\.md$/i, "user-skill"],
  [new RegExp(`^${SKILL_DOC_PATH}`, "i"), "user-skill-doc"],
  [/^skills\//i, "user-skill-file"],
  [/^agent-memory(?:-local)?\//i, "user-agent-memory"],
  [/^hooks\//i, "hook-script"],
  [/^projects\/[^/]{1,255}\/memory\/MEMORY\.md$/i, "auto-memory-index"],
  [/^projects\/[^/]{1,255}\/memory\/[^/]{1,255}\.md$/i, "auto-memory-topic"],
]);

/** Roles of a path relative to the managed directory M. */
const MANAGED_DIR_ROLES = bothCases([
  [/^CLAUDE\.md$/i, "managed-claude-md"],
  [/^managed-settings\.json$|^managed-settings\.d\/[^/]{1,255}\.json$/i, "managed-settings"],
  [/^managed-mcp\.json$/i, "managed-mcp"],
]);

const AGENT_MEMORY_DIR = /(?:^|\/)agent-memory(?:-local)?$/i;

/** A path's store `key` relative to `dir` as a store-key fragment (forward slashes;
 *  lower-cased on win32, where the role tables match in any case), or null
 *  when it is not strictly inside. */
function relativeKey(key: string, dir: string | null | undefined, platform: NodeJS.Platform): string | null {
  if (!dir) return null;
  const p = key;
  const d = storeKey(dir, platform);
  const prefix = d.endsWith("/") ? d : `${d}/`;
  return p.startsWith(prefix) && p.length > prefix.length ? p.slice(prefix.length) : null;
}

function firstMatch(rel: string | null, table: RoleTable): WatchedRole | null {
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
  const fold = foldsCase(platform);
  const t = (tables: RoleTables) => (fold ? tables.folded : tables.exact);

  if (ctx.appState?.some((j) => storeKey(j, platform) === key)) return "claude-json";
  const managed = firstMatch(relativeKey(key, ctx.managedDir, platform), t(MANAGED_DIR_ROLES));
  if (managed) return managed;
  const user = firstMatch(relativeKey(key, ctx.configDir, platform), t(CONFIG_DIR_ROLES));
  if (user) return user;
  const memory = memoryFileRole(relativeKey(key, ctx.autoMemoryDir, platform));
  if (memory) return memory;
  const codexSystem = firstMatch(relativeKey(key, ctx.codexSystemDir, platform), t(CODEX_SYSTEM_ROLES));
  if (codexSystem) return codexSystem;
  const codexUser = firstMatch(relativeKey(key, ctx.codexHome, platform), t(CODEX_HOME_ROLES));
  if (codexUser) return codexUser;
  const codexish = CODEXISH.test(slashed);
  if (codexish) {
    const homeSkill = firstMatch(relativeKey(key, ctx.home, platform), t(HOME_ROLES));
    if (homeSkill) return homeSkill;
  }
  const listsOf = () => (typeof prefixes === "function" ? prefixes() : prefixes);
  /** The role of `key` in a Codex home the context does not name (a `codexDirs` prefix: a CODEX_HOME another session used). */
  const inCodexDirs = (lists: PrefixLists | null | undefined): WatchedRole | null => {
    for (const dir of lists?.codexDirs ?? []) {
      const role = firstMatch(relativeKey(key, dir, platform), t(CODEX_HOME_ROLES));
      if (role) return role;
    }
    return null;
  };
  // AGENTS.md and AGENTS.override.md match a pattern wherever they are, but in such a Codex home they
  // are Codex's own instructions: the prefix lists are read for those names before the pattern answers
  for (const [re, role] of t(STATIC_ROLES)) if (re.test(slashed)) return role === "ancestor-agents-md" ? inCodexDirs(listsOf()) ?? role : role;
  if (codexish) for (const [re, role] of t(CODEX_STATIC_ROLES)) if (re.test(slashed)) return role === "codex-project-md" ? inCodexDirs(listsOf()) ?? role : role;

  const lists = listsOf();
  if (!lists) return null;
  for (const dir of lists.configDirs) {
    const role = firstMatch(relativeKey(key, dir, platform), t(CONFIG_DIR_ROLES));
    if (role) return role;
  }
  const codexDir = inCodexDirs(lists);
  if (codexDir) return codexDir;
  if (lists.codexDocs?.some((p) => storeKey(p, platform) === key)) return "codex-project-md";
  for (const dir of lists.memoryDirs) {
    const rel = relativeKey(key, dir, platform);
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
    return inside(ctx.root) || inside(ctx.configDir) || inside(ctx.codexHome) ? "import" : "external-import";
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
  /** Tests: Codex's system directory instead of the platform's. */
  codexSystemDir?: string;
};

/** The `watch-prefixes.json` lists, or null when missing or malformed. */
export function readPrefixLists(dataDir: string): PrefixLists | null {
  const read = readPrivateJson(join(dataDir, ...PREFIXES_FILE), MAX_PREFIX_BYTES);
  return read.state === "ok" ? prefixListsOf(read.value) : null;
}

/**
 * The watched role of `abs`, or null: §6.6 step 2 without touching the disk
 * for a path the patterns (or the payload's config dir U, the managed dir M,
 * the `.claude.json` app-state files, Codex's home C and system directory S)
 * recognise; otherwise the prefix lists, read once; otherwise all of that again
 * for the path through its real directory, when that differs. Both agents'
 * files are known whichever agent's session it is: Claude writing Codex's
 * AGENTS.md is gated as Codex writing CLAUDE.md is.
 */
export function writeRoleOf(abs: string, transcriptPath: unknown, deps: RoleDeps): WatchedRole | null {
  const p = deps.platform === "win32" ? win32 : posix;
  const transcript = typeof transcriptPath === "string" ? transcriptPath : undefined;
  const configDir = configDirFrom(transcript, deps).dir;
  const ctx: RoleContext = {
    platform: deps.platform,
    configDir,
    managedDir: deps.managedDir ?? managedDirFor(deps.platform, deps.env),
    appState: [p.join(deps.homedir, ".claude.json"), p.join(configDir, ".claude.json")],
    codexHome: codexHomeFrom(transcript, deps).dir,
    codexSystemDir: deps.codexSystemDir ?? codexSystemDirFor(deps.platform, deps.env),
    home: deps.homedir,
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
  "user-skill-doc": "a skill",
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
  "project-skill-doc": "a skill",
  "project-skill-file": "a skill",
  "project-agent-memory": "subagent memory",
  "claude-json-project": "MCP server config",
  "import": "project instructions",
  "external-import": "project instructions",
  "ledger-learned": "project instructions",
  "auto-memory-index": "auto memory",
  "auto-memory-topic": "auto memory",
  "codex-managed-config": "managed Codex config",
  "codex-user-instructions": "Codex user instructions",
  "codex-user-config": "Codex config",
  "codex-user-hooks": "Codex hooks",
  "codex-user-rules": "Codex exec-policy rules",
  "codex-user-skill": "a Codex skill",
  "codex-user-skill-doc": "a Codex skill",
  "codex-user-skill-file": "a Codex skill",
  "codex-memory": "Codex memory",
  "codex-project-md": "project instructions",
  "codex-project-config": "Codex project config",
  "codex-project-hooks": "Codex hooks",
  "codex-project-rules": "Codex exec-policy rules",
  "codex-project-skill": "a Codex skill",
  "codex-project-skill-doc": "a Codex skill",
  "codex-project-skill-file": "a Codex skill",
};

/** Roles of the files only Codex reads (the rest steer Claude Code, and AGENTS.md both). */
const CODEX_ROLES: ReadonlySet<WatchedRole> = new Set<WatchedRole>([
  "codex-managed-config", "codex-user-instructions", "codex-user-config", "codex-user-hooks", "codex-user-rules", "codex-user-skill",
  "codex-user-skill-doc", "codex-user-skill-file", "codex-memory", "codex-project-md", "codex-project-config", "codex-project-hooks",
  "codex-project-rules", "codex-project-skill", "codex-project-skill-doc", "codex-project-skill-file",
]);

/** Is this a file only Codex reads (its config, hooks, rules, skills, memories, `AGENTS.override.md`)? */
export function isCodexRole(role: WatchedRole): boolean {
  return CODEX_ROLES.has(role);
}

/** The short noun phrase PreToolUse messages use for a role ("project instructions", "a hook script", …). */
export function labelOf(role: WatchedRole): string {
  return LABELS[role];
}

