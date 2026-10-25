/**
 * Instruction-file integrity — the watched set (spec §3.2-3.5) and how each
 * file in it is read (§3.7).
 *
 * `enumerateWatched(ctx, opts)` walks the user-level, project and memory
 * stores' patterns for a resolved context — the user-level store is the
 * session's agent's: Claude Code's (`global`: U, M and the app-state files) or
 * Codex's (`codex`: C, S and `~/.agents/skills`); the project store holds both
 * agents' project files whichever agent's session it is, so neither reads the
 * other's as deleted — derives the hook scripts and `@imports` those files
 * reference (and the instruction files a Codex config names), adds the
 * ledger-learned paths it is given, and returns one snapshot entry per path
 * with its state, sha256, size, stat tuple and link text, plus (in memory
 * only) the bytes it read, for the caller to cut into units. It also returns
 * the `watch-prefixes.json` lists (§4.7), by scope.
 *
 * Mechanics:
 * - every path is `lstat`ed first; a symlink's `readlink` text is recorded and
 *   its target is hashed (Claude Code follows it), and the store key of the file
 *   it reaches is noted (for attribution); symlinked directories are never
 *   descended into;
 * - stat fast path: on POSIX, an entry whose `[size, mtimeMs, ctimeMs, ino, dev]`
 *   and link text match its baseline reuses the baseline sha without reading
 *   (win32 always re-reads); files whose text feeds hook-script or import
 *   discovery are always read, and an import target already enumerated under
 *   another role (an agent, a command) is read again for its own `@imports`
 *   when the fast path skipped it, so following imports never depends on it;
 * - caps: 200 candidates per directory (files the role's pattern takes and
 *   subdirectories still to be searched; other entries do not count), 400
 *   files per run, spent in priority order (`TIER`: settings and MCP config, hook
 *   scripts, launch-loaded instructions, imports and auto memory, on-demand
 *   files, skill support files) while each store and role is still settled in
 *   enumeration order, 4 MiB per file
 *   (`oversize`: size and stat only; a hook script that large is hashed whole,
 *   sha only, since it is code that runs), MAX_FILE_UNITS units per file (a
 *   hook script with more is watched by sha only too, and a skill's document
 *   with more by sha as the skill's other files are), 16 MiB hashed per run,
 *   `~/.claude.json` over 20 MiB, 64 ancestor levels (R's own always checked);
 *   anything past a cap is `unhashed` and the snapshot is marked incomplete;
 *   `@import` tokens are looked up at most 500 distinct paths per run;
 * - a hook command's script candidates are its words as bash reads them and as
 *   PowerShell does (`splitCommandWords` with and without escapes), plus any
 *   exec-form `args`; Codex's hooks, `notify` and MCP servers are read from its
 *   hooks.json and config.toml layers, relative scripts against the cwd (Codex
 *   runs them there);
 * - Codex's own system skills (`C/skills/.system`, which Codex rewrites on
 *   install and upgrade) are not walked, as Claude Code's plugin caches are not;
 * - files are opened non-blocking and checked to be regular files on the open
 *   descriptor, so a FIFO planted at a watched path never hangs the hook.
 *
 * Only the filesystem is touched; no subprocess, no network.
 */

import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, opendirSync, openSync, readlinkSync, readSync, statSync, type Dir, type Dirent, type Stats } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { canonicalJson } from "../../shared/sign.js";
import { nexusEntryScripts } from "../hook-command.js";
import { levelsDown, type IntegrityContext } from "./context.js";
import { importRoleOf, MAX_IMPORT_DEPTH, MAX_IMPORT_LOOKUPS, MAX_IMPORT_TARGETS, resolveImports, type ImportSource } from "./imports.js";
import { splitCommandWords } from "./nexus-hook.js";
import {
  canonicalDir, canonicalPath, h16, isUnder, memoryStoreId, onDiskPath, projectStoreId, realPathOrNull, SKILL_DOC_NAME, storeKey, userStoreId,
} from "./paths.js";
import { readToml, type TomlDoc } from "./toml.js";
import {
  MAX_CLAUDE_JSON_BYTES, MAX_DIR_ENTRIES, MAX_FILE_BYTES, MAX_FILE_UNITS, MAX_FILES_PER_RUN, MAX_HASHED_BYTES_PER_RUN, ROLE_UNITS,
  type EntryState, type StatTuple, type StoreEntry, type StoreId, type StoreKind, type WatchPrefixes, type WatchedRole,
} from "./types.js";
import {
  decodeText, execCommandsOf, nexusHookOf, projectClaudeJson, sha256Hex, tomlExecCommands, tomlInstructionFiles, unitBound, type ExecCommand,
} from "./units.js";

// ── Limits ──────────────────────────────────────────────────────────────────

export type EnumerateLimits = {
  /** Entries handled per enumerated directory; later (sorted) entries are `unhashed`. */
  maxDirEntries: number;
  /** Directory entries read at all; a larger directory is only partly known (incomplete). */
  dirScanLimit: number;
  maxFiles: number;
  maxFileBytes: number;
  /**
   * Units a file read this run may be cut into (`unitBound`): classification
   * cannot stop inside one file, so a file with more is `unhashed` (a hook
   * script: sha only), its content not kept.
   */
  maxFileUnits: number;
  maxHashedBytes: number;
  maxClaudeJsonBytes: number;
  /**
   * Ancestor levels (cwd and its nearest ancestors) checked for CLAUDE.md-style
   * files; R's level is checked as well, and files at the levels past the cap
   * are recorded `unhashed`.
   */
  maxAncestors: number;
  maxImportDepth: number;
  maxImportTargets: number;
  /** Distinct `@import` token paths looked up per run (an `@mention` that names no file is one). */
  maxImportLookups: number;
  maxHookScripts: number;
};

export const ENUMERATE_LIMITS: Readonly<EnumerateLimits> = {
  maxDirEntries: MAX_DIR_ENTRIES,
  dirScanLimit: 2000,
  maxFiles: MAX_FILES_PER_RUN,
  maxFileBytes: MAX_FILE_BYTES,
  maxFileUnits: MAX_FILE_UNITS,
  maxHashedBytes: MAX_HASHED_BYTES_PER_RUN,
  maxClaudeJsonBytes: MAX_CLAUDE_JSON_BYTES,
  maxAncestors: 64,
  maxImportDepth: MAX_IMPORT_DEPTH,
  maxImportTargets: MAX_IMPORT_TARGETS,
  maxImportLookups: MAX_IMPORT_LOOKUPS,
  maxHookScripts: 50,
};

// ── Snapshot shapes ─────────────────────────────────────────────────────────

/** One watched path as found this run. */
export type SnapshotEntry = {
  /** Canonical path (the directory's real path plus the file's own name). */
  path: string;
  /** Store key (forward slashes, lower-cased on win32). */
  key: string;
  role: WatchedRole;
  state: EntryState;
  /** Whole-file sha256 (for the `claude-json` roles: of the canonical projection); null when not hashed. */
  sha256: string | null;
  size: number | null;
  stat: StatTuple | null;
  /** `readlink` text when the path is a symlink. */
  link: string | null;
  /**
   * For a symlink that reaches a file, that file's store key (its real path),
   * when it differs from `key`: a write through either name changes both
   * entries, so attribution reads that key's ledger records too. Never persisted.
   */
  target?: string;
  /** The bytes read this run (the projection for `claude-json` roles); null when not read. Never persisted. */
  content: Buffer | null;
  /** The sha came from the baseline because the stat tuple was unchanged (nothing was read). */
  reused: boolean;
  /**
   * Watched by whole-file sha only, its bytes never held: a hook script over the
   * per-file cap (Claude Code still runs it). It has no units.
   */
  shaOnly?: true;
  /**
   * A `.claude.json` that is not valid JSON — most often one read while Claude
   * Code rewrites it: `unhashed` for this run, its baseline kept and compared
   * next run, its raw bytes never diffed; not a scan-limit gap.
   */
  unparsed?: true;
};

export type StoreSnapshot = {
  kind: StoreKind;
  id: StoreId;
  /** null for the user-level store (`global` or `codex`); R for the project store; A for the memory store. */
  root: string | null;
  /** Keyed by store key, in enumeration order. */
  entries: Record<string, SnapshotEntry>;
};

/** The `watch-prefixes.json` lists (§4.7), absolute canonical paths, sorted. */
export type WatchPrefixData = Pick<WatchPrefixes, "memoryDirs" | "configDirs" | "importTargets" | "hookScripts" | "codexDirs" | "codexDocs">;

export type Snapshot = {
  /** The user-level store of the session's agent: Claude Code's `global`, or Codex's `codex`. */
  global: StoreSnapshot;
  project: StoreSnapshot;
  /** null when auto memory was not located. */
  memory: StoreSnapshot | null;
  /**
   * Where this run looked for the user-level store's files, as store keys: U and
   * M (directories) and `~/.claude.json` with the rest of J (files); for Codex's
   * store, C, S and `~/.agents/skills`. Each user-level store is shared by
   * every config dir of its agent; a baseline key outside these belongs to
   * another one (another CLAUDE_CONFIG_DIR or CODEX_HOME) and was not looked at.
   */
  globalScope: { dirs: string[]; files: string[] };
  /**
   * This run's `watch-prefixes.json` lists, by the scope a SessionStart replaces
   * (store.ts `nextWatchPrefixScopes`): the user-level store's for this Claude
   * config dir (`config-<h16(U)>`) or Codex home (`codex-<h16(C)>`), the project
   * store's as seen from this cwd (`project-<h16(R)>`, plus `-<h16(cwd)>` below
   * R: a monorepo package's sessions find other imports and hooks than the
   * root's), and the auto-memory store's (its id).
   */
  prefixScopes: Record<string, WatchPrefixData>;
  /** Entries left `unhashed` by a cap, by store then key; status reports the check as incomplete. */
  unhashed: { store: StoreId; key: string }[];
  /** A cap was hit (an unhashed entry, a directory too large to read, or the import/hook-script cap). */
  incomplete: boolean;
  /** Bytes read and hashed this run. */
  hashedBytes: number;
  /** Files (not missing candidates) counted against the per-run cap. */
  files: number;
};

/** The baseline fields the stat fast path compares. */
export type BaselineEntry = Pick<StoreEntry, "state" | "sha256" | "stat" | "link">;

export type EnumerateOptions = {
  /** Accepted entries per store kind, keyed by store key, for the stat fast path. */
  baseline?: Partial<Record<StoreKind, Readonly<Record<string, BaselineEntry>> | null>>;
  /** Instruction-file paths from valid ledger records (e.g. a nested `src/api/CLAUDE.md`). */
  ledgerLearned?: readonly string[];
  limits?: Partial<EnumerateLimits>;
  /**
   * This Nexus install's entry scripts (default: `nexusEntryScripts()`). Only a
   * Nexus hook command naming one of them has its script left unwatched.
   */
  nexusEntries?: readonly string[];
  /**
   * Entries to read wherever they are, after the rest: the held entries of the
   * stores (the CLI). A HOLD found from a session's cwd — a nested
   * `packages/api/CLAUDE.md` — is not enumerated from the repository root.
   */
  held?: readonly { store: StoreKind; path: string; role: WatchedRole }[];
};

// ── Role groups ─────────────────────────────────────────────────────────────

/** Files whose `@imports` are followed. */
const IMPORT_SOURCE_ROLES: ReadonlySet<WatchedRole> = new Set<WatchedRole>([
  "managed-claude-md", "user-claude-md", "user-rules",
  "ancestor-claude-md", "ancestor-local-md", "ancestor-agents-md", "project-rules",
  "import", "external-import",
]);

/**
 * Files whose commands name hook scripts, and the directory a relative script
 * resolves against. Codex runs its hooks, `notify` and MCP servers in the
 * session's cwd.
 */
const HOOK_SOURCE_BASE: Partial<Record<WatchedRole, "root" | "config" | "managed" | "cwd">> = {
  "managed-settings": "managed",
  "managed-mcp": "managed",
  "user-settings": "config",
  "claude-json": "config",
  "project-settings": "root",
  "local-settings": "root",
  "project-mcp": "root",
  "claude-json-project": "root",
  "codex-managed-config": "cwd",
  "codex-user-config": "cwd",
  "codex-user-hooks": "cwd",
  "codex-project-config": "cwd",
  "codex-project-hooks": "cwd",
};

const isMarkdown = (name: string) => /\.md$/i.test(name);

/**
 * Files editors and file managers leave beside the ones being edited, which
 * Claude Code never loads: Emacs's lock link `.#name` and autosave `#name#`,
 * Vim's swap files `.name.swp` (`.swo`, …), `name~` backups, macOS's
 * `.DS_Store`. Directory walks skip them.
 */
const EDITOR_ARTIFACT = /^\.#|^#.*#$|~$|^\..*\.sw[a-p]$|^\.DS_Store$/;

/** A skill document's role, and the role it has when its bytes are not plain text after all. */
const SKILL_SCRIPT_ROLE: Partial<Record<WatchedRole, WatchedRole>> = {
  "user-skill-doc": "user-skill-file", "project-skill-doc": "project-skill-file",
  "codex-user-skill-doc": "codex-user-skill-file", "codex-project-skill-doc": "codex-project-skill-file",
};

/** A Codex skill file's role by its name below the skills root: SKILL.md (any case, as Codex matches it), a text document, or another file. */
type SkillRoles = { skill: WatchedRole; doc: WatchedRole; file: WatchedRole };
const CODEX_USER_SKILLS: SkillRoles = { skill: "codex-user-skill", doc: "codex-user-skill-doc", file: "codex-user-skill-file" };
const CODEX_PROJECT_SKILLS: SkillRoles = { skill: "codex-project-skill", doc: "codex-project-skill-doc", file: "codex-project-skill-file" };
/** Codex's skills root keeps the skills it ships here, and rewrites them on install and upgrade. */
const CODEX_SYSTEM_SKILLS = ".system";
/** How deep below a skills root Codex looks for SKILL.md (its loader's MAX_SCAN_DEPTH). */
const CODEX_SKILL_DEPTH = 6;

/** UTF-8 text with no NUL byte that does not start with `#!` (after a BOM). */
function plainText(bytes: Buffer): boolean {
  const at = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
  return !(bytes[at] === 0x23 && bytes[at + 1] === 0x21) && decodeText(bytes) !== null;
}

// ── Reading one file ────────────────────────────────────────────────────────

function tupleOf(st: Stats): StatTuple {
  return [st.size, st.mtimeMs, st.ctimeMs, st.ino, st.dev];
}

function sameTuple(a: StatTuple | null | undefined, b: StatTuple): boolean {
  return !!a && a.length === 5 && a.every((v, i) => v === b[i]);
}

/** Bytes of a regular file, opened without blocking on a FIFO; `oversize` when it is (or grew) past `max`. */
function readRegular(path: string, max: number): { bytes: Buffer; stat: Stats } | "oversize" | "unreadable" {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch {
    return "unreadable";
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) return "unreadable";
    if (stat.size > max) return "oversize";
    const chunks: Buffer[] = [];
    let total = 0;
    const buf = Buffer.allocUnsafe(Math.min(Math.max(stat.size, 1), 1 << 20) + 1);
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      total += n;
      if (total > max) return "oversize";
      chunks.push(Buffer.from(buf.subarray(0, n)));
    }
    return { bytes: Buffer.concat(chunks, total), stat };
  } catch {
    return "unreadable";
  } finally {
    closeSync(fd);
  }
}

/**
 * The sha256 of a regular file read in chunks, nothing kept; `over` once more
 * than `max` bytes were read (it grew past the budget). Non-blocking, like `readRegular`.
 */
function hashRegular(path: string, max: number): { sha: string; size: number; stat: Stats } | "over" | "unreadable" {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch {
    return "unreadable";
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) return "unreadable";
    if (stat.size > max) return "over";
    const hash = createHash("sha256");
    const buf = Buffer.allocUnsafe(1 << 20);
    let total = 0;
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      total += n;
      if (total > max) return "over";
      hash.update(buf.subarray(0, n));
    }
    return { sha: hash.digest("hex"), size: total, stat };
  } catch {
    return "unreadable";
  } finally {
    closeSync(fd);
  }
}

function safeLstat(path: string): Stats | undefined {
  try {
    return lstatSync(path, { throwIfNoEntry: false });
  } catch {
    return undefined;
  }
}

function safeStat(path: string): Stats | undefined {
  try {
    return statSync(path, { throwIfNoEntry: false });
  } catch {
    return undefined;
  }
}

/** A directory's entries, sorted by name, at most `scanLimit` read. Null when it is not a readable directory. */
function listDir(dir: string, scanLimit: number): { entries: Dirent[]; overflow: boolean } | null {
  let handle: Dir;
  try {
    handle = opendirSync(dir);
  } catch {
    return null;
  }
  const entries: Dirent[] = [];
  let overflow = false;
  try {
    for (;;) {
      const entry = handle.readSync();
      if (!entry) break;
      if (entries.length >= scanLimit) { overflow = true; break; }
      entries.push(entry);
    }
  } catch {
    // unreadable mid-way: keep what was read
  } finally {
    handle.closeSync();
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { entries, overflow };
}

// ── Hook-script commands ────────────────────────────────────────────────────

const PROJECT_DIR_OR_HOME = /\$\{(CLAUDE_PROJECT_DIR|HOME|CODEX_HOME)\}|\$(CLAUDE_PROJECT_DIR|HOME|CODEX_HOME)(?![A-Za-z0-9_])/g;

/**
 * The file a command word names, if it can be one: `$CLAUDE_PROJECT_DIR` /
 * `${CLAUDE_PROJECT_DIR}` → R, `$CODEX_HOME` → Codex's home (when given), and
 * `~`, `$HOME`, `${HOME}` → home expanded; then an absolute path as is, or a
 * relative one containing a slash against `base`.
 */
export function scriptPathOf(word: string, base: string, root: string, home: string, platform: NodeJS.Platform, codexHome?: string): string | null {
  let w = word.replace(PROJECT_DIR_OR_HOME, (m: string, braced: string | undefined, bare: string | undefined) => {
    const name = braced ?? bare;
    return name === "HOME" ? home : name === "CODEX_HOME" ? codexHome ?? m : root;
  });
  if (w === "~") w = home;
  else if (w.startsWith("~/")) w = join(home, w.slice(2));
  if (isAbsolute(w)) return resolve(w);
  const hasSlash = w.includes("/") || (platform === "win32" && w.includes("\\"));
  return hasSlash ? resolve(base, w) : null;
}

// ── Enumeration ─────────────────────────────────────────────────────────────

type ProbeOpts = {
  /** Record a candidate that does not exist as `missing` (fixed paths and ancestor candidates). */
  recordMissing?: boolean;
  /** Read the file even when the stat fast path would reuse the baseline sha. */
  needText?: boolean;
  /** The path is past a directory cap: record it `unhashed` without reading. */
  capped?: boolean;
  /** Over the per-file cap, hash it whole (sha only, within the run's hash budget) instead of `oversize`. */
  shaOnlyIfLarge?: boolean;
};

/**
 * The order the per-run file cap is spent in (§3.7): settings, MCP config and
 * the `~/.claude.json` projections; then hook scripts (read as they are found);
 * then the instruction files every session loads at launch; then `@import`
 * targets and auto memory; then on-demand agents, commands and skills (with
 * agent memory and ledger-learned paths); last, skill support files.
 */
const TIER = { config: 0, launch: 1, importsAndMemory: 2, onDemand: 3, skillFiles: 4 } as const;
type Tier = (typeof TIER)[keyof typeof TIER];

/** Enumerate, read and hash the watched set for `ctx` (see the module comment). */
export function enumerateWatched(ctx: IntegrityContext, opts: EnumerateOptions = {}): Snapshot {
  const limits: EnumerateLimits = { ...ENUMERATE_LIMITS, ...opts.limits };
  const { platform } = ctx;
  const posix = platform !== "win32";
  const run = { files: 0, hashed: 0, incomplete: false, hookScripts: 0, importTargets: 0, importLookups: 0 };
  const ownEntries = new Set((opts.nexusEntries ?? nexusEntryScripts()).map((p) => storeKey(realPathOrNull(p) ?? canonicalPath(p), platform)));

  /**
   * A hook that is exactly a Nexus guard command (shell form, no `args`) naming
   * this install's own entry script: that script is not watched, so rebuilding
   * Nexus's own dist/ is not a change. The same command naming any other file
   * (a repo's own `dist/guard/hook.js`) is watched like every hook script.
   */
  const isOwnNexusHook = (cmd: ExecCommand): boolean => {
    if (cmd.kind !== "hook" || cmd.args.length > 0) return false;
    const script = nexusHookOf(cmd.command)?.script;
    if (!script) return false;
    const abs = resolve(script);
    return ownEntries.has(storeKey(realPathOrNull(abs) ?? canonicalPath(abs), platform));
  };

  const codex = ctx.agent === "codex";
  const global: StoreSnapshot = { kind: "global", id: userStoreId(ctx.agent), root: null, entries: {} };
  const project: StoreSnapshot = { kind: "project", id: projectStoreId(ctx.root, platform), root: ctx.root, entries: {} };
  const memory: StoreSnapshot | null = ctx.autoMemoryDir
    ? { kind: "memory", id: memoryStoreId(ctx.autoMemoryDir, platform), root: ctx.autoMemoryDir, entries: {} }
    : null;
  /** Import targets found from each store's sources (`watch-prefixes.json` scopes). */
  const importTargets = new Map<StoreSnapshot, Set<string>>([[global, new Set()], [project, new Set()]]);

  /**
   * Fixed and walked candidates are claimed first, in enumeration order, which
   * settles each one's store and role; they are read later, tier by tier, so the
   * per-run cap is spent in priority order. `order` keeps each store's entries in
   * enumeration order (claims, then derived entries as they are found).
   */
  type Claim = { store: StoreSnapshot; path: string; canonical: string; key: string; role: WatchedRole; o: ProbeOpts };
  const claims = new Map<string, Claim>();
  const tiers: Claim[][] = Object.values(TIER).map(() => []);
  const order = new Map<string, number>();
  const slot = (store: StoreSnapshot, key: string) => `${store.id}\0${key}`;

  const blank = (path: string, key: string, role: WatchedRole): SnapshotEntry =>
    ({ path, key, role, state: "missing", sha256: null, size: null, stat: null, link: null, content: null, reused: false });

  const add = (store: StoreSnapshot, entry: SnapshotEntry): SnapshotEntry => {
    if (entry.state === "unhashed" && !entry.unparsed) run.incomplete = true;
    const s = slot(store, entry.key);
    if (!order.has(s)) order.set(s, order.size);
    store.entries[entry.key] = entry;
    return entry;
  };

  /** Settle `store`'s claim on `path` (with this role) for its tier, unless a store already holds or claims it. */
  function claim(tier: Tier, store: StoreSnapshot, path: string, role: WatchedRole, o: ProbeOpts = {}): void {
    const canonical = canonicalPath(path);
    const key = storeKey(canonical, platform);
    const s = slot(store, key);
    if (claims.has(s) || store.entries[key]) return;
    if (store !== global && (claims.has(slot(global, key)) || global.entries[key])) return; // the global store watches it
    const c: Claim = { store, path, canonical, key, role, o };
    claims.set(s, c);
    order.set(s, order.size);
    tiers[tier].push(c);
  }

  /** Read a claimed candidate now (its tier came, or something it is needed for came first). */
  function settle(c: Claim): SnapshotEntry | null {
    claims.delete(slot(c.store, c.key));
    return read(c.store, c.path, c.canonical, c.key, c.role, c.o);
  }

  const settleTier = (tier: Tier): void => {
    for (const c of tiers[tier]) if (claims.has(slot(c.store, c.key))) settle(c);
  };

  /** `store`'s entry for `key`, read now if it was only claimed; undefined when the store neither holds nor claims it. */
  function held(store: StoreSnapshot, key: string): SnapshotEntry | null | undefined {
    const entry = store.entries[key];
    if (entry) return entry;
    const c = claims.get(slot(store, key));
    return c ? settle(c) : undefined;
  }

  /** Does the global or project store hold or claim `key`? */
  const watched = (key: string): boolean =>
    [global, project].some((s) => !!s.entries[key] || claims.has(slot(s, key)));

  /**
   * A path found by following references (a hook script, an import target, a
   * ledger-learned path): the entry a store already has or claims for it, or
   * `store`'s new one. A store never takes a path the other one watches.
   */
  function probe(store: StoreSnapshot, path: string, role: WatchedRole, o: ProbeOpts = {}): SnapshotEntry | null {
    const canonical = canonicalPath(path);
    const key = storeKey(canonical, platform);
    const own = held(store, key);
    if (own !== undefined) return own;
    if (watched(key)) return null;
    return read(store, path, canonical, key, role, o);
  }

  /** Find, stat and (unless the fast path applies) read one path into `store`. */
  function read(store: StoreSnapshot, path: string, canonical: string, key: string, role: WatchedRole, o: ProbeOpts): SnapshotEntry | null {
    const existing = store.entries[key];
    if (existing) return existing;
    const entry = blank(canonical, key, role);
    if (o.capped) return add(store, { ...entry, state: "unhashed" });

    const lst = safeLstat(path);
    if (!lst) return o.recordMissing ? add(store, entry) : null;
    let st: Stats | undefined = lst;
    if (lst.isSymbolicLink()) {
      try { entry.link = readlinkSync(path); } catch { entry.link = ""; }
      st = safeStat(path);
      if (!st?.isFile()) return add(store, entry); // dangling, or a link to a directory: missing, link kept
      const real = realPathOrNull(path);
      const target = real === null ? key : storeKey(real, platform);
      if (target !== key) entry.target = target;
    } else if (!lst.isFile()) {
      return o.recordMissing ? add(store, entry) : null; // a directory or device where a file is expected
    }

    entry.size = st.size;
    entry.stat = tupleOf(st);
    if (run.files >= limits.maxFiles) return add(store, { ...entry, state: "unhashed" });
    run.files++;
    const large = st.size > limits.maxFileBytes;
    if (large && !o.shaOnlyIfLarge) return add(store, { ...entry, state: "oversize" });
    const shaOnly = large ? { shaOnly: true as const } : {};

    const prior = opts.baseline?.[store.kind]?.[key];
    if (!o.needText && posix && prior?.state === "file" && prior.sha256 && sameTuple(prior.stat, entry.stat) && (prior.link ?? null) === entry.link) {
      return add(store, { ...entry, state: "file", sha256: prior.sha256, reused: true, ...shaOnly });
    }
    if (run.hashed + st.size > limits.maxHashedBytes) return add(store, { ...entry, state: "unhashed" });
    if (large) {
      const hashed = hashRegular(path, limits.maxHashedBytes - run.hashed);
      if (typeof hashed === "string") return add(store, { ...entry, state: "unhashed" });
      run.hashed += hashed.size;
      return add(store, { ...entry, state: "file", sha256: hashed.sha, size: hashed.size, stat: tupleOf(hashed.stat), shaOnly: true });
    }

    const bytes = readRegular(path, limits.maxFileBytes);
    if (bytes === "oversize") return add(store, { ...entry, state: "oversize" });
    if (bytes === "unreadable") return add(store, { ...entry, state: "unhashed" });
    run.hashed += bytes.bytes.length;
    let units = unitBound(role, bytes.bytes);
    // a skill document that is not text, or starts with `#!`, is a script: watched by sha as code that runs;
    // one with more lines than a file may have units is watched by sha too, as the skill's other files are,
    // so that a change to it still waits for review rather than going past a cap
    if (role in SKILL_SCRIPT_ROLE && (units > limits.maxFileUnits || !plainText(bytes.bytes))) {
      role = entry.role = SKILL_SCRIPT_ROLE[role]!;
      units = unitBound(role, bytes.bytes);
    }
    const file = { ...entry, state: "file" as const, sha256: sha256Hex(bytes.bytes), size: bytes.bytes.length, stat: tupleOf(bytes.stat) };
    if (units > limits.maxFileUnits) {
      // too many units to diff within the deadline: code that runs keeps its sha, anything else is past a cap
      return add(store, o.shaOnlyIfLarge ? { ...file, shaOnly: true } : { ...entry, state: "unhashed" });
    }
    return add(store, { ...file, content: bytes.bytes });
  }

  /** A `.claude.json` file, reduced to its projection before hashing (only the projection is kept). */
  function probeAppState(store: StoreSnapshot, path: string, role: "claude-json" | "claude-json-project"): void {
    const canonical = canonicalPath(path);
    const key = storeKey(canonical, platform);
    if (store.entries[key]) return;
    const entry = blank(canonical, key, role);
    const lst = safeLstat(path);
    if (!lst) return;
    if (lst.isSymbolicLink()) {
      try { entry.link = readlinkSync(path); } catch { entry.link = ""; }
    }
    const st = safeStat(path);
    if (!st?.isFile()) { add(store, entry); return; }
    entry.size = st.size;
    entry.stat = tupleOf(st);
    if (run.files >= limits.maxFiles || st.size > limits.maxClaudeJsonBytes) { add(store, { ...entry, state: "unhashed" }); return; }
    run.files++;
    const read = readRegular(path, limits.maxClaudeJsonBytes);
    if (typeof read === "string") { add(store, { ...entry, state: "unhashed" }); return; }
    let content: Buffer;
    try {
      const text = read.bytes.toString("utf-8");
      const parsed: unknown = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
      content = Buffer.from(canonicalJson(projectClaudeJson(parsed, role, ctx)), "utf-8");
    } catch {
      add(store, { ...entry, state: "unhashed", unparsed: true }); // compared again next run (`unparsed`)
      return;
    }
    if (unitBound(role, content) > limits.maxFileUnits) { add(store, { ...entry, state: "unhashed" }); return; }
    run.hashed += content.length;
    add(store, { ...entry, state: "file", sha256: sha256Hex(content), size: st.size, stat: tupleOf(read.stat), content });
  }

  /**
   * Claim the files under `dir` (to `depth` levels) whose path relative to `dir`
   * passes `accept`. Only candidates count toward the per-directory cap — files
   * `accept` takes and subdirectories still to be searched — so files the walk
   * does not watch cannot push a watched one past it. `tier` and `role` may
   * depend on the file (a Codex skill's SKILL.md is read before its scripts).
   */
  function walk(
    tier: Tier | ((rel: string) => Tier), store: StoreSnapshot, dir: string, depth: number, role: WatchedRole | ((rel: string) => WatchedRole),
    accept: (rel: string) => boolean, o: ProbeOpts = {}, rel = "",
  ): void {
    const listing = listDir(dir, limits.dirScanLimit);
    if (!listing) return;
    if (listing.overflow) run.incomplete = true;
    let candidates = 0;
    for (const ent of listing.entries) {
      const path = join(dir, ent.name);
      const r = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) {
        if (depth <= 1) continue;
        if (candidates++ >= limits.maxDirEntries) run.incomplete = true;
        else walk(tier, store, path, depth - 1, role, accept, o, r);
        continue;
      }
      if (!(ent.isFile() || ent.isSymbolicLink()) || EDITOR_ARTIFACT.test(ent.name) || !accept(r)) continue;
      if (ent.isSymbolicLink()) {
        // symlinked directories are not followed; a dangling link is nothing Claude Code can load
        const st = safeStat(path);
        if (!st || st.isDirectory()) continue;
      }
      claim(typeof tier === "function" ? tier(r) : tier, store, path, typeof role === "function" ? role(r) : role, { ...o, capped: candidates++ >= limits.maxDirEntries });
    }
  }

  /**
   * A Codex skills root: every file below it to CODEX_SKILL_DEPTH, SKILL.md
   * (Codex's skills, at any depth) read with the on-demand files and the rest
   * with the skills' support files; `skip`, a top-level directory not walked.
   */
  function codexSkills(store: StoreSnapshot, root: string, roles: SkillRoles, skip?: string): void {
    const roleOf = (r: string) => (basename(r).toLowerCase() === "skill.md" ? roles.skill : SKILL_DOC_NAME.test(r) ? roles.doc : roles.file);
    const tierOf = (r: string) => (basename(r).toLowerCase() === "skill.md" ? TIER.onDemand : TIER.skillFiles);
    walk(tierOf, store, root, 1, roleOf, () => true);
    for (const sub of subdirs(root)) {
      const name = basename(sub);
      if (name !== skip) walk(tierOf, store, sub, CODEX_SKILL_DEPTH, roleOf, () => true, {}, name);
    }
  }

  /** The real (non-symlink) subdirectories of `dir`, within the per-directory cap (which only they count toward). */
  function subdirs(dir: string): string[] {
    const listing = listDir(dir, limits.dirScanLimit);
    if (!listing) return [];
    const dirs = listing.entries.filter((e) => e.isDirectory());
    if (listing.overflow || dirs.length > limits.maxDirEntries) run.incomplete = true;
    return dirs.slice(0, limits.maxDirEntries).map((e) => join(dir, e.name));
  }

  /** A Codex config's TOML, read once per entry this run. */
  const tomlDocs = new Map<SnapshotEntry, TomlDoc>();
  const tomlOf = (entry: SnapshotEntry): TomlDoc => {
    let doc = tomlDocs.get(entry);
    if (!doc) tomlDocs.set(entry, (doc = readToml(entry.content!.toString("utf-8"))));
    return doc;
  };

  /** The commands a settings, MCP, hooks or Codex config file makes its agent run. */
  function commandsOf(source: SnapshotEntry): ExecCommand[] {
    if (ROLE_UNITS[source.role] === "toml") return tomlExecCommands(tomlOf(source));
    let parsed: unknown;
    try { parsed = JSON.parse(source.content!.toString("utf-8").replace(/^\ufeff/, "")); } catch { return []; }
    return execCommandsOf(parsed);
  }

  function hookScripts(store: StoreSnapshot): void {
    const bases = { root: ctx.root, config: ctx.configDir, managed: ctx.managedDir, cwd: ctx.cwd };
    const roots = [ctx.root, ctx.configDir, ctx.managedDir, ctx.codexHome, ctx.codexSystemDir];
    for (const source of Object.values(store.entries)) {
      const base = HOOK_SOURCE_BASE[source.role];
      if (!base || !source.content) continue;
      for (const cmd of commandsOf(source)) {
        if (isOwnNexusHook(cmd)) continue; // rebuilding Nexus's own dist/ must not read as a change
        // the words as bash reads them and as PowerShell does (a backslash kept), so
        // neither shell's reading of `\"` or a Windows path hides a script
        const words = new Set([...splitCommandWords(cmd.command), ...splitCommandWords(cmd.command, false), ...cmd.args]);
        for (const word of words) {
          const path = scriptPathOf(word, bases[base], ctx.root, ctx.home, platform, ctx.codexHome);
          if (!path) continue;
          const st = safeStat(path);
          if (!st?.isFile()) continue;
          const canonical = canonicalPath(path);
          const key = storeKey(canonical, platform);
          if (key.split("/").includes("node_modules")) continue;
          if (!roots.some((r) => isUnder(canonical, r, platform))) continue;
          // a file watched under another role keeps it, read now with the hook scripts
          if (held(store, key) !== undefined || held(global, key) !== undefined || held(project, key) !== undefined) continue;
          const capped = run.hookScripts >= limits.maxHookScripts;
          if (!capped) run.hookScripts++;
          read(store, path, canonical, key, "hook-script", { capped, shaOnlyIfLarge: true });
        }
      }
    }
  }

  /**
   * The text of an import target, to follow its own `@imports`. An entry
   * enumerated under another role (an agent, a command) may not have been read
   * — the stat fast path reused its sha, or its role needs no text — so it is
   * read now (within the run's hash budget): import following must not depend on
   * the fast path. A read that finds other content than the reused sha updates
   * the entry, as if the fast path had not applied.
   */
  function importText(entry: SnapshotEntry): string | null {
    if (entry.content) return entry.content.toString("utf-8");
    if (entry.state !== "file" || entry.shaOnly) return null;
    if (run.hashed + (entry.size ?? 0) > limits.maxHashedBytes) {
      run.incomplete = true;
      return null;
    }
    const read = readRegular(entry.path, limits.maxFileBytes);
    if (typeof read === "string") return null;
    run.hashed += read.bytes.length;
    const sha = sha256Hex(read.bytes);
    if (unitBound(entry.role, read.bytes) > limits.maxFileUnits) {
      // past the unit cap, as `probe` would have found it: not followed, and once it changed
      // a hook script is watched by sha only, anything else is not compared
      if (sha === entry.sha256) return null;
      if (entry.role === "hook-script") {
        Object.assign(entry, { sha256: sha, size: read.bytes.length, stat: tupleOf(read.stat), reused: false, shaOnly: true });
      } else {
        Object.assign(entry, { state: "unhashed", sha256: null, reused: false });
        run.incomplete = true;
      }
      return null;
    }
    if (sha !== entry.sha256) {
      Object.assign(entry, { sha256: sha, size: read.bytes.length, stat: tupleOf(read.stat), reused: false });
    }
    entry.content = read.bytes;
    return read.bytes.toString("utf-8");
  }

  function imports(store: StoreSnapshot): void {
    const sources: ImportSource[] = [];
    for (const e of Object.values(store.entries)) {
      if (IMPORT_SOURCE_ROLES.has(e.role) && e.content) sources.push({ path: e.path, text: e.content.toString("utf-8") });
    }
    if (sources.length === 0) return;
    const result = resolveImports(sources, {
      home: ctx.home,
      root: ctx.root,
      configDir: ctx.configDir,
      platform,
      maxDepth: limits.maxImportDepth,
      maxTargets: Math.max(0, limits.maxImportTargets - run.importTargets),
      maxLookups: Math.max(0, limits.maxImportLookups - run.importLookups),
      load: (abs) => {
        if (!safeLstat(abs)) return null; // nothing there (an @mention): no canonical path needed
        const canonical = canonicalPath(abs);
        const key = storeKey(canonical, platform);
        // a file watched under another role (in either store) keeps it, read now with the imports
        const entry = held(store, key) ?? held(global, key) ?? held(project, key)
          ?? probe(store, abs, importRoleOf(canonical, ctx), { needText: true });
        if (!entry || entry.state === "missing") return null;
        return { real: realPathOrNull(abs) ?? canonical, text: importText(entry) };
      },
    });
    run.importTargets += result.targets.length;
    run.importLookups += result.lookups;
    if (result.truncated) run.incomplete = true;
    for (const t of result.targets) {
      importTargets.get(store)?.add(t.path);
      if (t.state === "missing") probe(store, t.path, t.role, { recordMissing: true });
    }
  }

  /**
   * The instruction files a Codex config names (`model_instructions_file`,
   * `experimental_compact_prompt_file`), watched as imports: relative to the
   * config's own directory, as Codex resolves them; one not there yet is
   * recorded missing, so a file planted there later shows up.
   */
  function codexImports(store: StoreSnapshot): void {
    for (const source of Object.values(store.entries)) {
      if (ROLE_UNITS[source.role] !== "toml" || !source.content) continue;
      for (const written of tomlInstructionFiles(tomlOf(source))) {
        if (run.importTargets >= limits.maxImportTargets) {
          run.incomplete = true;
          return;
        }
        run.importTargets++;
        const path = written === "~" || written.startsWith("~/") ? join(ctx.home, written.slice(1)) : resolve(dirname(source.path), written);
        const canonical = canonicalPath(path);
        importTargets.get(store)?.add(canonical);
        probe(store, path, importRoleOf(canonical, ctx), { recordMissing: true, needText: true });
      }
    }
  }

  // ── claims, in enumeration order ──
  const M = ctx.managedDir;
  const U = ctx.configDir;
  const C = ctx.codexHome;
  const S = ctx.codexSystemDir;
  const homeSkills = join(ctx.home, ".agents", "skills");
  const fixed = { recordMissing: true, needText: true };
  if (!codex) {
    // global store: Claude Code's managed and user-level files
    claim(TIER.launch, global, join(M, "CLAUDE.md"), "managed-claude-md", fixed);
    claim(TIER.config, global, join(M, "managed-settings.json"), "managed-settings", fixed);
    walk(TIER.config, global, join(M, "managed-settings.d"), 1, "managed-settings", (r) => /\.json$/i.test(r), { needText: true });
    claim(TIER.config, global, join(M, "managed-mcp.json"), "managed-mcp", fixed);
    claim(TIER.launch, global, join(U, "CLAUDE.md"), "user-claude-md", fixed);
    walk(TIER.launch, global, join(U, "rules"), 3, "user-rules", isMarkdown, { needText: true });
    claim(TIER.config, global, join(U, "settings.json"), "user-settings", fixed);
    walk(TIER.onDemand, global, join(U, "agents"), 1, "user-agent", isMarkdown);
    walk(TIER.onDemand, global, join(U, "commands"), 3, "user-command", isMarkdown);
    for (const skill of subdirs(join(U, "skills"))) {
      claim(TIER.onDemand, global, join(skill, "SKILL.md"), "user-skill");
      walk(TIER.skillFiles, global, skill, 3, (r) => (SKILL_DOC_NAME.test(r) ? "user-skill-doc" : "user-skill-file"), (r) => r !== "SKILL.md");
    }
    for (const agent of subdirs(join(U, "agent-memory"))) claim(TIER.onDemand, global, join(agent, "MEMORY.md"), "user-agent-memory");
  } else {
    // codex store: Codex's system layer, then its home C (instructions, config and
    // profiles, hooks, exec-policy rules, skills, memories) and ~/.agents/skills
    for (const name of ["config.toml", "requirements.toml", "managed_config.toml"]) claim(TIER.config, global, join(S, name), "codex-managed-config", fixed);
    claim(TIER.launch, global, join(C, "AGENTS.override.md"), "codex-user-instructions", fixed);
    claim(TIER.launch, global, join(C, "AGENTS.md"), "codex-user-instructions", fixed);
    claim(TIER.config, global, join(C, "config.toml"), "codex-user-config", fixed);
    walk(TIER.config, global, C, 1, "codex-user-config", (r) => /^[^/]+\.config\.toml$/i.test(r), { needText: true });
    claim(TIER.config, global, join(C, "hooks.json"), "codex-user-hooks", fixed);
    walk(TIER.launch, global, join(C, "rules"), 1, "codex-user-rules", (r) => /\.rules$/i.test(r), { needText: true });
    codexSkills(global, join(C, "skills"), CODEX_USER_SKILLS, CODEX_SYSTEM_SKILLS);
    codexSkills(global, homeSkills, CODEX_USER_SKILLS);
    for (const dir of ["memories", "memories_v2"]) {
      claim(TIER.importsAndMemory, global, join(C, dir, "memory_summary.md"), "codex-memory", { recordMissing: true });
      claim(TIER.importsAndMemory, global, join(C, dir, "MEMORY.md"), "codex-memory");
    }
  }

  // project store: every level from the filesystem root down to cwd (a path's length bounds them)
  const levels: string[] = [];
  for (let dir = ctx.cwd; ; ) {
    levels.unshift(dir);
    const parent = resolve(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  const rootKey = storeKey(ctx.root, platform);
  const firstKept = Math.max(0, levels.length - limits.maxAncestors);
  /** The files Codex's fallback names name at each level (`codexDocs`): a write creating one is watched too. */
  const codexDocs: string[] = [];
  for (let i = 0; i < levels.length; i++) {
    const dir = levels[i];
    // the levels nearest cwd, and R's own; a level past the cap is not read, but
    // a candidate present there is recorded unhashed (the check is incomplete)
    const kept = i >= firstKept || storeKey(dir, platform) === rootKey;
    if (!kept) run.incomplete = true;
    for (const [path, role] of [
      [join(dir, "CLAUDE.md"), "ancestor-claude-md"],
      [join(dir, ".claude", "CLAUDE.md"), "ancestor-claude-md"],
      [join(dir, "CLAUDE.local.md"), "ancestor-local-md"],
      [join(dir, "AGENTS.md"), "ancestor-agents-md"],
      [join(dir, ".claude", "AGENTS.md"), "ancestor-agents-md"],
      [join(dir, "AGENTS.override.md"), "codex-project-md"],
    ] as const) {
      if (kept) claim(TIER.launch, project, path, role, fixed);
      else if (safeLstat(path)) claim(TIER.launch, project, path, role, { capped: true });
    }
    // Codex's project_doc_fallback_filenames (a name another role watches, CLAUDE.md, keeps that role)
    for (const name of ctx.codexDocNames) {
      const path = join(dir, name);
      if (kept) {
        codexDocs.push(canonicalPath(path));
        claim(TIER.launch, project, path, "codex-project-md", { needText: true });
      } else if (safeLstat(path)) {
        claim(TIER.launch, project, path, "codex-project-md", { capped: true });
      }
    }
  }
  for (const x of ctx.root === ctx.cwd ? [ctx.root] : [ctx.root, ctx.cwd]) {
    const c = join(x, ".claude");
    claim(TIER.config, project, join(c, "settings.json"), "project-settings", fixed);
    claim(TIER.config, project, join(c, "settings.local.json"), "local-settings", fixed);
    claim(TIER.config, project, join(x, ".mcp.json"), "project-mcp", fixed);
    walk(TIER.launch, project, join(c, "rules"), 4, "project-rules", isMarkdown, { needText: true });
    walk(TIER.onDemand, project, join(c, "agents"), 1, "project-agent", isMarkdown);
    walk(TIER.onDemand, project, join(c, "commands"), 3, "project-command", isMarkdown);
    for (const skill of subdirs(join(c, "skills"))) {
      claim(TIER.onDemand, project, join(skill, "SKILL.md"), "project-skill");
      walk(TIER.skillFiles, project, skill, 3, (r) => (SKILL_DOC_NAME.test(r) ? "project-skill-doc" : "project-skill-file"), (r) => r !== "SKILL.md");
    }
    for (const memDir of ["agent-memory", "agent-memory-local"]) {
      for (const agent of subdirs(join(c, memDir))) claim(TIER.onDemand, project, join(agent, "MEMORY.md"), "project-agent-memory");
    }
  }
  // Codex's project layers, from its root (or R, whichever is higher) down to cwd: `.codex/` (unless it
  // is C itself, which Codex skips too) and `.agents/skills/` (unless it is the user's own)
  const codexTop = isUnder(ctx.codexRoot, ctx.root, platform) ? ctx.root : ctx.codexRoot;
  const homeKey = storeKey(canonicalDir(C), platform);
  const homeSkillsKey = storeKey(canonicalDir(homeSkills), platform);
  for (const x of levelsDown(codexTop, ctx.cwd)) {
    const dot = join(x, ".codex");
    if (storeKey(canonicalDir(dot), platform) !== homeKey) {
      claim(TIER.config, project, join(dot, "config.toml"), "codex-project-config", fixed);
      claim(TIER.config, project, join(dot, "hooks.json"), "codex-project-hooks", fixed);
      walk(TIER.launch, project, join(dot, "rules"), 1, "codex-project-rules", (r) => /\.rules$/i.test(r), { needText: true });
      codexSkills(project, join(dot, "skills"), CODEX_PROJECT_SKILLS);
    }
    const skills = join(x, ".agents", "skills");
    if (storeKey(canonicalDir(skills), platform) !== homeSkillsKey) codexSkills(project, skills, CODEX_PROJECT_SKILLS);
  }

  // memory store
  if (memory && ctx.autoMemoryDir) {
    const A = ctx.autoMemoryDir;
    claim(TIER.importsAndMemory, memory, join(A, "MEMORY.md"), "auto-memory-index", { recordMissing: true });
    walk(TIER.importsAndMemory, memory, A, 1, "auto-memory-topic", (r) => isMarkdown(r) && r.toLowerCase() !== "memory.md");
  }

  // ── reading, in priority order ──
  settleTier(TIER.config);
  // `~/.claude.json`: its user MCP servers are Claude Code's user-level config; this project's part is the project store's
  if (!codex) for (const j of ctx.appState) probeAppState(global, j, "claude-json");
  for (const j of ctx.appState) probeAppState(project, j, "claude-json-project");
  hookScripts(global);
  hookScripts(project);
  settleTier(TIER.launch);
  imports(global);
  imports(project);
  codexImports(global);
  codexImports(project);
  settleTier(TIER.importsAndMemory);
  settleTier(TIER.onDemand);
  // a learned path may be a ledger record's store key, lower-cased on win32: probe it as spelled on disk
  for (const path of opts.ledgerLearned ?? []) probe(project, onDiskPath(path, platform), "ledger-learned", { recordMissing: true });
  settleTier(TIER.skillFiles);
  for (const h of opts.held ?? []) {
    const store = h.store === "global" ? global : h.store === "project" ? project : memory;
    if (store) probe(store, h.path, h.role, { recordMissing: true, needText: true });
  }

  // each store's entries in enumeration order, whatever order they were read in
  for (const s of [global, project, memory]) {
    if (!s) continue;
    const at = (key: string) => order.get(slot(s, key)) ?? 0;
    s.entries = Object.fromEntries(Object.entries(s.entries).sort(([a], [b]) => at(a) - at(b)));
  }

  // ── watch prefixes, by scope ──
  const sorted = (paths: Iterable<string>) => [...new Set(paths)].sort();
  const hookScriptsOf = (s: StoreSnapshot) => Object.values(s.entries).filter((e) => e.role === "hook-script").map((e) => e.path);
  const projectScope = ctx.cwd === ctx.root ? project.id : `${project.id}-${h16(storeKey(ctx.cwd, platform))}`;
  const userScope: [string, WatchPrefixData] = codex
    ? [`codex-${h16(storeKey(C, platform))}`, {
      memoryDirs: [],
      configDirs: [],
      importTargets: sorted(importTargets.get(global)!),
      hookScripts: sorted(hookScriptsOf(global)),
      // the default `.codex` is known to the hooks by name (paths.ts); another C by this
      codexDirs: basename(C) === ".codex" ? [] : [C],
    }]
    : [`config-${h16(storeKey(U, platform))}`, {
      memoryDirs: [canonicalDir(join(U, "agent-memory"))],
      configDirs: basename(U) === ".claude" ? [] : [U],
      importTargets: sorted(importTargets.get(global)!),
      hookScripts: sorted(hookScriptsOf(global)),
    }];
  const prefixScopes: Record<string, WatchPrefixData> = {
    [userScope[0]]: userScope[1],
    [projectScope]: {
      memoryDirs: sorted([...new Set([ctx.root, ctx.cwd])].flatMap((x) => ["agent-memory", "agent-memory-local"].map((d) => canonicalDir(join(x, ".claude", d))))),
      configDirs: [],
      importTargets: sorted(importTargets.get(project)!),
      hookScripts: sorted(hookScriptsOf(project)),
      ...(codexDocs.length ? { codexDocs: sorted(codexDocs) } : {}),
    },
  };
  if (memory && ctx.autoMemoryDir) prefixScopes[memory.id] = { memoryDirs: [ctx.autoMemoryDir], configDirs: [], importTargets: [], hookScripts: [] };

  const unhashed: { store: StoreId; key: string }[] = [];
  for (const s of [global, project, memory]) {
    if (!s) continue;
    const keys = Object.values(s.entries).filter((e) => e.state === "unhashed" && !e.unparsed).map((e) => e.key).sort();
    for (const key of keys) unhashed.push({ store: s.id, key });
  }
  const globalScope = codex
    ? { dirs: [...new Set([S, C, canonicalDir(homeSkills)].map((d) => storeKey(d, platform)))], files: [] }
    : {
      dirs: [...new Set([M, U].map((d) => storeKey(d, platform)))],
      files: [...new Set([join(ctx.home, ".claude.json"), ...ctx.appState].map((p) => storeKey(canonicalPath(p), platform)))],
    };
  return {
    global,
    project,
    memory,
    globalScope,
    prefixScopes,
    unhashed,
    incomplete: run.incomplete,
    hashedBytes: run.hashed,
    files: run.files,
  };
}
