/**
 * Instruction-file integrity — the watched set (spec §3.2-3.5) and how each
 * file in it is read (§3.7).
 *
 * `enumerateWatched(ctx, opts)` walks the global, project and memory stores'
 * patterns for a resolved context, derives the hook scripts and `@imports` those
 * files reference, adds the ledger-learned paths it is given, and returns one
 * snapshot entry per path with its state, sha256, size, stat tuple and link
 * text, plus (in memory only) the bytes it read, for the caller to cut into
 * units. It also returns the `watch-prefixes.json` lists (§4.7).
 *
 * Mechanics:
 * - every path is `lstat`ed first; a symlink's `readlink` text is recorded and
 *   its target is hashed (Claude Code follows it); symlinked directories are
 *   never descended into;
 * - stat fast path: on POSIX, an entry whose `[size, mtimeMs, ctimeMs, ino, dev]`
 *   and link text match its baseline reuses the baseline sha without reading
 *   (win32 always re-reads); files whose text feeds hook-script or import
 *   discovery are always read;
 * - caps: 200 entries per directory, 400 files per run, 4 MiB per file
 *   (`oversize`: size and stat only), 16 MiB hashed per run, `~/.claude.json`
 *   over 20 MiB; anything past a cap is `unhashed` and the snapshot is marked
 *   incomplete; `@import` tokens are looked up at most 500 distinct paths per run;
 * - files are opened non-blocking and checked to be regular files on the open
 *   descriptor, so a FIFO planted at a watched path never hangs the hook.
 *
 * Only the filesystem is touched; no subprocess, no network.
 */

import { closeSync, constants, fstatSync, lstatSync, opendirSync, openSync, readlinkSync, readSync, statSync, type Dir, type Dirent, type Stats } from "node:fs";
import { basename, isAbsolute, join, resolve } from "node:path";
import { canonicalJson } from "../../shared/sign.js";
import { nexusEntryScripts } from "../install.js";
import type { IntegrityContext } from "./context.js";
import { importRoleOf, MAX_IMPORT_DEPTH, MAX_IMPORT_LOOKUPS, MAX_IMPORT_TARGETS, resolveImports, type ImportSource } from "./imports.js";
import { nexusHookCommand, splitCommandWords } from "./nexus-hook.js";
import { canonicalDir, canonicalPath, isUnder, memoryStoreId, projectStoreId, realPathOrNull, storeKey } from "./paths.js";
import {
  MAX_CLAUDE_JSON_BYTES, MAX_DIR_ENTRIES, MAX_FILE_BYTES, MAX_FILES_PER_RUN, MAX_HASHED_BYTES_PER_RUN,
  type EntryState, type StatTuple, type StoreEntry, type StoreId, type StoreKind, type WatchPrefixes, type WatchedRole,
} from "./types.js";
import { execCommandsOf, projectClaudeJson, sha256Hex, type ExecCommand } from "./units.js";

// ── Limits ──────────────────────────────────────────────────────────────────

export type EnumerateLimits = {
  /** Entries handled per enumerated directory; later (sorted) entries are `unhashed`. */
  maxDirEntries: number;
  /** Directory entries read at all; a larger directory is only partly known (incomplete). */
  dirScanLimit: number;
  maxFiles: number;
  maxFileBytes: number;
  maxHashedBytes: number;
  maxClaudeJsonBytes: number;
  /** Ancestor levels (cwd and its nearest ancestors) checked for CLAUDE.md-style files. */
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
  /** The bytes read this run (the projection for `claude-json` roles); null when not read. Never persisted. */
  content: Buffer | null;
  /** The sha came from the baseline because the stat tuple was unchanged (nothing was read). */
  reused: boolean;
};

export type StoreSnapshot = {
  kind: StoreKind;
  id: StoreId;
  /** null for the global store; R for the project store; A for the memory store. */
  root: string | null;
  /** Keyed by store key, in enumeration order. */
  entries: Record<string, SnapshotEntry>;
};

/** The `watch-prefixes.json` lists (§4.7), absolute canonical paths, sorted. */
export type WatchPrefixData = Omit<WatchPrefixes, "v" | "updatedAt">;

export type Snapshot = {
  global: StoreSnapshot;
  project: StoreSnapshot;
  /** null when auto memory was not located. */
  memory: StoreSnapshot | null;
  prefixes: WatchPrefixData;
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
};

// ── Role groups ─────────────────────────────────────────────────────────────

/** Files whose `@imports` are followed. */
const IMPORT_SOURCE_ROLES: ReadonlySet<WatchedRole> = new Set<WatchedRole>([
  "managed-claude-md", "user-claude-md", "user-rules",
  "ancestor-claude-md", "ancestor-local-md", "ancestor-agents-md", "project-rules",
  "import", "external-import",
]);

/** Files whose commands name hook scripts, and the directory a relative script resolves against. */
const HOOK_SOURCE_BASE: Partial<Record<WatchedRole, "root" | "config" | "managed">> = {
  "managed-settings": "managed",
  "managed-mcp": "managed",
  "user-settings": "config",
  "claude-json": "config",
  "project-settings": "root",
  "local-settings": "root",
  "project-mcp": "root",
  "claude-json-project": "root",
};

const isMarkdown = (name: string) => /\.md$/i.test(name);

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

const PROJECT_DIR_OR_HOME = /\$\{(CLAUDE_PROJECT_DIR|HOME)\}|\$(CLAUDE_PROJECT_DIR|HOME)(?![A-Za-z0-9_])/g;

/**
 * The file a command word names, if it can be one: `$CLAUDE_PROJECT_DIR` /
 * `${CLAUDE_PROJECT_DIR}` → R and `~`, `$HOME`, `${HOME}` → home expanded; then
 * an absolute path as is, or a relative one containing a slash against `base`.
 */
export function scriptPathOf(word: string, base: string, root: string, home: string, platform: NodeJS.Platform): string | null {
  let w = word.replace(PROJECT_DIR_OR_HOME, (_m, braced: string | undefined, bare: string | undefined) =>
    (braced ?? bare) === "HOME" ? home : root);
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
};

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
    const script = nexusHookCommand(cmd.command)?.script;
    if (!script) return false;
    const abs = resolve(script);
    return ownEntries.has(storeKey(realPathOrNull(abs) ?? canonicalPath(abs), platform));
  };

  const global: StoreSnapshot = { kind: "global", id: "global", root: null, entries: {} };
  const project: StoreSnapshot = { kind: "project", id: projectStoreId(ctx.root, platform), root: ctx.root, entries: {} };
  const memory: StoreSnapshot | null = ctx.autoMemoryDir
    ? { kind: "memory", id: memoryStoreId(ctx.autoMemoryDir, platform), root: ctx.autoMemoryDir, entries: {} }
    : null;
  const importTargets = new Set<string>();

  const blank = (path: string, key: string, role: WatchedRole): SnapshotEntry =>
    ({ path, key, role, state: "missing", sha256: null, size: null, stat: null, link: null, content: null, reused: false });

  const add = (store: StoreSnapshot, entry: SnapshotEntry): SnapshotEntry => {
    if (entry.state === "unhashed") run.incomplete = true;
    store.entries[entry.key] = entry;
    return entry;
  };

  /** Find, stat and (unless the fast path applies) read one path into `store`. */
  function probe(store: StoreSnapshot, path: string, role: WatchedRole, o: ProbeOpts = {}): SnapshotEntry | null {
    const canonical = canonicalPath(path);
    const key = storeKey(canonical, platform);
    const existing = store.entries[key];
    if (existing) return existing;
    if (store !== global && global.entries[key]) return null; // the global store already watches it
    const entry = blank(canonical, key, role);
    if (o.capped) return add(store, { ...entry, state: "unhashed" });

    const lst = safeLstat(path);
    if (!lst) return o.recordMissing ? add(store, entry) : null;
    let st: Stats | undefined = lst;
    if (lst.isSymbolicLink()) {
      try { entry.link = readlinkSync(path); } catch { entry.link = ""; }
      st = safeStat(path);
      if (!st?.isFile()) return add(store, entry); // dangling, or a link to a directory: missing, link kept
    } else if (!lst.isFile()) {
      return o.recordMissing ? add(store, entry) : null; // a directory or device where a file is expected
    }

    entry.size = st.size;
    entry.stat = tupleOf(st);
    if (run.files >= limits.maxFiles) return add(store, { ...entry, state: "unhashed" });
    run.files++;
    if (st.size > limits.maxFileBytes) return add(store, { ...entry, state: "oversize" });

    const prior = opts.baseline?.[store.kind]?.[key];
    if (!o.needText && posix && prior?.state === "file" && prior.sha256 && sameTuple(prior.stat, entry.stat) && (prior.link ?? null) === entry.link) {
      return add(store, { ...entry, state: "file", sha256: prior.sha256, reused: true });
    }
    if (run.hashed + st.size > limits.maxHashedBytes) return add(store, { ...entry, state: "unhashed" });

    const read = readRegular(path, limits.maxFileBytes);
    if (read === "oversize") return add(store, { ...entry, state: "oversize" });
    if (read === "unreadable") return add(store, { ...entry, state: "unhashed" });
    run.hashed += read.bytes.length;
    return add(store, {
      ...entry,
      state: "file",
      sha256: sha256Hex(read.bytes),
      size: read.bytes.length,
      stat: tupleOf(read.stat),
      content: read.bytes,
    });
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
      content = read.bytes; // unparseable: its units are the one "invalid" unit (a hash, no content)
    }
    run.hashed += content.length;
    add(store, { ...entry, state: "file", sha256: sha256Hex(content), size: st.size, stat: tupleOf(read.stat), content });
  }

  /** Files under `dir` (to `depth` levels) whose path relative to `dir` passes `accept`. */
  function walk(store: StoreSnapshot, dir: string, depth: number, role: WatchedRole, accept: (rel: string) => boolean, o: ProbeOpts = {}, rel = ""): void {
    const listing = listDir(dir, limits.dirScanLimit);
    if (!listing) return;
    if (listing.overflow) run.incomplete = true;
    listing.entries.forEach((ent, i) => {
      const capped = i >= limits.maxDirEntries;
      const path = join(dir, ent.name);
      const r = rel ? `${rel}/${ent.name}` : ent.name;
      let isDir = ent.isDirectory();
      if (ent.isSymbolicLink()) {
        if (safeStat(path)?.isDirectory()) return; // symlinked directories are not followed
        isDir = false;
      }
      if (isDir) {
        if (capped) run.incomplete = true;
        else if (depth > 1) walk(store, path, depth - 1, role, accept, o, r);
        return;
      }
      if ((ent.isFile() || ent.isSymbolicLink()) && accept(r)) probe(store, path, role, { ...o, capped });
    });
  }

  /** The real (non-symlink) subdirectories of `dir`, within the per-directory cap. */
  function subdirs(dir: string): string[] {
    const listing = listDir(dir, limits.dirScanLimit);
    if (!listing) return [];
    if (listing.overflow || listing.entries.length > limits.maxDirEntries) run.incomplete = true;
    return listing.entries.slice(0, limits.maxDirEntries).filter((e) => e.isDirectory()).map((e) => join(dir, e.name));
  }

  function hookScripts(store: StoreSnapshot): void {
    const bases = { root: ctx.root, config: ctx.configDir, managed: ctx.managedDir };
    const roots = [ctx.root, ctx.configDir, ctx.managedDir];
    for (const source of Object.values(store.entries)) {
      const base = HOOK_SOURCE_BASE[source.role];
      if (!base || !source.content) continue;
      let parsed: unknown;
      try { parsed = JSON.parse(source.content.toString("utf-8").replace(/^\ufeff/, "")); } catch { continue; }
      for (const cmd of execCommandsOf(parsed)) {
        if (isOwnNexusHook(cmd)) continue; // rebuilding Nexus's own dist/ must not read as a change
        for (const word of [...splitCommandWords(cmd.command), ...cmd.args]) {
          const path = scriptPathOf(word, bases[base], ctx.root, ctx.home, platform);
          if (!path) continue;
          const st = safeStat(path);
          if (!st?.isFile() || st.size > limits.maxFileBytes) continue;
          const canonical = canonicalPath(path);
          const key = storeKey(canonical, platform);
          if (store.entries[key] || global.entries[key]) continue;
          if (key.split("/").includes("node_modules")) continue;
          if (!roots.some((r) => isUnder(canonical, r, platform))) continue;
          const capped = run.hookScripts >= limits.maxHookScripts;
          if (!capped) run.hookScripts++;
          probe(store, path, "hook-script", { capped });
        }
      }
    }
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
        const entry = store.entries[key] ?? global.entries[key]
          ?? probe(store, abs, importRoleOf(canonical, ctx), { needText: true });
        if (!entry || entry.state === "missing") return null;
        return { real: realPathOrNull(abs) ?? canonical, text: entry.content ? entry.content.toString("utf-8") : null };
      },
    });
    run.importTargets += result.targets.length;
    run.importLookups += result.lookups;
    if (result.truncated) run.incomplete = true;
    for (const t of result.targets) {
      importTargets.add(t.path);
      if (t.state === "missing") probe(store, t.path, t.role, { recordMissing: true });
    }
  }

  // ── global store ──
  const M = ctx.managedDir;
  const U = ctx.configDir;
  probe(global, join(M, "CLAUDE.md"), "managed-claude-md", { recordMissing: true, needText: true });
  probe(global, join(M, "managed-settings.json"), "managed-settings", { recordMissing: true, needText: true });
  walk(global, join(M, "managed-settings.d"), 1, "managed-settings", (r) => /\.json$/i.test(r), { needText: true });
  probe(global, join(M, "managed-mcp.json"), "managed-mcp", { recordMissing: true, needText: true });
  probe(global, join(U, "CLAUDE.md"), "user-claude-md", { recordMissing: true, needText: true });
  walk(global, join(U, "rules"), 3, "user-rules", isMarkdown, { needText: true });
  probe(global, join(U, "settings.json"), "user-settings", { recordMissing: true, needText: true });
  walk(global, join(U, "agents"), 1, "user-agent", isMarkdown);
  walk(global, join(U, "commands"), 3, "user-command", isMarkdown);
  for (const skill of subdirs(join(U, "skills"))) {
    probe(global, join(skill, "SKILL.md"), "user-skill");
    walk(global, skill, 3, "user-skill-file", (r) => r !== "SKILL.md");
  }
  for (const agent of subdirs(join(U, "agent-memory"))) probe(global, join(agent, "MEMORY.md"), "user-agent-memory");
  for (const j of ctx.appState) probeAppState(global, j, "claude-json");
  hookScripts(global);
  imports(global);

  // ── project store ──
  const levels: string[] = [];
  for (let dir = ctx.cwd; levels.length < limits.maxAncestors; ) {
    levels.unshift(dir);
    const parent = resolve(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  for (const dir of levels) {
    const local = { recordMissing: true, needText: true };
    probe(project, join(dir, "CLAUDE.md"), "ancestor-claude-md", local);
    probe(project, join(dir, ".claude", "CLAUDE.md"), "ancestor-claude-md", local);
    probe(project, join(dir, "CLAUDE.local.md"), "ancestor-local-md", local);
    probe(project, join(dir, "AGENTS.md"), "ancestor-agents-md", local);
    probe(project, join(dir, ".claude", "AGENTS.md"), "ancestor-agents-md", local);
  }
  for (const x of ctx.root === ctx.cwd ? [ctx.root] : [ctx.root, ctx.cwd]) {
    const c = join(x, ".claude");
    probe(project, join(c, "settings.json"), "project-settings", { recordMissing: true, needText: true });
    probe(project, join(c, "settings.local.json"), "local-settings", { recordMissing: true, needText: true });
    probe(project, join(x, ".mcp.json"), "project-mcp", { recordMissing: true, needText: true });
    walk(project, join(c, "rules"), 4, "project-rules", isMarkdown, { needText: true });
    walk(project, join(c, "agents"), 1, "project-agent", isMarkdown);
    walk(project, join(c, "commands"), 3, "project-command", isMarkdown);
    for (const skill of subdirs(join(c, "skills"))) {
      probe(project, join(skill, "SKILL.md"), "project-skill");
      walk(project, skill, 3, "project-skill-file", (r) => r !== "SKILL.md");
    }
    for (const memDir of ["agent-memory", "agent-memory-local"]) {
      for (const agent of subdirs(join(c, memDir))) probe(project, join(agent, "MEMORY.md"), "project-agent-memory");
    }
  }
  for (const j of ctx.appState) probeAppState(project, j, "claude-json-project");
  hookScripts(project);
  imports(project);
  for (const path of opts.ledgerLearned ?? []) probe(project, path, "ledger-learned", { recordMissing: true });

  // ── memory store ──
  if (memory && ctx.autoMemoryDir) {
    const A = ctx.autoMemoryDir;
    probe(memory, join(A, "MEMORY.md"), "auto-memory-index", { recordMissing: true });
    walk(memory, A, 1, "auto-memory-topic", (r) => isMarkdown(r) && r.toLowerCase() !== "memory.md");
  }

  // ── watch prefixes ──
  const memoryDirs = new Set<string>();
  if (ctx.autoMemoryDir) memoryDirs.add(ctx.autoMemoryDir);
  memoryDirs.add(canonicalDir(join(U, "agent-memory")));
  for (const x of new Set([ctx.root, ctx.cwd])) {
    for (const d of ["agent-memory", "agent-memory-local"]) memoryDirs.add(canonicalDir(join(x, ".claude", d)));
  }
  const hookScriptPaths = [global, project]
    .flatMap((s) => Object.values(s.entries))
    .filter((e) => e.role === "hook-script")
    .map((e) => e.path);
  const prefixes: WatchPrefixData = {
    memoryDirs: [...memoryDirs].sort(),
    configDirs: basename(U) === ".claude" ? [] : [U],
    importTargets: [...importTargets].sort(),
    hookScripts: [...new Set(hookScriptPaths)].sort(),
  };

  const unhashed: { store: StoreId; key: string }[] = [];
  for (const s of [global, project, memory]) {
    if (!s) continue;
    const keys = Object.values(s.entries).filter((e) => e.state === "unhashed").map((e) => e.key).sort();
    for (const key of keys) unhashed.push({ store: s.id, key });
  }
  return {
    global,
    project,
    memory,
    prefixes,
    unhashed,
    incomplete: run.incomplete,
    hashedBytes: run.hashed,
    files: run.files,
  };
}
