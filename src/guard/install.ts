/**
 * Install / remove the agent firewall into a Claude Code settings file by
 * merging hooks that run the guard: PreToolUse / PostToolUse for the tool
 * guards, and one SessionStart group for instruction-file integrity. Idempotent
 * and non-destructive: unrelated hooks and settings are preserved, and our hooks
 * are recognised by their command (in every form any Nexus version has written)
 * so install replaces them in place and uninstall removes all of them.
 *
 * Install also prepares instruction-file integrity (spec §6.1, §7): it creates
 * the store's key and anchor when missing (the first fingerprint is taken at the
 * next SessionStart; under a §5.6 `redirect` nothing is created) and removes a
 * valid `.disabled` marker — or, with `integrity: false`, leaves the SessionStart
 * group out and writes the marker — and records each settings change it makes
 * as a signed `nexus` ledger record, so the next SessionStart attributes that
 * change to Nexus instead of reporting it. Uninstall records its change the same
 * way and leaves the store in place.
 *
 * Each install or uninstall reads, changes and writes the file under a lock in
 * its directory (`withInstallLock`), and replaces it atomically (`replaceFile`),
 * so concurrent runs and a session starting meanwhile never see half of a change.
 *
 * Whether the hooks are there and run is `checkNexusHooks`, across every
 * settings layer Claude Code reads: `guard status` and `guard integrity status`
 * both report from it, so they agree.
 *
 * Codex CLI's hooks.json has the same `hooks.<Event>` shape, so the Codex
 * install (codex/install.ts) reuses the merge (`placeNexusGroups`,
 * `removeNexusHooks`), the lock, the store preparation and the ledger record
 * exported here.
 */

import { chmodSync, closeSync, constants, existsSync, fstatSync, mkdirSync, openSync, readFileSync, readlinkSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { atomicWriteFile, ensurePrivateDir, LockBusyError, withExclusiveLock } from "../shared/atomic-file.js";
import { dataDirFrom, type DataDirChoice } from "../shared/data-dir.js";
import { guardCommand, isNexusGuardCommand, withoutAgentFlag } from "./hook-command.js";
import { configDirFrom, contextFromCli, managedDirFor } from "./integrity/context.js";
import { appendNexusRecord } from "./integrity/ledger.js";
import { canonicalDir, canonicalPath, storeKey } from "./integrity/paths.js";
import { listDir } from "./integrity/private-file.js";
import { displayRaw } from "./integrity/render.js";
import {
  initIntegrity, integrityPaths, isIntegrityDisabled, loadIntegrity, readIntegrityKey, removeDisabled, signerFor, TAMPER_FRAGMENTS,
  withStoreLock, writeDisabled, type InitResult, type IntegrityPaths, type Signer,
} from "./integrity/store.js";
import { LOCK_STALE_MS, LOCK_WAIT_CLI_MS, MAX_DIR_ENTRIES, MAX_FILE_BYTES, type WatchedRole } from "./integrity/types.js";
import { unitsOf } from "./integrity/units.js";

export { guardCommand, isNexusGuardCommand, nexusEntryScripts, withoutAgentFlag } from "./hook-command.js";

/**
 * Tools whose output is untrusted external content (PostToolUse content guard).
 * `mcp__.*` is a Claude Code matcher regex (matchers are regex alternations tested
 * against `tool_name`), so it covers EVERY MCP tool's output — the user-decided
 * default coverage is web + all MCP tools. Nexus's own MCP output is already
 * spotlighted, and the handler frames idempotently, so guarding it is safe.
 */
export const DEFAULT_GUARDED_TOOLS = ["WebFetch", "WebSearch", "mcp__.*"];
/**
 * The PostToolUse content tools Nexus <= 0.7.4 installed by default. A plain
 * `guard install` treats an existing hook guarding EXACTLY this set as the stock
 * old default and migrates it forward to `DEFAULT_GUARDED_TOOLS` (so a user who
 * never set `--tools` gains MCP coverage on the documented upgrade step). Any
 * other set is a custom list and is preserved verbatim. See `installGuard`.
 */
export const OLD_STOCK_GUARDED_TOOLS = ["WebFetch", "WebSearch"];
/** Command-executing tools screened before they run (PreToolUse command guard). */
export const DEFAULT_COMMAND_TOOLS = ["Bash", "PowerShell"];
/** File-writing tools screened for sensitive paths / secrets (PreToolUse). */
export const DEFAULT_FILE_TOOLS = ["Write", "Edit", "NotebookEdit", "MultiEdit"];
/**
 * The PostToolUse group instruction-file integrity adds (its own Nexus entry,
 * after the content tools'): Claude Code runs PostToolUse only once a tool
 * succeeded, so it confirms that a write PreToolUse recorded landed, and an ask
 * the user rejected never counts as an approved edit. A matcher of plain names
 * is matched exactly (one with a regex character, like the content tools',
 * would also match TodoWrite or NotebookEdit). The handler leaves these tools'
 * output alone.
 */
export const INTEGRITY_CONFIRM_MATCHER = "Write|Edit|MultiEdit";

/** Claude Code reads a hook's `timeout` in SECONDS. The guard answers in
 *  milliseconds; if it ever hangs, a cancelled hook fails open after this. */
export const DEFAULT_HOOK_TIMEOUT = 30;
/** No deliberate seconds value is this large — it is the milliseconds figure
 *  (15000 → ~4h10m) that Nexus <= 0.7.4 wrote, so status flags it. */
const MAX_HOOK_TIMEOUT = 600;

/** Events whose Nexus group matches tool names (`matcher`: the guarded tools). */
export const TOOL_EVENTS = ["PostToolUse", "PreToolUse"] as const;
/** Session events: the Nexus group has no `matcher` key, so it runs for every
 *  source (startup, resume, clear, compact). */
export const LIFECYCLE_EVENTS = ["SessionStart"] as const;
const EVENTS = [...TOOL_EVENTS, ...LIFECYCLE_EVENTS] as const;
type ToolEvent = (typeof TOOL_EVENTS)[number];
type HookEvent = (typeof EVENTS)[number];

/** `guardStatus`'s outdated reason when integrity is on but its hook is not installed. */
const SESSION_START_MISSING = "SessionStart hook is missing (instruction-file integrity)";
/** … and when its PostToolUse group is not: an approved edit then reads as an unexplained change. */
const CONFIRM_MISSING = `PostToolUse ${INTEGRITY_CONFIRM_MATCHER} hook is missing (instruction-file integrity: approved edits would show as unexplained changes)`;

/**
 * A settings-derived string (a hook's command, script path or timeout) in status
 * text: cleaned like integrity display text (control, ANSI, bidi, zero-width,
 * line-separator and tag characters gone) and cut, a path from its start.
 */
const shown = (text: string, max = 200) => displayRaw(text, max);
const shownPath = (path: string) => displayRaw(path, 200, true);

/**
 * What install, uninstall and status read from the process; each defaults to
 * the real process's value. Tests inject all of them, so nothing reaches the
 * real ~/.claude, ~/.codex or ~/.nexus.
 */
export type InstallDeps = {
  /** When the change happens: the ledger record's time and the anchor's `createdAt`. */
  now?: Date;
  platform?: NodeJS.Platform;
  homedir?: string;
  /** Only `CLAUDE_CONFIG_DIR`, `CODEX_HOME` (the Codex install), `NEXUS_DATA` and `ProgramFiles` are read. */
  env?: Readonly<Record<string, string | undefined>>;
  /** The project directory `scope: "project"` means, and whose layers status checks (default `process.cwd()`). */
  cwd?: string;
  /** D (default: `NEXUS_DATA`, else `~/.nexus`, read as `nexusDataDir()` reads it: `dataDirFrom`). */
  dataDir?: string;
  /** M, the managed-settings directory (default: the platform's, `managedDirFor`). */
  managedDir?: string;
};

/** InstallDeps with every default filled in. */
export type Deps = Required<InstallDeps>;

export function resolveDeps(deps: InstallDeps): Deps {
  const platform = deps.platform ?? process.platform;
  const home = deps.homedir ?? homedir();
  const env = deps.env ?? process.env;
  return {
    now: deps.now ?? new Date(),
    platform,
    homedir: home,
    env,
    cwd: deps.cwd ?? process.cwd(),
    dataDir: deps.dataDir !== undefined ? resolve(deps.dataDir) : dataDirFrom(env.NEXUS_DATA, home, platform).dir,
    managedDir: deps.managedDir ?? managedDirFor(platform, env),
  };
}

/**
 * The settings file a scope means: for the user, `settings.json` in an absolute
 * `CLAUDE_CONFIG_DIR` if set (as Claude Code reads it), else in `~/.claude`;
 * for the project, `<cwd>/.claude/settings.json`.
 */
export function settingsPath(scope: "user" | "project" = "user", deps: InstallDeps = {}): string {
  if (scope === "project") return join(deps.cwd ?? process.cwd(), ".claude", "settings.json");
  const { dir } = configDirFrom(undefined, { env: deps.env ?? process.env, homedir: deps.homedir ?? homedir() });
  return join(dir, "settings.json");
}

/** Does this (Nexus) hook command run the whole CLI's `guard check` (with or without `--agent`)? */
export function runsCliGuardCheck(command: string): boolean {
  return /\sguard\s+check$/.test(withoutAgentFlag(command));
}

export type HookCommand = { type?: string; command?: unknown; timeout?: unknown; [k: string]: unknown };
export type HookMatcher = { matcher?: string; hooks?: HookCommand[]; [k: string]: unknown };
/** A Claude Code settings file, or Codex's hooks.json: both keep their hooks under `hooks.<Event>`. */
export type Settings = { hooks?: { [event: string]: unknown }; [k: string]: unknown };

/** A settings file's (or hooks.json's) text as an object with an object `hooks`; throws, naming `path`, on anything else. */
export function parseSettings(text: string, path: string): Settings {
  const raw = text.trim();
  if (!raw) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(
      `Could not parse ${path} as JSON (comments / trailing commas aren't supported here). ` +
      `Fix or remove it, then re-run — the guard will not overwrite a file it can't safely parse.`,
    );
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${path} is not a JSON object — the guard will not overwrite it.`);
  }
  const hooks = (parsed as Settings).hooks;
  if (hooks !== undefined && (typeof hooks !== "object" || hooks === null || Array.isArray(hooks))) {
    throw new Error(`${path}: hooks is not an object — fix it by hand; the guard will not overwrite it.`);
  }
  return parsed as Settings;
}

/** The file's text as read (null when it does not exist), for the ledger, and its settings. */
export function readSettingsFile(path: string): { text: string | null; settings: Settings } {
  if (!existsSync(path)) return { text: null, settings: {} };
  const text = readFileSync(path, "utf-8");
  return { text, settings: parseSettings(text, path) };
}

/** Writes `settings` (`replaceFile`) and returns the text written. */
export function writeSettings(path: string, settings: Settings): string {
  mkdirSync(dirname(path), { recursive: true });
  const text = JSON.stringify(settings, null, 2) + "\n";
  replaceFile(path, text, 0o666);
  return text;
}

/**
 * The file a write to `path` lands in: `path` itself, or what a symlink there
 * points at (a dotfile manager's link), followed even when that file does not
 * exist yet, as writeFileSync would follow it.
 */
function writeTarget(path: string): string {
  let target = path;
  for (let hops = 0; hops < 40; hops++) {
    try {
      return realpathSync(target);
    } catch { /* missing, or a link to nothing yet */ }
    try {
      target = resolve(dirname(target), readlinkSync(target));
    } catch {
      return target; // not a link: a file to create
    }
  }
  return target;
}

/**
 * Replace a config file Nexus edits (Claude Code's settings, Codex's hooks.json
 * and config.toml) so that whoever reads it meanwhile (the agent starting a
 * session, a status run, another install) sees the old file or the new one,
 * never a torn write: `atomicWriteFile`, a temporary file renamed over it. A
 * symlink stays a link, the file it points at replaced; an existing file keeps
 * its mode, and a new one gets `mode` (less the umask).
 */
export function replaceFile(path: string, text: string, mode: number): void {
  const target = writeTarget(path);
  let keep: number | null = null;
  try {
    keep = statSync(target).mode & 0o7777;
  } catch { /* a new file */ }
  atomicWriteFile(target, text, { mode: keep ?? mode });
  // the temporary file was created less the umask: widen it back to what the file had
  if (keep !== null && (statSync(target).mode & 0o7777) !== keep) chmodSync(target, keep);
}

/** The lock file an install or uninstall holds in the directory whose files it changes. */
export const INSTALL_LOCK = ".nexus-install.lock";

/**
 * Run `fn` holding `<dir>/.nexus-install.lock` (`dir` created when missing), so
 * that Nexus installs and uninstalls changing the files there cannot interleave
 * their read, change and write: each reads what the one before it wrote, and
 * none writes back a file without the other's change (or without the user's
 * hooks, read as empty mid-write). Waits LOCK_WAIT_CLI_MS for a busy lock, then
 * throws; a dead owner's lock is taken over after LOCK_STALE_MS.
 */
export function withInstallLock<T>(dir: string, fn: () => T): T {
  mkdirSync(dir, { recursive: true });
  const lock = join(dir, INSTALL_LOCK);
  let entered = false;
  try {
    return withExclusiveLock(lock, () => {
      entered = true;
      return fn();
    }, { waitMs: LOCK_WAIT_CLI_MS, staleMs: LOCK_STALE_MS });
  } catch (error) {
    if (entered || !(error instanceof LockBusyError)) throw error;
    throw new Error(`Another Nexus install or uninstall is changing the files in ${shownPath(dir)} (it holds ${shownPath(lock)}). Try again once it is done.`);
  }
}

/** The matcher list for `event`; refuses to touch a hand-broken non-array. */
export function eventList(settings: Settings, event: string, path: string): HookMatcher[] {
  const list = settings.hooks?.[event];
  if (list === undefined) return [];
  if (!Array.isArray(list)) {
    throw new Error(`${path}: hooks.${event} is not an array — fix it by hand; the guard will not overwrite it.`);
  }
  return list as HookMatcher[];
}

export function hooksOf(m: HookMatcher): HookCommand[] {
  return Array.isArray(m?.hooks) ? m.hooks : [];
}

/** The distinct tools currently guarded by our hooks for `event` (from their
 *  matcher strings). Used so a plain `guard install` keeps a custom --tools list
 *  instead of silently narrowing it back to the defaults. */
function currentNexusTools(settings: Settings, event: ToolEvent, path: string): string[] {
  const ours = eventList(settings, event, path).filter((m) => hooksOf(m).some(isNexusHook) && !isConfirmGroup(event, m));
  const tools = ours.flatMap((m) => (m.matcher ? m.matcher.split("|") : []));
  return [...new Set(tools.filter(Boolean))];
}

export function isNexusHook(h: HookCommand): boolean {
  return isNexusGuardCommand(h?.command);
}

/** Is `m` the PostToolUse group integrity adds (`INTEGRITY_CONFIRM_MATCHER`), not the content tools'? */
function isConfirmGroup(event: HookEvent, m: HookMatcher): boolean {
  return event === "PostToolUse" && m.matcher === INTEGRITY_CONFIRM_MATCHER;
}

/** Order-insensitive set equality for two tool lists (matcher alternation parts). */
function sameToolSet(a: string[], b: string[]): boolean {
  const sa = new Set(a);
  const sb = new Set(b);
  return sa.size === sb.size && [...sa].every((t) => sb.has(t));
}

/** `list` with every Nexus hook taken out. A matcher entry left empty is dropped;
 *  one that also holds the user's own hooks keeps them. `at` is where the first
 *  of ours sat, so a replacement goes back in the same place. */
function withoutNexus(list: HookMatcher[]): { kept: HookMatcher[]; removed: number; at: number } {
  const kept: HookMatcher[] = [];
  let removed = 0;
  let at = -1;
  for (const m of list) {
    const hooks = hooksOf(m);
    const ours = hooks.filter(isNexusHook).length;
    if (ours === 0) {
      kept.push(m);
      continue;
    }
    removed += ours;
    if (at < 0) at = kept.length;
    if (ours < hooks.length) kept.push({ ...m, hooks: hooks.filter((h) => !isNexusHook(h)) });
  }
  return { kept, removed, at };
}

/** `list` with every Nexus hook taken out and `entries` put where the first of
 *  them sat, or after the user's own when there was none (`withoutNexus`), so
 *  the user's groups keep their order. A new list; `list` is not changed. */
export function placeNexusGroups(list: HookMatcher[], entries: HookMatcher[]): { list: HookMatcher[]; removed: number } {
  const { kept, removed, at } = withoutNexus(list);
  kept.splice(at < 0 ? kept.length : at, 0, ...entries);
  return { list: kept, removed };
}

/** Make our hook for `event` exactly one entry (two for PostToolUse with
 *  `confirm`: the content tools', then `INTEGRITY_CONFIRM_MATCHER`'s), replacing
 *  any older / duplicate Nexus entries in place; a first one goes after the
 *  user's own. It matches `tools`, or, with `tools` null (a lifecycle event), has
 *  no `matcher` key at all, so it runs for every source. Returns whether the
 *  list changed. */
function upsertHook(
  settings: Settings, event: HookEvent, tools: string[] | null, timeout: number, path: string, confirm = false,
): { changed: boolean; replaced: number } {
  const list = eventList(settings, event, path);
  const hook = (): HookCommand[] => [{ type: "command", command: guardCommand(), timeout }];
  const entries: HookMatcher[] = [tools === null ? { hooks: hook() } : { matcher: tools.join("|"), hooks: hook() }];
  if (confirm) entries.push({ matcher: INTEGRITY_CONFIRM_MATCHER, hooks: hook() });
  const { list: next, removed } = placeNexusGroups(list, entries);
  if (JSON.stringify(next) === JSON.stringify(list)) return { changed: false, replaced: removed };
  settings.hooks ??= {};
  settings.hooks[event] = next;
  return { changed: true, replaced: removed };
}

/** Take every Nexus hook out of `event`'s list, dropping the list when it is left empty. Returns how many. */
export function removeNexusHooks(settings: Settings, event: string, path: string): number {
  const r = withoutNexus(eventList(settings, event, path));
  if (r.removed === 0) return 0;
  if (r.kept.length > 0) settings.hooks![event] = r.kept;
  else delete settings.hooks![event];
  return r.removed;
}

// ── Instruction-file integrity ──────────────────────────────────────────────

/** What install did for instruction-file integrity. */
export type InstallIntegrity = {
  /** On: the SessionStart group is installed and no valid `.disabled` marker is left.
   *  Off (`integrity: false`): the group is left out (an existing one removed) and the marker written,
   *  unless `problem` says it could not be. */
  enabled: boolean;
  /** A `nexus` ledger record of this install's settings change was written. */
  recorded: boolean;
  /** Why the integrity store could not be prepared or written; the settings change stands. Null when all went well. */
  problem: string | null;
};

/** Settings roles all cut into the same JSON unit ids; the role only changes categories, which a ledger record does not carry. */
const SETTINGS_ROLE = "user-settings";

export const messageOf = (error: unknown) => (error instanceof Error ? error.message : String(error));

/** The signer of a trusted key already in the store, or null. Never creates a key. */
export function existingSigner(paths: IntegrityPaths): Signer | null {
  const key = readIntegrityKey(paths);
  return key.state === "ok" ? signerFor(key.key) : null;
}

/**
 * Create D/integrity, the key and the anchor when missing (`initIntegrity`,
 * under the store lock), then make the `.disabled` marker match `enabled`.
 * Returns the signer for the ledger record, or the problem. A busy lock leaves
 * the store as it is, but a trusted key already there still signs the record.
 *
 * Under a §5.6 `redirect` (D is not ~/.nexus, which has an anchor, and D has
 * none) nothing is created or written in D: an anchor there would clear that
 * TAMPER, whose recovery is the gated `integrity baseline`, and a plain install
 * is not gated (an agent may run it with the session's NEXUS_DATA).
 */
export function prepareIntegrity(paths: IntegrityPaths, enabled: boolean, d: Deps): { signer: Signer | null; problem: string | null } {
  try {
    if (loadIntegrity({ dataDir: paths.dataDir, homedir: d.homedir, platform: d.platform }, []).tamper.includes("redirect")) {
      const why = TAMPER_FRAGMENTS.redirect;
      return { signer: null, problem: enabled ? why : `the .disabled marker was not written: ${why}` };
    }
    ensurePrivateDir(paths.dir); // the lock lives in it
    const locked = withStoreLock(paths, (): InitResult => {
      const init = initIntegrity(paths, d.now);
      if (!init.ok) return init;
      const disabled = isIntegrityDisabled(paths);
      if (enabled && disabled) removeDisabled(paths);
      if (!enabled && !disabled) writeDisabled(paths, init.signer, "install", d.now);
      return init;
    }, LOCK_WAIT_CLI_MS);
    if (!locked.ok) return { signer: existingSigner(paths), problem: `the integrity store is ${locked.reason} (${locked.error.message})` };
    if (!locked.value.ok) return { signer: null, problem: `the integrity key ${locked.value.why}` };
    return { signer: locked.value.signer, problem: null };
  } catch (error) {
    let signer: Signer | null = null;
    try { signer = existingSigner(paths); } catch { /* none */ }
    return { signer, problem: messageOf(error) };
  }
}

/**
 * Sign and write the `nexus` ledger record of one settings change: the JSON
 * units it added and removed (keyed like the store's), and the Nexus hook
 * events left in the file. The action is `uninstall` when the change took a
 * Nexus hook event out (uninstall, or `integrity: false` removing SessionStart),
 * since that is what the next SessionStart checks before it reports a removed
 * Nexus hook (S3); otherwise `install`. `role` picks how the file is cut into
 * units, which must be how the store cuts it (Codex's files pass theirs).
 */
export function recordChange(
  paths: IntegrityPaths, signer: Signer, uninstall: boolean, path: string, before: string | null, after: string, d: Deps,
  role: WatchedRole = SETTINGS_ROLE,
): void {
  const hasher = (text: string) => signer.hmac16("unit", text);
  const was = before === null ? null : unitsOf(role, before, { hasher });
  const now = unitsOf(role, after, { hasher });
  const old = new Set(was?.ids ?? []);
  const cur = new Set(now.ids);
  const lostHook = (was?.nexusHooks ?? []).some((e) => !now.nexusHooks.includes(e));
  appendNexusRecord(paths, signer, {
    action: uninstall || lostHook ? "uninstall" : "install",
    path: storeKey(canonicalPath(path), d.platform),
    added: now.ids.filter((u) => !old.has(u)),
    removed: (was?.ids ?? []).filter((u) => !cur.has(u)),
    nexusHooks: now.nexusHooks,
  }, { now: d.now.getTime() });
}

// ── Install / uninstall ─────────────────────────────────────────────────────

export type InstallResult = {
  path: string;
  contentTools: string[];
  commandTools: string[];
  fileTools: string[];
  created: boolean;
  /** Every hook was already exactly as this install writes it; the file was left untouched. */
  alreadyInstalled: boolean;
  /** Existing Nexus hooks (older versions, other tool lists, duplicates) this install replaced. */
  replaced: number;
  integrity: InstallIntegrity;
};

type Target = { scope?: "user" | "project"; /** Explicit settings file; overrides `scope`. */ path?: string };
/** `tools`: the PostToolUse content tools (`--tools`); `commandTools`: the PreToolUse command tools. */
type ToolLists = { tools?: string[]; commandTools?: string[] };

function targetPath(opts: Target, deps: InstallDeps): string {
  return opts.path ?? settingsPath(opts.scope ?? "user", deps);
}

/**
 * The content and command tools an install into `settings` writes. Explicit
 * `--tools` always wins. With no explicit list, a plain re-install keeps
 * whatever the existing Nexus hook guards (so a custom list like
 * `mcp__github.*` is never silently dropped) — EXCEPT when that existing set is
 * exactly the stock old default (web-only, Nexus <= 0.7.4), which is migrated
 * forward to the current default so a user who never set `--tools` gains MCP
 * coverage on the documented `guard install` upgrade step. A fresh install (no
 * existing hook) also gets the current default.
 */
function plannedTools(settings: Settings, path: string, opts: ToolLists): { contentTools: string[]; commandTools: string[] } {
  const existingContent = currentNexusTools(settings, "PostToolUse", path);
  const existingCommand = currentNexusTools(settings, "PreToolUse", path)
    .filter((t) => !DEFAULT_FILE_TOOLS.includes(t));
  const contentTools = opts.tools
    ?? (existingContent.length === 0 || sameToolSet(existingContent, OLD_STOCK_GUARDED_TOOLS)
      ? DEFAULT_GUARDED_TOOLS
      : existingContent);
  const commandTools = opts.commandTools ?? (existingCommand.length > 0 ? existingCommand : DEFAULT_COMMAND_TOOLS);
  return { contentTools, commandTools };
}

/**
 * What an install with `opts` would stop guarding: the matcher parts of the
 * Nexus PostToolUse content and PreToolUse groups in the target file that its
 * new lists leave out (a group with no matcher, which runs for every tool,
 * counts as `*`). Empty when it keeps or widens every one. A list entry is
 * split on `|` like a matcher, since install joins the list into one:
 * `--tools 'WebFetch|WebSearch'` keeps both. Read-only. The CLI asks the human
 * first when this is not empty (spec §7, A7): install records its settings
 * change as Nexus's own, so a narrowing an agent ran would pass the next
 * SessionStart in silence.
 */
export function droppedTools(opts: Target & ToolLists = {}, deps: InstallDeps = {}): string[] {
  const d = resolveDeps(deps);
  const path = targetPath(opts, d);
  const { settings } = readSettingsFile(path);
  const { contentTools, commandTools } = plannedTools(settings, path, opts);
  const parts = (list: readonly string[]) => new Set(list.flatMap((t) => t.split("|")));
  const kept: Record<ToolEvent, ReadonlySet<string>> = {
    PostToolUse: parts(contentTools),
    PreToolUse: parts([...commandTools, ...DEFAULT_FILE_TOOLS]),
  };
  const dropped = TOOL_EVENTS.flatMap((event) => eventList(settings, event, path)
    .filter((m) => hooksOf(m).some(isNexusHook) && !isConfirmGroup(event, m))
    .flatMap((m) => (m.matcher ? m.matcher.split("|") : ["*"]))
    .filter((tool) => tool && !kept[event].has(tool)));
  return [...new Set(dropped)];
}

/**
 * `integrity: false` is `guard install --no-integrity`: no SessionStart group
 * (an existing Nexus one is removed) and a signed `.disabled` marker. Neither it
 * nor tool lists that drop a guarded tool (`droppedTools`) are gated here; the
 * CLI asks the human first.
 */
export function installGuard(
  opts: Target & ToolLists & { timeout?: number; integrity?: boolean } = {},
  deps: InstallDeps = {},
): InstallResult {
  const d = resolveDeps(deps);
  const path = targetPath(opts, d);
  return withInstallLock(dirname(path), () => installLocked(path, opts, d));
}

function installLocked(path: string, opts: ToolLists & { timeout?: number; integrity?: boolean }, d: Deps): InstallResult {
  const timeout = opts.timeout ?? DEFAULT_HOOK_TIMEOUT; // seconds
  const integrity = opts.integrity ?? true;
  const created = !existsSync(path);
  const { text: before, settings } = readSettingsFile(path);
  const { contentTools, commandTools } = plannedTools(settings, path, opts);

  // PostToolUse: redact prompt injection in untrusted tool output; with integrity,
  // also confirm that a recorded write to a watched file landed.
  const post = upsertHook(settings, "PostToolUse", contentTools, timeout, path, integrity);
  // PreToolUse: block dangerous commands AND sensitive file writes before they run.
  const pre = upsertHook(settings, "PreToolUse", [...commandTools, ...DEFAULT_FILE_TOOLS], timeout, path);
  // SessionStart: instruction-file integrity, one group with no matcher.
  const session = integrity
    ? upsertHook(settings, "SessionStart", null, timeout, path)
    : { changed: removeNexusHooks(settings, "SessionStart", path) > 0, replaced: 0 };
  const changed = post.changed || pre.changed || session.changed;

  // The store is prepared before the settings change lands and the change is
  // recorded right after, so a SessionStart in between has the least to misread.
  const paths = integrityPaths(d.dataDir);
  const prepared = prepareIntegrity(paths, integrity, d);
  const after = changed ? writeSettings(path, settings) : null;
  let problem = prepared.problem;
  let recorded = false;
  if (after !== null && prepared.signer) {
    try {
      recordChange(paths, prepared.signer, false, path, before, after, d);
      recorded = true;
    } catch (error) {
      problem ??= messageOf(error);
    }
  }
  return {
    path, contentTools, commandTools, fileTools: DEFAULT_FILE_TOOLS, created,
    alreadyInstalled: !changed,
    // Only count a replacement where an event's hooks actually changed; an install
    // removes and re-inserts unchanged hooks identically, which is not a replacement.
    replaced: [post, pre, session].reduce((n, e) => n + (e.changed ? e.replaced : 0), 0),
    integrity: { enabled: integrity, recorded, problem },
  };
}

/**
 * Remove every Nexus hook (all events) from the settings file. When the
 * integrity store exists with a trusted key, the change is recorded as a
 * `nexus` uninstall; the store itself stays.
 */
export function uninstallGuard(opts: Target = {}, deps: InstallDeps = {}): { path: string; removed: number; recorded: boolean } {
  const d = resolveDeps(deps);
  const path = targetPath(opts, d);
  if (!existsSync(path)) return { path, removed: 0, recorded: false };
  return withInstallLock(dirname(path), () => uninstallLocked(path, d));
}

function uninstallLocked(path: string, d: Deps): { path: string; removed: number; recorded: boolean } {
  const { text: before, settings } = readSettingsFile(path);
  if (before === null) return { path, removed: 0, recorded: false }; // removed while this waited for the lock
  let removed = 0;
  for (const event of EVENTS) removed += removeNexusHooks(settings, event, path);
  if (removed === 0) return { path, removed, recorded: false }; // nothing of ours: leave the file byte-for-byte
  if (settings.hooks && Object.keys(settings.hooks).length === 0) delete settings.hooks;
  const after = writeSettings(path, settings);
  let recorded = false;
  try {
    const paths = integrityPaths(d.dataDir);
    const signer = existingSigner(paths);
    if (signer) {
      recordChange(paths, signer, true, path, before, after, d);
      recorded = true;
    }
  } catch {
    // the hooks are gone either way; an unrecorded removal is reported at the next SessionStart
  }
  return { path, removed, recorded };
}

// ── Are integrity's hooks there, and do they run ───────────────────────────

/** A Claude Code settings layer. */
export type SettingsScope = "user" | "project" | "local" | "managed";

/** Where the layers are: the caller resolves U, the project dirs and M (for the CLI's cwd, `layersFor`). */
export type HookLayers = {
  /** U/settings.json. */
  user: string;
  /** The project root R and, when it differs, cwd: each one's `.claude/settings.json` and `.claude/settings.local.json`. */
  projectDirs: readonly string[];
  /** M: its `managed-settings.json` and `managed-settings.d/*.json`. */
  managedDir: string;
  homedir: string;
  platform: NodeJS.Platform;
};

/** What `checkNexusHooks` found across the settings layers. */
export type NexusHookCheck = {
  /**
   * Instruction-file integrity's hooks all run: a Nexus SessionStart hook, a
   * Nexus PreToolUse group and the PostToolUse `INTEGRITY_CONFIRM_MATCHER`
   * group, each in some layer, with the script its `node "<path>"` command
   * names present. `disableAllHooks` is reported apart and not counted here.
   */
  live: boolean;
  /** Some layer holds a Nexus SessionStart hook, whether it runs or not. */
  sessionStart: boolean;
  /** The first layer (user, project, local, managed) whose Nexus SessionStart hook runs, else the first holding any Nexus hook. */
  scope: SettingsScope | null;
  /** That layer's file. */
  path: string | null;
  /** Every layer holding a Nexus hook, in the order read: managed, user, project, local. */
  layers: { scope: SettingsScope; path: string }[];
  /** Why `live` is false, one line per hook that does not run (as `guardStatus`'s outdated reasons word it). */
  problems: string[];
  /** Layers that set `disableAllHooks: true`: no hook runs, live or not. */
  disableAllHooksIn: string[];
  /**
   * The `env.NEXUS_DATA` the hooks get, when they ignore it (`dataDirFrom`) and
   * use ~/.nexus: at most one, from the layer whose value wins (`envPrecedes`).
   * A value a higher layer overrides, even with "", reaches no hook.
   */
  ignoredDataDir: { scope: SettingsScope; path: string; value: string }[];
};

/** The hooks instruction-file integrity needs: how a group is told apart, and the status line when none runs. */
const INTEGRITY_HOOKS = [
  { kind: "SessionStart", label: "SessionStart", missing: SESSION_START_MISSING },
  { kind: "PreToolUse", label: "PreToolUse", missing: "PreToolUse hook is missing" },
  { kind: "confirm", label: `PostToolUse ${INTEGRITY_CONFIRM_MATCHER}`, missing: CONFIRM_MISSING },
] as const;
type IntegrityHook = (typeof INTEGRITY_HOOKS)[number]["kind"];

const SCOPE_ORDER: readonly SettingsScope[] = ["user", "project", "local", "managed"];

/**
 * Claude Code merges `env` across the layers, managed over local over project
 * over user (context.ts reads `autoMemoryDirectory` the same way). Within a
 * layer, a file `layerFiles` lists later wins: a managed drop-in over the base
 * file and a later drop-in over an earlier one, the cwd's project settings
 * over the root's.
 */
const ENV_RANK: Readonly<Record<SettingsScope, number>> = { user: 0, project: 1, local: 2, managed: 3 };
const envPrecedes = (a: SettingsScope, b: SettingsScope) => ENV_RANK[a] >= ENV_RANK[b];

/** The layer files, in precedence order: managed (and its drop-ins), user, then project and local per project dir. */
function layerFiles(l: HookLayers): { scope: SettingsScope; path: string }[] {
  const dropIns = join(l.managedDir, "managed-settings.d");
  return [
    { scope: "managed", path: join(l.managedDir, "managed-settings.json") },
    ...listDir(dropIns, MAX_DIR_ENTRIES).names.filter((n) => n.endsWith(".json")).sort()
      .map((n) => ({ scope: "managed" as const, path: join(dropIns, n) })),
    { scope: "user", path: l.user },
    ...l.projectDirs.flatMap((dir) => [
      { scope: "project" as const, path: join(dir, ".claude", "settings.json") },
      { scope: "local" as const, path: join(dir, ".claude", "settings.local.json") },
    ]),
  ];
}

/** The Nexus command hooks of one settings document, by the integrity hook their group is (null: the content tools'). */
function nexusCommandsOf(doc: Record<string, unknown>): { kind: IntegrityHook | null; command: string }[] {
  const hooks = doc.hooks;
  if (!hooks || typeof hooks !== "object" || Array.isArray(hooks)) return [];
  const out: { kind: IntegrityHook | null; command: string }[] = [];
  for (const event of EVENTS) {
    const groups = (hooks as Record<string, unknown>)[event];
    if (!Array.isArray(groups)) continue;
    for (const m of groups as HookMatcher[]) {
      if (!m || typeof m !== "object") continue;
      const kind = event === "PostToolUse" ? (isConfirmGroup(event, m) ? "confirm" : null) : event;
      for (const h of hooksOf(m)) {
        if (h && (h.type === undefined || h.type === "command") && isNexusHook(h)) out.push({ kind, command: h.command as string });
      }
    }
  }
  return out;
}

/**
 * Whether Nexus's hooks are present and live across the settings layers Claude
 * Code merges: `guard status` and `guard integrity status` both decide it here,
 * so they agree. A hook runs when its command names no script (`nexus guard
 * check`) or the script exists: after an nvm switch, a moved global prefix or a
 * cleaned npx cache, every call fails and Claude Code carries on without it.
 * Read-only; each layer is read as `readLayer` reads it.
 */
export function checkNexusHooks(l: HookLayers, exists: (path: string) => boolean = existsSync): NexusHookCheck {
  const seen = new Set<string>();
  const layers: NexusHookCheck["layers"] = [];
  const disableAllHooksIn: string[] = [];
  /** The `env.NEXUS_DATA` the hooks get: the winning layer's so far (`envPrecedes`). */
  let dataDirEnv: NexusHookCheck["ignoredDataDir"][number] | null = null;
  const runs = new Set<IntegrityHook>();
  /** A hook that does not run: what its command names that is gone. */
  const dead = new Map<IntegrityHook, string>();
  const liveSessionStart: NexusHookCheck["layers"] = [];
  let sessionStart = false;
  for (const { scope, path } of layerFiles(l)) {
    const abs = resolve(path);
    const id = storeKey(abs, l.platform);
    if (seen.has(id)) continue;
    seen.add(id);
    const doc = readLayer(abs);
    if (!doc) continue;
    if (doc.disableAllHooks === true) disableAllHooksIn.push(abs);
    const env = doc.env;
    const value = env && typeof env === "object" ? (env as Record<string, unknown>).NEXUS_DATA : undefined;
    if (typeof value === "string" && (dataDirEnv === null || envPrecedes(scope, dataDirEnv.scope))) dataDirEnv = { scope, path: abs, value };
    const commands = nexusCommandsOf(doc);
    if (commands.length === 0) continue;
    layers.push({ scope, path: abs });
    for (const { kind, command } of commands) {
      if (kind === null) continue;
      if (kind === "SessionStart") sessionStart = true;
      const script = scriptPathOf(command);
      if (script === null || exists(script)) {
        runs.add(kind);
        if (kind === "SessionStart") liveSessionStart.push({ scope, path: abs });
      } else if (!dead.has(kind)) {
        dead.set(kind, `${runsCliGuardCheck(command) ? "a CLI" : "a hook entry"} that no longer exists: ${shownPath(script)}`);
      }
    }
  }
  const first = (list: NexusHookCheck["layers"]) => SCOPE_ORDER.map((s) => list.find((x) => x.scope === s)).find((x) => x !== undefined) ?? null;
  const at = first(liveSessionStart) ?? first(layers);
  const problems: string[] = [];
  const down = INTEGRITY_HOOKS.filter((h) => !runs.has(h.kind));
  for (const h of down) {
    const what = dead.get(h.kind);
    if (what === undefined) {
      problems.push(h.missing);
      continue;
    }
    // hooks that run the same missing script (one install from a package dir since removed) are one problem
    const labels = down.filter((x) => dead.get(x.kind) === what).map((x) => x.label);
    if (labels[0] !== h.label) continue;
    const names = labels.length > 1 ? `${labels.slice(0, -1).join(", ")} and ${labels.at(-1)} hooks run` : `${h.label} hook runs`;
    problems.push(`${names} ${what}`);
  }
  const ignored = dataDirEnv === null ? null : dataDirFrom(dataDirEnv.value, l.homedir, l.platform).ignored;
  return {
    live: problems.length === 0, sessionStart, scope: at?.scope ?? null, path: at?.path ?? null, layers, problems,
    disableAllHooksIn, ignoredDataDir: dataDirEnv !== null && ignored !== null ? [{ ...dataDirEnv, value: ignored }] : [],
  };
}

/** The layers Claude Code reads for `d.cwd`: U's settings, R's and cwd's project and local settings, M's. */
function layersFor(d: Deps): HookLayers {
  const ctx = contextFromCli(d.cwd, { platform: d.platform, homedir: d.homedir, env: d.env, dataDir: d.dataDir, managedDir: d.managedDir });
  return {
    user: settingsPath("user", d),
    projectDirs: ctx && ctx.root !== ctx.cwd ? [ctx.root, d.cwd] : [d.cwd],
    managedDir: d.managedDir,
    homedir: d.homedir,
    platform: d.platform,
  };
}

// ── Status ──────────────────────────────────────────────────────────────────

export type GuardStatus = {
  path: string;
  installed: boolean;
  contentTools: string[];
  commandTools: string[];
  /** Why the installed hooks need `nexus guard install` re-run; empty when current. */
  outdated: string[];
  /** Set when the settings file exists but can't be read as settings. */
  error?: string;
  integrity: {
    /** This settings file holds a Nexus SessionStart hook. */
    sessionStartHook: boolean;
    /** A valid `.disabled` marker has turned instruction-file integrity off. */
    disabled: boolean;
    /** Settings files Claude Code reads (managed, user, project, local, and this one) that set
     *  `disableAllHooks: true`, so no Nexus hook runs. */
    disableAllHooksIn: string[];
    /** Integrity's hooks across every layer Claude Code reads for this cwd, as `guard integrity status` judges them. */
    hooks: NexusHookCheck;
  };
  /** `~/.claude/settings.json` when it still holds Nexus hooks that Claude Code does not run, because
   *  `CLAUDE_CONFIG_DIR` points elsewhere (`staleDefaultSettings`); else null. */
  staleDefaultSettings: string | null;
  /** D, and the `NEXUS_DATA` value it ignored (not absolute), if any. */
  dataDir: DataDirChoice;
};

/** The script a `node "<path>"` (or `node '<path>'`) hook entry or `node "<path>" guard check`
 *  command runs, with or without the Codex install's `--agent codex`, if it names one. */
export function scriptPathOf(command: string): string | null {
  const m = /^\S*node(?:\.exe)?\s+("(?:[^"\\]|\\.)*"|'[^']*'|\S+)(?:\s+guard\s+check)?$/i.exec(withoutAgentFlag(command));
  if (!m) return null;
  if (m[1].startsWith("'")) return m[1].slice(1, -1);
  if (!m[1].startsWith('"')) return m[1];
  try { return JSON.parse(m[1]) as string; } catch { return m[1].slice(1, -1); }
}

function matcherTools(entries: HookMatcher[]): string[] {
  const tools = entries.flatMap((m) => (m.matcher ? m.matcher.split("|") : []));
  return [...new Set(tools)];
}

/** A settings layer's JSON object (a leading BOM allowed), or null: missing, not a regular file, over 4 MiB or not an object. Never blocks on a FIFO. */
export function readLayer(path: string): Record<string, unknown> | null {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch {
    return null;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) return null;
    const parsed: unknown = JSON.parse(readFileSync(fd, "utf-8").replace(/^\ufeff/, "").trim());
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

/**
 * `~/.claude/settings.json` when an absolute `CLAUDE_CONFIG_DIR` points Claude
 * Code at another directory and that file still holds Nexus hooks (any event):
 * Claude Code does not read it then, so those hooks never run (spec §7). Null
 * otherwise. Read-only; a symlinked config dir that is `~/.claude` is the same.
 */
export function staleDefaultSettings(deps: Pick<InstallDeps, "env" | "homedir" | "platform"> = {}): string | null {
  const home = deps.homedir ?? homedir();
  const platform = deps.platform ?? process.platform;
  const { dir, source } = configDirFrom(undefined, { env: deps.env ?? process.env, homedir: home });
  const defaultDir = join(home, ".claude");
  if (source !== "env" || storeKey(canonicalDir(dir), platform) === storeKey(canonicalDir(defaultDir), platform)) return null;
  const path = join(defaultDir, "settings.json");
  const hooks = readLayer(path)?.hooks;
  if (!hooks || typeof hooks !== "object" || Array.isArray(hooks)) return null;
  const ours = Object.values(hooks).some((list) => Array.isArray(list) && list.some((m: HookMatcher) => hooksOf(m).some(isNexusHook)));
  return ours ? path : null;
}

/** Read-only: never writes the settings file or the integrity store, even when the install is outdated. */
export function guardStatus(opts: Target = {}, deps: InstallDeps = {}): GuardStatus {
  const d = resolveDeps(deps);
  const path = targetPath(opts, d);
  const check = checkNexusHooks(layersFor(d));
  const target = resolve(path);
  // the target is listed too when it is none of the layers (an explicit path)
  const targetOff = !check.disableAllHooksIn.some((p) => storeKey(p, d.platform) === storeKey(target, d.platform))
    && readLayer(target)?.disableAllHooks === true;
  const integrity: GuardStatus["integrity"] = {
    sessionStartHook: false,
    disabled: isIntegrityDisabled(integrityPaths(d.dataDir)),
    disableAllHooksIn: targetOff ? [...check.disableAllHooksIn, target] : check.disableAllHooksIn,
    hooks: check,
  };
  const status: GuardStatus = {
    path, installed: false, contentTools: [], commandTools: [], outdated: [], integrity, staleDefaultSettings: staleDefaultSettings(d),
    dataDir: deps.dataDir !== undefined ? { dir: d.dataDir, ignored: null } : dataDirFrom(d.env.NEXUS_DATA, d.homedir, d.platform),
  };
  if (!existsSync(path)) return status;

  const ours = {} as Record<HookEvent, HookMatcher[]>;
  try {
    const settings = readSettingsFile(path).settings;
    for (const event of EVENTS) ours[event] = eventList(settings, event, path).filter((m) => hooksOf(m).some(isNexusHook));
  } catch (err) {
    return { ...status, error: shown(err instanceof Error ? err.message : String(err), 400) };
  }

  integrity.sessionStartHook = ours.SessionStart.length > 0;
  status.installed = EVENTS.reduce((n, event) => n + ours[event].length, 0) > 0;
  if (!status.installed) return status;
  // PostToolUse's integrity group is counted on its own: the content tools are the other group's.
  const confirmGroups = ours.PostToolUse.filter((m) => isConfirmGroup("PostToolUse", m));
  const contentGroups = ours.PostToolUse.filter((m) => !isConfirmGroup("PostToolUse", m));
  status.contentTools = matcherTools(contentGroups);
  status.commandTools = matcherTools(ours.PreToolUse);

  const reasons = new Set<string>();
  const current = guardCommand();
  const nexusHooks = (groups: HookMatcher[]) => groups.flatMap((m) => hooksOf(m).filter(isNexusHook));
  const confirmHooks = nexusHooks(confirmGroups);
  if (confirmHooks.length > 1) reasons.add(`${confirmHooks.length} duplicate PostToolUse ${INTEGRITY_CONFIRM_MATCHER} hooks`);
  for (const event of EVENTS) {
    const hooks = nexusHooks(event === "PostToolUse" ? contentGroups : ours[event]);
    // SessionStart is reported below, unless integrity is off
    if (hooks.length === 0 && event !== "SessionStart") reasons.add(`${event} hook is missing`);
    if (hooks.length > 1) reasons.add(`${hooks.length} duplicate ${event} hooks`);
    for (const h of event === "PostToolUse" ? [...hooks, ...confirmHooks] : hooks) {
      const command = h.command as string;
      if (typeof h.timeout !== "number" || h.timeout > MAX_HOOK_TIMEOUT) {
        reasons.add(`hook timeout is ${shown(String(h.timeout ?? "unset"), 32)} — Claude Code reads seconds, so it should be ${DEFAULT_HOOK_TIMEOUT}`);
      }
      const script = scriptPathOf(command);
      if (script && !existsSync(script)) {
        reasons.add(`hook runs ${runsCliGuardCheck(command) ? "a CLI" : "a hook entry"} that no longer exists: ${shownPath(script)}`);
      } else if (command !== current && runsCliGuardCheck(command) && !runsCliGuardCheck(current)) {
        // Nexus <= 0.7.4 ran the whole CLI (`… guard check`) on every guarded tool call.
        reasons.add(`hook runs the full CLI (\`${shown(command)}\`) on every tool call — the dedicated hook entry (\`${shown(current)}\`) starts faster`);
      } else if (command !== current) {
        reasons.add(`hook runs \`${shown(command)}\` instead of this version's (\`${shown(current)}\`)`);
      }
    }
  }
  const matchesAll = ours.PreToolUse.some((m) => !m.matcher || m.matcher === "*");
  const uncovered = DEFAULT_FILE_TOOLS.filter((t) => !status.commandTools.includes(t));
  if (ours.PreToolUse.length > 0 && !matchesAll && uncovered.length > 0) {
    reasons.add(`file-write guard does not cover ${uncovered.join(", ")}`);
  }
  if (!integrity.sessionStartHook && !integrity.disabled) reasons.add(SESSION_START_MISSING);
  if (confirmHooks.length === 0 && !integrity.disabled) reasons.add(CONFIRM_MISSING);
  status.outdated = [...reasons];
  return status;
}
