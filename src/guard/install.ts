/**
 * Install / remove the agent firewall into a Claude Code settings file by
 * merging PreToolUse / PostToolUse hooks that run the guard. Idempotent and
 * non-destructive: unrelated hooks and settings are preserved, and our hooks are
 * recognised by their command (in every form any Nexus version has written) so
 * install replaces them in place and uninstall removes all of them.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Tools whose output is untrusted external content (PostToolUse content guard). */
export const DEFAULT_GUARDED_TOOLS = ["WebFetch", "WebSearch"];
/** Command-executing tools screened before they run (PreToolUse command guard). */
export const DEFAULT_COMMAND_TOOLS = ["Bash", "PowerShell"];
/** File-writing tools screened for sensitive paths / secrets (PreToolUse). */
export const DEFAULT_FILE_TOOLS = ["Write", "Edit", "NotebookEdit", "MultiEdit"];

/** Claude Code reads a hook's `timeout` in SECONDS. The guard answers in
 *  milliseconds; if it ever hangs, a cancelled hook fails open after this. */
export const DEFAULT_HOOK_TIMEOUT = 30;
/** No deliberate seconds value is this large — it is the milliseconds figure
 *  (15000 → ~4h10m) that Nexus <= 0.7.4 wrote, so status flags it. */
const MAX_HOOK_TIMEOUT = 600;

const EVENTS = ["PostToolUse", "PreToolUse"] as const;
type HookEvent = (typeof EVENTS)[number];

export function settingsPath(scope: "user" | "project" = "user"): string {
  return scope === "user"
    ? join(homedir(), ".claude", "settings.json")
    : join(process.cwd(), ".claude", "settings.json");
}

/** Absolute command Claude Code runs for each guarded tool call. Resolved to
 *  the running CLI so it works even without a global `nexus` on PATH. */
export function guardCommand(): string {
  // dist/guard/install.js → dist/cli/index.js. fileURLToPath (not .pathname)
  // so paths with spaces (common on macOS: "/Users/me/My Project") don't break.
  const cli = resolve(dirname(fileURLToPath(import.meta.url)), "..", "cli", "index.js");
  return existsSync(cli) ? `node ${JSON.stringify(cli)} guard check` : "nexus guard check";
}

/**
 * Is this hook command ours? Matches every form Nexus has installed — the bare
 * `nexus guard check` fallback and `node "<pkg>/dist/cli/index.js" guard check`
 * (POSIX or JSON-escaped Windows path) — plus a hand-written
 * `npx @hawon/nexus guard check`, so none of them survive as a stale duplicate.
 */
export function isNexusGuardCommand(command: unknown): boolean {
  if (typeof command !== "string") return false;
  const words = command.trim().split(/\s+/);
  if (words.length < 3 || words.at(-2) !== "guard" || words.at(-1) !== "check") return false;
  const runner = words.slice(0, -2).join(" ").replace(/["']/g, "").replace(/\\+/g, "/");
  return /(?:^|\/)nexus(?:\.cmd|\.exe)?$/i.test(runner)
    || /(?:^|\s)@hawon\/nexus(?:@\S+)?$/.test(runner)
    || /(?:^|[\s/])dist\/cli\/index\.js$/.test(runner);
}

type HookCommand = { type?: string; command?: unknown; timeout?: unknown; [k: string]: unknown };
type HookMatcher = { matcher?: string; hooks?: HookCommand[]; [k: string]: unknown };
type Settings = { hooks?: { [event: string]: unknown }; [k: string]: unknown };

function readSettings(path: string): Settings {
  if (!existsSync(path)) return {};
  const raw = readFileSync(path, "utf-8").trim();
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
  return parsed as Settings;
}

function writeSettings(path: string, settings: Settings): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(settings, null, 2) + "\n", "utf-8");
}

/** The matcher list for `event`; refuses to touch a hand-broken non-array. */
function eventList(settings: Settings, event: HookEvent, path: string): HookMatcher[] {
  const list = settings.hooks?.[event];
  if (list === undefined) return [];
  if (!Array.isArray(list)) {
    throw new Error(`${path}: hooks.${event} is not an array — fix it by hand; the guard will not overwrite it.`);
  }
  return list as HookMatcher[];
}

function hooksOf(m: HookMatcher): HookCommand[] {
  return Array.isArray(m?.hooks) ? m.hooks : [];
}

function isNexusHook(h: HookCommand): boolean {
  return isNexusGuardCommand(h?.command);
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

/** Make our hook for `event` exactly one entry matching `tools`, replacing any
 *  older / duplicate Nexus entries. Returns whether the list changed. */
function upsertHook(settings: Settings, event: HookEvent, tools: string[], timeout: number, path: string): { changed: boolean; replaced: number } {
  const list = eventList(settings, event, path);
  const { kept, removed, at } = withoutNexus(list);
  const entry: HookMatcher = { matcher: tools.join("|"), hooks: [{ type: "command", command: guardCommand(), timeout }] };
  kept.splice(at < 0 ? kept.length : at, 0, entry);
  if (JSON.stringify(kept) === JSON.stringify(list)) return { changed: false, replaced: removed };
  settings.hooks ??= {};
  settings.hooks[event] = kept;
  return { changed: true, replaced: removed };
}

export type InstallResult = {
  path: string;
  contentTools: string[];
  commandTools: string[];
  fileTools: string[];
  created: boolean;
  /** Both hooks were already exactly as this install writes them; the file was left untouched. */
  alreadyInstalled: boolean;
  /** Existing Nexus hooks (older versions, other tool lists, duplicates) this install replaced. */
  replaced: number;
};

type Target = { scope?: "user" | "project"; /** Explicit settings file; overrides `scope`. */ path?: string };

function targetPath(opts: Target): string {
  return opts.path ?? settingsPath(opts.scope ?? "user");
}

export function installGuard(opts: Target & { tools?: string[]; commandTools?: string[]; timeout?: number } = {}): InstallResult {
  const path = targetPath(opts);
  const contentTools = opts.tools ?? DEFAULT_GUARDED_TOOLS;
  const commandTools = opts.commandTools ?? DEFAULT_COMMAND_TOOLS;
  const timeout = opts.timeout ?? DEFAULT_HOOK_TIMEOUT; // seconds
  const created = !existsSync(path);
  const settings = readSettings(path);

  // PostToolUse: redact prompt injection in untrusted tool output.
  const post = upsertHook(settings, "PostToolUse", contentTools, timeout, path);
  // PreToolUse: block dangerous commands AND sensitive file writes before they run.
  const pre = upsertHook(settings, "PreToolUse", [...commandTools, ...DEFAULT_FILE_TOOLS], timeout, path);

  const changed = post.changed || pre.changed;
  if (changed) writeSettings(path, settings);
  return {
    path, contentTools, commandTools, fileTools: DEFAULT_FILE_TOOLS, created,
    alreadyInstalled: !changed,
    replaced: post.replaced + pre.replaced,
  };
}

export function uninstallGuard(opts: Target = {}): { path: string; removed: number } {
  const path = targetPath(opts);
  if (!existsSync(path)) return { path, removed: 0 };
  const settings = readSettings(path);
  let removed = 0;
  for (const event of EVENTS) {
    const r = withoutNexus(eventList(settings, event, path));
    if (r.removed === 0) continue;
    removed += r.removed;
    if (r.kept.length > 0) settings.hooks![event] = r.kept;
    else delete settings.hooks![event];
  }
  if (removed === 0) return { path, removed }; // nothing of ours: leave the file byte-for-byte
  if (settings.hooks && Object.keys(settings.hooks).length === 0) delete settings.hooks;
  writeSettings(path, settings);
  return { path, removed };
}

export type GuardStatus = {
  path: string;
  installed: boolean;
  contentTools: string[];
  commandTools: string[];
  /** Why the installed hooks need `nexus guard install` re-run; empty when current. */
  outdated: string[];
  /** Set when the settings file exists but can't be read as settings. */
  error?: string;
};

/** The script a `node "<path>" guard check` command runs, if it names one. */
function scriptPathOf(command: string): string | null {
  const m = /^\S*node(?:\.exe)?\s+("(?:[^"\\]|\\.)*"|\S+)\s+guard\s+check$/i.exec(command.trim());
  if (!m) return null;
  if (!m[1].startsWith('"')) return m[1];
  try { return JSON.parse(m[1]) as string; } catch { return m[1].slice(1, -1); }
}

function matcherTools(entries: HookMatcher[]): string[] {
  const tools = entries.flatMap((m) => (m.matcher ? m.matcher.split("|") : []));
  return [...new Set(tools)];
}

/** Read-only: never writes the settings file, even when the install is outdated. */
export function guardStatus(opts: Target = {}): GuardStatus {
  const path = targetPath(opts);
  const status: GuardStatus = { path, installed: false, contentTools: [], commandTools: [], outdated: [] };
  if (!existsSync(path)) return status;

  const ours = {} as Record<HookEvent, HookMatcher[]>;
  try {
    const settings = readSettings(path);
    for (const event of EVENTS) ours[event] = eventList(settings, event, path).filter((m) => hooksOf(m).some(isNexusHook));
  } catch (err) {
    return { ...status, error: err instanceof Error ? err.message : String(err) };
  }

  status.installed = ours.PostToolUse.length + ours.PreToolUse.length > 0;
  if (!status.installed) return status;
  status.contentTools = matcherTools(ours.PostToolUse);
  status.commandTools = matcherTools(ours.PreToolUse);

  const reasons = new Set<string>();
  const current = guardCommand();
  for (const event of EVENTS) {
    const hooks = ours[event].flatMap((m) => hooksOf(m).filter(isNexusHook));
    if (hooks.length === 0) reasons.add(`${event} hook is missing`);
    if (hooks.length > 1) reasons.add(`${hooks.length} duplicate ${event} hooks`);
    for (const h of hooks) {
      const command = h.command as string;
      if (typeof h.timeout !== "number" || h.timeout > MAX_HOOK_TIMEOUT) {
        reasons.add(`hook timeout is ${String(h.timeout ?? "unset")} — Claude Code reads seconds, so it should be ${DEFAULT_HOOK_TIMEOUT}`);
      }
      const script = scriptPathOf(command);
      if (script && !existsSync(script)) reasons.add(`hook runs a CLI that no longer exists: ${script}`);
      else if (command !== current) reasons.add(`hook runs \`${command}\` instead of this CLI (\`${current}\`)`);
    }
  }
  const matchesAll = ours.PreToolUse.some((m) => !m.matcher || m.matcher === "*");
  const uncovered = DEFAULT_FILE_TOOLS.filter((t) => !status.commandTools.includes(t));
  if (ours.PreToolUse.length > 0 && !matchesAll && uncovered.length > 0) {
    reasons.add(`file-write guard does not cover ${uncovered.join(", ")}`);
  }
  status.outdated = [...reasons];
  return status;
}
