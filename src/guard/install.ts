/**
 * Install / remove the agent firewall into a Claude Code settings file by
 * merging a PostToolUse hook that runs the guard on untrusted tool output.
 * Idempotent and non-destructive: existing hooks are preserved, ours are tagged
 * so they can be cleanly removed.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

/** Tag embedded in our hook command so install/uninstall can find exactly it. */
const MARKER = "nexus guard check"; // also the command users see

/** Tools whose output is untrusted external content (PostToolUse content guard). */
export const DEFAULT_GUARDED_TOOLS = ["WebFetch", "WebSearch"];
/** Command-executing tools screened before they run (PreToolUse command guard). */
export const DEFAULT_COMMAND_TOOLS = ["Bash", "PowerShell"];
/** File-writing tools screened for sensitive paths / secrets (PreToolUse). */
export const DEFAULT_FILE_TOOLS = ["Write", "Edit", "NotebookEdit"];

export function settingsPath(scope: "user" | "project" = "user"): string {
  return scope === "user"
    ? join(homedir(), ".claude", "settings.json")
    : join(process.cwd(), ".claude", "settings.json");
}

/** Absolute command Claude Code runs for each guarded tool result. Resolved to
 *  the running CLI so it works even without a global `nexus` on PATH. */
export function guardCommand(): string {
  // dist/guard/install.js → dist/cli/index.js
  const cli = resolve(dirname(new URL(import.meta.url).pathname), "..", "cli", "index.js");
  return existsSync(cli) ? `node ${JSON.stringify(cli)} guard check` : "nexus guard check";
}

type Settings = { hooks?: { PreToolUse?: HookMatcher[]; PostToolUse?: HookMatcher[]; [k: string]: unknown }; [k: string]: unknown };
type HookMatcher = { matcher?: string; hooks?: { type: string; command: string; timeout?: number }[] };

/** Ensure our hook (matching `tools`) is present in the given event array. */
function ensureHook(settings: Settings, event: "PreToolUse" | "PostToolUse", tools: string[], timeout: number): boolean {
  settings.hooks ??= {};
  (settings.hooks as Record<string, HookMatcher[]>)[event] ??= [];
  const list = (settings.hooks as Record<string, HookMatcher[]>)[event];
  if (list.some(isNexusHook)) return false;
  list.push({ matcher: tools.join("|"), hooks: [{ type: "command", command: guardCommand(), timeout }] });
  return true;
}

function readSettings(path: string): Settings {
  if (!existsSync(path)) return {};
  const raw = readFileSync(path, "utf-8").trim();
  if (!raw) return {};
  try {
    return JSON.parse(raw) as Settings;
  } catch {
    throw new Error(
      `Could not parse ${path} as JSON (comments / trailing commas aren't supported here). ` +
      `Fix or remove it, then re-run — the guard will not overwrite a file it can't safely parse.`,
    );
  }
}

function isNexusHook(m: HookMatcher): boolean {
  return (m.hooks ?? []).some((h) => h.command.includes(MARKER));
}

export type InstallResult = {
  path: string;
  contentTools: string[];
  commandTools: string[];
  created: boolean;
  alreadyInstalled: boolean;
};

export function installGuard(opts: { scope?: "user" | "project"; tools?: string[]; commandTools?: string[]; timeout?: number } = {}): InstallResult {
  const path = settingsPath(opts.scope ?? "user");
  const contentTools = opts.tools ?? DEFAULT_GUARDED_TOOLS;
  const commandTools = opts.commandTools ?? DEFAULT_COMMAND_TOOLS;
  const timeout = opts.timeout ?? 15000; // ms
  const created = !existsSync(path);
  const settings = readSettings(path);

  // PostToolUse: redact prompt injection in untrusted tool output.
  const addedPost = ensureHook(settings, "PostToolUse", contentTools, timeout);
  // PreToolUse: block dangerous commands AND sensitive file writes before they run.
  const addedPre = ensureHook(settings, "PreToolUse", [...commandTools, ...DEFAULT_FILE_TOOLS], timeout);

  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(settings, null, 2) + "\n", "utf-8");
  return { path, contentTools, commandTools, created, alreadyInstalled: !addedPost && !addedPre };
}

export function uninstallGuard(opts: { scope?: "user" | "project" } = {}): { path: string; removed: number } {
  const path = settingsPath(opts.scope ?? "user");
  if (!existsSync(path)) return { path, removed: 0 };
  const settings = readSettings(path);
  let removed = 0;
  for (const event of ["PreToolUse", "PostToolUse"] as const) {
    const list = (settings.hooks?.[event] ?? []) as HookMatcher[];
    const kept = list.filter((m) => !isNexusHook(m));
    removed += list.length - kept.length;
    if (settings.hooks) (settings.hooks as Record<string, HookMatcher[]>)[event] = kept;
  }
  writeFileSync(path, JSON.stringify(settings, null, 2) + "\n", "utf-8");
  return { path, removed };
}

export function guardStatus(opts: { scope?: "user" | "project" } = {}): { path: string; installed: boolean; contentTools: string[]; commandTools: string[] } {
  const path = settingsPath(opts.scope ?? "user");
  const empty = { path, installed: false, contentTools: [] as string[], commandTools: [] as string[] };
  if (!existsSync(path)) return empty;
  let settings: Settings;
  try { settings = readSettings(path); } catch { return empty; }
  const post = ((settings.hooks?.PostToolUse ?? []) as HookMatcher[]).find(isNexusHook);
  const pre = ((settings.hooks?.PreToolUse ?? []) as HookMatcher[]).find(isNexusHook);
  return {
    path,
    installed: !!(post || pre),
    contentTools: post?.matcher ? post.matcher.split("|") : [],
    commandTools: pre?.matcher ? pre.matcher.split("|") : [],
  };
}
