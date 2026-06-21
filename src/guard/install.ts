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

/** Tools whose output is untrusted external content worth scanning by default. */
export const DEFAULT_GUARDED_TOOLS = ["WebFetch", "WebSearch"];

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

type Settings = { hooks?: { PostToolUse?: HookMatcher[]; [k: string]: unknown }; [k: string]: unknown };
type HookMatcher = { matcher?: string; hooks?: { type: string; command: string; timeout?: number }[] };

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

export type InstallResult = { path: string; tools: string[]; created: boolean; alreadyInstalled: boolean };

export function installGuard(opts: { scope?: "user" | "project"; tools?: string[]; timeout?: number } = {}): InstallResult {
  const path = settingsPath(opts.scope ?? "user");
  const tools = opts.tools ?? DEFAULT_GUARDED_TOOLS;
  const settings = readSettings(path);

  settings.hooks ??= {};
  settings.hooks.PostToolUse ??= [];
  const list = settings.hooks.PostToolUse as HookMatcher[];

  const alreadyInstalled = list.some(isNexusHook);
  if (!alreadyInstalled) {
    list.push({
      matcher: tools.join("|"),
      hooks: [{ type: "command", command: guardCommand(), timeout: opts.timeout ?? 15000 }], // ms
    });
  }

  const created = !existsSync(path);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(settings, null, 2) + "\n", "utf-8");
  return { path, tools, created, alreadyInstalled };
}

export function uninstallGuard(opts: { scope?: "user" | "project" } = {}): { path: string; removed: number } {
  const path = settingsPath(opts.scope ?? "user");
  if (!existsSync(path)) return { path, removed: 0 };
  const settings = readSettings(path);
  const list = (settings.hooks?.PostToolUse ?? []) as HookMatcher[];
  const before = list.length;
  const kept = list.filter((m) => !isNexusHook(m));
  if (settings.hooks) settings.hooks.PostToolUse = kept;
  writeFileSync(path, JSON.stringify(settings, null, 2) + "\n", "utf-8");
  return { path, removed: before - kept.length };
}

export function guardStatus(opts: { scope?: "user" | "project" } = {}): { path: string; installed: boolean; tools: string[] } {
  const path = settingsPath(opts.scope ?? "user");
  if (!existsSync(path)) return { path, installed: false, tools: [] };
  let settings: Settings;
  try { settings = readSettings(path); } catch { return { path, installed: false, tools: [] }; }
  const list = (settings.hooks?.PostToolUse ?? []) as HookMatcher[];
  const ours = list.find(isNexusHook);
  return { path, installed: !!ours, tools: ours?.matcher ? ours.matcher.split("|") : [] };
}
