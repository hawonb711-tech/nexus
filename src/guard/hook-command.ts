/**
 * The hook command `nexus guard install` writes, and recognising every command
 * any Nexus version has written. Self-contained (node: builtins only): the
 * command is resolved next to this module, so a copy of it beside a built
 * `hook.js` names that hook, and instruction-file integrity's enumeration can
 * import it without loading the installer.
 */

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Absolute command Claude Code runs for each guarded tool call: the dedicated
 * hook entry, which loads only the guard instead of the whole CLI. Resolved next
 * to this module so it works even without a global `nexus` on PATH; from source
 * (no built hook.js) it falls back to `nexus guard check`. The path is
 * double-quoted (JSON-escaped), or single-quoted when it holds `$` or a
 * backtick, which the shell would still expand inside double quotes.
 */
export function guardCommand(): string {
  const [hook] = nexusEntryScripts();
  if (!existsSync(hook)) return "nexus guard check";
  return /[$`]/.test(hook) && !hook.includes("'") ? `node '${hook}'` : `node ${JSON.stringify(hook)}`;
}

/**
 * The entry scripts this install's hook commands name: the hook entry
 * `guardCommand()` writes and the CLI entry Nexus <= 0.7.4 ran as
 * `node "<cli>" guard check`. Instruction-file integrity leaves only these
 * unwatched, so rebuilding Nexus's own dist/ is not a change.
 */
export function nexusEntryScripts(): [hook: string, cli: string] {
  // dist/guard/hook-command.js → dist/guard/hook.js. fileURLToPath (not .pathname)
  // so paths with spaces (common on macOS: "/Users/me/My Project") don't break.
  const here = dirname(fileURLToPath(import.meta.url));
  return [resolve(here, "hook.js"), resolve(here, "..", "cli", "index.js")];
}

/** `node "<pkg>/dist/guard/hook.js"` (quotes and Windows backslashes already
 *  normalized away): the dedicated hook entry `guardCommand()` writes. */
function isHookEntry(normalized: string): boolean {
  return /^(?:\S*\/)?node(?:\.exe)?\s/i.test(normalized) && /(?:^|[\s/])dist\/guard\/hook\.js$/.test(normalized);
}

/** The flag alone, anchored at both ends: `--agent codex` or `--agent=codex`. */
const AGENT_FLAG = /^--agent(?:=|\s+)[A-Za-z]{1,16}$/;

/**
 * `command` trimmed, without the answer-format flag at its end: the Codex
 * install writes `guardCommand()` followed by `--agent codex`
 * (codex/install.ts), and the hook entry and `guard check` both read
 * `--agent=codex` too. Linear: `guard status` runs this on every hook command of
 * every settings layer, a cloned repository's included, and a regex unanchored
 * on the left (`\s+--agent…$`) retries its whitespace run from each start, which
 * is quadratic on a long one. The flag is the last `--agent` (its value is
 * letters only), so only that tail is tested, against an anchored pattern.
 */
export function withoutAgentFlag(command: string): string {
  const trimmed = command.trim();
  const at = trimmed.lastIndexOf("--agent");
  if (at <= 0 || !/\s/.test(trimmed[at - 1]) || !AGENT_FLAG.test(trimmed.slice(at))) return trimmed;
  return trimmed.slice(0, at).trimEnd();
}

/**
 * Is this hook command ours? Matches every form Nexus has installed — the
 * current `node "<pkg>/dist/guard/hook.js"` hook entry, the bare
 * `nexus guard check` fallback and `node "<pkg>/dist/cli/index.js" guard check`
 * (POSIX or JSON-escaped Windows paths), each with or without the Codex
 * install's `--agent codex` — plus a hand-written `npx @hawon/nexus guard check`,
 * so none of them survive as a stale duplicate.
 */
export function isNexusGuardCommand(command: unknown): boolean {
  if (typeof command !== "string") return false;
  const trimmed = withoutAgentFlag(command);
  const normalized = trimmed.replace(/["']/g, "").replace(/\\+/g, "/");
  // The repo's own compatibility wrapper (scripts/scan-tool-result.sh) runs
  // `guard check` internally, so the hook command is just the script path.
  if (/(?:^|[\s/])scan-tool-result\.sh\b/.test(normalized)) return true;
  if (isHookEntry(normalized)) return true;
  const words = trimmed.split(/\s+/);
  if (words.length < 3 || words.at(-2) !== "guard" || words.at(-1) !== "check") return false;
  const runner = words.slice(0, -2).join(" ").replace(/["']/g, "").replace(/\\+/g, "/");
  return /(?:^|\/)nexus(?:\.cmd|\.exe)?$/i.test(runner)
    || /(?:^|\s)@hawon\/nexus(?:@\S+)?$/.test(runner)
    || /(?:^|[\s/])dist\/cli\/index\.js$/.test(runner);
}
