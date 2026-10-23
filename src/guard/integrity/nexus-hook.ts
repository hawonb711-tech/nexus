/**
 * Instruction-file integrity — which hook commands are Nexus's own guard hook.
 *
 * A hook counts only when its command is exactly one that `nexus guard install`
 * writes (or the documented `npx` form), word for word, with no shell syntax
 * the shell would act on (a quoted install path may hold `( ) &`):
 * units.ts lists the events of such hooks (`nexusHooks`, which S3 compares), and
 * enumerate.ts leaves the entry script unwatched when it is this install's own.
 * `isNexusGuardCommand` (install.ts) is deliberately looser: it finds every
 * line that ends the way a Nexus command does, so install can replace stale
 * hooks, but such a line can run anything before its last words.
 */

/** Shell operators that end a word when unquoted: `; & | < > ( )` and the backtick. */
const OPERATOR_CHARS = new Set([59, 38, 124, 60, 62, 40, 41, 96]);

/**
 * Words split at whitespace and unquoted shell operators, honouring simple
 * `'…'` and `"…"` quoting (no escapes), so `sh a.sh; nexus …` yields `a.sh`.
 */
export function splitCommandWords(command: string): string[] {
  const words: string[] = [];
  let cur = "";
  let started = false;
  let quote = 0;
  for (let i = 0; i < command.length; i++) {
    const c = command.charCodeAt(i);
    if (quote) {
      if (c === quote) quote = 0;
      else cur += command[i];
    } else if (c === 34 || c === 39) {
      quote = c;
      started = true;
    } else if (c === 32 || c === 9 || c === 10 || c === 13 || OPERATOR_CHARS.has(c)) {
      if (started) words.push(cur);
      cur = "";
      started = false;
    } else {
      cur += command[i];
      started = true;
    }
  }
  if (started) words.push(cur);
  return words;
}

/** Longer than any Nexus command (a path and three words). */
const MAX_COMMAND = 8192;
/** Unquoted shell syntax that makes a command line run more than one plain program. */
const SHELL_SYNTAX = new Set([..."\n\r;&|<>()$`"].map((c) => c.charCodeAt(0)));
/** What the shell still expands inside double quotes: parameters, command substitution. */
const DOUBLE_QUOTED_SYNTAX = new Set([..."\n\r$`"].map((c) => c.charCodeAt(0)));

/**
 * Does `command` use shell syntax where the shell would act on it? Outside
 * quotes, any of `; & | < > ( ) $` and the backtick; inside `"…"`, `$` and the
 * backtick; inside `'…'`, nothing. A line break anywhere, or a quote left open
 * (the shell refuses the line, so the hook never runs). An install path with
 * `( ) &` in it is therefore literal once quoted, as `guardCommand()` quotes it.
 */
function hasShellSyntax(command: string): boolean {
  let quote = 0;
  for (let i = 0; i < command.length; i++) {
    const c = command.charCodeAt(i);
    if (quote) {
      if (c === quote) quote = 0;
      else if (c === 10 || c === 13 || (quote === 34 && DOUBLE_QUOTED_SYNTAX.has(c))) return true;
    } else if (c === 34 || c === 39) {
      quote = c;
    } else if (SHELL_SYNTAX.has(c)) {
      return true;
    }
  }
  return quote !== 0;
}
const NODE = /^node(?:\.exe)?$/i;
const NEXUS = /^nexus(?:\.cmd|\.exe)?$/i;
const NPX = /^npx(?:\.cmd)?$/i;
const NPX_PACKAGE = /^@hawon\/nexus(?:@[\w.~^-]{1,64})?$/;
/** POSIX or Windows absolute (guardCommand() writes JSON-quoted, so `\\` may be doubled). */
const ABSOLUTE = /^(?:\/|[A-Za-z]:[\\/]|\\\\)/;
const HOOK_ENTRY = /[\\/]{1,2}dist[\\/]{1,2}guard[\\/]{1,2}hook\.js$/;
const CLI_ENTRY = /[\\/]{1,2}dist[\\/]{1,2}cli[\\/]{1,2}index\.js$/;

/**
 * Is `command` exactly one of Nexus's guard-hook commands?
 * - `node "<abs>/dist/guard/hook.js"` — what `guardCommand()` writes (single-quoted
 *   when the path holds `$` or a backtick);
 * - `node "<abs>/dist/cli/index.js" guard check` — what Nexus <= 0.7.4 wrote;
 * - `nexus guard check` — `guardCommand()` without a built hook entry;
 * - `npx @hawon/nexus[@version] guard check` — the documented hand-written form.
 * Returns the entry script it names (null for the last two), or null when the
 * command is not one of these. The hook must also have no exec-form `args`; the
 * caller checks that.
 */
export function nexusHookCommand(command: string): { script: string | null } | null {
  if (command.length > MAX_COMMAND || hasShellSyntax(command)) return null;
  const w = splitCommandWords(command);
  const guardCheck = w.length >= 3 && w[w.length - 2] === "guard" && w[w.length - 1] === "check";
  if (w.length === 2 && NODE.test(w[0]) && ABSOLUTE.test(w[1]) && HOOK_ENTRY.test(w[1])) return { script: w[1] };
  if (w.length === 4 && guardCheck && NODE.test(w[0]) && ABSOLUTE.test(w[1]) && CLI_ENTRY.test(w[1])) return { script: w[1] };
  if (w.length === 3 && guardCheck && NEXUS.test(w[0])) return { script: null };
  if (w.length === 4 && guardCheck && NPX.test(w[0]) && NPX_PACKAGE.test(w[1])) return { script: null };
  return null;
}
