/**
 * Which agent's hook format an answer is written in.
 *
 * Claude Code and Codex CLI (0.164.0) send nearly the same hook payloads but
 * parse the answers differently: Codex rejects any field it does not know for
 * the event (the whole answer is then ignored, and the call runs), has no
 * `ask`, and cannot rewrite a tool's output in place. The Codex install runs
 * `node "<pkg>/dist/guard/hook.js" --agent codex`; without the flag every
 * answer stays exactly as it was (the Claude dialect).
 *
 * Loaded by the hook entry before anything else, so it imports nothing.
 */

export type Dialect = "claude" | "codex";

/**
 * The agent a command is for, from its `--codex` switch and `--agent` value:
 * the one reading of them, for `guard check` and the hook entry
 * (`hookDialect`), `guard install|uninstall|status` and `guard integrity`.
 * `--codex` or `--agent codex` (any case) is Codex; `--agent claude`, or
 * neither, Claude Code. An `--agent` value that names neither agent, or
 * `--agent claude` with `--codex`, is an error, with the text to show.
 */
export function agentFromFlags(codex: boolean, agent: string | undefined): { agent: Dialect } | { error: string } {
  const value = agent?.toLowerCase();
  if (value !== undefined && value !== "claude" && value !== "codex") {
    // shown cut and with anything but printable ASCII replaced: it is typed or read from a hooks file
    return { error: `--agent must be claude or codex (got ${JSON.stringify(agent!.slice(0, 40).replace(/[^\x20-\x7e]/g, "?"))})` };
  }
  if (codex && value === "claude") return { error: "--codex and --agent claude contradict each other" };
  return { agent: codex || value === "codex" ? "codex" : "claude" };
}

/**
 * The dialect a hook answers in (`guard check`, the hook entry), from the same
 * flags. A hook must fail open, so an error is not one: it answers in Codex's
 * dialect, whose answers are a subset of what Claude Code accepts, so the
 * answer is valid whichever agent runs the misspelled hook and still blocks
 * (at worst a deny where Claude Code could have asked), where Claude's
 * dialect would be ignored by Codex and let the call run.
 */
export function hookDialect(codex: boolean, agent: string | undefined): Dialect {
  const r = agentFromFlags(codex, agent);
  return "error" in r ? "codex" : r.agent;
}

/** The dialect a hook command's arguments ask for (`--codex`, `--agent codex`, `--agent=codex`), by `hookDialect`. */
export function dialectFromArgs(args: readonly string[]): Dialect {
  let agent: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--agent") agent = args[++i] ?? "";
    else if (a.startsWith("--agent=")) agent = a.slice("--agent=".length);
  }
  return hookDialect(args.includes("--codex"), agent);
}

/**
 * The dialect a payload is answered in: the one the hook command asked for,
 * except that a call of Codex's `apply_patch` tool is always answered in
 * Codex's.
 *
 * Why apply_patch alone: Claude Code has no tool of that name (its file tools
 * are Write, Edit, MultiEdit and NotebookEdit, and an MCP tool is always named
 * `mcp__<server>__<tool>`), so the payload can only come from Codex, through
 * a hooks.json written by hand or by an install older than the flag. Answered
 * in Claude's dialect, every `ask` there would be ignored and the patch would
 * land; Codex's answers are a subset of what Claude Code accepts, so even a
 * Claude-format agent that did name a tool apply_patch would get a valid
 * answer, at worst a deny where it could have asked. Other Codex payloads
 * (Bash, MCP tools, SessionStart) look like Claude Code's, so they are not
 * guessed at: they need the flag.
 */
export function dialectFor(payload: unknown, requested: Dialect | undefined): Dialect {
  if (requested === "codex") return "codex";
  const tool = typeof payload === "object" && payload !== null ? (payload as Record<string, unknown>).tool_name : undefined;
  return tool === APPLY_PATCH ? "codex" : "claude";
}

/** Codex's file-editing tool: tool_input.command holds the whole patch text. */
export const APPLY_PATCH = "apply_patch";
