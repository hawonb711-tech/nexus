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

/** `--agent codex` / `--agent=codex` in `args` (a hook command's arguments): the Codex dialect; anything else, Claude's. */
export function dialectFromArgs(args: readonly string[]): Dialect {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--agent") return parseDialect(args[i + 1]);
    if (a.startsWith("--agent=")) return parseDialect(a.slice("--agent=".length));
  }
  return "claude";
}

/** An `--agent` value as a dialect: `codex` (any case) is Codex; anything else, or nothing, is Claude's. */
export function parseDialect(value: string | undefined): Dialect {
  return value?.toLowerCase() === "codex" ? "codex" : "claude";
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
