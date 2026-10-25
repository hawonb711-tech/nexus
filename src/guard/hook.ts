/**
 * The Claude Code hook entry — the command `nexus guard install` writes, run once
 * per guarded tool call: `node "<pkg>/dist/guard/hook.js"`.
 *
 * It answers exactly like `nexus guard check` (same stdin → same stdout, stderr
 * and exit code; both answer through handler.ts), but imports only the guard,
 * not the whole CLI with its memory engine, session parsers, codebase mapper and
 * ML code, so each guarded call starts noticeably faster.
 *
 * A file tool's PostToolUse (the integrity confirm hook, run after every
 * Write, Edit and MultiEdit) only confirms a write PreToolUse recorded, and
 * gets no output either way; with no pending marker for it there is nothing
 * to confirm, so it stops before the guard is even loaded (pending.ts).
 *
 * Keep the import graph small: hook-entry.test.ts fails if it ever reaches
 * src/cli, src/memory-engine, src/parser, src/obsidian or src/codebase.
 */

import { nothingToConfirm } from "./integrity/pending.js";
import { readStdin } from "./stdin.js";

async function main(): Promise<void> {
  const raw = await readStdin();
  if (!raw.trim()) return; // nothing to inspect → pass through
  let data: unknown;
  try { data = JSON.parse(raw); } catch { return; } // not JSON → pass through
  if (nothingToConfirm(data)) return;
  const { answerPayload } = await import("./handler.js");
  await answerPayload(data);
}

// Fails open: never break the agent because the guard threw. Deliberately not a
// top-level await: like the CLI's plain promise chain, a read that somehow never
// settles can then only end as `guard check` would (exit 0), never with Node's
// code 13 for an unsettled top-level await.
void main().catch(() => {});
