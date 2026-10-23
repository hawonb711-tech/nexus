/**
 * The Claude Code hook entry — the command `nexus guard install` writes, run once
 * per guarded tool call: `node "<pkg>/dist/guard/hook.js"`.
 *
 * It answers exactly like `nexus guard check` (same stdin → same stdout, stderr
 * and exit code; both call `runHandler`), but imports only the guard, not the
 * whole CLI with its memory engine, session parsers, codebase mapper and ML
 * code, so each guarded call starts noticeably faster.
 *
 * Keep the import graph small: hook-entry.test.ts fails if it ever reaches
 * src/cli, src/memory-engine, src/parser, src/obsidian or src/codebase.
 */

import { runHandler } from "./handler.js";

// runHandler never rejects (it fails open). Deliberately not a top-level await:
// like the CLI's plain promise chain, a read that somehow never settles can then
// only end as `guard check` would (exit 0), never with Node's code 13 for an
// unsettled top-level await.
void runHandler();
