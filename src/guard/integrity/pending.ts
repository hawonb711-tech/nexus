/**
 * Pending-confirm markers. PreToolUse leaves an empty marker when it records
 * an agent write to a watched file (pre-tool.ts); the PostToolUse confirm
 * (handler.ts) removes it. The hook entry (hook.ts) checks for the marker
 * before it loads the guard, so the PostToolUse of an ordinary file edit,
 * which has nothing to confirm, exits after one existsSync.
 *
 * A marker carries nothing: the signed ledger record is the evidence, and the
 * confirm verifies that as before. A marker lost or never written leaves the
 * write unconfirmed, and the next SessionStart reports it as unexplained
 * (fail safe). Markers whose ask the user rejected are never confirmed; the
 * store's garbage collection removes them after a day.
 *
 * Imports only node built-ins and the data-dir helper: it runs on every
 * file-tool PostToolUse.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { nexusDataDir } from "../../shared/data-dir.js";

/** types.ts's INTEGRITY_DIR and PENDING_DIR, repeated so the hook entry loads no other integrity module (pending.test.ts checks they agree). */
const INTEGRITY_DIR_NAME = "integrity";
const PENDING_DIR_NAME = "pending";

/**
 * The file tools whose PostToolUse can only confirm a write (handler.ts answers
 * them with no output): Claude Code's, and Codex's apply_patch, whose
 * PostToolUse confirms every watched file the patch wrote under the one marker
 * its tool use left.
 */
const FILE_WRITE_TOOLS = new Set(["Write", "Edit", "NotebookEdit", "MultiEdit", "apply_patch"]);

/** `D/integrity/pending/<sha256(session_id NUL tool_use_id)[:32]>`. */
export function pendingMarkerPath(dataDir: string, sessionId: string, toolUseId: string): string {
  const name = createHash("sha256").update(`${sessionId}\u0000${toolUseId}`).digest("hex").slice(0, 32);
  return join(dataDir, INTEGRITY_DIR_NAME, PENDING_DIR_NAME, name);
}

/** Leave the marker for one recorded write. Never throws: without it the write stays unconfirmed (fail safe). */
export function markPending(dataDir: string, sessionId: string, toolUseId: string): void {
  try {
    const path = pendingMarkerPath(dataDir, sessionId, toolUseId);
    mkdirSync(join(dataDir, INTEGRITY_DIR_NAME, PENDING_DIR_NAME), { recursive: true, mode: 0o700 });
    writeFileSync(path, "", { mode: 0o600 });
  } catch {
    // unconfirmed, the write shows as unexplained next session
  }
}

/** Remove the marker once the confirm ran. Never throws. */
export function clearPending(dataDir: string, sessionId: string, toolUseId: string): void {
  try {
    unlinkSync(pendingMarkerPath(dataDir, sessionId, toolUseId));
  } catch {
    // gone already
  }
}

/**
 * Is this payload a file tool's PostToolUse with nothing to confirm? Then the
 * full handler would answer it with no output and change nothing, so the hook
 * entry can stop here. False for anything else, and whenever the marker exists.
 */
export function nothingToConfirm(data: unknown, dataDir: () => string = nexusDataDir): boolean {
  if (typeof data !== "object" || data === null || Array.isArray(data)) return false;
  const p = data as Record<string, unknown>;
  if (p.hook_event_name !== "PostToolUse" || typeof p.tool_name !== "string" || !FILE_WRITE_TOOLS.has(p.tool_name)) return false;
  const sessionId = p.session_id;
  const toolUseId = p.tool_use_id;
  // the confirm needs both; without them it does nothing
  if (typeof sessionId !== "string" || sessionId === "" || typeof toolUseId !== "string" || toolUseId === "") return true;
  try {
    return !existsSync(pendingMarkerPath(dataDir(), sessionId, toolUseId));
  } catch {
    return false;
  }
}
