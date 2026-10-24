/**
 * Instruction-file integrity — the PreToolUse / PostToolUse hot path (spec
 * §6.6-6.9): the small pieces the handler's integrity overlay runs on every
 * guarded tool call, before (and usually instead of) loading anything else.
 *
 * - `integrityEnabled`: D/integrity exists (one existsSync), and no signed
 *   `.disabled` marker is there (a second existsSync; the marker's signature is
 *   checked, by a lazily loaded store.ts, only when the file exists);
 * - `writeTarget`: the absolute path a file tool writes (its watched role is
 *   paths.ts's `writeRoleOf`, loaded only for file tools);
 * - `matchIndicator`, `stricter`, `withheldServer` and the fixed-text results
 *   (`integrity-tripwire`, `integrity-error`) that need no context;
 * - `confirmWrite`: a watched write's PostToolUse confirms its ledger record;
 * - the session-log functions the overlay uses, re-exported.
 *
 * It loads only session-log.ts (and what that needs): a Bash command or a
 * PostToolUse loads nothing else, a file write paths.ts, and a watched write
 * pre-tool.ts. No subprocess, no network.
 */

import { existsSync } from "node:fs";
import { join, posix, win32 } from "node:path";
import type { CommandResult } from "../command.js";
import { integrityDirExists, normalizeMcpServerName } from "./session-log.js";
import type { SessionIndicator, SessionStateDoc } from "./types.js";

// What the handler's overlay uses from the session log, from this one module.
export { appendSessionEvents, readSessionState, sid16, tailMsFor } from "./session-log.js";

// types.ts's INTEGRITY_DIR and DISABLED_FILE, repeated so the hot path loads no
// runtime code from types.ts (overlay.test.ts relies on them agreeing).
const INTEGRITY_DIR = "integrity";
const DISABLED_FILE = ".disabled";

// ── Enabled ─────────────────────────────────────────────────────────────────

/** store.ts, imported (once) only to check a `.disabled` marker or the config. */
let store: Promise<typeof import("./store.js")> | undefined;
const storeModule = () => (store ??= import("./store.js"));

/**
 * May the overlay act (and write state)? Only when D/integrity exists and no
 * `.disabled` marker with a valid signature is in it (an unsigned or forged
 * marker leaves integrity on). Costs one existsSync when integrity was never
 * enabled, two when it is on.
 */
export async function integrityEnabled(dataDir: string): Promise<boolean> {
  if (!integrityDirExists(dataDir)) return false;
  if (!existsSync(join(dataDir, INTEGRITY_DIR, DISABLED_FILE))) return true;
  const { integrityPaths, isIntegrityDisabled } = await storeModule();
  return !isIntegrityDisabled(integrityPaths(dataDir));
}

/**
 * PostToolUse of a write to a watched file: sign the `confirm` record that lets
 * attribution count the write PreToolUse recorded (store.ts and ledger.ts are
 * loaded only here). Nothing is written without a trusted key, as at PreToolUse.
 */
export async function confirmWrite(dataDir: string, input: { sid: string; tu: string; path: string }, now: number): Promise<boolean> {
  const [{ integrityPaths, readIntegrityKey, signerFor }, { appendConfirmRecord }] = await Promise.all([storeModule(), import("./ledger.js")]);
  const paths = integrityPaths(dataDir);
  const key = readIntegrityKey(paths);
  if (key.state !== "ok") return false;
  appendConfirmRecord(paths, signerFor(key.key), input, { now });
  return true;
}

/** config `withholdMcp` is not "off" (a config that does not verify is the default, "suspect"). */
export async function withholdingEnabled(dataDir: string): Promise<boolean> {
  const { integrityPaths, readConfig, readIntegrityKey, signerFor } = await storeModule();
  const paths = integrityPaths(dataDir);
  const key = readIntegrityKey(paths);
  return readConfig(paths, key.state === "ok" ? signerFor(key.key) : null).config.withholdMcp !== "off";
}

// ── Where a file tool writes ────────────────────────────────────────────────

const pathsFor = (platform: NodeJS.Platform) => (platform === "win32" ? win32 : posix);

/**
 * The absolute path a file tool's `path` names: a leading `~/` is the home
 * directory, a relative path resolves against the payload's `cwd` (never the
 * process's), and with no absolute cwd a relative path has none (null).
 */
export function writeTarget(path: string, cwd: unknown, deps: { homedir: string; platform: NodeJS.Platform }): string | null {
  const p = pathsFor(deps.platform);
  const expanded = path.startsWith("~/") || (deps.platform === "win32" && path.startsWith("~\\")) ? p.join(deps.homedir, path.slice(2)) : path;
  if (p.isAbsolute(expanded)) return p.resolve(expanded);
  return typeof cwd === "string" && p.isAbsolute(cwd) ? p.resolve(cwd, expanded) : null;
}

// ── Decisions ───────────────────────────────────────────────────────────────

const RANK: Readonly<Record<CommandResult["decision"], number>> = { allow: 0, ask: 1, deny: 2 };

/**
 * The stricter of the static decision and the integrity layer's (deny > ask >
 * allow); on a tie, the integrity layer's (its reason says more). Null only
 * when both are.
 */
export function stricter(base: CommandResult | null, integrity: CommandResult | null): CommandResult | null {
  if (!integrity) return base;
  if (!base) return integrity;
  return RANK[base.decision] > RANK[integrity.decision] ? base : integrity;
}

/** ANSI CSI sequences, then C0 / C1 controls, bidi and invisible format characters: made spaces in display text. */
const ANSI_CSI = /\u001b\[[0-?]{0,64}[ -/]{0,16}[@-~]/g;
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb\u{E0000}-\u{E007F}]/gu;
const SPACES = / {2,64}/g;
const PRE_CUT = 4096;

/** `text` for a message: escapes and control characters made spaces, at most `max` characters. */
export function plainText(text: string, max: number): string {
  const head = text.length > PRE_CUT ? text.slice(0, PRE_CUT) : text;
  const clean = head.replace(ANSI_CSI, " ").replace(UNSAFE, " ").replace(SPACES, " ").trim();
  return clean.length <= max ? clean : `${clean.slice(0, max - 1)}…`;
}

/** Characters of a token or file name shown in a reason. */
const SHOWN_CHARS = 120;

/** The first indicator (`sessions/<sid16>.json`, lower-cased) that the lower-cased `text` contains, or null. */
export function matchIndicator(text: string, indicators: readonly SessionIndicator[]): SessionIndicator | null {
  if (indicators.length === 0 || text === "") return null;
  const hay = text.toLowerCase();
  for (const ind of indicators) if (hay.includes(ind.t)) return ind;
  return null;
}

/** §6.7: a command that uses a token only flagged instruction text carries. */
export function tripwireResult(ind: SessionIndicator): CommandResult {
  return {
    decision: "ask",
    rule: "integrity-tripwire",
    reason: `Caution: this command uses ${plainText(ind.t, SHOWN_CHARS)}, which appears only in instruction text Nexus flagged at session start (${plainText(ind.file, SHOWN_CHARS)}) and that you have not reviewed. Approve only if you added that instruction yourself.`,
  };
}

/** §6.6 step 7: the integrity layer threw after the path matched a watched role. */
export function integrityErrorResult(path: string): CommandResult {
  return {
    decision: "ask",
    rule: "integrity-error",
    reason: `Nexus could not verify this write to ${plainText(path, SHOWN_CHARS)} (internal error); approve only if you asked for it.`,
  };
}

/**
 * The withheld MCP server (`sessions/<sid16>.json`) whose tools `toolName`
 * belongs to, or null (A9): `toolName` starts with `mcp__<n>__`, where n is the
 * listed name as written or as Claude Code normalises it. Two names with one
 * normalised form share their tools' names, so withholding either withholds both.
 */
export function withheldServer(toolName: string, withheld: SessionStateDoc["withheldMcp"]): SessionStateDoc["withheldMcp"][number] | null {
  if (!toolName.startsWith("mcp__")) return null;
  for (const w of withheld) {
    for (const n of [w.name, normalizeMcpServerName(w.name)]) {
      if (n !== "" && toolName.startsWith(`mcp__${n}__`)) return w;
    }
  }
  return null;
}
