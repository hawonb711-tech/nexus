/**
 * Instruction-file integrity — the PreToolUse / PostToolUse hot path (spec
 * §6.6-6.9): the small pieces the handler's integrity overlay runs on every
 * guarded tool call, before (and usually instead of) loading anything else.
 *
 * - `integrityEnabled`: D/integrity exists (one existsSync), and no signed
 *   `.disabled` marker is there (a second existsSync; the marker's signature is
 *   checked, by a lazily loaded store.ts, only when the file exists);
 * - `writeTarget` / `shellWriteTarget` / `patchTarget`: the absolute path a
 *   file tool, a shell write target or a Codex patch names (its watched role
 *   is paths.ts's `writeRoleOf`,
 *   loaded only for file tools and commands that write a file), and
 *   `inNexusStore`: whether it is in the trust store of the data dir in use;
 * - `matchIndicator`, `stricter`, `withheldServer` and the fixed-text results
 *   (`integrity-tripwire`, `integrity-error`, a patch's delete or move of a
 *   watched file) that need no context;
 * - `confirmWrite`: a watched write's PostToolUse confirms its ledger record;
 * - the session-log functions the overlay uses, re-exported.
 *
 * It loads only session-log.ts (and what that needs): a Bash command with no
 * write target or a PostToolUse loads nothing else, a file write (or a command
 * that writes one) paths.ts, and a watched write pre-tool.ts. No subprocess,
 * no network.
 */

import { existsSync } from "node:fs";
import { join, posix, win32 } from "node:path";
import type { CommandResult } from "../command.js";
import { headUnits } from "../codex/utf16.js";
import { integrityDirExists, normalizeMcpServerName } from "./session-log.js";
import type { SessionIndicator, SessionStateDoc } from "./types.js";

// What the handler's overlay uses from the session log, from this one module.
export { appendSessionEvents, readSessionState, sid16, tailMsFor, UNREVIEWED_MCP_REASON } from "./session-log.js";

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
 * PostToolUse of a write to a watched file: sign the `confirm` records that let
 * attribution count the write PreToolUse recorded, one per store key it was
 * recorded under (store.ts and ledger.ts are loaded only here). Nothing is
 * written without a trusted key, as at PreToolUse.
 */
export async function confirmWrite(dataDir: string, input: { sid: string; tu: string; paths: readonly string[] }, now: number): Promise<boolean> {
  const [{ integrityPaths, readIntegrityKey, signerFor }, { appendConfirmRecord }] = await Promise.all([storeModule(), import("./ledger.js")]);
  const paths = integrityPaths(dataDir);
  const key = readIntegrityKey(paths);
  if (key.state !== "ok") return false;
  const signer = signerFor(key.key);
  for (const path of input.paths) appendConfirmRecord(paths, signer, { sid: input.sid, tu: input.tu, path }, { now });
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

/**
 * The absolute path a Codex apply_patch operation names: Codex joins a
 * relative path to the session's cwd as it is (`~/x` is a directory named `~`
 * there, not the home directory), so unlike `writeTarget` nothing is expanded;
 * with no absolute cwd a relative path has none (null).
 */
export function patchTarget(path: string, cwd: unknown, deps: { platform: NodeJS.Platform }): string | null {
  const p = pathsFor(deps.platform);
  if (path === "") return null;
  if (p.isAbsolute(path)) return p.resolve(path);
  return typeof cwd === "string" && p.isAbsolute(cwd) ? p.resolve(cwd, path) : null;
}

/** A shell target's leading home or working-directory variable (`~`, `$HOME`, `${HOME}`, PowerShell's and cmd's home; `$PWD`, `${PWD}`). */
const SHELL_HOME = /^(?:~|\$HOME|\$\{HOME\}|\$env:(?:USERPROFILE|HOME)|%USERPROFILE%)(?=[\\/]|$)/i;
const SHELL_PWD = /^(?:\$PWD|\$\{PWD\})(?=[\\/]|$)/;

/**
 * The absolute path a shell write target names (as `analyzeShellCommand` found
 * it), as `writeTarget` resolves a file tool's: a leading home or `$PWD`
 * variable expanded first. Null for a device (`/dev/null`) and for a target
 * that still holds a variable or a substitution: the shell resolves those, and
 * SessionStart reports what they changed.
 */
export function shellWriteTarget(target: string, cwd: unknown, deps: { homedir: string; platform: NodeJS.Platform }): string | null {
  let t = target;
  const home = SHELL_HOME.exec(t);
  if (home) t = `~${t.slice(home[0].length) || "/"}`;
  const pwd = SHELL_PWD.exec(t);
  if (pwd) t = `.${t.slice(pwd[0].length)}`;
  if (t.includes("$") || t.startsWith("/dev/")) return null;
  if (t.startsWith("~") && !t.startsWith("~/") && !(deps.platform === "win32" && t.startsWith("~\\"))) return null; // ~user
  return writeTarget(t, cwd, deps);
}

// ── Nexus's own store ───────────────────────────────────────────────────────

/** A shell target's leading reference to the Nexus data directory (`$NEXUS_DATA`, `${NEXUS_DATA}`, PowerShell's and cmd's). */
const SHELL_DATA_DIR = /^(?:\$NEXUS_DATA|\$\{NEXUS_DATA\}|\$env:NEXUS_DATA|%NEXUS_DATA%)(?=[\\/]|$)/i;

/** `target` with a leading `$NEXUS_DATA` (any spelling) made D, which the hook's own NEXUS_DATA names. */
export function expandDataDir(target: string, dataDir: string): string {
  const m = SHELL_DATA_DIR.exec(target);
  return m ? `${dataDir}${target.slice(m[0].length)}` : target;
}

/**
 * Is `abs` part of Nexus's trust store at D: inside D/integrity or
 * D/observations (or one of them), or D/.integrity-anchor? Compared lexically
 * as store keys (forward slashes; lower-cased on win32).
 */
export function inNexusStore(abs: string, dataDir: string, platform: NodeJS.Platform): boolean {
  const p = pathsFor(platform);
  const key = (path: string) => {
    const k = p.resolve(path).replace(/\\/g, "/"); // resolve drops a trailing separator
    return platform === "win32" ? k.toLowerCase() : k;
  };
  const a = key(abs);
  const d = key(dataDir);
  const inside = (dir: string) => a === dir || a.startsWith(`${dir}/`);
  return inside(`${d}/integrity`) || inside(`${d}/observations`) || a === `${d}/.integrity-anchor`;
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

/** `text` for a message: escapes and control characters made spaces, at most `max` characters (a surrogate pair kept whole). */
export function plainText(text: string, max: number): string {
  const clean = headUnits(text, PRE_CUT).replace(ANSI_CSI, " ").replace(UNSAFE, " ").replace(SPACES, " ").trim();
  return clean.length <= max ? clean : `${headUnits(clean, max - 1)}…`;
}

/** Characters of a token or file name shown in a reason. */
const SHOWN_CHARS = 120;

/**
 * The first indicator (`sessions/<sid16>.json`, lower-cased) that the
 * lower-cased `text` contains, or null: a command argument (`cmd`) as a whole
 * shell word or a path's last segment (`wordIn`: `npx eslint`, `bin/eslint`,
 * `Run eslint.`, not `.eslintrc`, `eslint-plugin-x` or the directory
 * `eslint/`), any other anywhere. With `anywhere`, a command argument too: a
 * write that would persist flagged text is denied on the safe side (pre-tool.ts).
 */
export function matchIndicator(text: string, indicators: readonly SessionIndicator[], anywhere = false): SessionIndicator | null {
  if (indicators.length === 0 || text === "") return null;
  const hay = text.toLowerCase();
  for (const ind of indicators) if (ind.cmd && !anywhere ? wordIn(hay, ind.t) : hay.includes(ind.t)) return ind;
  return null;
}

/** A character that continues a shell word or path segment. */
const WORD_CHAR = /[A-Za-z0-9_.-]/;
const isWordChar = (c: string | undefined) => c !== undefined && WORD_CHAR.test(c);
/**
 * Does `hay` from `at` on continue a word that ends at `at`? A word character
 * does, and so does a path separator (`prisma/schema.prisma` names a directory,
 * not the command); dots only when one of those follows them
 * (`eslint.config.js`), not a sentence's full stop (`Run eslint.`).
 */
function continuesAt(hay: string, at: number): boolean {
  let i = at;
  while (hay[i] === ".") i++;
  const c = hay[i];
  return isWordChar(c) || c === "/" || c === "\\";
}
/** Occurrences of a command indicator looked at per text; one past them counts as a match (asking is the safe side). */
const MAX_WORD_CHECKS = 64;

/**
 * Does `t` occur in `hay` with no word character continuing it on either side,
 * nor a path separator after it (`continuesAt`; a side where `t` itself starts
 * or ends with a non-word character needs none)? Each occurrence is found from
 * the last one on, and at most MAX_WORD_CHECKS of them are looked at: linear in
 * `hay`.
 */
function wordIn(hay: string, t: string): boolean {
  const openStart = !isWordChar(t[0]);
  const openEnd = !isWordChar(t[t.length - 1]);
  let checks = 0;
  for (let at = hay.indexOf(t); at >= 0; at = hay.indexOf(t, at + 1)) {
    if ((openStart || !isWordChar(hay[at - 1])) && (openEnd || !continuesAt(hay, at + t.length))) return true;
    if (++checks >= MAX_WORD_CHECKS) return true;
  }
  return false;
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
 * A Codex patch deletes a watched file, or moves one (away, or onto another):
 * nothing records a delete or a move as an edit, so the next session start
 * would report the change as made outside the file tools. `label` is the
 * role's noun.
 */
export function patchRemoveResult(kind: "delete" | "move", label: string): CommandResult {
  return {
    decision: "ask",
    rule: kind === "delete" ? "instruction-file-delete" : "instruction-file-move",
    reason: `Caution: this patch ${kind === "delete" ? "deletes" : "moves"} a watched file (${label}), which steers future agent sessions. Nexus records edits, not deletes or moves; confirm you asked for this.`,
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
