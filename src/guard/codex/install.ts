/**
 * `nexus guard install|uninstall|status --codex`: Nexus's hooks for OpenAI's
 * Codex CLI (0.164.0), in `$CODEX_HOME/hooks.json` (CODEX_HOME from the
 * environment, else ~/.codex).
 *
 * Each hook runs `node "<pkg>/dist/guard/hook.js" --agent codex`, so it answers
 * in Codex's format (codex/output.ts), in four groups:
 * - SessionStart, with no matcher (every source): instruction-file integrity,
 *   with an `additionalContextLimit` large enough for Nexus's whole context;
 * - PreToolUse `^(Bash|apply_patch|mcp__.*)$`: the command and file-write
 *   guards and the integrity write gate. Anchored, because Codex reads any
 *   matcher that is not a plain list of names as an unanchored regex;
 * - PostToolUse `^mcp__.*$`: the content guard on every MCP tool's result;
 * - PostToolUse `apply_patch` (a plain name, matched exactly): integrity's
 *   confirmation that a recorded patch landed.
 * `integrity: false` leaves out SessionStart and the confirm group, as for
 * Claude Code; the store's `.disabled` marker it writes is one switch for both
 * agents.
 *
 * The merge (`placeCodexGroups`) keeps every hook that is not Nexus's; a Nexus
 * group is replaced where it sat and a new one goes at the end of its event's
 * list, so adding one never moves a group of the user's; and a file whose hooks
 * are already right is left byte for byte (but for a leading byte-order mark,
 * which Codex cannot read). A file that changes is written as 2-space JSON with
 * the user's number literals as they were (codex/json-literals.ts): Codex hashes
 * an MCP hook's input into its trust, `1.0` and `1` apart.
 * hooks.json is checked as Codex parses it (`codexHooksProblem`): Codex ignores
 * a file it cannot load whole, and Nexus will not add hooks to one.
 *
 * Codex runs a user hook only once it is trusted (codex/trust.ts), and trust is
 * keyed by position: a hook Nexus's change moves (a group after a removed one)
 * must be trusted again, which install and uninstall report. `trust: true`
 * writes the trust state of Nexus's own hooks into config.toml; nothing else in
 * that file is touched, and the CLI lets only the human run it, or any install
 * that would make Codex stop running a hook it trusts now: a Nexus hook
 * (`stoppedCodexHooks`: a re-install from another copy of Nexus rewrites every
 * command), or one of the user's it moves (`movedCodexHooks`). Install removes
 * the trust of the Nexus hooks it replaces, uninstall Nexus's trust entries
 * with its hooks. Both hold the install lock in CODEX_HOME and replace each
 * file atomically (install.ts). Every change to hooks.json and config.toml is
 * recorded as a signed `nexus` ledger record, cut into units the way the
 * integrity store cuts that file (`recordRole`), so the next session start
 * attributes it to Nexus.
 *
 * Status (`codexStatus`, and `checkCodexHooks` for `guard integrity status`)
 * reports each Nexus group: installed, live (the script it names is there, and
 * it asks for Codex's format), trusted, untrusted or modified, and whether
 * config.toml turns Codex's hooks off.
 */

import { existsSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  DEFAULT_HOOK_TIMEOUT, eventList, existingSigner, guardCommand, hooksOf, isNexusHook, messageOf, parseSettings,
  prepareIntegrity, recordChange, replaceFile, resolveDeps, scriptPathOf, withInstallLock,
  type Deps, type HookCommand, type HookMatcher, type InstallDeps, type InstallIntegrity, type Settings,
} from "../install.js";
import { realPathOrNull, writeRoleOf } from "../integrity/paths.js";
import { displayRaw } from "../integrity/render.js";
import { integrityPaths, isIntegrityDisabled, type IntegrityPaths, type Signer } from "../integrity/store.js";
import { CONTEXT_HARD_CAP, type WatchedRole } from "../integrity/types.js";
import { numberLiterals, stringifyKeeping, type NumberLiterals } from "./json-literals.js";
import {
  CODEX_EVENT_LABELS, editHookTrust, hookStates, hooksFeatureOff, readTextFile, scanToml, trustHash, trustKey, type HookState,
} from "./trust.js";
import { hasLoneSurrogate } from "./utf16.js";

// ── What the install writes ─────────────────────────────────────────────────

/** PreToolUse: the shell, apply_patch and every MCP tool, anchored (Codex reads a non-name matcher as an unanchored regex). */
export const CODEX_PRE_MATCHER = "^(Bash|apply_patch|mcp__.*)$";
/** PostToolUse content guard: every MCP tool's result. */
export const CODEX_CONTENT_MATCHER = "^mcp__.*$";
/** PostToolUse integrity confirm: Codex runs PostToolUse only after the patch applied. A plain name, matched exactly. */
export const CODEX_CONFIRM_MATCHER = "apply_patch";
/**
 * The SessionStart handler's `additionalContextLimit`, in tokens: Codex counts
 * a token as 4 bytes and replaces context over the limit (default 2,500) with a
 * head-and-tail preview. Nexus's context is at most CONTEXT_HARD_CAP UTF-16
 * units, at most 3 UTF-8 bytes each, so this limit is never reached.
 */
export const CODEX_CONTEXT_LIMIT = Math.ceil((CONTEXT_HARD_CAP * 3) / 4);

/** The hook command the Codex install writes: the Claude install's, asking for Codex's answer format. */
export function codexGuardCommand(): string {
  return `${guardCommand()} --agent codex`;
}

/** The groups Nexus installs, in the order they are reported. */
export type CodexGroupKind = "SessionStart" | "PreToolUse" | "content" | "confirm";

type GroupSpec = {
  kind: CodexGroupKind;
  event: "SessionStart" | "PreToolUse" | "PostToolUse";
  matcher: string | null;
  label: string;
  /** Part of instruction-file integrity: left out with `integrity: false`. */
  integrity: boolean;
  /** Names the matcher must match: tool names, or SessionStart's sources. */
  covers: readonly string[];
};

const GROUPS: readonly GroupSpec[] = [
  { kind: "SessionStart", event: "SessionStart", matcher: null, label: "SessionStart", integrity: true, covers: ["startup", "resume", "clear", "compact", "fork"] },
  { kind: "PreToolUse", event: "PreToolUse", matcher: CODEX_PRE_MATCHER, label: "PreToolUse", integrity: false, covers: ["Bash", "apply_patch", "mcp__server__tool"] },
  { kind: "content", event: "PostToolUse", matcher: CODEX_CONTENT_MATCHER, label: "PostToolUse MCP", integrity: false, covers: ["mcp__server__tool"] },
  { kind: "confirm", event: "PostToolUse", matcher: CODEX_CONFIRM_MATCHER, label: `PostToolUse ${CODEX_CONFIRM_MATCHER}`, integrity: true, covers: [CODEX_CONFIRM_MATCHER] },
];
const INSTALL_EVENTS = ["SessionStart", "PreToolUse", "PostToolUse"] as const;
/** The groups instruction-file integrity needs running (as `checkNexusHooks` needs them under Claude Code). */
const INTEGRITY_KINDS: readonly CodexGroupKind[] = ["SessionStart", "PreToolUse", "confirm"];

function plannedGroups(integrity: boolean): GroupSpec[] {
  return GROUPS.filter((g) => integrity || !g.integrity);
}

/** The handler each group gets; SessionStart's also raises Codex's cap on its context. */
function handlerFor(spec: GroupSpec, timeout: number): HookCommand {
  const handler: HookCommand = { type: "command", command: codexGuardCommand(), timeout };
  if (spec.kind === "SessionStart") handler.additionalContextLimit = CODEX_CONTEXT_LIMIT;
  return handler;
}

function groupFor(spec: GroupSpec, timeout: number): HookMatcher {
  const hooks = [handlerFor(spec, timeout)];
  return spec.matcher === null ? { hooks } : { matcher: spec.matcher, hooks };
}

/** A group's place in GROUPS (the order status reports in); one Nexus installs nothing in comes last. */
const kindRank = (kind: CodexGroupKind | null) => (kind === null ? GROUPS.length : GROUPS.findIndex((g) => g.kind === kind));

/** Which of Nexus's groups a Nexus handler sits in, by its event and matcher; null in an event Nexus installs nothing in. */
function kindOf(event: string, matcher: unknown): CodexGroupKind | null {
  if (event === "SessionStart" || event === "PreToolUse") return event;
  if (event === "PostToolUse") return matcher === CODEX_CONFIRM_MATCHER ? "confirm" : "content";
  return null;
}

// ── Where Codex keeps its hooks ─────────────────────────────────────────────

/**
 * CODEX_HOME as Codex resolves it (`find_codex_home`): the variable's real path
 * when it is set (Codex canonicalizes it, and its trust keys name that path),
 * else `~/.codex` as written. Checked with the real binary: a symlinked
 * CODEX_HOME is keyed by its target, a symlinked HOME's `.codex` by the link.
 */
export function codexHome(d: Pick<Deps, "env" | "homedir">): string {
  const raw = d.env.CODEX_HOME;
  if (raw) {
    const abs = resolve(raw);
    return realPathOrNull(abs) ?? abs;
  }
  return join(d.homedir, ".codex");
}

export function codexHooksPath(deps: InstallDeps = {}): string {
  return join(codexHome(resolveDeps(deps)), "hooks.json");
}

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const isAbsent = (v: unknown) => v === undefined || v === null;
const isCount = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
/** A string from hooks.json or config.toml in a message: cleaned like status text, and cut. */
const shown = (text: string, max = 200) => displayRaw(text, max);
const shownPath = (path: string) => displayRaw(path, 200, true);

/**
 * hooks.json's text (null when it does not exist), its settings and their
 * number literals (`numberLiterals`), read as status reads it
 * (`readTextFile`): one non-blocking descriptor, so install and uninstall refuse
 * a FIFO or a file over the size cap instead of hanging on it.
 */
function readHooksFile(path: string): { text: string | null; settings: Settings; literals: NumberLiterals } {
  const read = readTextFile(path);
  if (read.state === "missing") return { text: null, settings: {}, literals: new Map() };
  if (read.state === "invalid") throw new Error(`${shownPath(path)} cannot be read: ${read.why}. Nexus will not change it.`);
  const settings = parseSettings(read.text, path);
  return { text: read.text, settings, literals: numberLiterals(read.text.trim(), settings) };
}

/** Writes hooks.json (`replaceFile`) with the user's number literals as they were, and returns the text written. */
function writeHooks(path: string, settings: Settings, literals: NumberLiterals): string {
  const text = stringifyKeeping(settings, literals) + "\n";
  replaceFile(path, text, 0o666);
  return text;
}

/** Codex cannot read a hooks.json that starts with a byte-order mark (serde_json refuses one). */
const hasBom = (text: string | null) => text?.charCodeAt(0) === 0xfeff;

/** Why Codex cannot read a string that holds an unpaired surrogate (`hasLoneSurrogate`): JSON.parse takes it, serde_json does not. */
const LONE_SURROGATE = "a lone UTF-16 surrogate (an escape such as \\ud800 without its pair), which Codex cannot read";
const isLone = (v: unknown) => typeof v === "string" && hasLoneSurrogate(v);

/**
 * Why Codex would not load this hooks.json, or null. Codex parses the file
 * strictly (codex-rs/config/src/hook_config.rs `HooksFile`): only `hooks` and
 * `description` at the top, and every group and handler of a known event of the
 * right types; any error and it ignores the whole file. That includes a key or
 * a string it reads holding a lone surrogate: every one but the values it
 * skips unread (an unknown event's, a group's unknown key's; checked with the
 * real binary). With `text`, a leading byte-order mark counts too; install
 * rewrites the file without it. With the file's `literals`, so does a whole
 * number (a timeout, a context limit) written as a fraction or with an
 * exponent (`30.0`, `3e1`), which serde_json reads as a float.
 */
export function codexHooksProblem(doc: Record<string, unknown>, from: { text?: string; literals?: NumberLiterals } = {}): string | null {
  if (from.text !== undefined && hasBom(from.text)) return "it starts with a byte-order mark, which Codex cannot read";
  const extra = Object.keys(doc).find((k) => k !== "hooks" && k !== "description");
  if (extra !== undefined) return `it has a top-level key ${JSON.stringify(shown(extra, 60))}, and Codex allows only "hooks" and "description"`;
  if (!isAbsent(doc.description) && typeof doc.description !== "string") return `"description" is not a string`;
  if (isLone(doc.description)) return `"description" holds ${LONE_SURROGATE}`;
  if (doc.hooks === undefined) return null;
  if (!isObject(doc.hooks)) return `"hooks" is not an object`;
  if (Object.keys(doc.hooks).some(isLone)) return `"hooks" has a key that holds ${LONE_SURROGATE}`;
  for (const event of Object.keys(CODEX_EVENT_LABELS)) {
    const groups = doc.hooks[event];
    if (groups === undefined) continue;
    if (!Array.isArray(groups)) return `hooks.${event} is not an array`;
    for (const [gi, group] of groups.entries()) {
      const at = `hooks.${event}[${gi}]`;
      if (!isObject(group)) return `${at} is not an object`;
      if (Object.keys(group).some(isLone)) return `${at} has a key that holds ${LONE_SURROGATE}`;
      if (!isAbsent(group.matcher) && typeof group.matcher !== "string") return `${at}.matcher is not a string`;
      if (isLone(group.matcher)) return `${at}.matcher holds ${LONE_SURROGATE}`;
      if (group.hooks === undefined) continue;
      if (!Array.isArray(group.hooks)) return `${at}.hooks is not an array`;
      for (const [hi, handler] of group.hooks.entries()) {
        const why = handlerProblem(handler, from.literals);
        if (why) return `${at}.hooks[${hi}] ${why}`;
      }
    }
  }
  return null;
}

/** Why Codex would not parse one handler (`HookHandlerConfig`), or null. */
function handlerProblem(h: unknown, literals: NumberLiterals | undefined): string | null {
  if (!isObject(h)) return "is not an object";
  // Codex reads a handler whole before it looks at its type: a lone surrogate anywhere in it counts, in a key Codex ignores too
  if (anyIn(h, isLone)) return `holds ${LONE_SURROGATE}`;
  const optString = (k: string) => (isAbsent(h[k]) || typeof h[k] === "string" ? null : `has a ${k} that is not a string`);
  const optCount = (k: string) => {
    if (isAbsent(h[k])) return null;
    if (!isCount(h[k])) return `has a ${k} that is not a whole number of at least 0`;
    const literal = literals?.get(h)?.get(k);
    return literal !== undefined && /[.eE]/.test(literal) ? `has a ${k} written as ${shown(literal, 40)}, which Codex reads as a fraction, not a whole number` : null;
  };
  switch (h.type) {
    case "command":
      if (typeof h.command !== "string") return "has no command";
      if (!(h.async === undefined || typeof h.async === "boolean")) return "has an async that is not true or false";
      return optString("commandWindows") ?? optString("statusMessage") ?? optCount("timeout") ?? optCount("additionalContextLimit");
    case "mcp_tool":
      if (typeof h.server !== "string" || typeof h.tool !== "string") return "needs a server and a tool";
      // `input` defaults only when absent; Codex also converts it to TOML (`deserialize_mcp_tool_input`), which has no null
      if (h.input !== undefined && !isObject(h.input)) return "has an input that is not an object";
      if (h.input !== undefined && anyIn(h.input, (v) => v === null)) return "has a null in its input, which Codex cannot represent in TOML";
      return optString("statusMessage") ?? optCount("timeout");
    case "prompt":
    case "agent":
      return null;
    default:
      return `has no known type (command, mcp_tool, prompt or agent)`;
  }
}

/**
 * Does `test` hold for `value`, or for a value or an object's key at any depth
 * in it? A stack, not recursion: JSON.parse takes nesting deeper than the call
 * stack.
 */
function anyIn(value: unknown, test: (v: unknown) => boolean): boolean {
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const v = stack.pop();
    if (test(v)) return true;
    if (v === null || typeof v !== "object") continue;
    if (!Array.isArray(v) && Object.keys(v).some(test)) return true;
    for (const child of Object.values(v)) stack.push(child);
  }
  return false;
}

/** Codex's matcher (codex-rs/hooks/src/engine/matcher.rs): none, `""` or `*` match all; plain names, exactly; anything else is an unanchored regex. Null when the regex is one JavaScript cannot read. */
export function codexMatcherMatches(matcher: unknown, name: string): boolean | null {
  if (isAbsent(matcher) || matcher === "" || matcher === "*") return true;
  if (typeof matcher !== "string") return false;
  if (/^[A-Za-z0-9_|]+$/.test(matcher)) return matcher.split("|").includes(name);
  try {
    return new RegExp(matcher, "u").test(name);
  } catch {
    return null;
  }
}

/** Where a handler sits in hooks.json, and its group's matcher (which its trust hash covers). */
type Position = { event: string; group: number; handler: number; matcher: unknown };

/** Every handler object of the file's known events, with where it sits. Objects are compared by identity across a change. */
function positionsOf(settings: Settings): Map<HookCommand, Position> {
  const out = new Map<HookCommand, Position>();
  if (!isObject(settings.hooks)) return out;
  for (const event of Object.keys(CODEX_EVENT_LABELS)) {
    const groups = settings.hooks[event];
    if (!Array.isArray(groups)) continue;
    groups.forEach((g: HookMatcher, gi) => {
      if (isObject(g)) hooksOf(g).forEach((h, hi) => { if (isObject(h)) out.set(h, { event, group: gi, handler: hi, matcher: g.matcher }); });
    });
  }
  return out;
}

// ── config.toml ─────────────────────────────────────────────────────────────

/** What config.toml says that matters here, or why it could not be read. */
type CodexConfig = { text: string | null; states: Map<string, HookState>; hooksOff: string | null; error: string | null };

function readCodexConfig(path: string): CodexConfig {
  const read = readTextFile(path);
  if (read.state === "missing") return { text: null, states: new Map(), hooksOff: null, error: null };
  if (read.state === "invalid") return { text: null, states: new Map(), hooksOff: null, error: `${shownPath(path)} cannot be read: ${read.why}` };
  const scan = scanToml(read.text);
  const error = scan.error ? `${shownPath(path)} line ${scan.error.line}: ${scan.error.message}` : null;
  return { text: read.text, states: hookStates(scan), hooksOff: hooksFeatureOff(scan), error };
}

export type CodexTrust = "trusted" | "untrusted" | "modified";

function trustOf(hash: string | null, state: HookState | undefined): CodexTrust {
  if (hash !== null && state?.trustedHash === hash) return "trusted";
  return state?.trustedHash ? "modified" : "untrusted";
}

// ── The integrity ledger ────────────────────────────────────────────────────

/**
 * How a ledger record cuts a Codex file into units: as the integrity store cuts
 * it (`writeRoleOf`: the role the integrity layer gives the path), so the next
 * session start finds Nexus's own change explained. A file the store does not
 * watch gets `fallback`; its record is then never consulted.
 */
function recordRole(path: string, d: Deps, fallback: WatchedRole): WatchedRole {
  try {
    return writeRoleOf(resolve(path), undefined, { dataDir: d.dataDir, homedir: d.homedir, platform: d.platform, env: d.env, managedDir: d.managedDir }) ?? fallback;
  } catch {
    return fallback;
  }
}
/** hooks.json has Claude Code settings' hook shape, so its fallback units are the settings ones. */
const HOOKS_FALLBACK_ROLE: WatchedRole = "user-settings";
/** config.toml's fallback units: one per line. */
const CONFIG_FALLBACK_ROLE: WatchedRole = "user-rules";

/** Record a change Nexus made to a Codex file; returns the problem, or null once recorded. */
function recordCodexChange(
  paths: IntegrityPaths, signer: Signer | null, uninstall: boolean, path: string, before: string | null, after: string, d: Deps, fallback: WatchedRole,
): string | null {
  if (!signer) return "no integrity key to sign a record with";
  try {
    recordChange(paths, signer, uninstall, path, before, after, d, recordRole(path, d, fallback));
    return null;
  } catch (error) {
    return messageOf(error);
  }
}

// ── Trust state changes ─────────────────────────────────────────────────────

/** A user's hook a change moved, so that its trust (kept under its old position's key) no longer applies: from and to as [group, handler]. */
export type MovedHook = { event: string; from: [number, number]; to: [number, number]; command: string };

const samePlace = (p: Position, q: Position) => p.event === q.event && p.group === q.group && p.handler === q.handler;
/** What a hook runs, to name it by: its command, or an MCP hook's server and tool. */
const hookText = (h: HookCommand) =>
  typeof h.command === "string" ? h.command : h.type === "mcp_tool" ? `mcp_tool ${String(h.server)}/${String(h.tool)}` : String(h.type);
const movedHook = (h: HookCommand, p: Position, q: Position): MovedHook => ({ event: p.event, from: [p.group, p.handler], to: [q.group, q.handler], command: hookText(h) });

/** The user's hooks that `before` → `after` moved and that config.toml holds state for (all moved ones when it could not be read). */
function movedHooks(before: Map<HookCommand, Position>, after: Map<HookCommand, Position>, hooksPath: string, config: CodexConfig): MovedHook[] {
  const moved: MovedHook[] = [];
  for (const [h, p] of before) {
    const q = after.get(h);
    if (isNexusHook(h) || !q || samePlace(p, q)) continue;
    if (config.error === null && !config.states.has(trustKey(hooksPath, p.event, p.group, p.handler))) continue;
    moved.push(movedHook(h, p, q));
  }
  return moved;
}

/**
 * Does config.toml let Codex run the user's hook `h` at `p`: trusted there at
 * its hash, and not turned off? Nexus does not work out an MCP hook's hash
 * (Codex hashes its input as TOML), so for one any trust at `p` counts as its
 * own when `mcp` says so.
 */
function userHookTrusted(h: HookCommand, p: Position, hooksPath: string, config: CodexConfig, d: Deps, mcp: boolean): boolean {
  const state = config.states.get(trustKey(hooksPath, p.event, p.group, p.handler));
  if (!state?.trustedHash || state.enabled === false) return false;
  return h.type === "mcp_tool" ? mcp : trustHash(p.event, p.matcher, h, d.platform) === state.trustedHash;
}

/**
 * The trust edit for a change: each handler `trusted` names trusted at its hash
 * where it now sits; and the state of every Nexus handler the change replaced,
 * moved or took away when that state is Nexus's (trusted at that handler's
 * hash, or holding no hash), so state another hook was trusted at stays, as does
 * trust that still fits the handler now at that position (one written again
 * exactly as it was). `trusted` is only ever the handlers the install itself
 * wrote (`ownHandler`): `isNexusHook` also accepts a line that runs something
 * else before `nexus guard check`, which must never be trusted under Nexus's name.
 */
function trustChanges(
  before: Map<HookCommand, Position>, after: Map<HookCommand, Position>, hooksPath: string, config: CodexConfig,
  trusted: (h: HookCommand, at: Position) => boolean, d: Deps,
): { set: Map<string, string>; remove: Set<string> } {
  const set = new Map<string, string>();
  const remove = new Set<string>();
  const hashNow = new Map<string, string | null>();
  for (const [h, q] of after) {
    const key = trustKey(hooksPath, q.event, q.group, q.handler);
    const hash = trustHash(q.event, q.matcher, h, d.platform);
    hashNow.set(key, hash);
    if (hash && trusted(h, q)) set.set(key, hash);
  }
  for (const [h, p] of before) {
    const q = after.get(h);
    if (!isNexusHook(h) || (q && samePlace(p, q))) continue;
    const key = trustKey(hooksPath, p.event, p.group, p.handler);
    const state = config.states.get(key);
    if (!state || set.has(key) || (state.trustedHash !== null && state.trustedHash === hashNow.get(key))) continue;
    if (state.trustedHash === null || state.trustedHash === trustHash(p.event, p.matcher, h, d.platform)) remove.add(key);
  }
  return { set, remove };
}

/** Is `h` (at `at`) exactly a handler this install writes: in one of `planned`'s groups, as `handlerFor` makes it? */
function ownHandler(h: HookCommand, at: Position, planned: readonly GroupSpec[], timeout: number): boolean {
  const spec = planned.find((g) => g.event === at.event && (g.matcher ?? undefined) === (at.matcher ?? undefined));
  return spec !== undefined && JSON.stringify(h) === JSON.stringify(handlerFor(spec, timeout));
}

/** What a change did to config.toml's trust state. */
export type TrustOutcome = {
  /** Trust entries written for Nexus's hooks. */
  set: number;
  /** Nexus's trust entries removed. */
  removed: number;
  /** A `nexus` ledger record of the config.toml change was written. */
  recorded: boolean;
  /** Why config.toml was not changed, or the change not recorded; null when all went well. */
  problem: string | null;
};

/** Apply the trust edit to config.toml (created when missing and there is something to set), and record it. */
function applyTrust(
  configPath: string, config: CodexConfig, edit: { set: Map<string, string>; remove: Set<string> },
  ledger: { paths: IntegrityPaths; signer: Signer | null; uninstall: boolean }, d: Deps,
): TrustOutcome {
  const none: TrustOutcome = { set: 0, removed: 0, recorded: false, problem: null };
  if (edit.set.size === 0 && edit.remove.size === 0) return none;
  if (config.error !== null && config.text === null) return { ...none, problem: `${config.error}; Nexus did not change it` };
  const before = config.text;
  const r = editHookTrust(before ?? "", edit);
  if (!r.ok) return { ...none, problem: `Nexus did not change ${shownPath(configPath)}: ${r.reason}` };
  if (r.text === (before ?? "")) return none;
  try {
    replaceFile(configPath, r.text, 0o600);
  } catch (error) {
    // the hooks.json change stands either way: report this one rather than lose it
    return { ...none, problem: `Nexus could not write ${shownPath(configPath)}: ${messageOf(error)}` };
  }
  const problem = recordCodexChange(ledger.paths, ledger.signer, ledger.uninstall, configPath, before, r.text, d, CONFIG_FALLBACK_ROLE);
  return { set: r.set.length, removed: r.removed.length, recorded: problem === null, problem };
}

// ── Install / uninstall ─────────────────────────────────────────────────────

export type CodexInstallResult = {
  /** $CODEX_HOME/hooks.json. */
  path: string;
  configPath: string;
  created: boolean;
  /** Every Nexus group was already exactly as this install writes it; hooks.json was left untouched. */
  alreadyInstalled: boolean;
  /** Existing Nexus hooks (other matchers or commands, duplicates) this install replaced. */
  replaced: number;
  /** hooks.json started with a byte-order mark, which Codex cannot read: the rewrite dropped it. */
  strippedBom: boolean;
  groups: { kind: CodexGroupKind; event: string; matcher: string | null }[];
  integrity: InstallIntegrity;
  /**
   * The edit of config.toml: with `trust`, the trust it wrote for Nexus's hooks;
   * with or without it, the trust it removed of the Nexus hooks it replaced.
   */
  trust: TrustOutcome;
  /** Nexus's hooks Codex will not run until they are trusted, by group label, after this install. */
  untrusted: string[];
  /** Nexus's hooks config.toml turns off (`enabled = false`), by group label: Codex does not run them, trusted or not. */
  disabled: string[];
  /** Where config.toml turns Codex's hooks feature off (no hook runs), or null. */
  hooksOff: string | null;
  /** config.toml could not be read: trust and the feature switch are unknown. */
  configError: string | null;
  /** The user's own hooks this change moved, whose trust Codex no longer applies. */
  moved: MovedHook[];
};

/**
 * What an install with `integrity` would stop guarding: the parts of the Nexus
 * PreToolUse and PostToolUse content groups' matchers in hooks.json that the
 * groups it writes do not cover (`*` for a group with none; a regex other than
 * the one written, whole, since what it covers cannot be told). Read-only. The
 * CLI asks the human first when this is not empty, as for Claude Code.
 */
export function droppedCodexTools(opts: { integrity?: boolean } = {}, deps: InstallDeps = {}): string[] {
  const d = resolveDeps(deps);
  const path = join(codexHome(d), "hooks.json");
  const { settings } = readHooksFile(path);
  const planned = plannedGroups(opts.integrity ?? true);
  const dropped = new Set<string>();
  for (const event of ["PreToolUse", "PostToolUse"] as const) {
    const kept = planned.filter((g) => g.event === event).map((g) => g.matcher);
    for (const m of eventList(settings, event, path)) {
      if (!hooksOf(m).some(isNexusHook) || kindOf(event, m.matcher) === "confirm" || kept.includes(m.matcher ?? null)) continue;
      const matcher: unknown = m.matcher;
      if (isAbsent(matcher) || matcher === "" || matcher === "*") dropped.add("*");
      else if (typeof matcher === "string" && /^[A-Za-z0-9_|]+$/.test(matcher)) {
        for (const name of matcher.split("|")) if (name && !kept.some((k) => codexMatcherMatches(k, name))) dropped.add(name);
      } else dropped.add(String(matcher));
    }
  }
  return [...dropped];
}

/** What an install makes of hooks.json, worked out in memory before anything is written. */
type InstallPlan = {
  /** hooks.json's text, null when it does not exist yet. */
  before: string | null;
  /** hooks.json as the install leaves it. */
  settings: Settings;
  /** The user's number literals in it (`numberLiterals`), to write back as they were. */
  literals: NumberLiterals;
  /** Where every handler sat before the change, and where the ones left sit after it. */
  was: Map<HookCommand, Position>;
  now: Map<HookCommand, Position>;
  planned: GroupSpec[];
  changed: boolean;
  replaced: number;
  strippedBom: boolean;
};

/**
 * One event's `list` with every Nexus hook taken out and `entries` put back:
 * each in place of the first group of only Nexus hooks of its kind, or at the
 * end of the list when there is none. A group that also holds the user's hooks
 * keeps them where it is. So adding a group never moves one of the user's,
 * which Codex keeps trust for by position; taking one out does move the groups
 * after it (a duplicate, one `integrity: false` leaves out, uninstall). A new
 * list; `list` is not changed. A group copied without Nexus's hooks gets the
 * number literals of the group it copies.
 */
function placeCodexGroups(
  list: HookMatcher[], event: string, entries: { kind: CodexGroupKind; group: HookMatcher }[], literals: NumberLiterals,
): { list: HookMatcher[]; removed: number } {
  const out: HookMatcher[] = [];
  const placed = new Set<CodexGroupKind>();
  let removed = 0;
  for (const m of list) {
    const hooks = hooksOf(m);
    const ours = hooks.filter(isNexusHook).length;
    removed += ours;
    if (ours === 0) out.push(m);
    else if (ours < hooks.length) {
      const copy = { ...m, hooks: hooks.filter((h) => !isNexusHook(h)) };
      const own = literals.get(m);
      if (own) literals.set(copy, own); // its numbers are the group's, written as they were
      out.push(copy);
    } else {
      const entry = entries.find((e) => e.kind === kindOf(event, m.matcher) && !placed.has(e.kind));
      if (entry) {
        out.push(entry.group);
        placed.add(entry.kind);
      }
    }
  }
  for (const e of entries) if (!placed.has(e.kind)) out.push(e.group);
  return { list: out, removed };
}

/** hooks.json read and Nexus's groups placed in it (`placeCodexGroups`). Throws on a file Codex would not load. */
function planInstall(path: string, integrity: boolean, timeout: number): InstallPlan {
  const { text: before, settings, literals } = readHooksFile(path);
  const problem = codexHooksProblem(settings, { literals });
  if (problem) {
    throw new Error(`Codex would not load ${shownPath(path)}: ${problem}. Fix it, then re-run — Nexus will not add hooks to a file Codex ignores.`);
  }
  const was = positionsOf(settings);
  const planned = plannedGroups(integrity);
  // a byte-order mark makes Codex ignore the file however right its hooks are: rewritten without it
  const strippedBom = hasBom(before);
  let changed = strippedBom;
  let replaced = 0;
  for (const event of INSTALL_EVENTS) {
    const list = eventList(settings, event, path);
    const entries = planned.filter((g) => g.event === event).map((g) => ({ kind: g.kind, group: groupFor(g, timeout) }));
    const { list: next, removed } = placeCodexGroups(list, event, entries, literals);
    if (JSON.stringify(next) === JSON.stringify(list)) continue;
    changed = true;
    replaced += removed;
    settings.hooks ??= {};
    if (next.length > 0) settings.hooks[event] = next;
    else delete settings.hooks[event];
  }
  if (settings.hooks && Object.keys(settings.hooks).length === 0) delete settings.hooks;
  return { before, settings, literals, was, now: positionsOf(settings), planned, changed, replaced: changed ? replaced : 0, strippedBom };
}

/** The label status reports a Nexus handler at `p` under: its group's, or its event's in an event Nexus installs nothing in. */
function labelAt(p: Position): string {
  return GROUPS.find((g) => g.kind === kindOf(p.event, p.matcher))?.label ?? p.event;
}

/** Labels in the order status reports the groups, each once. */
function inGroupOrder(labels: Iterable<string>): string[] {
  const rank = (label: string) => {
    const i = GROUPS.findIndex((g) => g.label === label);
    return i < 0 ? GROUPS.length : i;
  };
  return [...new Set(labels)].sort((a, b) => rank(a) - rank(b));
}

/**
 * The groups (`labelAt`) holding a Nexus hook Codex runs: its script there (or
 * none named), trusted at its hash where it sits, and not turned off. Whether
 * config.toml turns every hook off does not count: the trust outlasts that switch.
 */
function runningGroups(
  positions: Map<HookCommand, Position>, hooksPath: string, config: CodexConfig, d: Deps, exists: (path: string) => boolean,
): Set<string> {
  const running = new Set<string>();
  for (const [h, p] of positions) {
    if (!isNexusHook(h)) continue;
    const script = scriptPathOf(h.command as string);
    const state = config.states.get(trustKey(hooksPath, p.event, p.group, p.handler));
    if ((script !== null && !exists(script)) || state?.enabled === false) continue;
    if (trustOf(trustHash(p.event, p.matcher, h, d.platform), state) === "trusted") running.add(labelAt(p));
  }
  return running;
}

/**
 * What an install with `integrity` would stop Codex running: the groups of
 * Nexus's hooks that run now (`runningGroups`) and that the install rewrites or
 * moves out of the trust Codex holds for them, by label. A re-install from
 * another copy of Nexus (npx, another Node version's global install) rewrites
 * every command, and Codex then skips each hook without a word until the user
 * trusts it again; any process may run that install, an agent's shell included.
 * Read-only. The CLI lets only the human run such an install (with `trust`, the
 * new hooks are trusted at once).
 */
export function stoppedCodexHooks(
  opts: { integrity?: boolean; timeout?: number } = {}, deps: InstallDeps = {}, exists: (path: string) => boolean = existsSync,
): string[] {
  const d = resolveDeps(deps);
  const home = codexHome(d);
  const path = join(home, "hooks.json");
  const plan = planInstall(path, opts.integrity ?? true, opts.timeout ?? DEFAULT_HOOK_TIMEOUT);
  if (!plan.changed) return [];
  const config = readCodexConfig(join(home, "config.toml"));
  const after = runningGroups(plan.now, path, config, d, exists);
  return inGroupOrder([...runningGroups(plan.was, path, config, d, exists)].filter((label) => !after.has(label)));
}

/**
 * The user's own hooks that Codex runs now (`userHookTrusted`) and that an
 * install with `integrity` would move out of that trust, Codex keeping it by
 * position: from the next session on Codex would skip each one, without a
 * word. An install that adds or replaces Nexus's groups moves none
 * (`placeCodexGroups`); one that takes a group out from before them (a
 * duplicate Nexus group) does. Read-only. The CLI lets only the human run such
 * an install.
 */
export function movedCodexHooks(opts: { integrity?: boolean; timeout?: number } = {}, deps: InstallDeps = {}): MovedHook[] {
  const d = resolveDeps(deps);
  const home = codexHome(d);
  const path = join(home, "hooks.json");
  const plan = planInstall(path, opts.integrity ?? true, opts.timeout ?? DEFAULT_HOOK_TIMEOUT);
  if (!plan.changed) return [];
  const config = readCodexConfig(join(home, "config.toml"));
  const moved: MovedHook[] = [];
  for (const [h, p] of plan.was) {
    const q = plan.now.get(h);
    if (isNexusHook(h) || !q || samePlace(p, q)) continue;
    if (userHookTrusted(h, p, path, config, d, true) && !userHookTrusted(h, q, path, config, d, false)) moved.push(movedHook(h, p, q));
  }
  return moved;
}

/**
 * Install Nexus's Codex hooks (see the module comment). `integrity: false`, a
 * narrowing (`droppedCodexTools`), an install that stops trusted hooks running
 * (`stoppedCodexHooks`, `movedCodexHooks`) and `trust` are not gated here: the
 * CLI asks the human first. The trust Codex holds for a Nexus hook the install
 * replaces is removed with or without `trust`: it can only ever match the old
 * hook, and left there it would read as Nexus's hook "changed since trusted",
 * which no later uninstall could tell for Nexus's.
 */
export function installCodex(opts: { integrity?: boolean; trust?: boolean; timeout?: number } = {}, deps: InstallDeps = {}): CodexInstallResult {
  const d = resolveDeps(deps);
  // CODEX_HOME must exist before its real path (which the trust keys name) is known
  if (d.env.CODEX_HOME) mkdirSync(resolve(d.env.CODEX_HOME), { recursive: true });
  const home = codexHome(d);
  return withInstallLock(home, () => installLocked(home, opts, d));
}

function installLocked(home: string, opts: { integrity?: boolean; trust?: boolean; timeout?: number }, d: Deps): CodexInstallResult {
  const integrity = opts.integrity ?? true;
  const timeout = opts.timeout ?? DEFAULT_HOOK_TIMEOUT; // seconds, as Codex reads it
  const path = join(home, "hooks.json");
  const configPath = join(home, "config.toml");
  const { before, settings, literals, was, now, planned, changed, replaced, strippedBom } = planInstall(path, integrity, timeout);
  const config = readCodexConfig(configPath);

  // As for Claude Code: the store is prepared before the change lands, and the change recorded right after.
  const paths = integrityPaths(d.dataDir);
  const prepared = prepareIntegrity(paths, integrity, d);
  let integrityProblem = prepared.problem;
  let recorded = false;
  if (changed) {
    const after = writeHooks(path, settings, literals);
    const why = recordCodexChange(paths, prepared.signer, false, path, before, after, d, HOOKS_FALLBACK_ROLE);
    recorded = why === null;
    if (prepared.signer) integrityProblem ??= why;
  }
  const own = (h: HookCommand, at: Position) => ownHandler(h, at, planned, timeout);
  const edit = trustChanges(was, now, path, config, opts.trust ? own : () => false, d);
  const trust = applyTrust(configPath, config, edit, { paths, signer: prepared.signer, uninstall: false }, d);

  const states = trust.set + trust.removed > 0 ? readCodexConfig(configPath).states : config.states;
  const mine = [...now].filter(([h, q]) => own(h, q));
  const stateAt = (q: Position) => states.get(trustKey(path, q.event, q.group, q.handler));
  return {
    path, configPath, created: before === null, alreadyInstalled: !changed, replaced, strippedBom,
    groups: planned.map((g) => ({ kind: g.kind, event: g.event, matcher: g.matcher })),
    integrity: { enabled: integrity, recorded, problem: integrityProblem, reenabled: prepared.reenabled },
    trust,
    untrusted: inGroupOrder(mine.filter(([h, q]) => trustOf(trustHash(q.event, q.matcher, h, d.platform), stateAt(q)) !== "trusted").map(([, q]) => labelAt(q))),
    disabled: inGroupOrder(mine.filter(([, q]) => stateAt(q)?.enabled === false).map(([, q]) => labelAt(q))),
    hooksOff: config.hooksOff, configError: config.error,
    moved: movedHooks(was, now, path, config),
  };
}

export type CodexUninstallResult = {
  path: string;
  removed: number;
  /** A `nexus` ledger record of the hooks.json change was written. */
  recorded: boolean;
  trust: TrustOutcome;
  moved: MovedHook[];
};

/**
 * Remove every Nexus hook (any event) from hooks.json, and Nexus's trust
 * entries from config.toml; the user's hooks and their trust stay. Recorded as
 * a `nexus` uninstall when the store has a trusted key. Not gated.
 */
export function uninstallCodex(deps: InstallDeps = {}): CodexUninstallResult {
  const d = resolveDeps(deps);
  const home = codexHome(d);
  const path = join(home, "hooks.json");
  const none: CodexUninstallResult = { path, removed: 0, recorded: false, trust: { set: 0, removed: 0, recorded: false, problem: null }, moved: [] };
  if (!existsSync(path)) return none;
  return withInstallLock(home, () => {
    const { text: before, settings, literals } = readHooksFile(path);
    if (before === null) return none;
    const was = positionsOf(settings);
    let removed = 0;
    for (const event of Object.keys(CODEX_EVENT_LABELS)) {
      const r = placeCodexGroups(eventList(settings, event, path), event, [], literals);
      if (r.removed === 0) continue;
      removed += r.removed;
      if (r.list.length > 0) settings.hooks![event] = r.list;
      else delete settings.hooks![event];
    }
    if (removed === 0) return none; // nothing of ours: leave the file byte for byte
    if (settings.hooks && Object.keys(settings.hooks).length === 0) delete settings.hooks;
    const after = writeHooks(path, settings, literals);
    const now = positionsOf(settings);
    const paths = integrityPaths(d.dataDir);
    let signer: Signer | null = null;
    try { signer = existingSigner(paths); } catch { /* no record: reported at the next session start */ }
    const recorded = signer !== null && recordCodexChange(paths, signer, true, path, before, after, d, HOOKS_FALLBACK_ROLE) === null;
    const configPath = join(home, "config.toml");
    const config = readCodexConfig(configPath);
    const trust = applyTrust(configPath, config, trustChanges(was, now, path, config, () => false, d), { paths, signer, uninstall: true }, d);
    return { path, removed, recorded, trust, moved: movedHooks(was, now, path, config) };
  });
}

// ── Status ──────────────────────────────────────────────────────────────────

/** One Nexus handler in hooks.json, as status sees it. */
export type CodexHookEntry = {
  /** Which Nexus group it sits in; null in an event Nexus installs nothing in. */
  kind: CodexGroupKind | null;
  event: string;
  group: number;
  handler: number;
  matcher: string | null;
  command: string;
  /** The key Codex keeps its trust under. */
  key: string;
  /** The script its command names (null for `nexus guard check`). */
  script: string | null;
  /** The command asks for Codex's answer format (`--agent codex`). */
  codexFormat: boolean;
  /** The script is there (or none is named), and the command asks for Codex's format. */
  live: boolean;
  trust: CodexTrust;
  /** config.toml turns it off (`enabled = false`). */
  disabled: boolean;
};

export type CodexGroupStatus = {
  kind: CodexGroupKind;
  label: string;
  installed: boolean;
  /** One of its handlers is live. */
  live: boolean;
  /** One of its live handlers is trusted and not turned off. */
  trusted: boolean;
  /** Codex runs it: trusted, hooks.json loadable and the hooks feature on. */
  runs: boolean;
};

export type CodexStatus = {
  codexHome: string;
  hooksPath: string;
  configPath: string;
  /** hooks.json holds a Nexus hook. */
  installed: boolean;
  /** hooks.json cannot be read, or Codex would not load it. */
  error: string | null;
  /** config.toml cannot be read: trust and the hooks switch are unknown. */
  configError: string | null;
  /** Where config.toml turns Codex's hooks feature off (no hook runs), or null. */
  hooksOff: string | null;
  groups: CodexGroupStatus[];
  entries: CodexHookEntry[];
  /** Labels of Nexus's groups not installed (integrity's only while integrity is on). */
  missing: string[];
  /** Why the hooks need `nexus guard install --codex` re-run; empty when current. */
  outdated: string[];
  /** Why installed hooks do not run: hooks.json not loadable, hooks off, not trusted, changed since trusted, turned off. */
  notRunning: string[];
  integrity: { disabled: boolean };
};

/** Read-only: never writes hooks.json, config.toml or the integrity store. */
export function codexStatus(deps: InstallDeps = {}, exists: (path: string) => boolean = existsSync): CodexStatus {
  const d = resolveDeps(deps);
  const home = codexHome(d);
  const hooksPath = join(home, "hooks.json");
  const configPath = join(home, "config.toml");
  const config = readCodexConfig(configPath);
  const status: CodexStatus = {
    codexHome: home, hooksPath, configPath, installed: false, error: null, configError: config.error, hooksOff: config.hooksOff,
    groups: [], entries: [], missing: [], outdated: [], notRunning: [], integrity: { disabled: isIntegrityDisabled(integrityPaths(d.dataDir)) },
  };
  const read = readTextFile(hooksPath);
  if (read.state === "missing") return status;
  if (read.state === "invalid") return { ...status, error: `${shownPath(hooksPath)} cannot be read: ${read.why}` };
  const body = read.text.replace(/^\ufeff/, "");
  let doc: unknown;
  try {
    doc = JSON.parse(body);
  } catch {
    return { ...status, error: `${shownPath(hooksPath)} is not valid JSON, so Codex does not load it` };
  }
  if (!isObject(doc)) return { ...status, error: `${shownPath(hooksPath)} is not a JSON object, so Codex does not load it` };
  const problem = codexHooksProblem(doc, { text: read.text, literals: numberLiterals(body, doc) });
  if (problem) status.error = `Codex does not load ${shownPath(hooksPath)}: ${problem}`;

  for (const [h, p] of positionsOf(doc as Settings)) {
    if (!isNexusHook(h)) continue;
    const command = h.command as string;
    const script = scriptPathOf(command);
    const codexFormat = /(?:^|\s)--agent(?:=|\s+)codex$/i.test(command.trim());
    const key = trustKey(hooksPath, p.event, p.group, p.handler);
    const state = config.states.get(key);
    status.entries.push({
      kind: kindOf(p.event, p.matcher), event: p.event, group: p.group, handler: p.handler,
      matcher: typeof p.matcher === "string" ? p.matcher : null, command, key, script, codexFormat,
      live: codexFormat && (script === null || exists(script)),
      trust: trustOf(trustHash(p.event, p.matcher, h, d.platform), state), disabled: state?.enabled === false,
    });
  }
  status.installed = status.entries.length > 0;
  if (!status.installed) return status;
  status.entries.sort((a, b) => kindRank(a.kind) - kindRank(b.kind));

  const off = status.error !== null || status.hooksOff !== null;
  for (const spec of GROUPS) {
    const mine = status.entries.filter((e) => e.kind === spec.kind);
    const live = mine.filter((e) => e.live);
    const trusted = live.some((e) => e.trust === "trusted" && !e.disabled);
    status.groups.push({ kind: spec.kind, label: spec.label, installed: mine.length > 0, live: live.length > 0, trusted, runs: trusted && !off });
  }
  const needed = GROUPS.filter((g) => !g.integrity || !status.integrity.disabled);
  status.missing = needed.filter((g) => !status.entries.some((e) => e.kind === g.kind)).map((g) => g.label);
  status.outdated = outdatedReasons(status, needed);
  status.notRunning = notRunningReasons(status);
  return status;
}

/**
 * The outdated reason, and `checkCodexHooks`'s problem, when integrity is on and
 * the install has neither of integrity's own groups (SessionStart, PostToolUse
 * apply_patch): as `--no-integrity` installs it, before an install for either
 * agent turned the one switch both share back on (install.ts
 * `INTEGRITY_LEFT_OUT`, `prepareIntegrity`).
 */
export const CODEX_INTEGRITY_LEFT_OUT =
  `installed without integrity's SessionStart and ${GROUPS[3].label} hooks (by --no-integrity, or a Nexus version before them), ` +
  "while integrity is on: one switch for Claude Code and Codex";

/** Integrity's own groups are both missing, the guard's two there (`CODEX_INTEGRITY_LEFT_OUT`). */
const integrityLeftOut = (missing: readonly string[]) =>
  missing.includes("SessionStart") && missing.includes(GROUPS[3].label) && !missing.includes(GROUPS[1].label) && !missing.includes(GROUPS[2].label);

/** Why a re-install would change Nexus's groups: as `guardStatus` words the Claude install's. */
function outdatedReasons(s: CodexStatus, needed: readonly GroupSpec[]): string[] {
  const reasons = new Set<string>();
  const current = codexGuardCommand();
  const leftOut = integrityLeftOut(s.missing);
  if (leftOut) reasons.add(CODEX_INTEGRITY_LEFT_OUT);
  for (const label of s.missing) {
    if (leftOut && (label === "SessionStart" || label === GROUPS[3].label)) continue;
    reasons.add(label === "SessionStart" ? "SessionStart hook is missing (instruction-file integrity)"
      : label === GROUPS[3].label ? `${label} hook is missing (instruction-file integrity: approved patches would show as unexplained changes)`
        : `${label} hook is missing`);
  }
  for (const spec of needed) {
    const mine = s.entries.filter((e) => e.kind === spec.kind);
    if (mine.length > 1) reasons.add(`${mine.length} duplicate ${spec.label} hooks`);
    const uncovered = mine.length === 0 ? [] : spec.covers.filter((name) => !mine.some((e) => codexMatcherMatches(e.matcher, name)));
    if (uncovered.length) reasons.add(`${spec.label} hook does not cover ${uncovered.map((n) => (n.startsWith("mcp__") ? "MCP tools" : n)).join(", ")}`);
  }
  for (const e of s.entries) {
    const label = GROUPS.find((g) => g.kind === e.kind)?.label ?? e.event;
    if (e.kind === null) reasons.add(`a Nexus hook in ${e.event}, where this version installs none`);
    if (!e.codexFormat) {
      reasons.add(`${label} hook answers in Claude Code's format (no --agent codex): Codex ignores every ask in it and runs the call`);
    } else if (e.script !== null && !e.live) {
      reasons.add(`${label} hook runs a hook entry that no longer exists: ${shownPath(e.script)}`);
    } else if (e.command !== current) {
      reasons.add(`${label} hook runs \`${shown(e.command)}\` instead of this version's (\`${shown(current)}\`)`);
    }
  }
  return [...reasons];
}

/** Why the installed groups do not run, one line each. */
function notRunningReasons(s: CodexStatus): string[] {
  const out: string[] = [];
  if (s.error) out.push(s.error);
  if (s.hooksOff) out.push(`config.toml turns Codex's hooks off (${shown(s.hooksOff, 120)}): Codex runs no hook`);
  if (s.configError) out.push(`${s.configError}: Nexus cannot tell which hooks Codex trusts`);
  for (const g of s.groups) {
    if (!g.installed || !g.live || g.trusted) continue;
    const live = s.entries.filter((e) => e.kind === g.kind && e.live);
    if (live.some((e) => e.disabled)) out.push(`${g.label} hook is turned off in config.toml (enabled = false)`);
    else if (live.some((e) => e.trust === "modified")) out.push(`${g.label} hook changed since it was trusted: Codex skips it until it is trusted again`);
    else out.push(`${g.label} hook is not trusted: Codex skips it (codex exec says nothing)`);
  }
  return out;
}

/** What `guard integrity status` reports of the Codex install: as `checkNexusHooks` does for Claude Code's. */
export type CodexHookCheck = {
  /** $CODEX_HOME/hooks.json. */
  path: string;
  /**
   * Integrity's hooks run under Codex: SessionStart, PreToolUse and the
   * PostToolUse apply_patch group, each live and trusted, hooks.json loadable
   * and the hooks feature on.
   */
  live: boolean;
  /** hooks.json holds a Nexus SessionStart hook, running or not. */
  sessionStart: boolean;
  /** That hook's trust (its live one's, when there are several); null when there is none. */
  sessionStartTrust: CodexTrust | null;
  /** Why `live` is false, one line each. */
  problems: string[];
  /** Where config.toml turns Codex's hooks off, or null. */
  hooksOff: string | null;
};

/** The Codex install as `guard integrity status` reports it, or null when hooks.json holds no Nexus hook. Read-only. */
export function checkCodexHooks(deps: InstallDeps = {}, exists: (path: string) => boolean = existsSync): CodexHookCheck | null {
  const s = codexStatus(deps, exists);
  if (!s.installed) return null;
  const problems: string[] = [];
  if (s.error) problems.push(s.error);
  if (s.hooksOff) problems.push(`config.toml turns Codex's hooks off (${shown(s.hooksOff, 120)})`);
  const leftOut = !s.integrity.disabled && integrityLeftOut(s.groups.filter((g) => !g.installed).map((g) => g.label));
  if (leftOut) problems.push(CODEX_INTEGRITY_LEFT_OUT);
  for (const kind of INTEGRITY_KINDS) {
    const g = s.groups.find((x) => x.kind === kind)!;
    if (!g.installed) {
      if (!leftOut || kind === "PreToolUse") problems.push(`${g.label} hook is missing`);
    }
    else if (!g.live) problems.push(`${g.label} hook does not run Nexus in Codex's format (a hook entry that no longer exists, or no --agent codex)`);
    else if (!g.trusted) problems.push(s.notRunning.find((r) => r.startsWith(`${g.label} hook`)) ?? `${g.label} hook is not trusted`);
  }
  const ss = s.entries.filter((e) => e.kind === "SessionStart");
  return {
    path: s.hooksPath, live: problems.length === 0, sessionStart: ss.length > 0,
    sessionStartTrust: (ss.find((e) => e.live) ?? ss[0])?.trust ?? null, problems, hooksOff: s.hooksOff,
  };
}
