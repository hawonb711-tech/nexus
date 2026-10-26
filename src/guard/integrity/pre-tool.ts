/**
 * Instruction-file integrity — an agent's write to a watched file (spec §6.6,
 * the integrity layer; amendments A3, A5, A10).
 *
 * The handler imports this module only when a Write, Edit or MultiEdit (or a
 * file a Codex apply_patch adds or updates) targets a path with a watched
 * role, so an ordinary write never loads it. `watchedWriteDecision`:
 *
 *  1. resolves the context (R, U, A, M, J) from the payload, and the path's
 *     role in it (the hot path's role when the context adds nothing);
 *  2. simulates the write on the current file (at most 4 MiB; an apply_patch
 *     operation as Codex applies it, codex/simulate.ts) and diffs its
 *     units before and after (memory files normalised as A10 says), giving the
 *     units added and removed and the added text: the added lines in order; for
 *     JSON, the descriptions of the added units and their commands;
 *  3. decides, most severe first: a settings file the write leaves with
 *     `disableAllHooks: true` it did not have is denied (`claude-settings`, as
 *     the static rule denies a body that says so), and so is a Codex config
 *     the write leaves with Codex's hooks turned off (`codex-config`:
 *     `[features] hooks = false`, …); a session indicator repeated into an
 *     instruction, settings or memory file is denied when it comes from a
 *     SUSPECT item, and asks when from a HOLD item (`integrity-indicator`);
 *     an instruction, settings, hook or skill file
 *     asks, saying what the write adds and which dangerous switches it turns
 *     on (with `[TAINT]` and `[SCREEN]`) — with `instructionGate: risky`, an
 *     instruction or settings write asks only when `riskyWrite` says so; a
 *     memory file is denied when the added
 *     text carries a prompt-injection pattern, and asks when it reads as a
 *     persistent instruction, when the session is tainted, or after web or MCP
 *     content as `memoryGate` says (`memory-*`); anything else is allowed;
 *  4. merges stricter-wins with the static decision (deny > ask > allow; a tie
 *     takes this reason); a static ask that only names the watched path
 *     (`agent-instructions`, `claude-settings`) is this layer's to make, so
 *     under `instructionGate: risky` it gives way to this layer's allow;
 *  5. unless the result is deny, records the write in the ledger — decision,
 *     permission mode (display only, A3), session level, novelty, detector
 *     reason, a subagent's id and type (A5) and the sha the write leaves — when
 *     the integrity key is trusted, under every store key that names the
 *     written file (through a symlink, the watched file it reaches too), and
 *     leaves a pending marker (pending.ts); attribution counts the record only
 *     once the tool's PostToolUse confirms the write landed (handler.ts).
 *     Under Codex, which cannot ask, an ask is answered as a deny, so only an
 *     allowed write is recorded: a confirmed ask record reads as a change the
 *     user approved in a prompt, and Codex never showed one (if the call runs
 *     anyway, its deny lost to a hook timeout, the change is unexplained at
 *     the next session start, as it should be);
 *  6. if anything throws, asks (`integrity-error`); a static deny stays deny.
 *
 * No subprocess, no network, no model API.
 */

import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import {
  CODEX_HOOKS_OFF_DENY, codexHooksOffIn, DISABLE_ALL_HOOKS, DISABLE_ALL_HOOKS_DENY, inspectFileWrite, steeredBy, type CommandResult,
} from "../command.js";
import { canonicalJson } from "../../shared/sign.js";
import { commandNoun, commandVerdict, markdownVerdict, SCAN_CAP_CHARS, scriptVerdict, type Verdict } from "./screen.js";
import { contextFromHook, type IntegrityContext } from "./context.js";
import { APPLY_PATCH, type Dialect } from "../codex/dialect.js";
import { addedText, type PatchOp } from "../codex/patch.js";
import { simulatePatchOp } from "../codex/simulate.js";
import { headUnits } from "../codex/utf16.js";
import { appendWriteRecord, expectedShaOf, simulateWrite, type SimulatedWrite } from "./ledger.js";
import {
  canonicalPath, isCodexRole, labelOf, linkedWrite, memoryStoreId, projectStoreId, readPrefixLists, storeKey, userStoreId, watchedRoleOf,
  type PrefixLists, type RoleContext,
} from "./paths.js";
import { integrityErrorResult, matchIndicator, plainText, stricter } from "./overlay.js";
import { markPending } from "./pending.js";
import { cleanText, displayCommand, displayPath, displayText, redactText, type DisplayContext } from "./render.js";
import { readSessionLog, readSessionState, sessionLevel, type SessionLog } from "./session-log.js";
import { loadIntegrity, type IntegrityState } from "./store.js";
import { readToml } from "./toml.js";
import { extractTokens, novelTokens, type ActionableToken, type TokenOptions } from "./tokens.js";
import {
  MAX_FILE_BYTES, MAX_FILE_UNITS, ROLE_CLASS, ROLE_UNITS, type InstructionGate, type LedgerWriteRecord, type MemoryGate, type SessionIndicator, type SessionLevel, type WatchedRole,
} from "./types.js";
import { hookEventName, projectClaudeJson, sha256Hex, unitsOf, type FileUnits, type Unit, type UnitHasher } from "./units.js";

/** One agent file-tool write to a watched path. */
export type WatchedWriteRequest = {
  /** The PreToolUse payload: session, cwd, transcript path, permission mode, tool use and subagent ids. */
  payload: Record<string, unknown>;
  /** `Write`, `Edit` or `MultiEdit`; or `apply_patch`, with one Add or Update operation (a PatchOp) as `input`. */
  tool: string;
  input: unknown;
  /**
   * Whose hook format the answer is in (codex/dialect.ts; Claude Code's when
   * absent): under Codex the reasons name Codex as the writer, and an ask,
   * which Codex answers as a deny, is not recorded.
   */
  dialect?: Dialect;
  /** The absolute path written (`writeTarget`: a relative path resolved against the payload's cwd). */
  abs: string;
  /** Its role as the hot path found it. */
  role: WatchedRole;
  /** The static guard's decision, or null. */
  base: CommandResult | null;
  /** sha256(session_id)[:16]. */
  sid: string;
};

export type PreToolDeps = {
  /** Epoch ms of the write (its ledger record's time). */
  now: () => number;
  dataDir: string;
  homedir: string;
  platform: NodeJS.Platform;
  env: Readonly<Record<string, string | undefined>>;
  /** Tests: the managed-policy directory instead of the platform's. */
  managedDir?: string;
  /** Tests: Codex's system directory instead of the platform's. */
  codexSystemDir?: string;
  /** Masks secrets in display text (the handler passes `redactSecretsInText`); default: render's local subset. */
  redact?: (text: string) => string;
  /** Tests: the ledger file name's random part. */
  rand?: () => string;
};

/**
 * The PreToolUse decision for a write to a watched path: the integrity layer's
 * merged with the static one, stricter wins. Never throws: a failure asks
 * (`integrity-error`) unless the static decision already denies.
 */
export function watchedWriteDecision(req: WatchedWriteRequest, deps: PreToolDeps): CommandResult {
  if (req.base?.decision === "deny") return req.base; // nothing is stricter, and a denied write is not recorded
  let shown = req.abs;
  try {
    return decide(req, deps, (path) => { shown = path; });
  } catch {
    return stricter(req.base, integrityErrorResult(shown))!;
  }
}

function decide(req: WatchedWriteRequest, deps: PreToolDeps, show: (path: string) => void): CommandResult {
  const { platform } = deps;
  const ctx = contextFromHook(req.payload, {
    platform, homedir: deps.homedir, env: deps.env, dataDir: deps.dataDir,
    ...(deps.managedDir !== undefined ? { managedDir: deps.managedDir } : {}),
    ...(deps.codexSystemDir !== undefined ? { codexSystemDir: deps.codexSystemDir } : {}),
    ...(req.dialect ? { agent: req.dialect } : {}),
  });
  const display: DisplayContext = { root: ctx?.root ?? "", home: deps.homedir, platform, ...(deps.redact ? { redact: deps.redact } : {}) };
  const canonical = canonicalPath(req.abs);
  // shown from the canonical path: R is canonical, and on win32 a payload may spell the
  // same directory by its 8.3 short name
  const shown = displayPath(canonical, display);
  show(shown);
  const role = refineRole(req, ctx, canonical, deps.dataDir);

  const state = loadIntegrity({ dataDir: deps.dataDir, homedir: deps.homedir, platform }, storeIdsOf(ctx));
  const signer = state.signer;
  const hasher: UnitHasher = signer ? (t) => signer.hmac16("unit", t) : plainHasher;
  const current = readCurrent(req.abs);
  const written = simulated(req.tool, req.input, current);
  if (!written) throw new TypeError("the file tool's input cannot be simulated");
  const writes = toolText(req.tool, req.input);
  const change = diffWrite(role, current, written.text, writes, hasher, ctx);
  // §2.1 #2 on the file the write leaves: an Edit that flips only the value never names the key
  const hooksOff = turnsOffAllHooks(role, current, written.text, change);
  if (hooksOff) return stricter(req.base, { ...hooksOff })!;

  const session = sessionOf(deps.dataDir, req.sid);
  const tokens = tokensOf(change, { root: ctx?.root ?? null, home: deps.homedir, platform });
  const accepted = acceptedTokens(state);
  const novel = accepted ? novelTokens(tokens, accepted, hasher) : tokens;
  const screen = screenOf(role, change);
  const gate = state.config.instructionGate;
  const integrity = integrityDecision({
    path: req.abs, shown, role, change, screen, novel, session, gate: state.config.memoryGate, instructionGate: gate, display,
    agent: req.dialect === "codex" ? "Codex" : "Claude",
    // a file only Codex reads steers Codex whoever writes it (and wherever its C is)
    steered: isCodexRole(role) ? "Codex" : steeredBy(req.abs, req.dialect === "codex" ? "Codex" : undefined),
  });
  const final = stricter(gate === "risky" && ROLE_CLASS[role] === "notice" && pathRuleAsk(req.base) ? null : req.base, integrity)!;

  // what the agent will be let do: under Codex an ask is a deny (codex/output.ts)
  const proceeds = req.dialect === "codex" ? final.decision === "allow" : final.decision !== "deny";
  if (proceeds && signer) {
    const agentId = stringField(req.payload, "agent_id");
    const agentType = stringField(req.payload, "agent_type");
    // every store key that names the written file: the path as written, and through a symlink the file it reaches
    const keys: [string, WriteChange][] = [[storeKey(canonical, platform), change]];
    const linked = linkedWrite(req.abs, req.payload.transcript_path, deps);
    if (linked) keys.push([linked.key, sameUnits(role, linked.role) ? change : diffWrite(linked.role, current, written.text, writes, hasher, ctx)]);
    for (const [path, units] of keys) {
      appendWriteRecord(state.paths, signer, {
        sid: req.sid,
        tu: stringField(req.payload, "tool_use_id") ?? "",
        tool: req.tool as LedgerWriteRecord["tool"],
        path,
        added: units.added,
        removed: units.removed,
        expectedSha: expectedShaOf(written.text),
        approx: written.approx,
        decision: final.decision === "ask" ? "ask" : "allow",
        mode: stringField(req.payload, "permission_mode") ?? null,
        level: session.level,
        novel: novel.length > 0,
        screen: screen?.reason ?? null,
        ...(agentId ? { agentId } : {}),
        ...(agentType ? { agentType } : {}),
      }, { now: deps.now(), ...(deps.rand ? { rand: deps.rand } : {}) });
    }
    // so the hook entry runs this write's PostToolUse confirm (and skips every other file tool's)
    const sessionId = stringField(req.payload, "session_id");
    const toolUseId = stringField(req.payload, "tool_use_id");
    if (sessionId && toolUseId) markPending(deps.dataDir, sessionId, toolUseId);
  }
  return final;
}

/** The text a write leaves: a file tool's (ledger.ts), or one apply_patch operation's as Codex applies it; null when the input is not one. */
function simulated(tool: string, input: unknown, current: string | null): SimulatedWrite | null {
  if (tool !== APPLY_PATCH) return simulateWrite(tool, input, current);
  const op = input as PatchOp | null;
  return op && (op.op === "add" || op.op === "update") ? simulatePatchOp(op, current) : null;
}

/** Do two roles cut a file into the same units (a symlink's record can then reuse its target's)? */
const sameUnits = (a: WatchedRole, b: WatchedRole) =>
  a === b || (ROLE_UNITS[a] === ROLE_UNITS[b] && !CLAUDE_JSON_ROLES.has(a) && !CLAUDE_JSON_ROLES.has(b));
/** Roles fingerprinted by their `.claude.json` projections (`unitViews`). */
const CLAUDE_JSON_ROLES: ReadonlySet<WatchedRole> = new Set<WatchedRole>(["claude-json", "claude-json-project"]);

const stringField = (obj: Record<string, unknown>, key: string): string | undefined =>
  (typeof obj[key] === "string" && obj[key] !== "" ? (obj[key] as string) : undefined);

/** Unit ids for diffing when no key is trusted (nothing is recorded then); never stored. */
const plainHasher: UnitHasher = (t) => sha256Hex(`nexus/integrity/v1/plain-unit${String.fromCharCode(0)}${t}`).slice(0, 16);

// ── Context, role and state ─────────────────────────────────────────────────

/** The path's role with the full context (U, A, R and the prefix lists): its real path first, then as written, else the hot path's. */
function refineRole(req: WatchedWriteRequest, ctx: IntegrityContext | null, canonical: string, dataDir: string): WatchedRole {
  if (!ctx) return req.role;
  const roleCtx: RoleContext = {
    platform: ctx.platform, configDir: ctx.configDir, managedDir: ctx.managedDir, root: ctx.root, autoMemoryDir: ctx.autoMemoryDir, appState: ctx.appState,
    codexHome: ctx.codexHome, codexSystemDir: ctx.codexSystemDir, home: ctx.home,
  };
  let lists: PrefixLists | null | undefined;
  const prefixes = () => (lists === undefined ? (lists = readPrefixLists(dataDir)) : lists);
  return watchedRoleOf(canonical, roleCtx, prefixes) ?? watchedRoleOf(req.abs, roleCtx, prefixes) ?? req.role;
}

/** The context's store ids (§3.2-3.4): its agent's user-level store, the project's and its auto memory's; `global` alone without a context. */
function storeIdsOf(ctx: IntegrityContext | null): string[] {
  if (!ctx) return ["global"];
  const ids: string[] = [userStoreId(ctx.agent), projectStoreId(ctx.root, ctx.platform)];
  if (ctx.autoMemoryDir) ids.push(memoryStoreId(ctx.autoMemoryDir, ctx.platform));
  return ids;
}

/** The accepted token hashes of every verified store of the context; null without a trusted key (every token is then novel). */
function acceptedTokens(state: IntegrityState): Set<string> | null {
  if (!state.signer) return null;
  const out = new Set<string>();
  for (const load of Object.values(state.stores)) {
    if (!load.verified || load.tamper || !load.doc) continue;
    for (const e of Object.values(load.doc.entries)) for (const t of e.tok) out.add(t);
  }
  return out;
}

/** The current text of the file (null when absent, not a regular file, or over 4 MiB). Opened non-blocking: a FIFO never hangs the hook. */
function readCurrent(path: string): string | null {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch {
    return null;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) return null;
    const buf = Buffer.alloc(st.size);
    let n = 0;
    while (n < buf.length) {
      const r = readSync(fd, buf, n, buf.length - n, null);
      if (r === 0) break;
      n += r;
    }
    return buf.subarray(0, n).toString("utf-8");
  } finally {
    closeSync(fd);
  }
}

type Session = {
  level: SessionLevel;
  /** What tainted the session, for `[TAINT]` and `memory-tainted`. */
  taint: string;
  indicators: SessionIndicator[];
};

function sessionOf(dataDir: string, sid: string): Session {
  const log = readSessionLog(dataDir, sid);
  return { level: sessionLevel(log), taint: taintOf(log), indicators: readSessionState(dataDir, sid)?.indicators ?? [] };
}

/** The first thing that tainted the session: a flagged tool result (`f`), or flagged instruction text delivered at SessionStart (`t`). */
function taintOf(log: SessionLog): string {
  if (log.unreadable) return "its activity log could not be read";
  const ev = log.events.find((e) => e.kind === "f" || e.kind === "t");
  return ev?.kind === "f" ? `${ev.tool} result: ${ev.rule}` : "instruction text flagged at session start";
}

// ── What the write changes ──────────────────────────────────────────────────

type WriteChange = {
  /** Unit ids the write adds and removes (for `.claude.json`, of both projections). */
  added: string[];
  removed: string[];
  /**
   * The write adds a unit that escalates when added (category `e`/`a`: hooks,
   * MCP servers, env, widened permissions, an agent's `tools:` …) or a
   * dangerous switch, or removes one that escalates when removed (`e`/`r`: a
   * deny rule …); or its units cannot be cut (over the unit cap).
   */
  escalates: boolean;
  /** The added units, in file order (JSON: walk order). */
  units: Unit[];
  /**
   * The added text: the added lines in order; for JSON, the added units'
   * descriptions, then their commands; for a file watched by sha only, the
   * text the tool writes.
   */
  text: string;
  json: boolean;
  /** The files before and after were cut into units (false past the unit cap). */
  cut: boolean;
};

/** Structured roles: one unit per setting (JSON, and a Codex config's TOML keys). */
const isJsonRole = (role: WatchedRole) => {
  const kind = ROLE_UNITS[role];
  return kind === "settings-json" || kind === "mcp-json" || kind === "json" || kind === "codex-hooks" || kind === "toml";
};

/** The units of `text` as the role is fingerprinted: for `.claude.json`, both projections enumeration hashes (§3.2, §3.3). */
function unitViews(role: WatchedRole, text: string | null, hasher: UnitHasher, ctx: IntegrityContext | null): FileUnits[] {
  const body = text ?? "";
  if (!CLAUDE_JSON_ROLES.has(role)) return [unitsOf(role, body, { hasher })];
  let parsed: unknown;
  try {
    parsed = body.trim() === "" ? {} : JSON.parse(body.charCodeAt(0) === 0xfeff ? body.slice(1) : body);
  } catch {
    return [unitsOf("claude-json", body, { hasher })]; // not JSON: its one "invalid" unit
  }
  const where = { root: ctx?.root ?? "", cwd: ctx?.cwd ?? "", platform: ctx?.platform ?? "linux" as NodeJS.Platform };
  return (["claude-json", "claude-json-project"] as const).map((r) => unitsOf(r, canonicalJson(projectClaudeJson(parsed, r, where)), { hasher }));
}

/** The text a file tool writes: Write's content, Edit's new_string, MultiEdit's new_strings, an apply_patch operation's added lines. */
function toolText(tool: string, input: unknown): string {
  if (!input || typeof input !== "object") return "";
  if (tool === APPLY_PATCH) return addedText(input as PatchOp);
  const i = input as Record<string, unknown>;
  if (typeof i.content === "string") return i.content;
  if (typeof i.new_string === "string") return i.new_string;
  const edits = Array.isArray(i.edits) ? i.edits : [];
  return edits.map((e: unknown) => (e && typeof e === "object" && typeof (e as Record<string, unknown>).new_string === "string" ? (e as Record<string, string>).new_string : "")).join("\n");
}

/**
 * Does `text` cut into more than MAX_FILE_UNITS units (as `unitBound` counts:
 * a line each for Markdown and text, a value each for JSON, a key or line for
 * TOML)? Counted with an early exit, so a 4 MiB file of short lines costs a
 * scan, not a cut.
 */
function overUnitCap(role: WatchedRole, text: string | null): boolean {
  if (text === null || ROLE_UNITS[role] === "sha") return false;
  let n = 1;
  if (isJsonRole(role)) {
    const toml = ROLE_UNITS[role] === "toml";
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      const counts = toml ? c === 0x0a || c === 0x3d : c === 0x2c || c === 0x5b || c === 0x7b; // \n = (TOML), , [ { (JSON)
      if (counts && ++n > MAX_FILE_UNITS) return true;
    }
    return false;
  }
  for (let at = text.indexOf("\n"); at >= 0; at = text.indexOf("\n", at + 1)) if (++n > MAX_FILE_UNITS) return true;
  return false;
}

/** What a write changes in a role's units; `writes` is the text the tool writes (toolText), for a file past the unit cap or watched by sha only. */
function diffWrite(role: WatchedRole, before: string | null, after: string, writes: string, hasher: UnitHasher, ctx: IntegrityContext | null): WriteChange {
  const json = isJsonRole(role);
  // Past the unit cap SessionStart leaves the file unhashed (over the scan
  // limits), so there are no units to record: what the tool writes is still
  // previewed, screened and checked for indicators.
  if (overUnitCap(role, before) || overUnitCap(role, after)) return { added: [], removed: [], escalates: true, units: [], text: writes, json: false, cut: false };
  const was = unitViews(role, before, hasher, ctx);
  const now = unitViews(role, after, hasher, ctx);
  const added = new Set<string>();
  const removed = new Set<string>();
  const units: Unit[] = [];
  let escalates = false;
  now.forEach((fu, i) => {
    const old = new Set(was[i]?.ids ?? []);
    const cur = new Set(fu.ids);
    for (const u of fu.units) {
      if (old.has(u.id) || added.has(u.id)) continue;
      added.add(u.id);
      units.push(u);
      if (u.dangerous || fu.cat[u.id] === "e" || fu.cat[u.id] === "a") escalates = true;
    }
    for (const id of was[i]?.ids ?? []) {
      if (cur.has(id)) continue;
      removed.add(id);
      if (was[i].cat[id] === "e" || was[i].cat[id] === "r") escalates = true;
    }
  });
  let text: string;
  if (now[0].shaOnly) text = writes;
  else if (json) text = [...units.map((u) => u.desc ?? u.text), ...units.flatMap((u) => (u.command !== undefined ? [u.command] : []))].join("\n");
  else text = units.map((u) => u.text).join("\n");
  return { added: [...added], removed: [...removed], escalates, units, text, json, cut: true };
}

/**
 * Does a write turn off every hook of the agent the file configures, and if so
 * the deny for it: a Claude Code settings file gaining the top-level
 * `disableAllHooks: true`, or a Codex config gaining a key that turns Codex's
 * hooks off (units.ts `hooksOff`); or the file's text newly matching the
 * static rule's pattern where it has no units to say so: a settings file that
 * does not parse, a Codex config over the unit cap, or the lines of one the
 * TOML reader left unparsed. A Codex config cut into keys is not read as text
 * past that, so a comment that mentions `hooks = false` is no switch.
 */
function turnsOffAllHooks(role: WatchedRole, before: string | null, after: string, change: WriteChange): CommandResult | null {
  const kind = ROLE_UNITS[role];
  if (kind === "settings-json") {
    if (change.units.some((u) => u.hooksOff)) return DISABLE_ALL_HOOKS_DENY;
    return DISABLE_ALL_HOOKS.test(after) && !DISABLE_ALL_HOOKS.test(before ?? "") ? DISABLE_ALL_HOOKS_DENY : null;
  }
  if (kind !== "toml") return null;
  if (change.units.some((u) => u.hooksOff)) return CODEX_HOOKS_OFF_DENY;
  const off = (text: string | null) =>
    text !== null && codexHooksOffIn(text) && (!change.cut || readToml(text).unparsed.some((u) => codexHooksOffIn(u.whole ?? u.text)));
  return off(after) && !off(before) ? CODEX_HOOKS_OFF_DENY : null;
}

/** The actionable tokens of the added text: Markdown and text by line; JSON units by text, and their commands as command lines. */
function tokensOf(change: WriteChange, opts: TokenOptions): ActionableToken[] {
  if (!change.json) return extractTokens(capped(change.text), opts);
  const out: ActionableToken[] = [];
  const seen = new Set<string>();
  const push = (tokens: ActionableToken[]) => {
    for (const t of tokens) {
      const k = t.value.toLowerCase();
      if (!seen.has(k)) {
        seen.add(k);
        out.push(t);
      }
    }
  };
  for (const u of change.units) {
    push(extractTokens(u.prose ?? u.text, opts));
    if (u.command !== undefined) push(extractTokens(u.command, { ...opts, commands: true }));
  }
  return out;
}

const capped = (text: string) => (text.length > SCAN_CAP_CHARS ? text.slice(0, SCAN_CAP_CHARS) : text);

/** JSON units with a command screened at most per write. */
const MAX_SCREENED_COMMANDS = 64;

/**
 * The detectors' verdict on the added text, as SessionStart screens a hunk
 * (§5.2): Markdown with `classifyMemoryThreat`'s checks, hook and skill
 * scripts with the content capabilities, command-bearing JSON and TOML units
 * with `inspectCommand`, a Codex config's instruction text as Markdown (a
 * strong verdict first). At most 200 KB is screened.
 */
function screenOf(role: WatchedRole, change: WriteChange): Verdict | null {
  if (change.json) {
    let soft: Verdict | null = null;
    let n = 0;
    for (const u of change.units) {
      if (u.command === undefined && u.prose === undefined) continue;
      if (++n > MAX_SCREENED_COMMANDS) break;
      const v = u.command !== undefined ? commandVerdict(commandNoun(u), u.command) : markdownVerdict(capped(u.prose!));
      if (v?.strong) return v;
      soft ??= v;
    }
    return soft;
  }
  const text = capped(change.text);
  if (text === "") return null;
  const kind = ROLE_UNITS[role];
  return kind === "md" || kind === "md-frontmatter" || kind === "md-memory" ? markdownVerdict(text) : scriptVerdict(text);
}

// ── The decision (§6.6 step 4) ──────────────────────────────────────────────

type DecisionInput = {
  /** The path as the tool names it (absolute). */
  path: string;
  /** For display: relative to R, `~/…`, or absolute. */
  shown: string;
  role: WatchedRole;
  change: WriteChange;
  screen: Verdict | null;
  novel: ActionableToken[];
  session: Session;
  gate: MemoryGate;
  instructionGate: InstructionGate;
  display: DisplayContext;
  /** Who is writing: "Claude" or "Codex". */
  agent: string;
  /** Whose sessions the file steers (command.ts `steeredBy`): under Codex, Codex's for AGENTS.md, Claude's for the rest. */
  steered: string;
};

/** The static path rules a watched write may answer as (§6.6). */
const INTEGRITY_PATH_RULES = new Set(["claude-settings", "claude-hook-script", "agent-instructions", "codex-config"]);

/** A static ask for an instruction or settings path alone, not for what the write carries (`content:*`, `secret-in-write`). */
const pathRuleAsk = (base: CommandResult | null) =>
  base?.decision === "ask" && (base.rule === "agent-instructions" || base.rule === "claude-settings" || base.rule === "codex-config");

/**
 * `instructionGate: risky`: does an instruction or settings write still ask?
 * Yes when the session read web, MCP or flagged content, the detectors flag
 * the added text, it adds a URL, host or command no reviewed file has, it
 * escalates (code-running or permission config, a dangerous switch), or it
 * carries a secret. The rest — a rewording, a new convention, a model switch —
 * is allowed, and the next session start reports it once (N3).
 */
function riskyWrite(i: DecisionInput): boolean {
  if (i.session.level !== "clean" || i.screen || i.novel.length > 0 || i.change.escalates) return true;
  const text = capped(i.change.text);
  return text !== "" && redactText(text, i.display) !== text;
}

/** The static rule id of a watched path, or for a path only the context or the prefix lists watch, its role's. */
function pathRuleOf(path: string, role: WatchedRole): string {
  const rule = inspectFileWrite(path, "").rule;
  if (rule && INTEGRITY_PATH_RULES.has(rule)) return rule;
  if (role === "hook-script") return "claude-hook-script";
  const kind = ROLE_UNITS[role];
  if (kind === "toml" || kind === "codex-hooks" || kind === "rules") return "codex-config";
  return isJsonRole(role) ? "claude-settings" : "agent-instructions";
}

const PREVIEW_CHARS = 300;
/** Characters the redactor sees for a preview, so a secret the 300th character cuts is still masked whole. */
const PREVIEW_WINDOW = 4096;
const NEWLINE = /\r?\n/g;

/** `<preview>`: the added text's first 300 characters (a surrogate pair kept whole), secrets masked, control characters and ANSI stripped, newlines as ` / `. */
function previewOf(text: string, display: DisplayContext): { text: string; more: number } {
  const window = headUnits(text, PREVIEW_WINDOW).trimEnd();
  const masked = headUnits(redactText(window, display), PREVIEW_CHARS);
  return { text: cleanText(masked.replace(NEWLINE, " / ")), more: Math.max(0, text.length - PREVIEW_CHARS) };
}

const plural = (n: number, one: string, many = `${one}s`) => (n === 1 ? one : many);

/**
 * Under Codex, which cannot ask (the ask is a deny that tells the user they can
 * make the change themselves): what that edit meets at the next session start
 * when made while an agent session runs (H1).
 */
const CODEX_SELF_EDIT =
  " If the user makes this change themselves while an agent session runs, Nexus may hold it for their review (nexus guard integrity accept --agent codex keeps it).";
/** JSON changes named in an ask at most; the rest are counted. */
const MAX_NAMED_CHANGES = 5;

/** A hook unit's command line, URL or prompt. */
function hookTarget(u: Unit): string {
  if (u.command !== undefined) return u.command;
  if (u.target !== undefined) return u.target;
  const at = u.text.indexOf(" hook: ");
  return at >= 0 ? u.text.slice(at + 7) : u.text;
}

/**
 * `Adds: …` for a settings or MCP file: new hooks, MCP servers and widened
 * permissions; otherwise `Changes: <n> setting(s)`. Then the dangerous switches
 * it turns on (`permissions.defaultMode: bypassPermissions`, `env NEXUS_DATA set`).
 */
function jsonAdds(change: WriteChange, display: DisplayContext): string {
  const dangerous = change.units.filter((u) => u.dangerous).map((u) => plainText(u.text, 120));
  const turnsOn = dangerous.length ? ` Turns on ${dangerous.join(", ")}.` : "";
  return `${jsonChanges(change, display)}${turnsOn}`;
}

function jsonChanges(change: WriteChange, display: DisplayContext): string {
  const items: string[] = [];
  for (const u of change.units) {
    if (u.kind === "hook") {
      const event = hookEventName(u.name ?? "");
      items.push(`new ${event ? `${event} ` : ""}hook "${displayCommand(hookTarget(u), display)}"`);
    } else if (u.kind === "mcp-server") {
      items.push(`new MCP server "${plainText(u.name ?? "", 60)}"`);
    } else if (u.desc?.startsWith("permission widened: ")) {
      items.push(`permission widened: ${displayCommand(u.desc.slice("permission widened: ".length), display)}`);
    }
  }
  if (items.length) {
    const more = items.length - MAX_NAMED_CHANGES;
    return `Adds: ${items.slice(0, MAX_NAMED_CHANGES).join("; ")}${more > 0 ? `; and ${more} more` : ""}.`;
  }
  const n = Math.max(change.added.length, change.removed.length);
  return n > 0 ? `Changes: ${n} ${plural(n, "setting")}.` : "Changes only formatting.";
}

/** `Adds: "<preview>"[ (+N more characters)].`, or what a write that adds nothing does. */
function textAdds(change: WriteChange, display: DisplayContext): string {
  if (change.text === "") {
    const n = change.removed.length;
    return n > 0 ? `Removes ${n} ${plural(n, "line")}.` : "Adds nothing.";
  }
  const p = previewOf(change.text, display);
  return `Adds: "${p.text}"${p.more > 0 ? ` (+${p.more} more characters)` : ""}.`;
}

function integrityDecision(i: DecisionInput): CommandResult {
  const cls = ROLE_CLASS[i.role];
  const d = i.display;
  // An instruction, settings or memory file (not code: a hook or skill script) repeating a session
  // indicator: denied when a detector flagged its text (SUSPECT), asked when its text only waits for review.
  if (cls !== "exec") {
    const flagged = matchIndicator(i.change.text, i.session.indicators.filter((x) => x.tier === "SUSPECT"));
    if (flagged) {
      return {
        decision: "deny",
        rule: "integrity-indicator",
        reason: `Blocked: this write repeats ${plainText(flagged.t, 120)}, which appears only in instruction text Nexus flagged at session start (${plainText(flagged.file, 120)}) and the user has not reviewed. If they want it, they can add it themselves.`,
      };
    }
    const held = matchIndicator(i.change.text, i.session.indicators.filter((x) => x.tier !== "SUSPECT"));
    if (held) {
      const adds = i.change.json ? jsonAdds(i.change, d) : textAdds(i.change, d);
      const selfEdit = i.agent === "Codex" ? CODEX_SELF_EDIT : "";
      return {
        decision: "ask",
        rule: "integrity-indicator",
        reason: `Caution: this write repeats ${plainText(held.t, 120)}, which appears only in instruction text waiting for your review (${plainText(held.file, 120)}: changed outside an edit you approved). ${adds}${selfEdit} Approve only if you asked for this.`,
      };
    }
  }
  const taint = displayText(i.session.taint, d);
  if (cls === "notice" && i.instructionGate === "risky" && !riskyWrite(i)) {
    return { decision: "allow", rule: null, reason: "instructionGate is risky and this write is not: allowed, and reported once at the next session start." };
  }
  if (cls === "notice" || cls === "exec") {
    const tainted = i.session.level === "tainted" ? `This session read content Nexus flagged as a prompt injection (${taint}). ` : "";
    const screen = i.screen ? ` The added text matches ${displayText(i.screen.reason, d)}.` : "";
    const adds = i.change.json ? jsonAdds(i.change, d) : textAdds(i.change, d);
    const selfEdit = i.agent === "Codex" ? CODEX_SELF_EDIT : "";
    return {
      decision: "ask",
      rule: pathRuleOf(i.path, i.role),
      reason: `${tainted}Caution: ${i.agent} wants to change ${i.shown} (${labelOf(i.role)}), which steers every future ${i.steered} session. ${adds}${screen}${selfEdit} Approve only if you asked for this.`,
    };
  }
  if (cls === "memory") {
    const preview = () => previewOf(i.change.text, d).text;
    if (i.screen?.strong) {
      return {
        decision: "deny",
        rule: "memory-directive",
        reason: `Blocked: this memory write carries a prompt-injection pattern (${displayText(i.screen.reason, d)}). Persisting it would steer every later session.`,
      };
    }
    if (i.screen) {
      return {
        decision: "ask",
        rule: "memory-directive",
        reason: `Caution: this memory write looks like a persistent instruction (${displayText(i.screen.reason, d)}): "${preview()}". Approve only if you want this remembered.`,
      };
    }
    if (i.session.level === "tainted") {
      return {
        decision: "ask",
        rule: "memory-tainted",
        reason: `Caution: this session read content Nexus flagged as a prompt injection (${taint}); confirm ${i.agent} should save this to memory: "${preview()}".`,
      };
    }
    if (i.session.level === "exposed" && i.gate === "novel-tokens" && i.novel.length > 0) {
      const shown = i.novel.slice(0, 3).map((t) => displayCommand(t.value, d));
      const more = i.novel.length - shown.length;
      return {
        decision: "ask",
        rule: "memory-novel",
        reason: `Caution: after reading web or MCP content, ${i.agent} wants to save memory that mentions ${shown.join(", ")}${more > 0 ? ` and ${more} more` : ""} (not in any reviewed instruction file): "${preview()}". Approve only if you want this remembered.`,
      };
    }
    if (i.session.level === "exposed" && i.gate === "exposed") {
      return {
        decision: "ask",
        rule: "memory-exposed",
        reason: `Caution: ${i.agent} wants to save memory after reading web or MCP content: "${preview()}". Approve only if you want this remembered.`,
      };
    }
  }
  return { decision: "allow", rule: null, reason: "No integrity concern with this write." };
}
