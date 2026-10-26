/**
 * Instruction-file integrity — units (spec §4.4, amendment A10): the keyed,
 * comparable pieces a watched file is cut into, so a change reads as units
 * added and removed rather than as a new whole-file hash.
 *
 * - Markdown and text: one unit per non-empty line (trailing `\r` and whitespace
 *   stripped, a leading BOM dropped), as a multiset: the n-th identical line is
 *   `<hash>#n`. Memory roles drop the lines Claude Code stamps into a memory
 *   file's frontmatter and compare re-quoted scalars unquoted (A10). Agent and
 *   skill frontmatter keys that grant tools, hooks, MCP servers, a permission
 *   mode, a model or memory are escalation units.
 * - JSON (settings, MCP config, the `~/.claude.json` projection, Codex's
 *   hooks.json): one unit per hook, MCP server, env variable, array element
 *   (set semantics) and other leaf, each with its escalation category (§4.4
 *   `cat`). A hook unit is the whole hook object (exec-form `args`, http
 *   `headers` and `allowedEnvVars`, mcp_tool `input`, `if`, `timeout`, …),
 *   header values hashed like an MCP server's. A path, or a hook's event or
 *   matcher, past MAX_KEY_CHARS is cut and keyed by its sha (`bounded`), so a
 *   long key repeated in every unit under it still costs linear time.
 * - TOML (Codex's config.toml and its other layers, read by toml.ts): one unit
 *   per key, `table.key = value`, with the category of the setting it is
 *   (`tomlCategory`), as a multiset; secrets (MCP env and headers, tokens) are
 *   hashed, never shown.
 * - Codex's exec-policy rules: one unit per line, each an escalation (a rule
 *   lets a command run).
 * - Skill and binary files: whole-file sha only.
 *
 * Unit ids are `hmac16("unit", text) + "#" + n` under the integrity key, so the
 * stored ids reveal nothing about content. Each unit also carries its plain text
 * (a line, or a short description of a JSON unit) for rendering added lines in
 * this run — that text is never persisted. Pure; no I/O.
 */

import { createHash } from "node:crypto";
import { canonicalJson, hmacHex, subkey } from "../../shared/sign.js";
import { headUnits } from "../codex/utf16.js";
import { nexusHookCommand } from "./nexus-hook.js";
import { readToml, tomlJoin, tomlPath, tomlStrings, tomlValueText, type TomlDoc, type TomlEntry, type TomlUnparsed, type TomlValue } from "./toml.js";
import { ROLE_UNITS, type UnitCategory, type WatchedRole } from "./types.js";

// ── Keyed hashing ───────────────────────────────────────────────────────────

/** `text → hmac16("unit", text)`: the first 16 hex of HMAC-SHA256 under K("unit"). */
export type UnitHasher = (text: string) => string;

/** A hasher with the unit subkey derived once, for hashing many units. */
export function unitHasher(key: Buffer): UnitHasher {
  const k = subkey(key, "unit");
  return (text) => hmacHex(k, text).slice(0, 16);
}

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

// ── Unit shapes ─────────────────────────────────────────────────────────────

export type UnitKind =
  | "line"        // a Markdown / text line
  | "frontmatter" // an agent/skill frontmatter line that escalates (tools, hooks, …)
  | "hook"
  | "mcp-server"
  | "env"
  | "element"     // one element of a JSON array (set semantics)
  | "leaf"        // any other JSON value
  | "invalid";    // the whole file, when it is not valid JSON

export type Unit = {
  /** `<hmac16>#<n>`: what the store keeps. */
  id: string;
  kind: UnitKind;
  /** The line (Markdown/text), or a readable rendering of a JSON unit. In memory only — never persisted. */
  text: string;
  /** 1-based line in the file (line and frontmatter units). */
  line?: number;
  cat?: UnitCategory;
  /** A short human description of a JSON unit, e.g. `new PreToolUse hook "<cmd>"`. */
  desc?: string;
  /** What `inspectCommand` should screen: a hook or helper command, or an MCP server's command plus args. */
  command?: string;
  /** The MCP server name, env key or hook event the unit belongs to. */
  name?: string;
  /** What a hook or MCP-server unit with no command reaches (a Codex MCP server's URL). */
  target?: string;
  /** Instruction text the agent is given (a Codex config's `developer_instructions`, …): screened as Markdown. */
  prose?: string;
  /**
   * `disableAllHooks: true`, `permissions.defaultMode: "bypassPermissions"` or
   * any `env.NEXUS_DATA` (§4.4); in Codex's config, hooks turned off, approval
   * `never` with the sandbox off, or a `dangerously_*` switch on.
   */
  dangerous?: true;
  /** A dangerous switch that turns off every hook of the agent, Nexus's included. */
  hooksOff?: true;
};

export type FileUnits = {
  /** File order for Markdown (so hunks of consecutive added lines can be built); walk order for JSON. */
  units: Unit[];
  /** Sorted unit ids (the store's `units`). */
  ids: string[];
  /** unit id → category, for the units that have one (the store's `cat`). */
  cat: Record<string, UnitCategory>;
  /** Event names of Nexus's own guard hooks in a settings file (sorted). */
  nexusHooks: string[];
  /** The file is watched by whole-file sha only (skill files, non-text hook scripts). */
  shaOnly: boolean;
};

export type UnitOptions = {
  /** The integrity key (or pass `hasher` to reuse one across files). */
  key?: Buffer;
  hasher?: UnitHasher;
  /**
   * MCP server names from the accepted `project-mcp` baseline of the same
   * project store: enabling one of them in `enabledMcpjsonServers` is what Claude
   * Code's approval dialog writes, so it is benign (`b`) rather than `a`.
   */
  acceptedMcpjsonServers?: ReadonlySet<string>;
};

function hasherOf(opts: UnitOptions): UnitHasher {
  if (opts.hasher) return opts.hasher;
  if (!opts.key) throw new TypeError("units need the integrity key or a unit hasher");
  return unitHasher(opts.key);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

/** Collects unit texts into numbered, hashed units. */
class UnitBuilder {
  readonly units: Unit[] = [];
  /** unit text → [its hash, occurrences so far]: a repeated line is hashed once. */
  private readonly seen = new Map<string, [string, number]>();
  constructor(private readonly hash: UnitHasher, private readonly set: boolean) {}

  /** Adds a unit for `unitText`; with set semantics a repeat is dropped, otherwise numbered #2, #3, …. */
  add(unitText: string, unit: Omit<Unit, "id">): void {
    const prior = this.seen.get(unitText);
    if (prior && this.set) return;
    const h = prior ? prior[0] : this.hash(unitText);
    const n = prior ? prior[1] + 1 : 1;
    this.seen.set(unitText, [h, n]);
    this.units.push({ id: `${h}#${n}`, ...unit });
  }

  finish(nexusHooks: Iterable<string> = []): FileUnits {
    const cat: Record<string, UnitCategory> = {};
    for (const u of this.units) if (u.cat) cat[u.id] = u.cat;
    return {
      units: this.units,
      ids: this.units.map((u) => u.id).sort(),
      cat,
      nexusHooks: [...new Set(nexusHooks)].sort(),
      shaOnly: false,
    };
  }
}

const shaOnly = (): FileUnits => ({ units: [], ids: [], cat: {}, nexusHooks: [], shaOnly: true });

// ── Markdown and text ───────────────────────────────────────────────────────

type MdMode = "plain" | "frontmatter" | "memory";

/** Agent/skill frontmatter keys whose lines are escalation units. */
const ESCALATION_KEYS = new Set(["tools", "allowed-tools", "disallowedTools", "permissionMode", "mcpServers", "hooks", "model", "memory"]);
/** One of ESCALATION_KEYS as a key inside a flow mapping: after `{` or `,`, optionally quoted, then `:`. */
const FLOW_ESCALATION_KEY =
  /[{,][ \t]{0,64}["']?(?:tools|allowed-tools|disallowedTools|permissionMode|mcpServers|hooks|model|memory)["']?[ \t]{0,64}:/;
/**
 * Lines Claude Code stamps into a memory file's frontmatter (A10), matched on the
 * trimmed line. Each key matches only with the value Claude Code writes (an
 * ISO-8601 UTC time, a session UUID, `memory`), quoted or not: any other text
 * under these keys stays a unit, so it is diffed and scanned.
 */
const MEMORY_STAMP =
  /^(?:modified:[ \t]{0,16}(["']?)\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z\1|originSessionId:[ \t]{0,16}(["']?)[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\2|node_type:[ \t]{0,16}(["']?)memory\3)$/;
/** A `key: "value"` / `key: 'value'` line (A10: compare the value unquoted). */
const QUOTED_SCALAR = /^([ \t]{0,64}[^\s'"#:][^:]{0,255}):[ \t]{1,16}(["'])(.*)\2$/;

const isIndented = (line: string) => line.charCodeAt(0) === 32 || line.charCodeAt(0) === 9;

function unquote(line: string): string {
  const m = QUOTED_SCALAR.exec(line);
  if (!m) return line;
  const value = m[2] === '"' ? m[3].replace(/\\(["\\])/g, "$1") : m[3].replace(/''/g, "'");
  return `${m[1]}: ${value}`;
}

/** Leading spaces and tabs of a line. */
function indentOf(line: string): number {
  let i = 0;
  while (i < line.length && (line.charCodeAt(i) === 32 || line.charCodeAt(i) === 9)) i++;
  return i;
}

/**
 * The mapping key a frontmatter line starts with (after its indentation), or
 * null: an optional `- ` (a sequence item that is a mapping), then the key —
 * quoted with `"` or `'`, or plain up to the first `:` — followed by `:`. No
 * YAML parser; a line that only looks like a key still counts (escalation
 * fails closed).
 */
function frontmatterKey(body: string): string | null {
  let i = 0;
  if (body.charCodeAt(0) === 45 && (body.charCodeAt(1) === 32 || body.charCodeAt(1) === 9)) { // "- "
    i = 1;
    while (i < body.length && (body.charCodeAt(i) === 32 || body.charCodeAt(i) === 9)) i++;
  }
  const q = body.charCodeAt(i);
  if (q === 34 || q === 39) { // " or '
    const close = body.indexOf(body[i], i + 1);
    if (close < 0) return null;
    let j = close + 1;
    while (j < body.length && (body.charCodeAt(j) === 32 || body.charCodeAt(j) === 9)) j++;
    return body.charCodeAt(j) === 58 ? body.slice(i + 1, close) : null; // :
  }
  const colon = body.indexOf(":", i);
  return colon < 0 ? null : body.slice(i, colon).trim();
}

/** Index of the frontmatter's closing `---` when line 0 opens one, else -1. */
function frontmatterEnd(lines: readonly string[]): number {
  if (lines.length === 0 || lines[0].trimEnd() !== "---") return -1;
  for (let i = 1; i < lines.length; i++) if (lines[i].trimEnd() === "---") return i;
  return -1;
}

/**
 * Memory-role frontmatter lines to drop (A10): the stamped `modified`,
 * `originSessionId` and `node_type` lines at any indent (with their stamped
 * values only), and a top-level `metadata:` left with no other children (Claude
 * Code adds it to hold them).
 */
function memoryDrops(lines: readonly string[], end: number): Set<number> {
  const drop = new Set<number>();
  for (let i = 1; i < end; i++) if (MEMORY_STAMP.test(lines[i].trim())) drop.add(i);
  for (let i = 1; i < end; i++) {
    if (lines[i].trimEnd() !== "metadata:") continue;
    let child = false;
    for (let j = i + 1; j < end && (isIndented(lines[j]) || lines[j].trim() === ""); j++) {
      if (!drop.has(j) && lines[j].trim() !== "") { child = true; break; }
    }
    if (!child) drop.add(i);
  }
  return drop;
}

function markdownUnits(text: string, mode: MdMode, hash: UnitHasher): FileUnits {
  const lines = (text.charCodeAt(0) === 0xfeff ? text.slice(1) : text).split("\n");
  const end = mode === "plain" ? -1 : frontmatterEnd(lines);
  const drop = mode === "memory" && end > 0 ? memoryDrops(lines, end) : null;
  const b = new UnitBuilder(hash, false);
  const escalates = mode === "frontmatter" ? frontmatterEscalation() : () => false;
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trimEnd();
    if (line === "") continue;
    const inFrontmatter = i > 0 && i < end;
    if (inFrontmatter && mode === "memory") {
      if (drop!.has(i)) continue;
      line = unquote(line);
    }
    if (inFrontmatter && escalates(line)) {
      b.add(`f\0${line}`, { kind: "frontmatter", text: line, line: i + 1, cat: "e" });
      continue;
    }
    b.add(`m\0${line}`, { kind: "line", text: line, line: i + 1 });
  }
  return b.finish();
}

/**
 * A reader of agent/skill frontmatter lines, in order, telling which are part of
 * an escalation: a line whose key (after indentation, an optional `- ` and
 * optional quotes) is an escalation key, at any depth; a line that continues
 * such a key's block (deeper indentation, or a `- item` at the key's own); and
 * a line where a flow mapping (opened on it, or still open from an earlier
 * line) has an escalation key as a key.
 */
function frontmatterEscalation(): (line: string) => boolean {
  /** Indentation of the escalation key whose block the following lines may continue; null outside one. */
  let block: number | null = null;
  /** Unclosed `{` of a flow mapping, across lines. */
  let flowDepth = 0;
  return (line) => {
    const indent = indentOf(line);
    const body = line.slice(indent);
    const inFlow = flowDepth > 0 || line.includes("{");
    for (let k = 0; k < line.length; k++) {
      const c = line.charCodeAt(k);
      if (c === 123) flowDepth++;
      else if (c === 125 && flowDepth > 0) flowDepth--;
    }
    if (block !== null && (indent > block || (indent === block && body.startsWith("-")))) return true;
    block = null;
    const key = frontmatterKey(body);
    if ((key !== null && ESCALATION_KEYS.has(key)) || (inFlow && FLOW_ESCALATION_KEY.test(line))) {
      block = indent;
      return true;
    }
    return false;
  };
}

/** UTF-8 text with no NUL byte, or null (then the file is watched by sha only: a binary file). */
export function decodeText(content: Buffer | string): string | null {
  if (typeof content === "string") return content.includes("\0") ? null : content;
  if (content.includes(0)) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(content);
  } catch {
    return null;
  }
}

// ── JSON ────────────────────────────────────────────────────────────────────

/** Pointer prefixes (first segment) that escalate in either direction. */
const ESCALATE_KEYS = new Set([
  "hooks", "statusLine", "fileSuggestion", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh",
  "otelHeadersHelper", "proxyAuthHelper", "processWrapper",
  "env", "mcpServers", "enableAllProjectMcpServers", "allowedMcpServers", "deniedMcpServers",
  "enabledPlugins", "extraKnownMarketplaces", "pluginConfigs", "disableAllHooks", "autoMemoryDirectory",
  "claudeMdExcludes",
]);
/**
 * Top-level keys whose changes are benign: the model and housekeeping, and
 * preferences Claude Code's own commands write to a settings file that change
 * neither what it runs nor what it tells Claude. As found in Claude Code
 * 2.1.310 — /config and /output-style: `outputStyle`, `defaultView`,
 * `prefersReducedMotion` and `spinnerTipsEnabled` to settings.local.json;
 * `timeFormat`, `syntaxHighlightingDisabled`, `tui`, `awaySummaryEnabled`
 * (session recap), `promptSuggestionEnabled`, `feedbackDrafts`, `idleCompaction`
 * and `precomputeCompactionEnabled` to the user settings; /fast, /voice
 * and /advisor: `fastMode`, `voiceEnabled` and `voice`, and `advisorModel` (a
 * model, as `model` is). Later releases add more, which stay unknown until
 * listed here. Not `language`, which /config also writes: Claude Code puts its
 * text into the system prompt ("Always respond in …"), so a change to it is a
 * change of instructions; nor the /config settings that let Claude go on
 * without the user (auto-continue, question and dialog timeouts, messages from
 * other sessions, auto mode during plan, `skipWorkflowUsageWarning`: auto mode
 * stops prompting before a workflow) or do more (workflows, artifacts).
 */
const BENIGN_KEYS = new Set([
  "$schema", "model", "cleanupPeriodDays", "includeCoAuthoredBy", "autoUpdates", "autoUpdatesChannel",
  "verbose", "alwaysThinkingEnabled", "autoMemoryEnabled", "spinnerTipsEnabled", "preferredNotifChannel",
  "outputStyle", "defaultView", "prefersReducedMotion", "timeFormat", "syntaxHighlightingDisabled", "tui",
  "awaySummaryEnabled", "promptSuggestionEnabled", "feedbackDrafts", "idleCompaction", "precomputeCompactionEnabled",
  "fastMode", "voiceEnabled", "voice", "advisorModel",
]);
/** Settings keys whose value is a command Claude Code runs. */
const HELPER_KEYS = [
  "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh", "otelHeadersHelper", "proxyAuthHelper", "processWrapper",
] as const;
/** Settings objects `{ type: "command", command }` whose command Claude Code runs. */
const COMMAND_OBJECT_KEYS = ["statusLine", "fileSuggestion"] as const;

const BARE_TOOL = /^[A-Za-z0-9_-]{1,256}$/;
const SCOPED_TOOL = /^([^()]{1,256})\(([^]{0,4096})\)$/;

/**
 * An allow rule with no real scope: a bare tool name, `Tool(*)`, `Tool(:*)`,
 * `Tool()`, `*`, any rule whose tool name has a wildcard (`mcp__*`), or WebFetch
 * without `domain:`. The "don't ask again" button writes scoped rules, and for
 * a tool that takes no scope the bare name: `WebSearch`, and one MCP tool
 * `mcp__<server>__<tool>` — so those two are scoped too. A whole server
 * (`mcp__<server>`) and other bare tool names are not.
 */
export function isUnscopedAllowRule(rule: unknown): boolean {
  if (typeof rule !== "string") return true;
  const r = rule.trim();
  if (r === "*") return true;
  if (BARE_TOOL.test(r)) return !(r === "WebSearch" || isMcpToolName(r));
  const m = r.match(SCOPED_TOOL);
  if (!m) return true; // not a rule shape Nexus understands: fail closed
  const [, tool, spec] = m;
  if (tool.includes("*")) return true;
  const s = spec.trim();
  if (s === "" || s === "*" || s === ":*") return true;
  return tool.trim() === "WebFetch" && !s.startsWith("domain:");
}

/** `mcp__<server>__<tool>` (a bare tool name, so no wildcard): one tool of one MCP server. */
function isMcpToolName(name: string): boolean {
  if (!name.startsWith("mcp__")) return false;
  const sep = name.indexOf("__", 5);
  return sep > 5 && sep + 2 < name.length;
}

/** A key as a pointer segment; `~` and `.` inside it are escaped so pointers stay unambiguous. */
const segment = (k: string) => k.replace(/~/g, "~0").replace(/\./g, "~1");

/**
 * A pointer, hook event or matcher longer than this is cut. Every unit under a
 * key repeats its path, so a long key would cost its length once per unit
 * under it: a longer one is replaced, once where it is met (`bounded`), by its
 * first MAX_KEY_CHARS characters, `…` and the sha256 of the whole, which is
 * longer than any string kept as it is, so the two never meet. No settings file
 * has one; the units of every other file are as they were.
 */
const MAX_KEY_CHARS = 1024;
/** Hex characters of a sha256. */
const SHA_HEX = 64;

/** `s`, or past MAX_KEY_CHARS its cut form (see MAX_KEY_CHARS). */
function bounded(s: string): string {
  return s.length > MAX_KEY_CHARS ? `${headUnits(s, MAX_KEY_CHARS)}…${sha256Hex(s)}` : s;
}

/** A `bounded` string as a unit's text shows it: a cut one without its sha. */
function shownKey(s: string): string {
  return s.length > MAX_KEY_CHARS ? s.slice(0, -SHA_HEX) : s;
}

/** The pointer of key `k` under `ptr` ("" at the top), `bounded`. */
function childPointer(ptr: string, k: string): string {
  return bounded(ptr === "" ? segment(k) : `${ptr}.${segment(k)}`);
}

function categoryOf(path: readonly string[], value: unknown, accepted: ReadonlySet<string>): UnitCategory | undefined {
  const [top, sub] = path;
  if (ESCALATE_KEYS.has(top)) return "e";
  if (top === "permissions") {
    if (sub === "defaultMode" || sub === "additionalDirectories") return "e";
    if (sub === "allow") return path.length === 2 && !isUnscopedAllowRule(value) ? "b" : "a";
    if (sub === "deny" || sub === "ask") return "r";
    return undefined;
  }
  if (top === "enabledMcpjsonServers") return typeof value === "string" && accepted.has(value) ? "b" : "a";
  if (top === "disabledMcpjsonServers") return "r";
  if (BENIGN_KEYS.has(top)) return "b";
  return undefined;
}

/** A readable one-liner for a JSON value (strings unquoted). */
function show(value: unknown): string {
  return typeof value === "string" ? value : canonicalJson(value);
}

function stringArgs(entry: Record<string, unknown>): string[] {
  return Array.isArray(entry.args) ? entry.args.filter((a): a is string => typeof a === "string") : [];
}

/** A hook's command line: `command` plus its exec-form `args`, or undefined for a hook with no command. */
function hookCommand(h: Record<string, unknown>): string | undefined {
  return typeof h.command === "string" ? [h.command, ...stringArgs(h)].join(" ") : undefined;
}

/**
 * What a hook runs or sends, for display: its command line, its URL (with the
 * header names and env variables it may send; never a header value), its MCP
 * server/tool and input, or its prompt.
 */
function hookTarget(h: Record<string, unknown>): string {
  const command = hookCommand(h);
  if (command !== undefined) return command;
  if (typeof h.url === "string") {
    const headers = isRecord(h.headers) ? Object.keys(h.headers) : [];
    const vars = Array.isArray(h.allowedEnvVars) ? h.allowedEnvVars.map(show) : [];
    return [h.url, headers.length ? `headers: ${headers.join(", ")}` : "", vars.length ? `env: ${vars.join(", ")}` : ""].filter(Boolean).join(" ");
  }
  if (typeof h.server === "string" && typeof h.tool === "string") {
    return `${h.server}/${h.tool}${h.input === undefined ? "" : ` ${canonicalJson(h.input)}`}`;
  }
  if (typeof h.prompt === "string") return h.prompt;
  return canonicalJson({ ...h, type: undefined });
}

const HOOK_EVENT_NAME = /^[A-Za-z]{1,40}$/;

/**
 * A hook event name fit for user- or model-facing text (`PreToolUse`,
 * `SessionStart`, …: letters only, at most 40), or null. The event is a key of
 * the settings file, so it is attacker text; anything else is shown as "a hook".
 */
export function hookEventName(event: string): string | null {
  return HOOK_EVENT_NAME.test(event) ? event : null;
}

/** ` --agent codex` (or `--agent=codex`) at the end of a command: the Codex install's dialect flag. */
const CODEX_AGENT_SUFFIX = /[ \t]--agent(?:[ \t]{1,8}|=)codex[ \t]{0,8}$/i;
/** Characters of a command's end the suffix is looked for in (it is short; a bounded look keeps the match linear). */
const SUFFIX_WINDOW = 48;

/**
 * The Nexus guard hook `command` is, as `nexusHookCommand` recognises one, also
 * with the `--agent codex` flag Codex's install adds (the same hook, answering
 * in Codex's dialect); null for any other command.
 */
export function nexusHookOf(command: string): { script: string | null } | null {
  const own = nexusHookCommand(command);
  if (own) return own;
  const from = Math.max(0, command.length - SUFFIX_WINDOW);
  const m = CODEX_AGENT_SUFFIX.exec(command.slice(from));
  return m ? nexusHookCommand(command.slice(0, from + m.index)) : null;
}

/** Nexus's own guard hook: exactly a command `nexus guard install` writes (`nexusHookOf`), as a shell-form command hook. */
function isNexusHook(h: Record<string, unknown>): boolean {
  return typeof h.command === "string" && h.args === undefined && (h.type === undefined || h.type === "command")
    && nexusHookOf(h.command) !== null;
}

/** An MCP server's command line (command plus args), or its URL, or "". */
function serverCommand(entry: unknown): string {
  if (!isRecord(entry)) return "";
  if (typeof entry.command === "string") return [entry.command, ...stringArgs(entry)].join(" ");
  return typeof entry.url === "string" ? entry.url : "";
}

class JsonWalker {
  readonly b: UnitBuilder;
  readonly nexusHooks = new Set<string>();
  constructor(private readonly hash: UnitHasher, private readonly accepted: ReadonlySet<string>) {
    this.b = new UnitBuilder(hash, true);
  }

  top(obj: Record<string, unknown>): void {
    for (const [k, v] of Object.entries(obj)) {
      if (k === "hooks" && isRecord(v)) this.hooks(v);
      else if (k === "mcpServers" && isRecord(v)) this.servers(v);
      else if (k === "env" && isRecord(v)) this.env(v);
      else this.walk([k], childPointer("", k), v);
    }
  }

  private hooks(hooks: Record<string, unknown>): void {
    for (const [event, groups] of Object.entries(hooks)) {
      // an event and a matcher are repeated in each of their hooks' units: `bounded` once here
      const at = childPointer("hooks", event);
      const eventKey = bounded(event);
      if (!Array.isArray(groups)) { this.walk(["hooks", event], at, groups); continue; }
      for (const group of groups) {
        if (!isRecord(group) || !Array.isArray(group.hooks)) { this.walk(["hooks", event], at, [group]); continue; }
        const matcher = bounded(group.matcher === undefined ? "" : show(group.matcher));
        for (const h of group.hooks) {
          if (!isRecord(h)) { this.walk(["hooks", event], at, [h]); continue; }
          const type = typeof h.type === "string" ? h.type : "";
          const target = hookTarget(h);
          const command = hookCommand(h);
          if (isNexusHook(h)) this.nexusHooks.add(event);
          // the event is a key of the file: its text and description name it only when it is a plain one
          const shown = hookEventName(event);
          // the whole hook: what it runs (args), sends (headers, allowedEnvVars,
          // input) and when (if, timeout, async) all change the unit
          this.b.add(`h\0${eventKey}\0${matcher}\0${type}\0${canonicalJson(this.maskSecrets(h))}`, {
            kind: "hook",
            text: `${shown ?? "a"}${matcher ? ` (${shownKey(matcher)})` : ""} hook: ${target}`,
            cat: "e",
            desc: shown ? `new ${shown} hook "${target}"` : `new hook "${target}"`,
            name: event,
            ...(command !== undefined ? { command } : {}),
          });
        }
      }
    }
  }

  private servers(servers: Record<string, unknown>): void {
    for (const [name, entry] of Object.entries(servers)) {
      const masked = isRecord(entry) ? this.maskSecrets(entry) : entry;
      const command = serverCommand(entry);
      this.b.add(`s\0${name}\0${canonicalJson(masked)}`, {
        kind: "mcp-server",
        text: `MCP server ${name}: ${command}`,
        cat: "e",
        desc: `new MCP server ${name}: ${command}`,
        name,
        ...(isRecord(entry) && typeof entry.command === "string" ? { command } : {}),
      });
    }
  }

  /** The entry (an MCP server or a hook) with every `env` / `headers` value replaced by its
   *  keyed hash: a changed secret still changes the unit, but no secret ever reaches a unit text. */
  private maskSecrets(entry: Record<string, unknown>): Record<string, unknown> {
    const out = { ...entry };
    for (const k of ["env", "headers"]) {
      const v = entry[k];
      if (isRecord(v)) out[k] = Object.fromEntries(Object.entries(v).map(([n, s]) => [n, this.hash(show(s))]));
    }
    return out;
  }

  private env(env: Record<string, unknown>): void {
    for (const [key, value] of Object.entries(env)) {
      this.b.add(`e\0${key}\0${this.hash(show(value))}`, {
        kind: "env",
        text: `env ${key} set`,
        cat: "e",
        desc: `env ${key} set`,
        name: key,
        ...(key === "NEXUS_DATA" ? { dangerous: true as const } : {}),
      });
    }
  }

  /** `value` at `path`, whose pointer is `ptr` (`childPointer`, worked out once per key). */
  private walk(path: string[], ptr: string, value: unknown): void {
    if (Array.isArray(value)) {
      for (const el of value) this.element(path, ptr, el);
    } else if (isRecord(value)) {
      const keys = Object.keys(value);
      for (const k of keys) this.walk([...path, k], childPointer(ptr, k), value[k]);
    } else {
      this.leaf(path, ptr, value);
    }
  }

  private element(path: string[], ptr: string, el: unknown): void {
    const cat = categoryOf(path, el, this.accepted);
    const rule = show(el);
    const widened = path[0] === "permissions" && path[1] === "allow" && path.length === 2 && cat === "a";
    this.b.add(`a\0${ptr}\0${canonicalJson(el)}`, {
      kind: "element",
      text: `${shownKey(ptr)}[]: ${rule}`,
      ...(cat ? { cat } : {}),
      ...(widened ? { desc: `permission widened: ${rule}` } : {}),
    });
  }

  private leaf(path: string[], ptr: string, value: unknown): void {
    const cat = categoryOf(path, value, this.accepted);
    const [top, sub] = path;
    const dangerous =
      (top === "disableAllHooks" && path.length === 1 && value === true) ||
      (top === "permissions" && sub === "defaultMode" && path.length === 2 && value === "bypassPermissions");
    const helper = path.length === 1 && (HELPER_KEYS as readonly string[]).includes(top);
    const objectCommand = (COMMAND_OBJECT_KEYS as readonly string[]).includes(top) && sub === "command" && path.length === 2;
    const plugin = top === "enabledPlugins" && path.length === 2 && value === true;
    this.b.add(`j\0${ptr}\0${canonicalJson(value)}`, {
      kind: "leaf",
      text: `${shownKey(ptr)}: ${show(value)}`,
      ...(cat ? { cat } : {}),
      ...(plugin ? { desc: `new plugin ${sub}` } : {}),
      ...((helper || objectCommand) && typeof value === "string" ? { command: value } : {}),
      ...(dangerous ? { dangerous: true as const } : {}),
      ...(dangerous && top === "disableAllHooks" ? { hooksOff: true as const } : {}),
    });
  }
}

/** Deeper JSON is one "invalid" unit: no settings file nests this far, and the
 *  recursive walk (and `canonicalJson`) must never run out of stack on one that does. */
const MAX_JSON_DEPTH = 64;

/** The deepest `{`/`[` nesting of a JSON text, in one pass that skips strings. */
function nestingDepth(text: string): number {
  let depth = 0;
  let max = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 34) { // a string: skip to its closing quote
      for (i++; i < text.length && text.charCodeAt(i) !== 34; i++) if (text.charCodeAt(i) === 92) i++;
    } else if (c === 123 || c === 91) {
      if (++depth > max) max = depth;
    } else if (c === 125 || c === 93) {
      depth--;
    }
  }
  return max;
}

function invalidJson(sha: string, hash: UnitHasher): FileUnits {
  const b = new UnitBuilder(hash, true);
  b.add(`x\0invalid\0${sha}`, { kind: "invalid", text: "(not valid JSON)", desc: "the file is not valid JSON" });
  return b.finish();
}

function jsonUnits(content: Buffer | string, opts: UnitOptions, hash: UnitHasher): FileUnits {
  const raw = typeof content === "string" ? content : content.toString("utf-8");
  const text = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
  let parsed: unknown;
  if (text.trim() === "") {
    parsed = {}; // an empty settings file is an empty object (as `guard install` reads it)
  } else {
    try {
      parsed = JSON.parse(text);
    } catch {
      return invalidJson(sha256Hex(content), hash);
    }
  }
  if (!isRecord(parsed) || nestingDepth(text) > MAX_JSON_DEPTH) return invalidJson(sha256Hex(content), hash);
  const w = new JsonWalker(hash, opts.acceptedMcpjsonServers ?? new Set());
  w.top(parsed);
  return w.b.finish(w.nexusHooks);
}

// ── TOML (Codex's config) ───────────────────────────────────────────────────

/**
 * Top-level Codex config keys whose changes escalate (category `e`): what Codex
 * runs or reaches — MCP servers, hooks (and their trust: `hooks.state` holds
 * the trusted hashes), `notify`, model providers and API base URLs (a
 * `base_url` repoints the model API), feature flags (one turns hooks off),
 * plugins and marketplaces — the sandbox, approval and permission settings and
 * the shell environment, and the instructions it gives the model or reads from
 * a file (`instructions`, `developer_instructions`, `model_instructions_file`,
 * the compaction and realtime prompts, the auto-reviewer's policy, which files
 * are instructions at all). `projects.<path>.trust_level` (a project's trust)
 * is `e` too (`tomlCategory`).
 */
const TOML_ESCALATE = new Set([
  "mcp_servers", "hooks", "notify", "model_providers", "model_provider", "openai_base_url", "chatgpt_base_url", "features", "plugins",
  "marketplaces", "apps", "tools", "web_search", "otel", "profile",
  "approval_policy", "approvals_reviewer", "sandbox_mode", "sandbox_workspace_write", "default_permissions", "permissions", "windows",
  "allow_login_shell", "shell_environment_policy",
  "instructions", "developer_instructions", "model_instructions_file", "compact_prompt", "experimental_compact_prompt_file", "auto_review",
  "experimental_realtime_start_instructions", "experimental_realtime_ws_backend_prompt", "experimental_realtime_ws_startup_context",
  "experimental_realtime_webrtc_call_base_url", "experimental_realtime_ws_base_url", "project_doc_fallback_filenames", "project_root_markers",
]);
/**
 * Top-level Codex config keys whose changes are benign: the model and its
 * reasoning settings (Codex's /model writes them), the service tier, and
 * display and housekeeping (`tui`, the acknowledgement flags under `notice`
 * that Codex's own prompts write, analytics and feedback switches, history
 * persistence, update checks), as Codex 0.164.0's config schema documents them.
 */
const TOML_BENIGN = new Set([
  "model", "model_reasoning_effort", "model_reasoning_summary", "model_verbosity", "plan_mode_reasoning_effort", "review_model",
  "service_tier", "personality", "notice", "tui", "hide_agent_reasoning", "show_raw_agent_reasoning", "check_for_update_on_startup",
  "suppress_unstable_features_warning", "analytics", "feedback", "history", "file_opener", "disable_paste_burst", "audio",
]);
/** Top-level keys whose string values are instructions the model is given (screened as Markdown). */
const TOML_PROSE = new Set([
  "instructions", "developer_instructions", "compact_prompt", "auto_review", "experimental_realtime_start_instructions",
  "experimental_realtime_ws_backend_prompt", "experimental_realtime_ws_startup_context",
]);
/** A key under one of these holds a secret value (an MCP server's env or headers): its unit hashes the value. */
const SECRET_TABLES = new Set(["env", "http_headers", "env_http_headers", "headers"]);
/** A key named like a secret: its value is hashed too. */
const SECRET_KEY = /token|secret|password|passwd|api_?key|credential/i;

/** A key's path as it applies: a legacy profile's keys (`profiles.<name>.…`) are the top-level keys it overrides. */
function effectivePath(path: readonly string[]): readonly string[] {
  return path[0] === "profiles" && path.length > 2 ? path.slice(2) : path;
}

/** The category of a Codex config key (`TOML_ESCALATE`, `TOML_BENIGN`); undefined is "other". */
export function tomlCategory(path: readonly string[]): UnitCategory | undefined {
  const p = effectivePath(path);
  const [top, second] = p;
  if (top === "projects") return p.length === 3 && p[2] === "trust_level" ? "e" : undefined;
  if (TOML_ESCALATE.has(top)) return "e";
  if (TOML_BENIGN.has(top)) return "b";
  if (top === "tool_suggest" && second === "disabled_tools") return "b"; // Codex's "don't suggest this tool again"
  return undefined;
}

/** `hooks.<Event>.hooks.command` (an inline `[[hooks.<Event>.hooks]]` handler's command). */
const isHookCommand = (p: readonly string[]) => p.length === 4 && p[0] === "hooks" && p[2] === "hooks" && p[3] === "command";

/** The tables of an array of inline tables and nothing else, or null. */
function inlineTables(value: TomlValue): [string[], TomlValue][][] | null {
  if (value.t !== "arr" || value.v.length === 0) return null;
  const out: [string[], TomlValue][][] = [];
  for (const v of value.v) {
    if (v.t !== "tbl") return null;
    out.push(v.v);
  }
  return out;
}

/**
 * A config's entries with hook groups written as arrays of inline tables —
 * `[hooks]` `PreToolUse = [{ matcher = …, hooks = [{ command = … }] }]`, or
 * `hooks = [{ … }]` inside a `[[hooks.<Event>]]` table — read as the entries
 * their `[[hooks.<Event>]]` and `[[hooks.<Event>.hooks]]` spelling gives (TOML
 * means the same by both): the same units whichever is written, and each
 * handler's command a hook. An entry whose keys would pass the reader's key
 * bounds stays as it is.
 */
function hookEntries(entries: readonly TomlEntry[]): TomlEntry[] {
  const out: TomlEntry[] = [];
  for (const e of entries) {
    const expanded = expandedHooks(e);
    if (expanded) for (const x of expanded) out.push(x);
    else out.push(e);
  }
  return out;
}

function expandedHooks(e: TomlEntry): TomlEntry[] | null {
  const p = effectivePath(e.path);
  if (p[0] !== "hooks") return null;
  const groups = p.length === 2 && p[1] !== "state" ? inlineTables(e.value) : null;
  const handlers = p.length === 3 && p[2] === "hooks" ? inlineTables(e.value) : null;
  if (!groups && !handlers) return null;
  const out: TomlEntry[] = [];
  /** `path = value` as entries, a nested inline table's keys each one of its own (as the reader reads one at a key's place). */
  const push = (path: string[] | null, value: TomlValue): boolean => {
    if (!path) return false;
    if (value.t !== "tbl") return out.push({ path, value, line: e.line }) > 0;
    return value.v.every(([k, v]) => push(tomlJoin(path, k), v));
  };
  const pushTables = (at: readonly string[], tables: [string[], TomlValue][][]) => tables.every((t) => t.every(([k, v]) => push(tomlJoin(at, k), v)));
  const ok = handlers
    ? pushTables(e.path, handlers)
    : groups!.every((group) => group.every(([k, v]) => {
      const at = tomlJoin(e.path, k);
      const nested = k.length === 1 && k[0] === "hooks" ? inlineTables(v) : null;
      return at && nested ? pushTables(at, nested) : push(at, v);
    }));
  return ok ? out : null;
}
/** `mcp_servers.<name>.<key>`. */
const isServerKey = (p: readonly string[], key: string) => p.length === 3 && p[0] === "mcp_servers" && p[2] === key;
const serverOf = (path: readonly string[]) => JSON.stringify(path.slice(0, -1));

/**
 * Codex's dangerous switches in a config (S4 when a non-user adds one): hooks
 * turned off (`[features] hooks = false`, or the legacy `codex_hooks`, and
 * requirements' `allow_managed_hooks_only = true`, which ignores the user's
 * hooks), any `dangerously_*` key set to true, and approval `never` in effect
 * with the sandbox off (`sandbox_mode = "danger-full-access"`, or the
 * `:danger-full-access` permissions profile) — top-level, or in a profile
 * over the top-level values. Returns the entries that are dangerous, and
 * which of them turn hooks off.
 */
function dangerousEntries(entries: readonly TomlEntry[]): { dangerous: Set<TomlEntry>; hooksOff: Set<TomlEntry> } {
  const dangerous = new Set<TomlEntry>();
  const hooksOff = new Set<TomlEntry>();
  /** Per scope ("" top-level, else the profile's name): the approval, sandbox and permissions entries. */
  const scopes = new Map<string, { approval?: TomlEntry; sandbox?: TomlEntry; permissions?: TomlEntry }>();
  for (const e of entries) {
    const p = effectivePath(e.path);
    const last = p[p.length - 1];
    const off = (p.length === 2 && p[0] === "features" && (last === "hooks" || last === "codex_hooks") && e.value.t === "bool" && !e.value.v)
      || (last === "allow_managed_hooks_only" && e.value.t === "bool" && e.value.v);
    if (off) {
      dangerous.add(e);
      hooksOff.add(e);
    } else if (last.startsWith("dangerously_") && e.value.t === "bool" && e.value.v) {
      dangerous.add(e);
    }
    if (p.length !== 1 || e.value.t !== "str") continue;
    const scope = e.path === p ? "" : e.path[1];
    const s = scopes.get(scope) ?? {};
    if (last === "approval_policy") s.approval = e;
    else if (last === "sandbox_mode") s.sandbox = e;
    else if (last === "default_permissions") s.permissions = e;
    else continue;
    scopes.set(scope, s);
  }
  const top = scopes.get("") ?? {};
  for (const s of scopes.values()) {
    const approval = s.approval ?? top.approval;
    const sandbox = s.sandbox ?? top.sandbox;
    const permissions = s.permissions ?? top.permissions;
    const never = approval?.value.t === "str" && approval.value.v === "never";
    const open = [sandbox, permissions].filter((x): x is TomlEntry =>
      !!x && x.value.t === "str" && (x.value.v === "danger-full-access" || x.value.v === ":danger-full-access"));
    if (!never || open.length === 0) continue;
    dangerous.add(approval!);
    for (const x of open) dangerous.add(x);
  }
  return { dangerous, hooksOff };
}

/** A Codex config key that turns hooks off, as its unit text reads (`hooksOff`). */
const HOOKS_OFF_TEXT = /(?:^|\.)(?:features\.(?:codex_)?hooks = false|allow_managed_hooks_only = true)$/;

/**
 * How a reason names a dangerous switch a unit's text shows: `turns on
 * disableAllHooks: true`, `turns on approval_policy = "never"`; one of Codex's
 * that turns its hooks off says so.
 */
export function switchPhrase(text: string): string {
  return switchesPhrase([text]);
}

/** `switchPhrase` for several switches: `turns on a, b`, a hooks-off switch said on its own. */
export function switchesPhrase(texts: readonly string[]): string {
  const off = texts.filter((t) => HOOKS_OFF_TEXT.test(t));
  const on = texts.filter((t) => !HOOKS_OFF_TEXT.test(t));
  return [...off.map((t) => `turns off every Codex hook (${t})`), ...(on.length ? [`turns on ${on.join(", ")}`] : [])].join(", and ");
}

/** One unit per key of a Codex config (see the module comment), unparsed lines as units of their own, in file order. */
function tomlUnits(text: string, hash: UnitHasher): FileUnits {
  const doc = readToml(text);
  const entries = hookEntries(doc.entries);
  const b = new UnitBuilder(hash, false);
  const { dangerous, hooksOff } = dangerousEntries(entries);
  const args = new Map<string, string[]>();
  for (const e of entries) if (isServerKey(effectivePath(e.path), "args")) args.set(serverOf(e.path), tomlStrings(e.value) ?? []);
  const nexusHooks: string[] = [];
  let u = 0;
  for (const e of entries) {
    for (; u < doc.unparsed.length && doc.unparsed[u].line < e.line; u++) unparsedUnit(b, doc.unparsed[u], hash);
    const p = effectivePath(e.path);
    const name = tomlPath(e.path);
    const value = tomlValueText(e.value);
    const secret = e.path.slice(1, -1).some((k) => SECRET_TABLES.has(k)) || SECRET_KEY.test(e.path[e.path.length - 1]);
    const cat = tomlCategory(e.path);
    const unit: Omit<Unit, "id"> = { kind: "leaf", text: `${name} = ${secret ? "(set)" : value}`, line: e.line, ...(cat ? { cat } : {}) };
    const str = e.value.t === "str" ? e.value.v : null;
    if (isHookCommand(p) && str !== null) {
      const event = p[1];
      const shown = hookEventName(event);
      if (nexusHookOf(str)) nexusHooks.push(event);
      Object.assign(unit, { kind: "hook", name: event, command: str, desc: shown ? `new ${shown} hook "${str}"` : `new hook "${str}"` });
    } else if (isServerKey(p, "command") && str !== null) {
      const line = [str, ...(args.get(serverOf(e.path)) ?? [])].join(" ");
      Object.assign(unit, { kind: "mcp-server", name: p[1], command: line, desc: `new MCP server ${p[1]}: ${line}` });
    } else if (isServerKey(p, "url") && str !== null) {
      Object.assign(unit, { kind: "mcp-server", name: p[1], target: str, desc: `new MCP server ${p[1]}: ${str}` });
    } else if (p.length === 1 && p[0] === "notify") {
      const argv = tomlStrings(e.value);
      if (argv?.length) unit.command = argv.join(" ");
    } else if (TOML_PROSE.has(p[0]) && str !== null) {
      unit.prose = str;
    }
    if (dangerous.has(e)) unit.dangerous = true;
    if (hooksOff.has(e)) unit.hooksOff = true;
    b.add(`t\0${JSON.stringify(e.path)}\0${secret ? hash(value) : value}`, unit);
  }
  for (; u < doc.unparsed.length; u++) unparsedUnit(b, doc.unparsed[u], hash);
  return b.finish(nexusHooks);
}

/** A line the TOML reader could not read: a unit of its own, with no category, keyed on the whole line (a long one shown cut). */
function unparsedUnit(b: UnitBuilder, line: TomlUnparsed, hash: UnitHasher): void {
  b.add(`x\0${line.whole === undefined ? line.text : hash(line.whole)}`, { kind: "leaf", text: `(unparsed) ${line.text}`, line: line.line });
}

/**
 * The commands a Codex config makes Codex run (for hook-script discovery):
 * hook handlers' commands, `notify`'s argv, and MCP servers' `command` with
 * their `args`, in any profile too.
 */
export function tomlExecCommands(doc: TomlDoc): ExecCommand[] {
  const out: ExecCommand[] = [];
  const entries = hookEntries(doc.entries);
  const args = new Map<string, string[]>();
  for (const e of entries) if (isServerKey(effectivePath(e.path), "args")) args.set(serverOf(e.path), tomlStrings(e.value) ?? []);
  for (const e of entries) {
    const p = effectivePath(e.path);
    if (isHookCommand(p) && e.value.t === "str") {
      out.push({ kind: "hook", command: e.value.v, args: [] });
    } else if (isServerKey(p, "command") && e.value.t === "str") {
      out.push({ kind: "mcp", command: e.value.v, args: args.get(serverOf(e.path)) ?? [] });
    } else if (p.length === 1 && p[0] === "notify") {
      const argv = tomlStrings(e.value);
      if (argv?.length) out.push({ kind: "helper", command: argv[0], args: argv.slice(1) });
    }
  }
  return out;
}

/** Config keys naming a file of instructions Codex reads: watched as `@imports` are. */
const INSTRUCTION_FILE_KEYS = new Set(["model_instructions_file", "experimental_compact_prompt_file"]);

/** The files a Codex config's `model_instructions_file` and `experimental_compact_prompt_file` name (in any profile), as written. */
export function tomlInstructionFiles(doc: TomlDoc): string[] {
  const out: string[] = [];
  for (const e of doc.entries) {
    const p = effectivePath(e.path);
    if (p.length === 1 && INSTRUCTION_FILE_KEYS.has(p[0]) && e.value.t === "str" && e.value.v !== "") out.push(e.value.v);
  }
  return out;
}

// ── Codex's exec-policy rules ───────────────────────────────────────────────

/** One unit per non-empty line of a `.rules` file; every line but a comment is an escalation (a rule lets commands run). */
function rulesUnits(text: string, hash: UnitHasher): FileUnits {
  const lines = (text.charCodeAt(0) === 0xfeff ? text.slice(1) : text).split("\n");
  const b = new UnitBuilder(hash, false);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trimEnd();
    if (line === "") continue;
    const comment = line.trimStart().startsWith("#");
    b.add(`r\0${line}`, { kind: "line", text: line, line: i + 1, ...(comment ? {} : { cat: "e" as const }) });
  }
  return b.finish();
}

// ── Entry points ────────────────────────────────────────────────────────────

/**
 * The units of one watched file. `content` is the file's bytes (or simulated
 * text); for the `claude-json` roles it is the projection (`projectClaudeJson`),
 * never the whole app-state file.
 */
export function unitsOf(role: WatchedRole, content: Buffer | string, opts: UnitOptions): FileUnits {
  const kind = ROLE_UNITS[role];
  if (kind === "sha") return shaOnly();
  const hash = hasherOf(opts);
  switch (kind) {
    case "settings-json":
    case "mcp-json":
    case "json":
    case "codex-hooks":
      return jsonUnits(content, opts, hash);
    case "toml":
      return tomlUnits(typeof content === "string" ? content : content.toString("utf-8"), hash);
    case "rules":
      return rulesUnits(typeof content === "string" ? content : content.toString("utf-8"), hash);
    case "text-or-sha": {
      const text = decodeText(content);
      return text === null ? shaOnly() : markdownUnits(text, "plain", hash);
    }
    default: {
      const text = typeof content === "string" ? content : content.toString("utf-8");
      return markdownUnits(text, kind === "md-memory" ? "memory" : kind === "md-frontmatter" ? "frontmatter" : "plain", hash);
    }
  }
}

/**
 * At least as many units as `unitsOf(role, content)` cuts `content` into,
 * counted in one pass over the bytes with nothing hashed: Markdown and text have
 * at most one unit per line; JSON at most one per value, and every member or
 * element follows a comma or its container's `[` or `{` (commas inside strings,
 * or in a file that does not parse, only raise the count); TOML at most one per
 * `=` (each key has its own) or unparsed line; roles watched by sha only have
 * none. Enumeration caps a file by it (MAX_FILE_UNITS).
 */
export function unitBound(role: WatchedRole, content: Buffer): number {
  const kind = ROLE_UNITS[role];
  if (kind === "sha") return 0;
  const json = kind === "settings-json" || kind === "mcp-json" || kind === "json" || kind === "codex-hooks";
  const toml = kind === "toml";
  let n = 1;
  for (let i = 0; i < content.length; i++) {
    const c = content[i];
    if (json ? c === 0x2c || c === 0x5b || c === 0x7b : c === 0x0a || (toml && c === 0x3d)) n++; // , [ {, or \n (and = for TOML)
  }
  return n;
}

/**
 * The part of a `~/.claude.json` Nexus watches. For `claude-json`, the top-level
 * `mcpServers`; for `claude-json-project`, `mcpServers`,
 * `enabledMcpjsonServers`, `disabledMcpjsonServers` and
 * `enableAllProjectMcpServers` of `projects[R]` and `projects[cwd]`, merged
 * (cwd's servers over R's, arrays unioned, `enableAll…` true if either sets it).
 * Everything else in the file (history, counters, trust flags) is never read
 * into a unit.
 */
export function projectClaudeJson(
  parsed: unknown,
  role: "claude-json" | "claude-json-project",
  where: { root: string; cwd: string; platform: NodeJS.Platform },
): Record<string, unknown> {
  if (!isRecord(parsed)) return {};
  if (role === "claude-json") return parsed.mcpServers === undefined ? {} : { mcpServers: parsed.mcpServers };
  const projects = isRecord(parsed.projects) ? parsed.projects : {};
  const lookup = (p: string): unknown =>
    projects[p] ?? (where.platform === "win32" ? projects[p.replace(/\\/g, "/")] : undefined);
  const out: Record<string, unknown> = {};
  for (const dir of where.root === where.cwd ? [where.root] : [where.root, where.cwd]) {
    const p = lookup(dir);
    if (!isRecord(p)) continue;
    if (isRecord(p.mcpServers)) out.mcpServers = { ...(out.mcpServers as Record<string, unknown> | undefined), ...p.mcpServers };
    for (const k of ["enabledMcpjsonServers", "disabledMcpjsonServers"]) {
      const v = p[k];
      if (!Array.isArray(v)) continue;
      const merged = (out[k] as unknown[] | undefined) ?? [];
      const seen = new Set(merged.map((x) => canonicalJson(x)));
      for (const x of v) {
        const c = canonicalJson(x);
        if (!seen.has(c)) { seen.add(c); merged.push(x); }
      }
      out[k] = merged;
    }
    if (p.enableAllProjectMcpServers !== undefined && out.enableAllProjectMcpServers !== true) {
      out.enableAllProjectMcpServers = p.enableAllProjectMcpServers;
    }
  }
  return out;
}

/** A command Claude Code runs on the user's behalf: a hook, a helper or status line, or an MCP server. */
export type ExecCommand = { kind: "hook" | "helper" | "mcp"; command: string; args: string[] };

/**
 * Every command string a settings / MCP / app-state document makes Claude Code
 * run: command hooks (with exec-form `args`), `statusLine.command`,
 * `fileSuggestion.command`, the credential, proxy, telemetry and process-wrapper
 * helpers, and MCP server `command` + `args`. Feeds hook-script discovery.
 */
export function execCommandsOf(parsed: unknown): ExecCommand[] {
  if (!isRecord(parsed)) return [];
  const out: ExecCommand[] = [];
  if (isRecord(parsed.hooks)) {
    for (const groups of Object.values(parsed.hooks)) {
      if (!Array.isArray(groups)) continue;
      for (const group of groups) {
        if (!isRecord(group) || !Array.isArray(group.hooks)) continue;
        for (const h of group.hooks) {
          if (isRecord(h) && typeof h.command === "string" && (h.type === undefined || h.type === "command")) {
            out.push({ kind: "hook", command: h.command, args: stringArgs(h) });
          }
        }
      }
    }
  }
  for (const k of COMMAND_OBJECT_KEYS) {
    const v = parsed[k];
    if (isRecord(v) && typeof v.command === "string") out.push({ kind: "helper", command: v.command, args: [] });
  }
  for (const k of HELPER_KEYS) if (typeof parsed[k] === "string") out.push({ kind: "helper", command: parsed[k] as string, args: [] });
  if (isRecord(parsed.mcpServers)) {
    for (const entry of Object.values(parsed.mcpServers)) {
      if (isRecord(entry) && typeof entry.command === "string") out.push({ kind: "mcp", command: entry.command, args: stringArgs(entry) });
    }
  }
  return out;
}

/**
 * Names of the MCP servers in `current` (units of a `project-mcp` file) whose
 * server unit is unchanged since the accepted baseline — the names to pass as
 * `acceptedMcpjsonServers` for that project store's other files.
 */
export function acceptedMcpServerNames(current: FileUnits, baselineIds: ReadonlySet<string>): Set<string> {
  const names = new Set<string>();
  for (const u of current.units) if (u.kind === "mcp-server" && u.name !== undefined && baselineIds.has(u.id)) names.add(u.name);
  return names;
}
