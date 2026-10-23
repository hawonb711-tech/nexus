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
 * - JSON (settings, MCP config, the `~/.claude.json` projection): one unit per
 *   hook, MCP server, env variable, array element (set semantics) and other
 *   leaf, each with its escalation category (§4.4 `cat`).
 * - Skill and binary files: whole-file sha only.
 *
 * Unit ids are `hmac16("unit", text) + "#" + n` under the integrity key, so the
 * stored ids reveal nothing about content. Each unit also carries its plain text
 * (a line, or a short description of a JSON unit) for rendering added lines in
 * this run — that text is never persisted. Pure; no I/O.
 */

import { createHash } from "node:crypto";
import { canonicalJson, hmacHex, subkey } from "../../shared/sign.js";
import { isNexusGuardCommand } from "../install.js";
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
  /** `disableAllHooks: true`, `permissions.defaultMode: "bypassPermissions"` or any `env.NEXUS_DATA` (§4.4). */
  dangerous?: true;
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
/** Lines Claude Code stamps into a memory file's frontmatter (A10), matched after the indent. */
const MEMORY_STAMP = /^(?:modified|originSessionId|node_type):[ \t]{0,16}\S/;
/** A `key: "value"` / `key: 'value'` line (A10: compare the value unquoted). */
const QUOTED_SCALAR = /^([ \t]{0,64}[^\s'"#:][^:]{0,255}):[ \t]{1,16}(["'])(.*)\2$/;

const isIndented = (line: string) => line.charCodeAt(0) === 32 || line.charCodeAt(0) === 9;

function unquote(line: string): string {
  const m = QUOTED_SCALAR.exec(line);
  if (!m) return line;
  const value = m[2] === '"' ? m[3].replace(/\\(["\\])/g, "$1") : m[3].replace(/''/g, "'");
  return `${m[1]}: ${value}`;
}

/** Index of the frontmatter's closing `---` when line 0 opens one, else -1. */
function frontmatterEnd(lines: readonly string[]): number {
  if (lines.length === 0 || lines[0].trimEnd() !== "---") return -1;
  for (let i = 1; i < lines.length; i++) if (lines[i].trimEnd() === "---") return i;
  return -1;
}

/**
 * Memory-role frontmatter lines to drop (A10): the stamped `modified`,
 * `originSessionId` and `node_type` lines at any indent, and a top-level
 * `metadata:` left with no other children (Claude Code adds it to hold them).
 */
function memoryDrops(lines: readonly string[], end: number): Set<number> {
  const drop = new Set<number>();
  for (let i = 1; i < end; i++) if (MEMORY_STAMP.test(lines[i].trimStart())) drop.add(i);
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
  let escalating = false;
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trimEnd();
    if (line === "") continue;
    const inFrontmatter = i > 0 && i < end;
    if (inFrontmatter && mode === "memory") {
      if (drop!.has(i)) continue;
      line = unquote(line);
    }
    if (inFrontmatter && mode === "frontmatter") {
      // A top-level key line starts (or ends) an escalation block; indented lines
      // and top-level `- item`s continue the block they are in.
      if (!isIndented(line) && !line.startsWith("-")) {
        const colon = line.indexOf(":");
        escalating = ESCALATION_KEYS.has((colon < 0 ? line : line.slice(0, colon)).trim());
      }
      if (escalating) {
        b.add(`f\0${line}`, { kind: "frontmatter", text: line, line: i + 1, cat: "e" });
        continue;
      }
    }
    b.add(`m\0${line}`, { kind: "line", text: line, line: i + 1 });
  }
  return b.finish();
}

/** UTF-8 text with no NUL byte, or null (then the file is watched by sha only). */
function decodeText(content: Buffer | string): string | null {
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
  "hooks", "statusLine", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper",
  "env", "mcpServers", "enableAllProjectMcpServers", "allowedMcpServers", "deniedMcpServers",
  "enabledPlugins", "extraKnownMarketplaces", "pluginConfigs", "disableAllHooks", "autoMemoryDirectory",
  "claudeMdExcludes",
]);
/** Top-level keys whose changes are benign. */
const BENIGN_KEYS = new Set([
  "$schema", "model", "cleanupPeriodDays", "includeCoAuthoredBy", "autoUpdates", "autoUpdatesChannel",
  "verbose", "alwaysThinkingEnabled", "autoMemoryEnabled", "spinnerTipsEnabled", "preferredNotifChannel",
]);
/** Settings keys whose value is a command Claude Code runs. */
const HELPER_KEYS = ["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"] as const;

const BARE_TOOL = /^[A-Za-z0-9_-]{1,256}$/;
const SCOPED_TOOL = /^([^()]{1,256})\(([^]{0,4096})\)$/;

/**
 * An allow rule with no real scope: a bare tool name, `Tool(*)`, `Tool(:*)`,
 * `Tool()`, `*`, any rule whose tool name has a wildcard (`mcp__*`), or WebFetch
 * without `domain:`. The "don't ask again" button writes scoped rules.
 */
export function isUnscopedAllowRule(rule: unknown): boolean {
  if (typeof rule !== "string") return true;
  const r = rule.trim();
  if (r === "*" || BARE_TOOL.test(r)) return true;
  const m = r.match(SCOPED_TOOL);
  if (!m) return true; // not a rule shape Nexus understands: fail closed
  const [, tool, spec] = m;
  if (tool.includes("*")) return true;
  const s = spec.trim();
  if (s === "" || s === "*" || s === ":*") return true;
  return tool.trim() === "WebFetch" && !s.startsWith("domain:");
}

/** A dotted pointer; `~` and `.` inside a key are escaped so pointers stay unambiguous. */
function pointer(path: readonly string[]): string {
  return path.map((k) => k.replace(/~/g, "~0").replace(/\./g, "~1")).join(".");
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

/** What a hook runs: its command, URL, MCP server/tool, or prompt. */
function hookTarget(h: Record<string, unknown>): string {
  if (typeof h.command === "string") return h.command;
  if (typeof h.url === "string") return h.url;
  if (typeof h.server === "string" && typeof h.tool === "string") return `${h.server}/${h.tool}`;
  if (typeof h.prompt === "string") return h.prompt;
  return canonicalJson({ ...h, type: undefined });
}

function stringArgs(entry: Record<string, unknown>): string[] {
  return Array.isArray(entry.args) ? entry.args.filter((a): a is string => typeof a === "string") : [];
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
      else this.walk([k], v);
    }
  }

  private hooks(hooks: Record<string, unknown>): void {
    for (const [event, groups] of Object.entries(hooks)) {
      if (!Array.isArray(groups)) { this.walk(["hooks", event], groups); continue; }
      for (const group of groups) {
        if (!isRecord(group) || !Array.isArray(group.hooks)) { this.walk(["hooks", event], [group]); continue; }
        const matcher = group.matcher === undefined ? "" : show(group.matcher);
        for (const h of group.hooks) {
          if (!isRecord(h)) { this.walk(["hooks", event], [h]); continue; }
          const type = typeof h.type === "string" ? h.type : "";
          const target = hookTarget(h);
          if (isNexusGuardCommand(h.command)) this.nexusHooks.add(event);
          this.b.add(`h\0${event}\0${matcher}\0${type}\0${target}`, {
            kind: "hook",
            text: `${event}${matcher ? ` (${matcher})` : ""} hook: ${target}`,
            cat: "e",
            desc: `new ${event} hook "${target}"`,
            name: event,
            ...(typeof h.command === "string" ? { command: h.command } : {}),
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

  /** The entry with every `env` / `headers` value replaced by its keyed hash: a changed
   *  secret still changes the unit, but no secret ever reaches a unit text. */
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

  private walk(path: string[], value: unknown): void {
    if (Array.isArray(value)) {
      for (const el of value) this.element(path, el);
    } else if (isRecord(value)) {
      const keys = Object.keys(value);
      for (const k of keys) this.walk([...path, k], value[k]);
    } else {
      this.leaf(path, value);
    }
  }

  private element(path: string[], el: unknown): void {
    const ptr = pointer(path);
    const cat = categoryOf(path, el, this.accepted);
    const rule = show(el);
    const widened = path[0] === "permissions" && path[1] === "allow" && path.length === 2 && cat === "a";
    this.b.add(`a\0${ptr}\0${canonicalJson(el)}`, {
      kind: "element",
      text: `${ptr}[]: ${rule}`,
      ...(cat ? { cat } : {}),
      ...(widened ? { desc: `permission widened: ${rule}` } : {}),
    });
  }

  private leaf(path: string[], value: unknown): void {
    const ptr = pointer(path);
    const cat = categoryOf(path, value, this.accepted);
    const [top, sub] = path;
    const dangerous =
      (top === "disableAllHooks" && path.length === 1 && value === true) ||
      (top === "permissions" && sub === "defaultMode" && path.length === 2 && value === "bypassPermissions");
    const helper = path.length === 1 && (HELPER_KEYS as readonly string[]).includes(top);
    const statusCommand = top === "statusLine" && sub === "command" && path.length === 2;
    const plugin = top === "enabledPlugins" && path.length === 2 && value === true;
    this.b.add(`j\0${ptr}\0${canonicalJson(value)}`, {
      kind: "leaf",
      text: `${ptr}: ${show(value)}`,
      ...(cat ? { cat } : {}),
      ...(plugin ? { desc: `new plugin ${sub}` } : {}),
      ...((helper || statusCommand) && typeof value === "string" ? { command: value } : {}),
      ...(dangerous ? { dangerous: true as const } : {}),
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
      return jsonUnits(content, opts, hash);
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

/** A command Claude Code runs on the user's behalf: a hook, a helper, a status line or an MCP server. */
export type ExecCommand = { command: string; args: string[] };

/**
 * Every command string a settings / MCP / app-state document makes Claude Code
 * run: command hooks, `statusLine.command`, the credential and telemetry
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
            out.push({ command: h.command, args: [] });
          }
        }
      }
    }
  }
  if (isRecord(parsed.statusLine) && typeof parsed.statusLine.command === "string") {
    out.push({ command: parsed.statusLine.command, args: [] });
  }
  for (const k of HELPER_KEYS) if (typeof parsed[k] === "string") out.push({ command: parsed[k] as string, args: [] });
  if (isRecord(parsed.mcpServers)) {
    for (const entry of Object.values(parsed.mcpServers)) {
      if (isRecord(entry) && typeof entry.command === "string") out.push({ command: entry.command, args: stringArgs(entry) });
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
