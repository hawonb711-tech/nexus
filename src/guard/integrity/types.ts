/**
 * Instruction-file integrity — shared types and constants.
 *
 * Nexus fingerprints the files that steer Claude Code (instructions, rules,
 * settings and hooks, MCP config, agents/commands/skills, memory) into signed
 * stores under `<data dir>/integrity/`, diffs them at every SessionStart, and
 * attributes each change to a recorded writer where it can. This module holds
 * only the vocabulary and the on-disk document shapes; it has no logic.
 */

// ── Watched roles and their classes ────────────────────────────────────────

/** Every role a watched file can have, grouped by the store that holds it. */
export const WATCHED_ROLES = [
  // global store
  "managed-claude-md",
  "managed-settings",
  "managed-mcp",
  "user-claude-md",
  "user-rules",
  "user-settings",
  "user-agent",
  "user-command",
  "user-skill",
  "user-skill-file",
  "user-agent-memory",
  "claude-json",
  // global or project store (scripts referenced by that store's settings)
  "hook-script",
  // project store
  "ancestor-claude-md",
  "ancestor-local-md",
  "ancestor-agents-md",
  "project-settings",
  "local-settings",
  "project-mcp",
  "project-rules",
  "project-agent",
  "project-command",
  "project-skill",
  "project-skill-file",
  "project-agent-memory",
  "claude-json-project",
  "import",
  "external-import",
  "ledger-learned",
  // memory store
  "auto-memory-index",
  "auto-memory-topic",
] as const;
export type WatchedRole = (typeof WATCHED_ROLES)[number];

/**
 * Which tier rules apply to a role:
 * - `notice`: all of them;
 * - `exec`: all, plus HOLD for a content change no record explains (code that runs);
 * - `memory`: SUSPECT rules always, the unknown-writer rules only once memory
 *   writes have been observed through the file tools (calibration);
 * - `import-silent`: SUSPECT rules only.
 */
export type RoleClass = "notice" | "exec" | "memory" | "import-silent";

/** How a role's content is cut into units. */
export type UnitKind =
  | "md"
  | "md-frontmatter" // md, plus escalation units for agent/skill frontmatter keys
  | "md-memory"      // md with memory normalization (the auto-added `modified:` line)
  | "settings-json"
  | "mcp-json"
  | "json"
  | "text-or-sha"    // md-style lines for UTF-8 text without NUL, else whole-file sha
  | "sha";           // whole-file sha only, no units

export const ROLE_CLASS: Readonly<Record<WatchedRole, RoleClass>> = {
  "managed-claude-md": "notice",
  "managed-settings": "notice",
  "managed-mcp": "notice",
  "user-claude-md": "notice",
  "user-rules": "notice",
  "user-settings": "notice",
  "user-agent": "notice",
  "user-command": "notice",
  "user-skill": "notice",
  "user-skill-file": "exec",
  "user-agent-memory": "memory",
  "claude-json": "notice",
  "hook-script": "exec",
  "ancestor-claude-md": "notice",
  "ancestor-local-md": "notice",
  "ancestor-agents-md": "notice",
  "project-settings": "notice",
  "local-settings": "notice",
  "project-mcp": "notice",
  "project-rules": "notice",
  "project-agent": "notice",
  "project-command": "notice",
  "project-skill": "notice",
  "project-skill-file": "exec",
  "project-agent-memory": "memory",
  "claude-json-project": "notice",
  "import": "import-silent",
  "external-import": "notice",
  "ledger-learned": "notice",
  "auto-memory-index": "memory",
  "auto-memory-topic": "memory",
};

export const ROLE_UNITS: Readonly<Record<WatchedRole, UnitKind>> = {
  "managed-claude-md": "md",
  "managed-settings": "settings-json",
  "managed-mcp": "mcp-json",
  "user-claude-md": "md",
  "user-rules": "md",
  "user-settings": "settings-json",
  "user-agent": "md-frontmatter",
  "user-command": "md",
  "user-skill": "md-frontmatter",
  "user-skill-file": "sha",
  "user-agent-memory": "md-memory",
  "claude-json": "mcp-json",
  "hook-script": "text-or-sha",
  "ancestor-claude-md": "md",
  "ancestor-local-md": "md",
  "ancestor-agents-md": "md",
  "project-settings": "settings-json",
  "local-settings": "settings-json",
  "project-mcp": "mcp-json",
  "project-rules": "md",
  "project-agent": "md-frontmatter",
  "project-command": "md",
  "project-skill": "md-frontmatter",
  "project-skill-file": "sha",
  "project-agent-memory": "md-memory",
  "claude-json-project": "json",
  "import": "md",
  "external-import": "md",
  "ledger-learned": "md",
  "auto-memory-index": "md-memory",
  "auto-memory-topic": "md-memory",
};

// ── Tiers ───────────────────────────────────────────────────────────────────

/** HOLD and SUSPECT do not advance the baseline; they repeat until accepted or reverted. */
export type HeldTier = "HOLD" | "SUSPECT";
export type Tier = "SILENT" | "NOTICE" | HeldTier;

/** The classification rule that decided a file's tier (first match wins, in this order). */
export type TierRule =
  | "S1" | "S2" | "S3" | "S4"
  | "H1" | "H2" | "H3" | "H4" | "H5"
  | "N1" | "N2" | "N3" | "N4" | "N5"
  | "Z";

/** Why a store failed verification. Under TAMPER nothing advances until `baseline --reset`. */
export type TamperReason = "mac" | "missing-store" | "rollback" | "store-deleted" | "key" | "redirect";

// ── Keys and signing ────────────────────────────────────────────────────────

/** Purposes a subkey of the integrity key is derived for. */
export type SubkeyLabel = "unit" | "store" | "registry" | "ledger" | "config" | "nonce" | "key-id";

// ── Store documents ─────────────────────────────────────────────────────────

export type StoreKind = "global" | "project" | "memory";
/** `project-<h16>` keys a project root, `memory-<h16>` an auto-memory directory. */
export type StoreId = "global" | `project-${string}` | `memory-${string}`;

export type EntryState = "file" | "missing" | "oversize" | "unhashed";
/** `[size, mtimeMs, ctimeMs, ino, dev]` — the stat fast path's change check. */
export type StatTuple = [size: number, mtimeMs: number, ctimeMs: number, ino: number, dev: number];
export type AcceptedBy = "first-run" | "auto" | "agent" | "nexus" | "user";

/**
 * A unit's JSON or frontmatter category: `e` escalation either way, `a`
 * escalation only when added, `r` only when removed, `b` benign. A unit with no
 * category is "other" and fails closed to NOTICE.
 */
export type UnitCategory = "e" | "a" | "r" | "b";

/** A detector's verdict on one hunk of a held version's added text (keyed unit ids; no content). */
export type HeldVerdict = { units: string[]; reason: string; strong: boolean };

/** Present on an entry only while it is HOLD or SUSPECT. */
export type HeldItem = {
  /** `h_` + 12 hex; changes whenever the file's content changes. */
  id: string;
  tier: HeldTier;
  /** When the item was first held (kept across sessions). */
  since: string;
  /**
   * Why it is held. While a first-run flag is held (`flaggedUnits` not empty),
   * the first-run scan's reasons: those of a later change are derived again
   * each session.
   */
  reasons: string[];
  /**
   * Units a first-run scan flagged, kept while the baseline holds them; the item
   * clears once the file holds none of them.
   */
  flaggedUnits: string[];
  /**
   * The verdicts screening gave the held version's added text. While the file
   * is still that version (the same `id`), they are reused instead of screening
   * it again. Absent when not recorded: the file is then screened.
   */
  screened?: HeldVerdict[];
};

export type StoreEntry = {
  path: string;
  role: WatchedRole;
  state: EntryState;
  /** Whole-file sha256 (hex) of the raw bytes; null when not hashed. */
  sha256: string | null;
  size: number | null;
  stat: StatTuple | null;
  /** `readlink` text when the path is a symlink (the target is what is hashed). */
  link: string | null;
  /** Sorted keyed unit hashes, `<hmac16>#<occurrence>` (a multiset). */
  units: string[];
  /** unit → category; empty for markdown. */
  cat: Record<string, UnitCategory>;
  /** Keyed hashes of the actionable tokens (URLs, hosts, emails, paths, commands) in this version. */
  tok: string[];
  /** Event names of the Nexus hooks found in this settings file. */
  nexusHooks: string[];
  /** Previously accepted versions, newest last, at most HISTORY_MAX. */
  history: { sha256: string; at: string }[];
  acceptedAt: string;
  acceptedBy: AcceptedBy;
  held: HeldItem | null;
};

export type StoreDoc = {
  schema: "nexus-integrity-store";
  /** INTEGRITY_SCHEMA the store was written with. */
  v: number;
  watchedSetVersion: number;
  kind: StoreKind;
  id: StoreId;
  /** null for the global store; the project root, or the auto-memory directory. */
  root: string | null;
  /** Project stores only; null when auto memory was not located. */
  autoMemoryDir?: string | null;
  /** Bumped on every write; the registry's copy detects a rolled-back store. */
  gen: number;
  createdAt: string;
  updatedAt: string;
  /** Global store only: a ledger write to a memory-class path has been seen. */
  memoryWritesObserved?: boolean;
  /** Keyed by the canonical path (forward slashes, lower-cased on win32). */
  entries: Record<string, StoreEntry>;
  mac: string;
};

// ── Ledger records (one signed file per event) ──────────────────────────────

/** Session level: tainted (read flagged content) > exposed (read web/MCP content) > clean. */
export type SessionLevel = "clean" | "exposed" | "tainted";

/** An agent write through the file tools, recorded before it lands. Denied writes are not recorded. */
export type LedgerWriteRecord = {
  v: 1;
  kind: "write";
  t: string;
  /** sha256(session_id)[:16]. */
  sid: string;
  /** tool_use_id. */
  tu: string;
  tool: "Write" | "Edit" | "MultiEdit";
  path: string;
  added: string[];
  removed: string[];
  /** sha256 of the file as the simulated write leaves it. */
  expectedSha: string;
  /** The edit could not be simulated exactly (old_string not found). */
  approx: boolean;
  decision: "allow" | "ask";
  /** The payload's raw `permission_mode`; null when it carries none. */
  mode: string | null;
  level: SessionLevel;
  /** The added text carries actionable tokens no accepted entry has. */
  novel: boolean;
  /** The detector's reason, or null. */
  screen: string | null;
  /** A subagent's `agent_id` / `agent_type`, copied from the payload when present
   *  (subagent tool calls carry the parent's session_id; amendment A5). */
  agentId?: string;
  agentType?: string;
  mac: string;
};

/** A settings change Nexus itself made (`guard install` / `guard uninstall`). */
export type LedgerNexusRecord = {
  v: 1;
  kind: "nexus";
  t: string;
  action: "install" | "uninstall";
  path: string;
  added: string[];
  removed: string[];
  nexusHooks: string[];
  mac: string;
};

export type LedgerRecord = LedgerWriteRecord | LedgerNexusRecord;

// ── Session files ───────────────────────────────────────────────────────────

/**
 * `sessions/<sid16>.log` line kinds (tab-separated, unsigned; lines only raise
 * the level): `s` SessionStart ran, `a` tool activity, `x` exposure to web/MCP
 * content, `f` a flagged tool result (tainted), `t` a SUSPECT item delivered (tainted).
 */
export type SessionLogKind = "s" | "a" | "x" | "f" | "t";

/** A token from held lines that commands and writes must not reuse unasked. */
export type SessionIndicator = { t: string; file: string; tier: HeldTier };

/** `sessions/<sid16>.json`, written by SessionStart for this session only. */
export type SessionStateDoc = {
  v: 1;
  sid: string;
  at: string;
  indicators: SessionIndicator[];
  withheldMcp: { name: string; reason: string }[];
  /** Held IDs whose user message this session has already received. */
  shown: string[];
};

// ── Registry, config and other files ────────────────────────────────────────

export type RegistryDoc = {
  schema: "nexus-integrity-registry";
  v: 1;
  stores: Record<string, { gen: number; updatedAt: string; root?: string }>;
  mac: string;
};

export type MemoryGate = "tainted-only" | "novel-tokens" | "exposed";
export type WithholdMcp = "off" | "suspect" | "unreviewed";

export type IntegrityConfig = {
  /** Which memory writes ask. */
  memoryGate: MemoryGate;
  /** Escalate unknown changes made inside agent-activity windows to HOLD. */
  agentWindowEscalation: boolean;
  /** Whose MCP output is withheld: none, SUSPECT servers, or HOLD servers too. */
  withholdMcp: WithholdMcp;
  /** Quote flagged lines in the counter-frame, or only describe them. */
  quoteFlaggedLines: boolean;
  /** Stored as the `.disabled` marker, not in config.json. */
  enabled: boolean;
};
export type ConfigKey = keyof IntegrityConfig;

export const CONFIG_KEYS: readonly ConfigKey[] = [
  "memoryGate",
  "agentWindowEscalation",
  "withholdMcp",
  "quoteFlaggedLines",
  "enabled",
];

export const CONFIG_DEFAULTS: Readonly<IntegrityConfig> = {
  memoryGate: "novel-tokens",
  agentWindowEscalation: true,
  withholdMcp: "suspect",
  quoteFlaggedLines: true,
  enabled: true,
};

/**
 * `config.json`; a missing file or key means its default. `kind` is signed: the
 * marker below shares the `config` subkey, and neither may pass for the other.
 */
export type ConfigDoc = Partial<Omit<IntegrityConfig, "enabled">> & { v: 1; kind: "config"; mac: string };

/** `.disabled`: integrity is off only while this marker carries a valid MAC (and its signed `kind`). */
export type DisabledMarker = { v: 1; kind: "disabled"; at: string; by: "cli" | "install"; mac: string };

/** `.integrity-anchor`, outside `integrity/`: proves a store existed, and which key it used. */
export type AnchorDoc = { v: 1; createdAt: string; keyId: string };

/** `watch-prefixes.json` (unsigned: it only ever adds asks). Absolute canonical paths. */
export type WatchPrefixes = {
  v: 1;
  memoryDirs: string[];
  configDirs: string[];
  importTargets: string[];
  hookScripts: string[];
  updatedAt: string;
};

export type LogEvent =
  | "advance" | "notice" | "hold" | "suspect" | "cleared-revert"
  | "accept" | "first-run" | "tamper" | "reset";

/** One `log.jsonl` line (display only). */
export type LogEntry = {
  at: string;
  event: LogEvent;
  store?: string;
  path?: string;
  tier?: Tier;
  by?: string;
  added?: number;
  removed?: number;
  /** First 8 hex of the old and new sha256. */
  old?: string;
  new?: string;
};

// ── Layout (under the Nexus data dir) ───────────────────────────────────────

export const INTEGRITY_DIR = "integrity";
export const ANCHOR_FILE = ".integrity-anchor";
export const KEY_FILE = ".integrity-key";
export const DISABLED_FILE = ".disabled";
export const LOCK_FILE = ".lock";
export const REGISTRY_FILE = "registry.json";
export const CONFIG_FILE = "config.json";
export const WATCH_PREFIXES_FILE = "watch-prefixes.json";
export const LOG_FILE = "log.jsonl";
export const STORES_DIR = "stores";
export const LEDGER_DIR = "ledger";
export const SESSIONS_DIR = "sessions";

// ── Constants ───────────────────────────────────────────────────────────────

export const INTEGRITY_SCHEMA = 1;
/** Bumped when the watched set changes; like INTEGRITY_SCHEMA, a bump recomputes
 *  derived fields for unchanged files and never produces a wave of reports. */
export const WATCHED_SET_VERSION = 1;

/**
 * Permission modes in which a hook `ask` was seen to prompt the user (amendment
 * A3: all six; in `-p` with no host an ask is a denial, so it never lands).
 * Display only: a ledger write counts as user-approved when its decision was
 * `ask`, in any mode, known or not.
 */
export const ASK_PROMPTS_IN_MODES: ReadonlySet<string> = new Set([
  "default", "acceptEdits", "plan", "bypassPermissions", "dontAsk", "auto",
]);

/** Where user-only notices go: the SessionStart `systemMessage`, or stderr with exit 2. */
export type NoticeChannel = "systemMessage" | "stderr-exit2";
export const NOTICE_CHANNEL: NoticeChannel = "systemMessage";

/** SessionStart gives up (nothing compared or advanced) after this long. */
export const DEADLINE_MS = 5000;
/** Characters of the counter-frame in SessionStart's `additionalContext`. */
export const CONTEXT_BUDGET = 8000;
/**
 * Characters of the whole `additionalContext` (header + frame). Claude Code
 * moves a string over 10,000 characters to a file and shows the model a short
 * preview, losing the frame's end (amendment A2).
 */
export const CONTEXT_HARD_CAP = 9500;
/**
 * SessionStart stops screening added text this long after it began (classify's
 * `stopScreening`), leaving the rest of DEADLINE_MS to persist and render; what
 * was not screened waits for the next session.
 */
export const SCREEN_DEADLINE_MS = 3000;
/** Characters of `systemMessage` SessionStart may emit. */
export const SYSTEM_MESSAGE_BUDGET = 600;
/** Previously accepted versions kept per entry. */
export const HISTORY_MAX = 8;

/** Files kept per enumerated directory. */
export const MAX_DIR_ENTRIES = 200;
/** Files watched per run, across all stores. */
export const MAX_FILES_PER_RUN = 400;
/** Larger files are `oversize`: size and stat only (Claude Code skips them too). */
export const MAX_FILE_BYTES = 4 * 1024 * 1024;
/** Bytes hashed per run. */
export const MAX_HASHED_BYTES_PER_RUN = 16 * 1024 * 1024;
/** A larger `~/.claude.json` is skipped and marked `unhashed`. */
export const MAX_CLAUDE_JSON_BYTES = 20 * 1024 * 1024;

/** Session indicators kept per session. */
export const MAX_INDICATORS = 32;

/** Ledger day directories and session files older than this are removed. */
export const RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
/** Deletions per garbage-collection run. */
export const MAX_GC_DELETIONS = 500;
/** `log.jsonl` is rewritten to its last LOG_KEEP_LINES once it reaches LOG_MAX_LINES. */
export const LOG_KEEP_LINES = 1000;
export const LOG_MAX_LINES = 1200;

/** Lock waits: SessionStart persists nothing rather than wait longer; the CLI waits longer. */
export const LOCK_WAIT_SESSION_START_MS = 1000;
export const LOCK_WAIT_CLI_MS = 5000;
export const LOCK_STALE_MS = 30_000;
