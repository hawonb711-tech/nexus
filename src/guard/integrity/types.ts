/**
 * Instruction-file integrity — shared types and constants.
 *
 * Nexus fingerprints the files that steer Claude Code (instructions, rules,
 * settings and hooks, MCP config, agents/commands/skills, memory) and Codex CLI
 * (AGENTS.md, config.toml, hooks.json, exec-policy rules, skills, memories)
 * into signed stores under `<data dir>/integrity/`, diffs them at every
 * SessionStart, and attributes each change to a recorded writer where it can.
 * This module holds only the vocabulary and the on-disk document shapes; it
 * has no logic.
 */

import type { APPLY_PATCH } from "../codex/dialect.js";

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
  "user-skill-doc",
  "user-skill-file",
  "user-agent-memory",
  "claude-json",
  // codex store: Codex's managed layer, and its user-level files under CODEX_HOME (and ~/.agents/skills)
  "codex-managed-config",
  "codex-user-instructions",
  "codex-user-config",
  "codex-user-hooks",
  "codex-user-rules",
  "codex-user-skill",
  "codex-user-skill-doc",
  "codex-user-skill-file",
  "codex-memory",
  // global, codex or project store (scripts referenced by that store's settings or hooks)
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
  "project-skill-doc",
  "project-skill-file",
  "project-agent-memory",
  "claude-json-project",
  "import",
  "external-import",
  "ledger-learned",
  // project store, Codex's files: AGENTS.override.md and the fallback names, and the project `.codex/` and `.agents/skills/`
  "codex-project-md",
  "codex-project-config",
  "codex-project-hooks",
  "codex-project-rules",
  "codex-project-skill",
  "codex-project-skill-doc",
  "codex-project-skill-file",
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
 * - `import-silent`: SUSPECT rules, and the tainted-session agent rules (H4, N4)
 *   that apply to every class.
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
  | "codex-hooks"    // Codex's hooks.json: JSON, its hooks cut like settings hooks
  | "toml"           // Codex's config.toml: one unit per key (toml.ts)
  | "rules"          // Codex's exec-policy rules: one unit per line, each an escalation
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
  "user-skill-doc": "notice",
  "user-skill-file": "exec",
  "user-agent-memory": "memory",
  "claude-json": "notice",
  "codex-managed-config": "notice",
  "codex-user-instructions": "notice",
  "codex-user-config": "notice",
  "codex-user-hooks": "notice",
  "codex-user-rules": "notice",
  "codex-user-skill": "notice",
  "codex-user-skill-doc": "notice",
  "codex-user-skill-file": "exec",
  "codex-memory": "memory",
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
  "project-skill-doc": "notice",
  "project-skill-file": "exec",
  "project-agent-memory": "memory",
  "claude-json-project": "notice",
  "import": "import-silent",
  "external-import": "notice",
  "ledger-learned": "notice",
  "codex-project-md": "notice",
  "codex-project-config": "notice",
  "codex-project-hooks": "notice",
  "codex-project-rules": "notice",
  "codex-project-skill": "notice",
  "codex-project-skill-doc": "notice",
  "codex-project-skill-file": "exec",
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
  "user-skill-doc": "md",
  "user-skill-file": "sha",
  "user-agent-memory": "md-memory",
  "claude-json": "mcp-json",
  "codex-managed-config": "toml",
  "codex-user-instructions": "md",
  "codex-user-config": "toml",
  "codex-user-hooks": "codex-hooks",
  "codex-user-rules": "rules",
  "codex-user-skill": "md-frontmatter",
  "codex-user-skill-doc": "md",
  "codex-user-skill-file": "sha",
  "codex-memory": "md",
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
  "project-skill-doc": "md",
  "project-skill-file": "sha",
  "project-agent-memory": "md-memory",
  "claude-json-project": "json",
  "import": "md",
  "external-import": "md",
  "ledger-learned": "md",
  "codex-project-md": "md",
  "codex-project-config": "toml",
  "codex-project-hooks": "codex-hooks",
  "codex-project-rules": "rules",
  "codex-project-skill": "md-frontmatter",
  "codex-project-skill-doc": "md",
  "codex-project-skill-file": "sha",
  "auto-memory-index": "md-memory",
  "auto-memory-topic": "md-memory",
};

// ── Tiers ───────────────────────────────────────────────────────────────────

/** HOLD and SUSPECT do not advance the baseline; they repeat until accepted or reverted. */
export type HeldTier = "HOLD" | "SUSPECT";
export type Tier = "SILENT" | "NOTICE" | HeldTier;

/** Tiers by how much attention they need. */
export const TIER_RANK: Readonly<Record<Tier, number>> = { SILENT: 0, NOTICE: 1, HOLD: 2, SUSPECT: 3 };

/** The classification rule that decided a file's tier (first match wins, in this order). */
export type TierRule =
  | "S1" | "S2" | "S3" | "S4"
  | "H1" | "H2" | "H3" | "H4" | "H5"
  | "N1" | "N2" | "N3" | "N4" | "N5"
  | "Z";

/**
 * The rules that hold a version, as its held item records them (`HeldItem.rule`).
 * Not S1: nothing a TAMPER reports is persisted.
 */
export const HELD_RULES: ReadonlySet<string> = new Set<TierRule>(["S2", "S3", "S4", "H1", "H2", "H3", "H4", "H5"]);

/**
 * Why a store failed verification. Under TAMPER nothing advances until
 * `baseline --reset` — or, for `permission` (the store or its key belongs to
 * another account, or may not be read), until that is fixed.
 */
export type TamperReason = "mac" | "missing-store" | "rollback" | "store-deleted" | "key" | "redirect" | "permission";

// ── Keys and signing ────────────────────────────────────────────────────────

/** Purposes a subkey of the integrity key is derived for. */
export type SubkeyLabel = "unit" | "store" | "registry" | "ledger" | "config" | "nonce" | "key-id";

// ── Store documents ─────────────────────────────────────────────────────────

/**
 * `global` is the user-level store of the session's agent: Claude Code's
 * (`global`) or Codex's (`codex`), never both in one run.
 */
export type StoreKind = "global" | "project" | "memory";
/**
 * `global` holds Claude Code's user-level and managed files, `codex` Codex's;
 * `project-<h16>` keys a project root (both agents' project files),
 * `memory-<h16>` an auto-memory directory.
 */
export type StoreId = "global" | "codex" | `project-${string}` | `memory-${string}`;

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
   * The rule that held this version (absent for a first-run flag). While the
   * file stays at this version it stays at least this held, with these reasons:
   * the session logs and ledger records a rule read age out of retention, and
   * a hold clears only on accept, a revert or a further change.
   */
  rule?: TierRule;
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
  /**
   * The held item a revert cleared, and when; dropped once the file changes
   * again, or RETENTION_MS later. The unreviewed version may live on in a copy
   * of the project: moved aside while a fresh checkout at the old path reads as
   * a revert here (`mv app app.bak`, then a clone at `app`). That copy's first
   * run carries the hold over when its file is at the held version
   * (evaluate.ts `movedHolds`).
   */
  reverted?: RevertedHold;
};

/** A held item a revert cleared (`StoreEntry.reverted`). */
export type RevertedHold = { held: HeldItem; at: string };

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
  /**
   * Keys a cap left `unhashed` at the last persisted run whose entry does not
   * record that (it keeps its accepted baseline, or has none), sorted. §6.4 F
   * reports files over the scan limits only when this set changes. Absent: none.
   */
  capped?: string[];
  /** Keyed by the canonical path (forward slashes, lower-cased on win32). */
  entries: Record<string, StoreEntry>;
  mac: string;
};

// ── Ledger records (one signed file per event) ──────────────────────────────

/** Session level: tainted (read flagged content) > exposed (read web/MCP content) > clean. */
export type SessionLevel = "clean" | "exposed" | "tainted";

/**
 * An agent write through the file tools, recorded at PreToolUse, before it
 * lands. Attribution counts it only once a `confirm` record says it landed.
 * Denied writes are not recorded.
 */
export type LedgerWriteRecord = {
  v: 1;
  kind: "write";
  t: string;
  /** sha256(session_id)[:16]. */
  sid: string;
  /** tool_use_id. */
  tu: string;
  /** The file tool: Claude Code's, or Codex's apply_patch (one record per watched file the patch adds or updates). */
  tool: "Write" | "Edit" | "MultiEdit" | typeof APPLY_PATCH;
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

/**
 * PostToolUse's word that the write recorded with this `sid`, `tu` and `path`
 * landed. Claude Code runs PostToolUse only after a tool succeeds, so an ask
 * the user rejected (or `-p` turned into a denial) never gets one, and its
 * record vouches for nothing.
 */
export type LedgerConfirmRecord = {
  v: 1;
  kind: "confirm";
  t: string;
  sid: string;
  tu: string;
  path: string;
  mac: string;
};

/** The records attribution uses: agent writes and Nexus's own settings changes. */
export type LedgerRecord = LedgerWriteRecord | LedgerNexusRecord;

// ── Session files ───────────────────────────────────────────────────────────

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
  stores: Record<string, RegistryEntry>;
  mac: string;
};

export type RegistryEntry = {
  gen: number;
  updatedAt: string;
  root?: string;
  /**
   * Entries the store held, or remembered a revert of (`StoreEntry.reverted`),
   * when last written: a project's first run reads only such stores for holds to
   * carry over. Absent in a registry entry written before it was recorded.
   */
  pending?: number;
};

export type MemoryGate = "tainted-only" | "novel-tokens" | "exposed";
/**
 * Which agent writes to instruction, settings, MCP, agent, command and skill
 * files ask: every one (`always`), or only a risky one (`risky`): it adds or
 * removes code-running or permission config, carries something the detectors
 * flag, a secret, or a URL, host or command not in a reviewed file, or comes
 * from a session that read web, MCP or flagged content. Hook and skill
 * scripts ask either way.
 */
export type InstructionGate = "always" | "risky";
export type WithholdMcp = "off" | "suspect" | "unreviewed";

export type IntegrityConfig = {
  /** Which instruction and config writes ask. */
  instructionGate: InstructionGate;
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
  "instructionGate",
  "memoryGate",
  "agentWindowEscalation",
  "withholdMcp",
  "quoteFlaggedLines",
  "enabled",
];

export const CONFIG_DEFAULTS: Readonly<IntegrityConfig> = {
  instructionGate: "always",
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

/**
 * One scope's lists in `watch-prefixes.json`, and when a SessionStart last
 * found them. `codexDirs` (a CODEX_HOME not named `.codex`) and `codexDocs`
 * (the instruction files Codex's `project_doc_fallback_filenames` name) are
 * absent in a file written before Codex's files were watched.
 */
export type WatchPrefixScope = {
  memoryDirs: string[];
  configDirs: string[];
  importTargets: string[];
  hookScripts: string[];
  codexDirs?: string[];
  codexDocs?: string[];
  seen: string;
};

/**
 * `watch-prefixes.json` (unsigned: it only ever adds asks), as read: the union
 * of every scope's lists (absolute canonical paths), and the scopes. A scope is
 * what one SessionStart replaces — a project store as seen from one directory,
 * an auto-memory store, or the global store's lists for one Claude config dir —
 * so sessions in other projects never drop each other's paths; a scope not
 * seen for RETENTION_MS is dropped.
 */
export type WatchPrefixes = {
  v: 1;
  memoryDirs: string[];
  configDirs: string[];
  importTargets: string[];
  hookScripts: string[];
  codexDirs?: string[];
  codexDocs?: string[];
  updatedAt: string;
  stores: Record<string, WatchPrefixScope>;
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
/** Pending-confirm markers (pending.ts). */
export const PENDING_DIR = "pending";

// ── Constants ───────────────────────────────────────────────────────────────

export const INTEGRITY_SCHEMA = 1;
/** Bumped when the watched set changes; like INTEGRITY_SCHEMA, a bump recomputes
 *  derived fields for unchanged files and never produces a wave of reports.
 *  2: a skill's text documents are cut into lines (`*-skill-doc`), not watched by sha.
 *  3: Codex's files (the `codex` store, and Codex's project files in the project store). */
export const WATCHED_SET_VERSION = 3;

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
/**
 * Units (lines, JSON values) a watched file may be cut into. Cutting and diffing
 * costs about 20 µs a unit and cannot stop inside one file, so a file with more
 * is `unhashed` (a hook script: watched by sha only) and one file never costs
 * SessionStart more than a fraction of DEADLINE_MS; 4 MiB of short lines would
 * be 850,000 units.
 */
export const MAX_FILE_UNITS = 10_000;
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
