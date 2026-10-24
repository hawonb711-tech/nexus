/**
 * Instruction-file integrity — provenance classification (spec §5, amendments
 * A3 and A10).
 *
 * `classify` compares this run's snapshot of the watched set with the baseline
 * stores and gives every changed file a tier:
 * - SILENT and NOTICE advance the baseline to the current file;
 * - HOLD and SUSPECT do not: the entry keeps its accepted version and carries a
 *   `held` item, derived again every session until the user accepts or reverts.
 *
 * Per changed entry (§5.1): a file back at a previously accepted version is
 * SILENT. Otherwise its units are diffed as multisets, and each added or removed
 * unit is attributed to the earliest signed ledger record that lists it (Nexus's
 * own install, or an agent write PostToolUse confirmed landed, prompted when
 * its decision was `ask` in any mode, A3), or is `unknown`. Added lines are grouped into hunks (maximal runs of
 * added units with one attribution; blank lines have no unit, so they do not
 * break a run) and screened (§5.2): Markdown with `classifyMemoryThreat`, hook,
 * helper and MCP commands with `inspectCommand`, text hook scripts with the
 * content capabilities `inspectFileWrite` applies, at most 200 KB of hunk text
 * per file and RUN_SCAN_CAP_CHARS per run, spent in priority order across the
 * stores (code and commands, then launch-loaded instructions, then memory, then
 * imports and on-demand files) and only until `stopScreening` says the deadline
 * is near. A file left unscreened is not advanced or held: its baseline stays,
 * and it is compared again next run (see `ClassifyResult.deferred`); a held one
 * keeps its held state as it was. A held file whose content is unchanged reuses
 * the verdicts its held item recorded instead of being screened again. The tier is the first rule of §5.3's table that
 * matches, gated by the role's class (§3.6). A store with no baseline gets the
 * first-run scan (§5.5); a store under TAMPER (§5.6) has every changed file
 * SUSPECT and nothing advanced.
 *
 * Agent-activity windows are asked for, through the lazy `windows` provider, only
 * when an unknown added unit could make a file HOLD (H1), and at most once per
 * run (from the earliest changed entry's acceptedAt); they only escalate, and a
 * partial read (its byte budget or deadline spent) puts every such change in one.
 *
 * Pure: no filesystem, clock or environment access. The result carries the next
 * store documents and the log lines; the caller persists them.
 */

import type { Snapshot, SnapshotEntry, StoreSnapshot } from "./enumerate.js";
import type { LedgerEntry } from "./ledger.js";
import { nexusHookCommand } from "./nexus-hook.js";
import { storeKey } from "./paths.js";
import { commandNoun, commandVerdict, markdownVerdict, SCAN_CAP_CHARS, scriptVerdict, type Verdict } from "./screen.js";
import { inWindows, type ActivityWindow } from "./session-log.js";
import { isCurrentVersion, newStoreDoc, TAMPER_FRAGMENTS, upgradeStore, type UnsignedStoreDoc } from "./store.js";
import { extractTokens, novelTokens, tokenHashes, type ActionableToken, type TokenOptions } from "./tokens.js";
import {
  HISTORY_MAX, ROLE_CLASS, ROLE_UNITS,
  type AcceptedBy, type HeldItem, type HeldTier, type HeldVerdict, type IntegrityConfig, type LogEntry, type RoleClass, type StoreDoc,
  type StoreEntry, type StoreId, type StoreKind, type TamperReason, type Tier, type TierRule, type WatchedRole,
} from "./types.js";
import { acceptedMcpServerNames, hookEventName, unitsOf, type FileUnits, type Unit, type UnitHasher, type UnitKind } from "./units.js";

// ── Inputs ──────────────────────────────────────────────────────────────────

/** Keyed hash functions derived from the integrity key. */
export type ClassifyHashers = {
  /** `hmac16("unit", ·)`; null only when no trusted key exists, in which case every store must be TAMPER. */
  unit: UnitHasher | null;
  /** `hmac16("nonce", ·)`: held ids (and, in render.ts, the frame nonce). */
  nonce: (text: string) => string;
};

export type StoreInput = {
  /** The baseline: verified, or under TAMPER a best-effort unverified parse. Null when there is none (a first run). */
  doc: StoreDoc | UnsignedStoreDoc | null;
  /** The TAMPER reason that applies to this store, or null. */
  tamper: TamperReason | null;
};

export type ClassifyInput = {
  stores: { global: StoreInput; project: StoreInput; memory: StoreInput | null };
  /**
   * This run's watched set. Files whose sha differs from the baseline must carry
   * their `content`; so must held entries whose lines should be quoted again, and
   * every entry of a store written under an older schema (the version bump
   * recomputes their units).
   */
  snapshot: Snapshot;
  /** Verified ledger records (any paths); each entry uses its own path's records after its `acceptedAt`. */
  ledger: readonly LedgerEntry[];
  /**
   * Activity windows of the session logs last modified at or after `sinceMs`,
   * sorted and merged (`activityWindowsSince`). Called lazily, at most once. A
   * `partial` read (its byte budget or deadline ran out) may miss windows, so
   * every unknown addition of the run is then taken to be inside one (H1):
   * windows only ever escalate.
   */
  windows: (sinceMs: number) => readonly ActivityWindow[] | { windows: readonly ActivityWindow[]; partial: boolean };
  config: Pick<IntegrityConfig, "agentWindowEscalation">;
  now: Date;
  hashers: ClassifyHashers;
  /** For path tokens (`~/…`) and store keys. */
  home: string;
  platform: NodeJS.Platform;
  /** This run creates the machine's first store (render shows case B). */
  machineFirstRun?: boolean;
  /**
   * The SessionStart deadline (§6.3 step 3), asked between files and before each
   * detector call. Once it returns true classification stops: the result is
   * `incomplete`, and the caller persists nothing.
   */
  expired?: () => boolean;
  /** Characters the detectors may screen this run, across files (default RUN_SCAN_CAP_CHARS); see `ClassifyResult.deferred`. */
  scanBudget?: number;
  /**
   * Asked before each file is screened (a held file at its held version reuses
   * its verdicts instead): once it returns
   * true — the SessionStart deadline is near (SCREEN_DEADLINE_MS) — screening
   * stops as if the run's budget were spent, and the rest of the run completes,
   * so what was classified can still be persisted. Unlike `expired`, it never
   * makes the result incomplete.
   */
  stopScreening?: () => boolean;
};

// ── Results ─────────────────────────────────────────────────────────────────

/** Who wrote a unit: an agent file-tool write, Nexus's own install / uninstall, or nobody on record. */
export type Attribution =
  | { kind: "unknown" }
  | { kind: "nexus"; file: string; action: "install" | "uninstall" }
  | {
      kind: "agent";
      /** The ledger record, `<YYYYMMDD>/<file>.json`. */
      file: string;
      tool: string;
      sid: string;
      /** The raw `permission_mode` (display only, A3). */
      mode: string | null;
      /** The write was asked (A3: an ask prompts in every mode, or never lands). */
      prompted: boolean;
      tainted: boolean;
      exposed: boolean;
      novel: boolean;
    };

export type { Verdict } from "./screen.js";

/** What a JSON hunk's unit is, for rendering (never persisted). */
export type HunkUnit = {
  kind: UnitKind;
  /** The hook event, MCP server name or env key. */
  name?: string;
  /** The command, URL or other target the unit makes Claude Code run or reach. */
  target: string;
  /** units.ts's description (`new plugin x`, `permission widened: Bash`, `env K set`). */
  desc?: string;
};

/** A maximal run of added lines with one attribution, or one added JSON unit. */
export type Hunk = {
  attribution: Attribution;
  /** 1-based line of the first added line; null for a JSON unit. */
  line: number | null;
  /** The added lines (in memory only), or one JSON unit's rendering. */
  lines: string[];
  units: string[];
  verdict: Verdict | null;
  unit?: HunkUnit;
};

export type ChangeKind = "modified" | "created" | "deleted" | "retargeted" | "unchanged" | "listed";

/** A §5.3 rule, or a first-run scan result (§5.5). */
export type ClassifyRule = TierRule | "first-run-block" | "first-run-hit";

export type EntryResult = {
  store: StoreKind;
  storeId: StoreId;
  key: string;
  path: string;
  role: WatchedRole;
  roleClass: RoleClass;
  tier: Tier;
  /** The rule that decided the tier. */
  rule: ClassifyRule;
  /** Every rule that matched, in table order (H1 is only evaluated while no SUSPECT rule matched). */
  rules: ClassifyRule[];
  reasons: string[];
  change: ChangeKind;
  /** Recorded by the first-run scan of its store (or of a newly watched path). */
  firstRun: boolean;
  tamper: TamperReason | null;
  hunks: Hunk[];
  /** Units added and removed. */
  added: number;
  removed: number;
  /** Descriptions of the escalating JSON units added (new hooks, MCP servers, plugins, permissions, env). */
  descriptions: string[];
  /** Nexus hook events removed with no Nexus uninstall on record (S3). */
  removedNexusHooks: string[];
  /** Renderings of dangerous-switch units added by a non-user (S4). */
  dangerous: string[];
  flaggedUnits: string[];
  /** Actionable tokens in the added text that no accepted entry carries (the indicators of a held file). */
  novel: ActionableToken[];
  /** The current symlink text, if the path is a symlink. */
  link: string | null;
  /** No line could be quoted: no comparable baseline (TAMPER), or the text was not read this run. */
  unquoted: boolean;
  /** More than 200 KB of added text: the rest was not screened. */
  scanTruncated: boolean;
  /** Whether the file's ctime fell in an agent-activity window, when that was evaluated. */
  inWindow: boolean | null;
  /** The agent write behind the deciding rule (H4, H5, N3, N4), for its message. */
  agent: Extract<Attribution, { kind: "agent" }> | null;
  /** The held item's id: the persisted one, or under TAMPER the one it would have. */
  heldId: string | null;
  /** The entry to persist: advanced, held, or under TAMPER the baseline unchanged (null when there is none). */
  next: StoreEntry | null;
};

export type ListingItem = { kind: "hook" | "mcp"; name: string; target: string };
/** §5.5: the hooks and MCP servers a newly seen project defines. */
export type ProjectListing = { hooks: number; servers: number; items: ListingItem[] };

export type StoreOutcome = {
  kind: StoreKind;
  id: StoreId;
  firstRun: boolean;
  tamper: TamperReason | null;
  /** The document to commit, or null when nothing may be written (TAMPER). */
  next: UnsignedStoreDoc | null;
  /** `next` differs from the baseline. */
  dirty: boolean;
  /** Keys whose derived fields a version bump recomputed. */
  recomputed: string[];
};

export type ClassifyResult = {
  /** Every entry that changed, was held, or (under TAMPER) is listed, in store and enumeration order. */
  items: EntryResult[];
  stores: { global: StoreOutcome; project: StoreOutcome; memory: StoreOutcome | null };
  log: LogEntry[];
  /** The global store's calibration flag after this run. */
  memoryWritesObserved: boolean;
  listing: ProjectListing | null;
  machineFirstRun: boolean;
  tamper: { store: StoreId; reason: TamperReason }[];
  /** `expired()` stopped classification: the items are partial and nothing may be advanced. */
  incomplete: boolean;
  /**
   * Files whose added text the run could not screen (its budget, or
   * `stopScreening`); a held file at the version it was held for reuses its
   * recorded verdicts instead. Nothing unscreened is persisted: a first-run file
   * is recorded `unhashed` (no content in the baseline yet) and scanned next run;
   * a changed file keeps its baseline, and any held item stays as it was, until
   * a later run screens it. One that a rule needing no detector makes HOLD or
   * SUSPECT, or that was held, is still reported (`scanTruncated`), not persisted. They make the check
   * incomplete ("N changed files not screened"), but what was classified may be
   * persisted.
   */
  deferred: { store: StoreId; key: string }[];
};

// ── Constants ───────────────────────────────────────────────────────────────

/**
 * Characters screened per run, across files. The detectors cost about 2-3 s per
 * MiB, so a run also stops screening at `stopScreening` (the SessionStart
 * deadline drawing near); the files past either are screened by later runs
 * instead of every run timing out on the same work.
 */
const RUN_SCAN_CAP_CHARS = 2 * 1024 * 1024;
/** Unit ids a held item records verdicts for at most; past it the file is screened again each run. */
const MAX_SCREENED_UNITS = 4096;
/** Tiers by how much attention they need. */
const TIER_RANK: Readonly<Record<Tier, number>> = { SILENT: 0, NOTICE: 1, HOLD: 2, SUSPECT: 3 };
/** Room between stores' places in the result order (more than any store's entries). */
const PLACE_STRIDE = 1e9;
const EPOCH = new Date(0).toISOString();
const NO_UNITS: FileUnits = { units: [], ids: [], cat: {}, nexusHooks: [], shaOnly: false };
const SHA_ONLY: FileUnits = { units: [], ids: [], cat: {}, nexusHooks: [], shaOnly: true };
const UNKNOWN: Attribution = { kind: "unknown" };
const JSON_KINDS = new Set(["settings-json", "mcp-json", "json"]);
const MD_KINDS = new Set(["md", "md-frontmatter", "md-memory"]);
/** Roles found by following references, not by fixed patterns: absence means "no longer referenced". */
const DERIVED_ROLES = new Set<WatchedRole>(["hook-script", "import", "external-import", "ledger-learned"]);
const LISTING_ROLES = new Set<WatchedRole>(["project-settings", "local-settings", "project-mcp", "claude-json-project"]);

const underKey = (k: string, dir: string) => k === dir || k.startsWith(dir.endsWith("/") ? dir : `${dir}/`);

/**
 * Is `key` one enumeration finds every run whatever the session's cwd? Then a
 * path missing from the baseline was created since, and one missing from the
 * snapshot was deleted. Otherwise (levels below R, X = cwd, derived paths, a
 * global file of another Claude config dir than this run's U) it is a new
 * candidate, or simply not looked at this run.
 */
export function stableKey(
  kind: StoreKind, role: WatchedRole, key: string, snapshot: Pick<Snapshot, "project" | "globalScope">, platform: NodeJS.Platform,
): boolean {
  if (DERIVED_ROLES.has(role)) return false;
  if (kind === "global") return inGlobalScope(key, snapshot.globalScope);
  if (kind !== "project") return true;
  const root = storeKey(snapshot.project.root ?? "", platform);
  const up = (k: string) => k.slice(0, Math.max(0, k.lastIndexOf("/"))) || "/";
  switch (role) {
    case "ancestor-claude-md":
    case "ancestor-local-md":
    case "ancestor-agents-md": {
      let dir = up(key);
      if (dir.endsWith("/.claude")) dir = up(dir);
      return underKey(root, dir); // R itself or one of its ancestors
    }
    case "project-settings":
    case "local-settings":
      return up(up(key)) === root;
    case "project-mcp":
      return up(key) === root;
    case "claude-json-project":
      return true;
    default:
      return underKey(key, `${root === "/" ? "" : root}/.claude`);
  }
}

/**
 * Is a global-store key under this run's U or M, or one of its app-state files?
 * The global store is shared by every Claude config dir (each CLAUDE_CONFIG_DIR
 * a session or the CLI resolved), so the rest belong to another one.
 */
function inGlobalScope(key: string, scope: Snapshot["globalScope"]): boolean {
  return scope.files.includes(key) || scope.dirs.some((d) => underKey(key, d));
}

/** Instruction files Claude Code reads into every session at launch. */
const LAUNCH_INSTRUCTIONS = new Set<WatchedRole>([
  "managed-claude-md", "user-claude-md", "user-rules", "ancestor-claude-md", "ancestor-local-md", "ancestor-agents-md", "project-rules",
]);

const RULE_REASONS: Partial<Record<ClassifyRule, string>> = {
  H1: "changed while a Claude session was running, not through Claude's file tools",
  H2: "changes what Claude Code runs (hooks, MCP servers, plugins, permissions or settings), not through an edit you approved",
  H3: "the script changed with no recorded edit",
  H4: "written by Claude without a confirmation prompt after it read content Nexus flagged",
  H5: "written by Claude after reading web or MCP content, adding hosts, URLs or commands no reviewed file has",
};

// ── Small helpers ───────────────────────────────────────────────────────────

const isJsonRole = (role: WatchedRole) => JSON_KINDS.has(ROLE_UNITS[role]);
const isMarkdownRole = (role: WatchedRole) => MD_KINDS.has(ROLE_UNITS[role]);
const sha8 = (sha: string | null) => (sha ? sha.slice(0, 8) : undefined);
const present = (state: string) => state === "file" || state === "oversize";
const parseTime = (iso: string) => {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : 0;
};

function missingEntry(path: string, role: WatchedRole, acceptedAt: string): StoreEntry {
  return {
    path, role, state: "missing", sha256: null, size: null, stat: null, link: null, units: [], cat: {}, tok: [],
    nexusHooks: [], history: [], acceptedAt, acceptedBy: "auto", held: null,
  };
}

function attributionOf(r: LedgerEntry): Attribution {
  if (r.kind === "nexus") return { kind: "nexus", file: r.file, action: r.action };
  return {
    kind: "agent", file: r.file, tool: r.tool, sid: r.sid, mode: r.mode,
    prompted: r.decision === "ask", tainted: r.level === "tainted", exposed: r.level !== "clean", novel: r.novel,
  };
}

const attributionKey = (a: Attribution) => (a.kind === "agent" ? `agent:${a.file}` : a.kind);
/** Nexus itself, or an agent write the user approved in a prompt. */
const byUser = (a: Attribution) => a.kind === "nexus" || (a.kind === "agent" && a.prompted);
type AgentAttribution = Extract<Attribution, { kind: "agent" }>;

/** The file's text (BOM kept: units and tokens handle it). */
const textOf = (cur: SnapshotEntry) => (cur.content ? cur.content.toString("utf-8") : null);

function dedupeTokens(tokens: Iterable<ActionableToken>): ActionableToken[] {
  const seen = new Set<string>();
  const out: ActionableToken[] = [];
  for (const t of tokens) {
    const k = t.value.toLowerCase();
    if (!seen.has(k)) {
      seen.add(k);
      out.push(t);
    }
  }
  return out;
}

/** The target text of a hook or MCP-server unit (its command line, URL or prompt). */
function unitTarget(u: Unit): string {
  if (u.command !== undefined) return u.command;
  if (u.kind === "hook") {
    const at = u.text.indexOf(" hook: ");
    return at >= 0 ? u.text.slice(at + 7) : u.text;
  }
  if (u.kind === "mcp-server" && u.name !== undefined) return u.text.slice(`MCP server ${u.name}: `.length);
  return u.text;
}

function hunkUnit(u: Unit): HunkUnit {
  return {
    kind: u.kind,
    ...(u.name !== undefined ? { name: u.name } : {}),
    target: unitTarget(u),
    ...(u.desc !== undefined ? { desc: u.desc } : {}),
  };
}

function sameStat(a: StoreEntry["stat"], b: SnapshotEntry["stat"]): boolean {
  if (a === b) return true;
  return !!a && !!b && a.length === b.length && a.every((v, i) => v === b[i]);
}

/** `acceptedBy` for an advance: whoever wrote most of the changed units (unknown → `auto`). */
function dominant(attrs: readonly Attribution[]): AcceptedBy {
  let agent = 0;
  let nexus = 0;
  let unknown = 0;
  for (const a of attrs) {
    if (a.kind === "agent") agent++;
    else if (a.kind === "nexus") nexus++;
    else unknown++;
  }
  if (nexus > agent && nexus > unknown) return "nexus";
  if (agent > nexus && agent > unknown) return "agent";
  return "auto";
}

/**
 * §5.1 steps 5-6. A unit belongs to the earliest record listing it (as added,
 * or as removed); the rest are unknown, with two narrowed fallbacks:
 * - the expectedSha fast path (the file is exactly what the latest write left)
 *   gives unlisted units to that write only when its record is `approx`. An
 *   exact record lists every unit its write changed, so an unlisted one was
 *   there before it — written by something nothing recorded, which the user's
 *   prompt for this write never showed;
 * - a removed unit goes to the latest whole-file Write only while the file is
 *   still exactly what that Write left (a later out-of-band removal, or a
 *   deletion, is not the Write's).
 */
function attribute(records: readonly LedgerEntry[], added: readonly string[], removed: readonly string[], nowSha: string | null) {
  const wantAdded = new Set(added);
  const wantRemoved = new Set(removed);
  const firstAdding = new Map<string, LedgerEntry>();
  const firstRemoving = new Map<string, LedgerEntry>();
  let latestWrite: Extract<LedgerEntry, { kind: "write" }> | undefined;
  let latestWholeWrite: Extract<LedgerEntry, { kind: "write" }> | undefined;
  for (const r of records) {
    if (r.kind === "write") {
      latestWrite = r;
      if (r.tool === "Write") latestWholeWrite = r;
    }
    for (const u of r.added) if (wantAdded.has(u) && !firstAdding.has(u)) firstAdding.set(u, r);
    for (const u of r.removed) if (wantRemoved.has(u) && !firstRemoving.has(u)) firstRemoving.set(u, r);
  }
  const isNow = (r: Extract<LedgerEntry, { kind: "write" }> | undefined) => r !== undefined && nowSha !== null && r.expectedSha === nowSha;
  const fast = isNow(latestWrite) && latestWrite!.approx ? latestWrite : undefined;
  const whole = isNow(latestWholeWrite) ? latestWholeWrite : undefined;
  const memo = new Map<LedgerEntry, Attribution>();
  const of = (r: LedgerEntry | undefined): Attribution => {
    if (!r) return UNKNOWN;
    let a = memo.get(r);
    if (!a) memo.set(r, (a = attributionOf(r)));
    return a;
  };
  const addedAttr = new Map(added.map((u) => [u, of(firstAdding.get(u) ?? fast)]));
  const removedAttr = new Map(removed.map((u) => [u, of(firstRemoving.get(u) ?? fast ?? whole)]));
  return { addedAttr, removedAttr };
}

/**
 * §5.2 hunks: maximal runs of added line units (in file order) with one
 * attribution key — blank lines have no unit, so they do not end a run — or
 * one hunk per added JSON unit.
 */
function buildHunks(fu: FileUnits, added: ReadonlySet<string>, attributionFor: (u: string) => Attribution, json: boolean): Hunk[] {
  const hunks: Hunk[] = [];
  let open: Hunk | null = null;
  for (const u of fu.units) {
    if (!added.has(u.id)) {
      open = null;
      continue;
    }
    const a = attributionFor(u.id);
    if (json) {
      hunks.push({ attribution: a, line: null, lines: [u.text], units: [u.id], verdict: null, unit: hunkUnit(u) });
    } else if (open && attributionKey(open.attribution) === attributionKey(a)) {
      open.lines.push(u.text);
      open.units.push(u.id);
    } else {
      open = { attribution: a, line: u.line ?? null, lines: [u.text], units: [u.id], verdict: null };
      hunks.push(open);
    }
  }
  return hunks;
}

/** Pieces (hunks, paragraphs, commands) screened one by one at most; more are screened in batches. */
const MAX_SEPARATE_SCREENS = 64;
/** Characters per batch once pieces are batched. */
const BATCH_CHARS = 8192;

/** Screens one piece (`index`) or a batch of them (`index` null). */
type Screen = (text: string, index: number | null) => Verdict | null;
/** `chars`: the characters handed to the detectors, which is what screening costs. */
type Screened = { verdicts: (Verdict | null)[]; truncated: boolean; stopped: boolean; chars: number };

/**
 * Screen `pieces` in order, at most SCAN_CAP_CHARS (§5.2's 200 KB per file) in
 * all. Up to MAX_SEPARATE_SCREENS pieces are screened one by one. More — a
 * planted file of thousands of one-line changes would cost a detector call each,
 * past the hook's timeout — are joined into batches of about BATCH_CHARS; a
 * batch with a `wanted` verdict is localised piece by piece when it holds at most
 * MAX_SEPARATE_SCREENS pieces, and otherwise (or when no piece is flagged alone)
 * every piece in it gets the batch's verdict. `stop()` is asked before each call.
 */
function screenPieces(pieces: readonly string[], screen: Screen, stop: () => boolean, wanted: (v: Verdict) => boolean = () => true): Screened {
  const verdicts: (Verdict | null)[] = pieces.map(() => null);
  let budget = SCAN_CAP_CHARS;
  let truncated = false;
  let chars = 0;
  /** The text to screen within the budget, or null once it is spent. */
  const take = (text: string): string | null => {
    if (budget <= 0) {
      truncated = true;
      return null;
    }
    const taken = text.length > budget ? text.slice(0, budget) : text;
    if (taken.length < text.length) truncated = true;
    budget -= text.length;
    return taken;
  };
  const run = (text: string, index: number | null) => {
    chars += text.length;
    return screen(text, index);
  };
  if (pieces.length <= MAX_SEPARATE_SCREENS) {
    for (let i = 0; i < pieces.length; i++) {
      if (stop()) return { verdicts, truncated, stopped: true, chars };
      const text = take(pieces[i]);
      if (text === null) break;
      verdicts[i] = run(text, i);
    }
    return { verdicts, truncated, stopped: false, chars };
  }
  for (let i = 0; i < pieces.length;) {
    let j = i + 1;
    let size = pieces[i].length;
    while (j < pieces.length && size + 1 + pieces[j].length <= BATCH_CHARS) size += 1 + pieces[j++].length;
    if (stop()) return { verdicts, truncated, stopped: true, chars };
    const text = take(pieces.slice(i, j).join("\n"));
    if (text === null) break;
    const v = run(text, null);
    if (v && wanted(v)) {
      let alone = false;
      if (j - i <= MAX_SEPARATE_SCREENS) {
        for (let k = i; k < j; k++) {
          if (stop()) return { verdicts, truncated, stopped: true, chars };
          verdicts[k] = run(pieces[k], k);
          if (verdicts[k] && wanted(verdicts[k]!)) alone = true;
        }
      }
      if (!alone) for (let k = i; k < j; k++) verdicts[k] = v;
    }
    i = j;
  }
  return { verdicts, truncated, stopped: false, chars };
}

/**
 * Set each hunk's verdict (§5.2): Markdown hunks with `markdownVerdict`, text
 * hook scripts with `scriptVerdict`, command-bearing JSON units with
 * `commandVerdict`, through `screenPieces`.
 */
function screenHunks(hunks: readonly Hunk[], fu: FileUnits, role: WatchedRole, stop: () => boolean): Omit<Screened, "verdicts"> {
  if (fu.shaOnly || hunks.length === 0) return { truncated: false, stopped: false, chars: 0 };
  if (isJsonRole(role)) {
    const byId = new Map(fu.units.map((u) => [u.id, u]));
    const withCommand: [Unit & { command: string }, Hunk][] = [];
    for (const h of hunks) {
      const u = byId.get(h.units[0]);
      if (u?.command !== undefined) withCommand.push([u as Unit & { command: string }, h]);
    }
    const res = screenPieces(withCommand.map(([u]) => u.command),
      (text, i) => commandVerdict(i === null ? "command" : commandNoun(withCommand[i][0]), text), stop);
    res.verdicts.forEach((v, i) => { withCommand[i][1].verdict = v; });
    return { truncated: res.truncated, stopped: res.stopped, chars: res.chars };
  }
  const res = screenPieces(hunks.map((h) => h.lines.join("\n")), isMarkdownRole(role) ? markdownVerdict : scriptVerdict, stop);
  res.verdicts.forEach((v, i) => { hunks[i].verdict = v; });
  return { truncated: res.truncated, stopped: res.stopped, chars: res.chars };
}

/** Would `screenHunks` hand any of `hunks` to a detector? */
function screenable(hunks: readonly Hunk[], fu: FileUnits, role: WatchedRole): boolean {
  if (fu.shaOnly || hunks.length === 0) return false;
  if (!isJsonRole(role)) return true;
  const commands = new Set(fu.units.filter((u) => u.command !== undefined).map((u) => u.id));
  return hunks.some((h) => commands.has(h.units[0]));
}

/**
 * The order the run's screening budget is spent in: code and commands first
 * (exec-class files, settings and MCP config), then the instruction files every
 * session loads at launch, then memory, then imports and the files read on
 * demand (agents, commands, skills, nested instructions).
 */
function screenRank(role: WatchedRole): number {
  if (ROLE_CLASS[role] === "exec" || isJsonRole(role)) return 0;
  if (LAUNCH_INSTRUCTIONS.has(role)) return 1;
  if (ROLE_CLASS[role] === "memory") return 2;
  return 3;
}

/** The verdicts of `hunks` as a held item records them (null past MAX_SCREENED_UNITS). */
function screenedOf(hunks: readonly Hunk[]): HeldVerdict[] | null {
  const out: HeldVerdict[] = [];
  let units = 0;
  for (const h of hunks) {
    if (!h.verdict) continue;
    units += h.units.length;
    if (units > MAX_SCREENED_UNITS) return null;
    out.push({ units: [...h.units], reason: h.verdict.reason, strong: h.verdict.strong });
  }
  return out;
}

/** Give each hunk the recorded verdict of the first of its units that has one. */
function applyScreened(hunks: readonly Hunk[], screened: readonly HeldVerdict[]): void {
  const byUnit = new Map<string, Verdict>();
  for (const v of screened) for (const u of v.units) if (!byUnit.has(u)) byUnit.set(u, { reason: v.reason, strong: v.strong });
  for (const h of hunks) {
    for (const u of h.units) {
      const v = byUnit.get(u);
      if (v) {
        h.verdict = v;
        break;
      }
    }
  }
}

/** Runs of line units on consecutive lines (a blank line ends one). */
function paragraphs(units: readonly Unit[]): Unit[][] {
  const out: Unit[][] = [];
  let run: Unit[] = [];
  let last = -2;
  for (const u of units) {
    const line = u.line ?? last + 1;
    if (run.length && line !== last + 1) {
      out.push(run);
      run = [];
    }
    run.push(u);
    last = line;
  }
  if (run.length) out.push(run);
  return out;
}

/** The actionable tokens of JSON units: each unit's text, and its command read as a command line. */
function unitTokens(units: readonly Unit[], tokenOpts: TokenOptions): ActionableToken[] {
  const out: ActionableToken[] = [];
  for (const u of units) {
    out.push(...extractTokens(u.text, tokenOpts));
    if (u.command !== undefined) out.push(...extractTokens(u.command, { ...tokenOpts, commands: true }));
  }
  return dedupeTokens(out);
}

/**
 * The accepted token hashes of a file version (an entry's `tok`): the actionable
 * tokens of its text, or for JSON of its units. The units in `unreviewed` (a
 * first-run flag's) are left out: until the user accepts the file, their URLs,
 * hosts and commands stay novel, so they become the held item's indicators and
 * the memory gate does not treat them as reviewed.
 */
export function versionTokens(cur: SnapshotEntry, fu: FileUnits, hasher: UnitHasher, tokenOpts: TokenOptions, unreviewed?: ReadonlySet<string>): string[] {
  if (cur.state !== "file" || fu.shaOnly) return [];
  const units = unreviewed?.size ? fu.units.filter((u) => !unreviewed.has(u.id)) : null;
  const tokens = isJsonRole(cur.role)
    ? unitTokens(units ?? fu.units, tokenOpts)
    : extractTokens(units ? units.map((u) => u.text).join("\n") : textOf(cur) ?? "", tokenOpts);
  return tokenHashes(tokens, hasher);
}

/** `history` with `sha` appended (moved to the end if already there), at most HISTORY_MAX. */
export function pushHistory(history: StoreEntry["history"], sha: string, at: string): StoreEntry["history"] {
  const kept = history.filter((h) => h.sha256 !== sha);
  kept.push({ sha256: sha, at });
  return kept.slice(-HISTORY_MAX);
}

// ── Classification ──────────────────────────────────────────────────────────

/** The store being classified: its next entries, built up from the baseline's. */
type Store = {
  kind: StoreKind;
  id: StoreId;
  /** MCP server names accepted in this project's `.mcp.json` baseline (enabling one is benign). */
  acceptedServers: ReadonlySet<string>;
  entries: Record<string, StoreEntry>;
  dirty: boolean;
  /** Units of the files a first run recorded (for the project listing). */
  firstRunUnits?: Map<string, FileUnits>;
};

/** A first-run scan: the units a strong verdict flags, whether a softer one hit, and the reasons (the strong verdicts' first). */
type FirstRunScan = { strong: string[]; soft: boolean; reasons: string[]; truncated: boolean };

/**
 * The first-run flag a baseline carries (§5.5): the flagged units, all in the
 * baseline, and the first-run scan's reasons. A first-run flag is always SUSPECT.
 */
type FirstRunFlag = { units: string[]; reasons: string[] };

/**
 * The verdict every hunk of a first-run flag carries, in its first session and
 * in each one after, so that its frame is byte-identical (§6.4).
 */
const firstRunVerdict = (reasons: readonly string[]): Verdict => ({ reason: reasons[0] ?? "matches an injection pattern", strong: true });

function sameHeld(a: HeldItem, b: HeldItem): boolean {
  const same = (x: readonly string[], y: readonly string[]) => x.length === y.length && x.every((v, i) => v === y[i]);
  const sameScreened = (x: readonly HeldVerdict[] | undefined, y: readonly HeldVerdict[] | undefined) =>
    x === y || (!!x && !!y && x.length === y.length && x.every((v, i) => v.reason === y[i].reason && v.strong === y[i].strong && same(v.units, y[i].units)));
  return a.id === b.id && a.tier === b.tier && a.since === b.since && same(a.reasons, b.reasons) && same(a.flaggedUnits, b.flaggedUnits)
    && sameScreened(a.screened, b.screened);
}

/** What a decided entry reports, before the store bookkeeping. */
type Outcome = {
  tier: Tier;
  rule: ClassifyRule;
  rules: ClassifyRule[];
  reasons: string[];
  change: ChangeKind;
  hunks: Hunk[];
  added: number;
  removed: number;
  firstRun?: boolean;
  descriptions?: string[];
  removedNexusHooks?: string[];
  dangerous?: string[];
  inWindow?: boolean | null;
  agent?: Extract<Attribution, { kind: "agent" }> | null;
  novel?: ActionableToken[];
  scanTruncated?: boolean;
  /** The verdicts screening gave this version's added text, for the held item to record. */
  screened?: HeldVerdict[] | null;
};

/** A store being classified: its baseline, its next entries, and the keys to visit. */
type Prepared = {
  kind: StoreKind;
  snap: StoreSnapshot;
  base: UnsignedStoreDoc;
  store: Store;
  firstRun: boolean;
  bumped: boolean;
  recomputed: string[];
  /** Snapshot keys, then baseline keys the snapshot lacks (enumeration order). */
  keys: string[];
  /** The store's place in the result order. */
  place: number;
};

/** An entry's comparison inputs, shared by the rule checks. */
type Diff = {
  prev: StoreEntry;
  cur: SnapshotEntry;
  fu: FileUnits;
  change: ChangeKind;
  added: string[];
  removed: string[];
  addedAttr: Map<string, Attribution>;
  removedAttr: Map<string, Attribution>;
  /** Records for this path after the entry's acceptedAt, by time. */
  records: LedgerEntry[];
  hunks: Hunk[];
  scanTruncated: boolean;
  /** Not screened (the run's screening was over): the hunks carry no verdicts, and nothing is persisted. */
  unscreened: boolean;
  /** The current file's unit ids. */
  nowSet: ReadonlySet<string>;
};

export function classify(input: ClassifyInput): ClassifyResult {
  return new Classifier(input).run();
}

class Classifier {
  private readonly nowIso: string;
  private readonly hasher: UnitHasher | null;
  private readonly tokenOpts: TokenOptions;
  private readonly ledgerByPath = new Map<string, LedgerEntry[]>();
  /** The one windows read of this run, the `since` it was read from, and whether it was partial. */
  private windowRead: { since: number; windows: readonly ActivityWindow[]; partial: boolean } | null = null;
  private pairs: [StoreKind, StoreInput, StoreSnapshot][] = [];
  private readonly acceptedTok = new Set<string>();
  /**
   * Results, log lines and deferred files, each with its place in store and
   * enumeration order: entries are classified in screening priority order, and
   * reported in the order they were enumerated.
   */
  private readonly itemsAt: [number, EntryResult][] = [];
  private readonly logAt: [number, LogEntry][] = [];
  private readonly deferredAt: [number, ClassifyResult["deferred"][number]][] = [];
  /** The place of what is being classified now. */
  private at = 0;
  private calibrated = false;
  private listing: ProjectListing | null = null;
  /** Characters the detectors may still screen this run (a held file at the version it was held for reuses its verdicts). */
  private scanLeft: number;
  private screeningOver = false;
  private stopped = false;
  /** Has the deadline passed? Sticky once it has. */
  private readonly stop = (): boolean => this.stopped || (this.stopped = this.input.expired?.() === true);
  /** Is screening over for this run: its budget spent, or `stopScreening` said so? Sticky. */
  private readonly screeningDone = (): boolean =>
    this.screeningOver || (this.screeningOver = this.scanLeft <= 0 || this.input.stopScreening?.() === true);

  private emitItem(item: EntryResult): void {
    this.itemsAt.push([this.at, item]);
  }

  private emitLog(entry: LogEntry): void {
    this.logAt.push([this.at, entry]);
  }

  private defer(store: StoreId, key: string): void {
    this.deferredAt.push([this.at, { store, key }]);
  }

  constructor(private readonly input: ClassifyInput) {
    this.nowIso = input.now.toISOString();
    this.scanLeft = input.scanBudget ?? RUN_SCAN_CAP_CHARS;
    this.hasher = input.hashers.unit;
    this.tokenOpts = { root: input.snapshot.project.root, home: input.home, platform: input.platform };
    const sorted = [...input.ledger].sort((a, b) => parseTime(a.t) - parseTime(b.t) || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
    for (const r of sorted) {
      const list = this.ledgerByPath.get(r.path);
      if (list) list.push(r);
      else this.ledgerByPath.set(r.path, [r]);
    }
  }

  run(): ClassifyResult {
    const { stores, snapshot } = this.input;
    const pairs: [StoreKind, StoreInput, StoreSnapshot][] = [
      ["global", stores.global, snapshot.global],
      ["project", stores.project, snapshot.project],
    ];
    if (stores.memory && snapshot.memory) pairs.push(["memory", stores.memory, snapshot.memory]);
    this.pairs = pairs;

    // The union of accepted token sets (an unverified store's lists are not trusted).
    for (const [, s] of pairs) {
      if (s.tamper || !s.doc) continue;
      for (const e of Object.values(s.doc.entries)) for (const t of e.tok) this.acceptedTok.add(t);
    }
    // Calibration (§5.1 step 9): a valid write record for a memory-class path.
    const globalDoc = stores.global.doc;
    this.calibrated = (!stores.global.tamper && globalDoc?.memoryWritesObserved === true) || this.memoryWriteSeen(pairs);

    if (!this.hasher && pairs.some(([, s]) => !s.tamper)) {
      throw new TypeError("classify needs the unit hasher for every store that is not under TAMPER");
    }

    const outcomes: Partial<Record<StoreKind, StoreOutcome>> = {};
    const tamper: ClassifyResult["tamper"] = [];
    const prepared: Prepared[] = [];
    pairs.forEach(([kind, s, snap], i) => {
      this.at = i * PLACE_STRIDE;
      if (s.tamper) {
        tamper.push({ store: snap.id, reason: s.tamper });
        outcomes[kind] = this.tamperStore(kind, s, snap);
      } else {
        prepared.push(this.prepare(kind, s, snap, this.at));
      }
    });
    // Every store's entries, in screening priority order (enumeration order within a rank).
    const work = prepared.flatMap((ps) => ps.keys.map((key, i) => ({
      ps, key, place: ps.place + 1 + i, rank: screenRank((ps.snap.entries[key] ?? ps.base.entries[key]).role),
    })));
    work.sort((a, b) => a.rank - b.rank || a.place - b.place);
    for (const w of work) {
      if (this.stop()) break; // the rest keep their baseline; the caller persists nothing
      this.at = w.place;
      this.entry(w.ps, w.key);
    }
    for (const ps of prepared) {
      this.at = ps.place + PLACE_STRIDE - 1;
      outcomes[ps.kind] = this.finish(ps);
    }
    const inOrder = <T>(list: [number, T][]): T[] => [...list].sort((a, b) => a[0] - b[0]).map(([, v]) => v);
    const memoryWritesObserved = this.calibrated;
    const g = outcomes.global!;
    if (g.next && g.next.memoryWritesObserved !== memoryWritesObserved) {
      g.next.memoryWritesObserved = memoryWritesObserved;
      g.dirty = true;
    }
    return {
      items: inOrder(this.itemsAt),
      stores: { global: g, project: outcomes.project!, memory: outcomes.memory ?? null },
      log: inOrder(this.logAt),
      memoryWritesObserved,
      listing: this.listing,
      machineFirstRun: this.input.machineFirstRun === true,
      tamper,
      incomplete: this.stopped,
      deferred: inOrder(this.deferredAt),
    };
  }

  private memoryWriteSeen(pairs: [StoreKind, StoreInput, StoreSnapshot][]): boolean {
    const memoryKeys = new Set<string>();
    for (const [, s, snap] of pairs) {
      for (const e of Object.values(snap.entries)) if (ROLE_CLASS[e.role] === "memory") memoryKeys.add(e.key);
      for (const [key, e] of Object.entries(s.doc?.entries ?? {})) if (ROLE_CLASS[e.role] === "memory") memoryKeys.add(key);
    }
    return this.input.ledger.some((r) => r.kind === "write" && memoryKeys.has(r.path));
  }

  /** Records for `key` written after `acceptedAt`, by time. */
  private recordsFor(key: string, acceptedAt: string): LedgerEntry[] {
    const since = parseTime(acceptedAt);
    return (this.ledgerByPath.get(key) ?? []).filter((r) => parseTime(r.t) > since);
  }

  /**
   * Activity windows of the session logs modified since `sinceMs`. The first
   * call reads them once from the earliest `since` any entry of this run can
   * ask for (`windowsFloor`); later calls reuse that superset. More logs only
   * add windows, and windows only escalate, so every entry is judged at least as
   * strictly as with its own `since` — at the cost of one log scan, not one per
   * changed file.
   */
  private windowsSince(sinceMs: number): { windows: readonly ActivityWindow[]; partial: boolean } {
    if (!this.windowRead || this.windowRead.since > sinceMs) {
      const since = Math.min(sinceMs, this.windowsFloor());
      const read = this.input.windows(since);
      this.windowRead = Array.isArray(read)
        ? { since, windows: read as readonly ActivityWindow[], partial: false }
        : { since, ...(read as { windows: readonly ActivityWindow[]; partial: boolean }) };
    }
    return this.windowRead;
  }

  /**
   * The earliest `acceptedAt` among the entries of trusted stores that `compare`
   * sees changed (0 for a created file, compared from EPOCH).
   */
  private windowsFloor(): number {
    let floor = Infinity;
    for (const [kind, s, snap] of this.pairs) {
      if (s.tamper || !s.doc) continue;
      const bumped = !isCurrentVersion(s.doc);
      for (const cur of Object.values(snap.entries)) {
        const prev = s.doc.entries[cur.key];
        if (!prev) {
          if (!bumped && this.stable(kind, cur.role, cur.key)) return 0;
        } else if (prev.state !== cur.state || prev.sha256 !== cur.sha256 || (prev.link ?? null) !== (cur.link ?? null)) {
          floor = Math.min(floor, parseTime(prev.acceptedAt));
        }
      }
    }
    return floor;
  }

  private heldId(key: string, cur: { sha256: string | null; state: string }): string {
    return `h_${this.input.hashers.nonce(`${key}\0${cur.sha256 ?? cur.state}`).slice(0, 12)}`;
  }

  // ── A store with a trusted baseline (or none: first run) ──

  /** A store's baseline (a new document on its first run, upgraded after a version bump) and the keys to visit. */
  private prepare(kind: StoreKind, s: StoreInput, snap: StoreSnapshot, place: number): Prepared {
    let base: UnsignedStoreDoc;
    let recomputed: string[] = [];
    let bumped = false;
    const firstRun = s.doc === null;
    if (s.doc === null) {
      base = newStoreDoc(kind, snap.id, snap.root, this.input.now);
      if (kind === "project") base.autoMemoryDir = this.input.snapshot.memory?.root ?? null;
    } else {
      const { mac: _mac, ...rest } = s.doc as StoreDoc;
      base = rest;
      if (!isCurrentVersion(base)) {
        bumped = true;
        ({ doc: base, recomputed } = upgradeStore(base, (key) => snap.entries[key]?.sha256, (key, entry) => this.derived(snap.entries[key], entry)));
      }
    }
    const store: Store = {
      kind, id: snap.id,
      acceptedServers: kind === "project" ? this.acceptedServers(snap, base) : new Set(),
      entries: { ...base.entries },
      dirty: firstRun || bumped,
    };
    const keys = [...Object.keys(snap.entries), ...Object.keys(base.entries).filter((k) => !(k in snap.entries))];
    return { kind, snap, base, store, firstRun, bumped, recomputed, keys, place };
  }

  /** One key of a prepared store: a first-run entry, or a comparison with its baseline. */
  private entry(ps: Prepared, key: string): void {
    const { kind, base, store, firstRun, bumped } = ps;
    const prev = base.entries[key];
    let cur = ps.snap.entries[key];
    if (!cur) {
      // Not found this run: a deleted file only where enumeration always looks.
      if (!prev || !present(prev.state) || this.input.snapshot.incomplete || !this.stable(kind, prev.role, key)) return;
      cur = { path: prev.path, key, role: prev.role, state: "missing", sha256: null, size: null, stat: null, link: null, content: null, reused: false };
    }
    if (firstRun || prev?.state === "unhashed" || (!prev && (bumped || !this.stable(kind, cur.role, key)))) {
      this.firstRunEntry(store, cur);
    } else {
      this.compare(store, prev ?? missingEntry(cur.path, cur.role, EPOCH), cur);
    }
  }

  /** The store's outcome once its entries are classified. */
  private finish(ps: Prepared): StoreOutcome {
    const { kind, snap, base, store, firstRun, recomputed } = ps;
    if (firstRun) {
      this.emitLog({ at: this.nowIso, event: "first-run", store: snap.id, added: Object.keys(store.entries).length });
      if (kind === "project") this.listing = this.projectListing(store);
    }
    const next: UnsignedStoreDoc = { ...base, entries: store.entries };
    if (kind === "project" && this.input.snapshot.memory && next.autoMemoryDir !== this.input.snapshot.memory.root) {
      next.autoMemoryDir = this.input.snapshot.memory.root;
      store.dirty = true;
    }
    // §6.4 F: the capped keys no entry records as unhashed (a file hashed before keeps
    // its baseline), so that the next run reports files over the limits only when they change;
    // another Claude config dir's, not looked at this run, are kept
    const was = base.capped ?? [];
    const capped = this.input.snapshot.unhashed
      .filter((u) => u.store === snap.id && store.entries[u.key]?.state !== "unhashed")
      .map((u) => u.key);
    if (kind === "global") capped.push(...was.filter((k) => !inGlobalScope(k, this.input.snapshot.globalScope)));
    capped.sort();
    if (capped.length !== was.length || capped.some((k, i) => k !== was[i])) {
      if (capped.length) next.capped = capped;
      else delete next.capped;
      store.dirty = true;
    }
    return { kind, id: snap.id, firstRun, tamper: null, next, dirty: store.dirty, recomputed };
  }

  private stable(kind: StoreKind, role: WatchedRole, key: string): boolean {
    return stableKey(kind, role, key, this.input.snapshot, this.input.platform);
  }

  /** Units of the current file (none for one watched by sha only); `null` when its text was not read. */
  private unitsNow(store: Pick<Store, "acceptedServers">, cur: SnapshotEntry): FileUnits | null {
    if (cur.state !== "file") return NO_UNITS;
    if (cur.shaOnly) return SHA_ONLY;
    if (!cur.content) return null;
    return unitsOf(cur.role, cur.content, { hasher: this.hasher!, acceptedMcpjsonServers: store.acceptedServers });
  }

  /** Names of the MCP servers this project's accepted `.mcp.json` files define (unchanged since accepted). */
  private acceptedServers(snap: StoreSnapshot, base: UnsignedStoreDoc): Set<string> {
    const names = new Set<string>();
    for (const cur of Object.values(snap.entries)) {
      if (cur.role !== "project-mcp" || cur.state !== "file" || !cur.content) continue;
      const prev = base.entries[cur.key];
      if (!prev) continue;
      const fu = unitsOf(cur.role, cur.content, { hasher: this.hasher! });
      for (const n of acceptedMcpServerNames(fu, new Set(prev.units))) names.add(n);
    }
    return names;
  }

  /** Version bump: the derived fields of an unchanged file, or null when its text was not read. */
  private derived(cur: SnapshotEntry | undefined, entry: StoreEntry): { units: string[]; cat: StoreEntry["cat"]; tok: string[]; nexusHooks: string[] } | null {
    if (!cur || cur.state !== "file" || (!cur.content && !cur.shaOnly)) return null;
    const fu = cur.content ? unitsOf(cur.role, cur.content, { hasher: this.hasher! }) : SHA_ONLY;
    const flagged = entry.acceptedBy === "first-run" && entry.held?.flaggedUnits.length ? new Set(entry.held.flaggedUnits) : undefined;
    return { units: fu.ids, cat: fu.cat, tok: this.tokOf(cur, fu, flagged), nexusHooks: fu.nexusHooks };
  }

  /** The accepted token hashes of a file version (`versionTokens`). */
  private tokOf(cur: SnapshotEntry, fu: FileUnits, unreviewed?: ReadonlySet<string>): string[] {
    return versionTokens(cur, fu, this.hasher!, this.tokenOpts, unreviewed);
  }

  /** Record `next` for `key`; the store needs writing when it is not the very object already there. */
  private setEntry(store: Store, key: string, next: StoreEntry): void {
    if (store.entries[key] !== next) store.dirty = true;
    store.entries[key] = next;
  }

  // ── First run (§5.5) ──

  private firstRunEntry(store: Store, cur: SnapshotEntry): void {
    const key = cur.key;
    const blank = (): StoreEntry => ({
      ...missingEntry(cur.path, cur.role, this.nowIso),
      state: cur.state, size: cur.size, stat: cur.stat, link: cur.link, acceptedBy: "first-run",
    });
    if (cur.state !== "file" || (!cur.content && !cur.shaOnly)) {
      // missing, oversize or unhashed (an unread file is re-read next run: recorded unhashed, no units)
      const entry = blank();
      if (cur.state === "file") entry.state = "unhashed";
      this.setEntry(store, key, entry);
      return;
    }
    const fu = this.unitsNow(store, cur)!;
    const scan = this.firstRunScan(cur, fu);
    if (!scan) return; // past the deadline
    store.firstRunUnits ??= new Map();
    store.firstRunUnits.set(key, fu);
    if (scan === "deferred") {
      // not screened this run: recorded unhashed (no content in the baseline yet), so the next run scans it
      this.setEntry(store, key, { ...blank(), state: "unhashed" });
      this.defer(store.id, key);
      return;
    }
    const cls = ROLE_CLASS[cur.role];
    let tier: Tier = "SILENT";
    let rule: ClassifyRule = "Z";
    if (scan.strong.length > 0) {
      tier = "SUSPECT";
      rule = "first-run-block";
    } else if (scan.soft && cls !== "import-silent") {
      tier = "NOTICE";
      rule = "first-run-hit";
    }
    const reasons = tier === "SILENT" ? [] : scan.reasons;
    const flagged = new Set(scan.strong);
    const held: HeldItem | null = tier === "SUSPECT"
      ? { id: this.heldId(key, cur), tier: "SUSPECT", since: this.nowIso, reasons, flaggedUnits: scan.strong }
      : null;
    const next: StoreEntry = {
      path: cur.path, role: cur.role, state: cur.state, sha256: cur.sha256, size: cur.size, stat: cur.stat, link: cur.link,
      units: fu.ids, cat: fu.cat, tok: this.tokOf(cur, fu, flagged), nexusHooks: fu.nexusHooks, history: [],
      acceptedAt: this.nowIso, acceptedBy: "first-run", held,
    };
    this.setEntry(store, key, next);
    if (tier === "SILENT") return;
    this.emitLog({ at: this.nowIso, event: tier === "SUSPECT" ? "suspect" : "notice", store: store.id, path: cur.path, tier, by: "first-run", new: sha8(cur.sha256) });
    const hunks = flagged.size ? this.runsOf(cur.role, fu, flagged, firstRunVerdict(reasons)) : [];
    this.emitItem(this.result(store, cur, {
      tier, rule, rules: [rule], reasons, change: "unchanged", firstRun: true, hunks,
      added: 0, removed: 0, flaggedUnits: scan.strong, next,
      novel: this.novelIn(hunks, fu, isJsonRole(cur.role), next.tok), scanTruncated: scan.truncated,
    }));
  }

  /**
   * The first-run scan of a whole file: Markdown text (first 200 KB) with
   * `classifyMemoryThreat`, text hook scripts with the content capabilities,
   * hook, helper and MCP commands with `inspectCommand`. A strong verdict is
   * localised to the paragraphs (runs of consecutive lines) that are strong on
   * their own, or to every line when none is. The reasons of the strong verdicts
   * come first: the first one is what the item's hunks show. `deferred` when
   * there is text to screen and the run's screening is over (`screeningDone`);
   * null past the deadline.
   */
  private firstRunScan(cur: SnapshotEntry, fu: FileUnits): FirstRunScan | "deferred" | null {
    const scan: FirstRunScan = { strong: [], soft: false, reasons: [], truncated: false };
    if (fu.shaOnly) return scan;
    const strongReasons: string[] = [];
    const otherReasons: string[] = [];
    const done = () => {
      scan.reasons = [...new Set([...strongReasons, ...otherReasons])];
      return scan;
    };
    if (isJsonRole(cur.role)) {
      const commands = fu.units.filter((u): u is Unit & { command: string } => u.command !== undefined);
      if (commands.length && this.screeningDone()) return "deferred";
      const res = screenPieces(commands.map((u) => u.command), (text, i) => commandVerdict(i === null ? "command" : commandNoun(commands[i]), text), this.stop);
      if (res.stopped) return null;
      this.scanLeft -= res.chars;
      scan.truncated = res.truncated;
      res.verdicts.forEach((v, i) => {
        if (!v) return;
        if (v.strong) {
          strongReasons.push(v.reason);
          scan.strong.push(commands[i].id);
        } else {
          otherReasons.push(v.reason);
          scan.soft = true;
        }
      });
      return done();
    }
    const screen = isMarkdownRole(cur.role) ? markdownVerdict : scriptVerdict;
    const full = textOf(cur) ?? "";
    if (full && this.screeningDone()) return "deferred";
    scan.truncated = full.length > SCAN_CAP_CHARS;
    if (this.stop()) return null;
    const text = scan.truncated ? full.slice(0, SCAN_CAP_CHARS) : full;
    this.scanLeft -= text.length;
    const whole = screen(text);
    if (!whole) return scan;
    otherReasons.push(whole.reason);
    if (!whole.strong) {
      scan.soft = true;
      return done();
    }
    // localise the strong verdict: the paragraphs that are strong on their own
    const paras = paragraphs(fu.units);
    const res = screenPieces(paras.map((p) => p.map((u) => u.text).join("\n")), screen, this.stop, (v) => v.strong);
    if (res.stopped) return null;
    this.scanLeft -= res.chars;
    res.verdicts.forEach((v, i) => {
      if (!v?.strong) return;
      strongReasons.push(v.reason);
      for (const u of paras[i]) scan.strong.push(u.id);
    });
    if (scan.strong.length === 0) for (const u of fu.units) scan.strong.push(u.id);
    return done();
  }

  /** Hunks (attribution unknown) of the units in `flagged`, in file order, each with `verdict`. */
  private runsOf(role: WatchedRole, fu: FileUnits, flagged: ReadonlySet<string>, verdict: Verdict): Hunk[] {
    return buildHunks(fu, flagged, () => UNKNOWN, isJsonRole(role)).map((h) => ({ ...h, verdict }));
  }

  private projectListing(store: Store): ProjectListing | null {
    const items: ListingItem[] = [];
    let hooks = 0;
    let servers = 0;
    for (const [key, fu] of store.firstRunUnits ?? []) {
      if (!LISTING_ROLES.has(store.entries[key]?.role)) continue;
      for (const u of fu.units) {
        if (u.kind === "hook" && !(u.command !== undefined && nexusHookCommand(u.command))) {
          hooks++;
          items.push({ kind: "hook", name: u.name ?? "", target: unitTarget(u) });
        } else if (u.kind === "mcp-server") {
          servers++;
          items.push({ kind: "mcp", name: u.name ?? "", target: unitTarget(u) });
        }
      }
    }
    return hooks + servers > 0 ? { hooks, servers, items } : null;
  }

  // ── A changed entry (§5.1-5.4) ──

  private compare(store: Store, prev: StoreEntry, cur: SnapshotEntry): void {
    const key = cur.key;
    if (cur.state === "unhashed") return; // past a cap: the baseline stays as it is
    const changed = prev.state !== cur.state || prev.sha256 !== cur.sha256 || (prev.link ?? null) !== (cur.link ?? null);
    if (!changed) {
      this.unchanged(store, prev, cur);
      return;
    }
    const fu = this.unitsNow(store, cur);
    if (!fu) return; // a changed file whose text was not read: compared next run
    const change: ChangeKind = !present(prev.state) && present(cur.state)
      ? "created"
      : present(prev.state) && !present(cur.state)
        ? "deleted"
        : cur.link !== null && cur.link !== prev.link ? "retargeted" : "modified";

    // 1. History match: the whole file is a previously accepted version.
    if (cur.sha256 !== null && prev.history.some((h) => h.sha256 === cur.sha256)) {
      this.advance(store, prev, cur, fu, "auto", { tier: "SILENT", rule: "Z", rules: ["Z"], reasons: [], change, hunks: [], added: 0, removed: 0 });
      return;
    }

    // 2. Multiset diff.
    const nowSet = new Set(fu.ids);
    const baseSet = new Set(prev.units);
    const added = fu.ids.filter((u) => !baseSet.has(u));
    const removed = prev.units.filter((u) => !nowSet.has(u));
    const cls = ROLE_CLASS[cur.role];

    // 3. Whitespace, reordering or blank lines only (code, and a retargeted link, are compared by sha).
    if (added.length === 0 && removed.length === 0 && cls !== "exec" && change !== "retargeted" && !this.firstRunFlag(prev)?.units.some((u) => nowSet.has(u))) {
      this.advance(store, prev, cur, fu, "auto", { tier: "SILENT", rule: "Z", rules: ["Z"], reasons: [], change, hunks: [], added: 0, removed: 0 });
      return;
    }

    // 4-7. Attribution.
    const records = this.recordsFor(key, prev.acceptedAt);
    const { addedAttr, removedAttr } = attribute(records, added, removed, cur.sha256);
    const json = isJsonRole(cur.role);
    const hunks = buildHunks(fu, new Set(added), (u) => addedAttr.get(u) ?? UNKNOWN, json);
    // A held file still at the version it was held for reuses the verdicts recorded
    // then. Any other change, a held file's included, spends the run's screening
    // budget; once screening is over it goes unscreened (and is not persisted). A
    // held file then keeps its held state as it was, the units it was flagged for
    // with the verdicts recorded for them.
    const reuse = prev.held?.screened && prev.held.id === this.heldId(key, cur) ? prev.held.screened : null;
    let unscreened = false;
    let scanTruncated: boolean;
    if (reuse) {
      applyScreened(hunks, reuse);
      scanTruncated = !json && !fu.shaOnly && hunks.reduce((n, h) => n + h.lines.join("\n").length, 0) > SCAN_CAP_CHARS;
    } else if (screenable(hunks, fu, cur.role) && this.screeningDone()) {
      unscreened = true;
      scanTruncated = true;
      if (prev.held?.screened) applyScreened(hunks, prev.held.screened);
    } else {
      const screened = screenHunks(hunks, fu, cur.role, this.stop);
      if (screened.stopped) return; // past the deadline: left for the next run
      this.scanLeft -= screened.chars;
      scanTruncated = screened.truncated;
    }
    this.decide(store, { prev, cur, fu, change, added, removed, addedAttr, removedAttr, records, hunks, scanTruncated, unscreened, nowSet });
  }

  /**
   * The first-run flag `prev` carries: the units a first-run scan flagged that
   * its baseline holds, with the scan's reasons. While an entry with one is not
   * advanced, `held.flaggedUnits` and `held.reasons` keep exactly these, whatever
   * the current file holds and whatever a later change adds (its units and
   * reasons are derived again each session), so a return to the baseline raises
   * the flag again. A held item a later change raised persists no units, and
   * clears on a revert like any other.
   */
  private firstRunFlag(prev: StoreEntry): FirstRunFlag | null {
    if (prev.acceptedBy !== "first-run" || !prev.held) return null;
    const base = new Set(prev.units);
    const units = prev.held.flaggedUnits.filter((u) => base.has(u));
    return units.length ? { units, reasons: prev.held.reasons } : null;
  }

  /** Same sha, state and link as the baseline: refresh the stat; a held item is re-emitted or cleared. */
  private unchanged(store: Store, prev: StoreEntry, cur: SnapshotEntry): void {
    const refreshed: StoreEntry = (prev.size === cur.size && sameStat(prev.stat, cur.stat)) ? prev : { ...prev, size: cur.size, stat: cur.stat };
    if (!prev.held) {
      this.setEntry(store, cur.key, refreshed);
      return;
    }
    const flag = this.firstRunFlag(prev);
    if (flag) {
      // At its first-run baseline (still, or again after a held change was reverted):
      // the first-run flag, as first shown, until accepted or edited away.
      const held: HeldItem = { id: this.heldId(cur.key, cur), tier: "SUSPECT", since: prev.held.since, reasons: flag.reasons, flaggedUnits: flag.units };
      const next: StoreEntry = refreshed === prev && sameHeld(prev.held, held) ? prev : { ...refreshed, held };
      this.setEntry(store, cur.key, next);
      if (prev.held.id !== held.id || prev.held.tier !== held.tier) {
        this.emitLog({ at: this.nowIso, event: "suspect", store: store.id, path: cur.path, tier: "SUSPECT", by: "first-run", new: sha8(cur.sha256) });
      }
      const fu = cur.content ? this.unitsNow(store, cur) : null;
      const hunks = fu ? this.runsOf(cur.role, fu, new Set(flag.units), firstRunVerdict(flag.reasons)) : [];
      this.emitItem(this.result(store, cur, {
        tier: "SUSPECT", rule: "first-run-block", rules: ["first-run-block"], reasons: flag.reasons, change: "unchanged", firstRun: true,
        hunks, unquoted: !fu, added: 0, removed: 0, flaggedUnits: flag.units, next,
        novel: fu ? this.novelIn(hunks, fu, isJsonRole(cur.role)) : [], scanTruncated: false,
      }));
      return;
    }
    // Reverted to the accepted version: the held item clears.
    const next: StoreEntry = { ...refreshed, held: null };
    this.setEntry(store, cur.key, next);
    this.emitLog({ at: this.nowIso, event: "cleared-revert", store: store.id, path: cur.path, tier: "SILENT", new: sha8(cur.sha256) });
    this.emitItem(this.result(store, cur, {
      tier: "SILENT", rule: "Z", rules: ["Z"], reasons: [], change: "unchanged", firstRun: false,
      hunks: [], added: 0, removed: 0, flaggedUnits: [], next, novel: [], scanTruncated: false,
    }));
  }

  /** §5.3: the first matching rule decides; then advance (SILENT, NOTICE) or hold (HOLD, SUSPECT). */
  private decide(store: Store, d: Diff): void {
    const { prev, cur, fu, added, removed, addedAttr, removedAttr, records, hunks, nowSet } = d;
    const screened = d.unscreened ? null : screenedOf(hunks);
    const cls = ROLE_CLASS[cur.role];
    const notice = cls === "notice";
    const exec = cls === "exec";
    const memory = cls === "memory";
    const writerRules = notice || exec; // H2, N2, N3
    const unknownRules = writerRules || (memory && this.calibrated); // H1, N1
    const agentRules = cls !== "import-silent"; // H4, N4
    const json = isJsonRole(cur.role);
    const byId = new Map(fu.units.map((u) => [u.id, u]));

    // One pass over the changed units: who wrote each, and what it is. Benign
    // (`cat: b`) settings — a model switch, the scoped allow rules "don't ask
    // again" writes — are silent whoever made them (§5.3 Z), so the unknown-writer
    // and unprompted rules skip them.
    const attrs: Attribution[] = [];
    const unknownAdded: string[] = [];
    const escalations: string[] = [];
    const dangerous: Unit[] = [];
    const unprompted: [string, AgentAttribution][] = [];
    let promptedTainted: AgentAttribution | null = null;
    let unknownSeen = false;
    let allAttributed = added.length + removed.length > 0;
    let otherByNonUser = false;
    let addedByNonUser = false;
    const visit = (u: string, a: Attribution, cat: string | undefined, isAdded: boolean) => {
      attrs.push(a);
      const user = byUser(a);
      const benign = cat === "b";
      if (!user) {
        if (isAdded) addedByNonUser = true;
        if (cat === "e" || cat === (isAdded ? "a" : "r")) escalations.push(u);
        if (json && cat === undefined) otherByNonUser = true;
      }
      if (a.kind === "unknown") {
        allAttributed = false;
        if (!benign) {
          unknownSeen = true;
          if (isAdded) unknownAdded.push(u);
        }
      } else if (a.kind === "agent") {
        if (!a.prompted && !benign) unprompted.push([u, a]);
        else if (a.prompted && a.tainted) promptedTainted ??= a;
      }
      if (isAdded && !user && byId.get(u)?.dangerous) dangerous.push(byId.get(u)!);
    };
    for (const u of added) visit(u, addedAttr.get(u) ?? UNKNOWN, fu.cat[u], true);
    for (const u of removed) visit(u, removedAttr.get(u) ?? UNKNOWN, prev.cat[u], false);

    const rules: ClassifyRule[] = [];
    const reasons: string[] = [];
    const flagged = new Set<string>();
    let agent: AgentAttribution | null = null;
    const hit = (rule: ClassifyRule, units: Iterable<string> = [], reason?: string) => {
      rules.push(rule);
      for (const u of units) flagged.add(u);
      const r = reason ?? RULE_REASONS[rule];
      if (r && !reasons.includes(r)) reasons.push(r);
    };
    const reason = (r: string) => {
      if (!reasons.includes(r)) reasons.push(r);
    };

    // S2: a hunk with a verdict, not from a prompted agent write.
    for (const h of hunks) {
      if (!h.verdict || (h.attribution.kind === "agent" && h.attribution.prompted)) continue;
      if (!rules.includes("S2")) rules.push("S2");
      for (const u of h.units) flagged.add(u);
      reason(h.verdict.reason);
    }
    // S3: a Nexus hook removed with no Nexus uninstall on record.
    const lostHooks = prev.nexusHooks.filter((e) => !fu.nexusHooks.includes(e));
    const removedNexusHooks = lostHooks.length && !records.some((r) => r.kind === "nexus" && r.action === "uninstall") ? lostHooks : [];
    if (removedNexusHooks.length) hit("S3", [], `a Nexus hook was removed (${removedNexusHooks.map((e) => hookEventName(e) ?? "a hook").join(", ")})`);
    // S4: a dangerous switch added by a non-user.
    if (dangerous.length) {
      rules.push("S4");
      for (const u of dangerous) {
        flagged.add(u.id);
        reason(`turns on ${u.text}`);
      }
    }

    // H1: an unknown addition while an agent was active. Windows are read only here,
    // and only while nothing stronger matched: they only ever escalate.
    let inWindow: boolean | null = null;
    if (unknownRules && unknownAdded.length && !rules.length && this.input.config.agentWindowEscalation) {
      const ctime = cur.stat?.[2];
      const read = this.windowsSince(parseTime(prev.acceptedAt));
      // a partial read may have missed the window this change fell in: taken as inside one
      inWindow = read.partial || (typeof ctime === "number" && inWindows(read.windows, ctime));
      if (inWindow) hit("H1", unknownAdded);
    }
    // H2: an escalation added (cat e/a) or removed (cat e/r) by a non-user.
    if (writerRules && escalations.length) hit("H2", escalations);
    // H3: code changed and no record explains the new sha.
    if (exec && cur.state === "file" && !allAttributed && !records.some((r) => r.kind === "write" && r.expectedSha === cur.sha256)) hit("H3");
    // H4: unprompted agent writes from a tainted session.
    const taintedUnprompted = unprompted.filter(([, a]) => a.tainted);
    if (agentRules && taintedUnprompted.length) {
      hit("H4", taintedUnprompted.map(([u]) => u));
      agent ??= taintedUnprompted[0][1];
    }
    // H5: unprompted memory writes after web/MCP exposure that add novel tokens.
    const risky = unprompted.filter(([, a]) => a.exposed && a.novel);
    if (memory && risky.length) {
      hit("H5", risky.map(([u]) => u));
      agent ??= risky[0][1];
    }
    // N1: unknown units added or removed.
    if (unknownRules && unknownSeen) rules.push("N1");
    // N2: created, deleted or retargeted by a non-user (the file tools cannot delete or
    // retarget, and nothing records either, so those are never the user's).
    if (writerRules && (d.change === "created" || d.change === "deleted" || d.change === "retargeted")) {
      const nonUser = d.change !== "created" || (added.length
        ? addedByNonUser
        : !records.some((r) => r.kind === "write" && r.expectedSha === cur.sha256 && byUser(attributionOf(r))));
      if (nonUser) rules.push("N2");
    }
    // N3: unprompted agent writes.
    if (writerRules && unprompted.length) {
      rules.push("N3");
      agent ??= unprompted[0][1];
    }
    // N4: prompted writes from a tainted session, or a prompted hunk the detectors flag
    // (the user approved a prompt that showed the reason).
    const promptedHit = hunks.find((h) => h.verdict && h.attribution.kind === "agent" && h.attribution.prompted);
    if (agentRules && (promptedTainted || promptedHit)) {
      rules.push("N4");
      for (const h of hunks) if (h.verdict && h.attribution.kind === "agent" && h.attribution.prompted) reason(h.verdict.reason);
      agent ??= promptedTainted ?? (promptedHit!.attribution as AgentAttribution);
    }
    // N5: a JSON unit with no category changed by a non-user.
    if (notice && otherByNonUser) rules.push("N5");
    if (!rules.length) rules.push("Z");

    const first = rules[0];
    let tier: Tier = first.startsWith("S") ? "SUSPECT" : first.startsWith("H") ? "HOLD" : first.startsWith("N") ? "NOTICE" : "SILENT";
    // A first-run flag still in the file keeps the item SUSPECT (§5.4), with its own reasons.
    let firstRun = false;
    let allReasons = reasons;
    const flag = this.firstRunFlag(prev);
    const firstRunLeft = flag ? flag.units.filter((u) => nowSet.has(u)) : [];
    if (flag && firstRunLeft.length) {
      if (tier !== "SUSPECT") {
        tier = "SUSPECT";
        rules.unshift("first-run-block");
        firstRun = true;
      } else {
        rules.push("first-run-block");
      }
      for (const u of firstRunLeft) flagged.add(u);
      allReasons = [...new Set(firstRun ? [...flag.reasons, ...reasons] : [...reasons, ...flag.reasons])];
      hunks.unshift(...this.runsOf(cur.role, fu, new Set(firstRunLeft), firstRunVerdict(flag.reasons)));
    }

    const outcome: Outcome = {
      tier,
      rule: rules[0],
      rules,
      reasons: tier === "SILENT" ? [] : allReasons,
      change: d.change,
      hunks,
      added: added.length,
      removed: removed.length,
      firstRun,
      descriptions: added.map((u) => byId.get(u)?.desc).filter((x): x is string => x !== undefined),
      removedNexusHooks,
      dangerous: dangerous.map((u) => u.text),
      inWindow,
      agent: tier === "SILENT" ? null : agent,
      novel: tier === "SILENT" ? [] : this.novelIn(hunks, fu, json),
      scanTruncated: d.scanTruncated,
      screened,
    };
    if (d.unscreened) {
      // Not screened this run: nothing is persisted (the baseline, and any held item,
      // stay as they were) and the file is compared again next run. A rule that needs
      // no detector may still make it HOLD or SUSPECT this session, and a held file
      // stays at least as held as it was: reported, only.
      this.defer(store.id, cur.key);
      const kept = prev.held && TIER_RANK[prev.held.tier] > TIER_RANK[tier] ? prev.held : null;
      const shown: Outcome = kept ? { ...outcome, tier: kept.tier, reasons: [...new Set([...kept.reasons, ...outcome.reasons])] } : outcome;
      if (shown.tier === "HOLD" || shown.tier === "SUSPECT") {
        this.emitItem(this.result(store, cur, { ...shown, flaggedUnits: [...flagged], next: prev, heldId: this.heldId(cur.key, cur) }));
      }
      return;
    }
    if (tier === "HOLD" || tier === "SUSPECT") {
      this.hold(store, prev, cur, tier, [...flagged], outcome);
      return;
    }
    this.advance(store, prev, cur, fu, dominant(attrs), outcome);
  }

  /** Novel actionable tokens in the added (or flagged) text: in no accepted entry's `tok`, nor in `alsoAccepted`. */
  private novelIn(hunks: readonly Hunk[], fu: FileUnits, isJson: boolean, alsoAccepted: readonly string[] = []): ActionableToken[] {
    if (!this.hasher || hunks.length === 0) return [];
    let tokens: ActionableToken[];
    if (isJson) {
      const ids = new Set(hunks.flatMap((h) => h.units));
      tokens = unitTokens(fu.units.filter((u) => ids.has(u.id)), this.tokenOpts);
    } else {
      tokens = extractTokens(hunks.map((h) => h.lines.join("\n")).join("\n"), this.tokenOpts);
    }
    const novel = novelTokens(tokens, this.acceptedTok, this.hasher);
    return alsoAccepted.length ? novelTokens(novel, new Set(alsoAccepted), this.hasher) : novel;
  }

  /**
   * SILENT / NOTICE: the entry becomes the current file (§5.4). The old version
   * joins `history` unless it still held a first-run flag: nobody reviewed it,
   * so a later return to it is compared, not matched.
   */
  private advance(store: Store, prev: StoreEntry, cur: SnapshotEntry, fu: FileUnits, by: AcceptedBy, o: Outcome): void {
    const reviewed = !this.firstRunFlag(prev);
    const history = reviewed && prev.sha256 !== null && prev.sha256 !== cur.sha256 ? pushHistory(prev.history, prev.sha256, prev.acceptedAt) : prev.history;
    const next: StoreEntry = {
      path: cur.path, role: cur.role, state: cur.state, sha256: cur.sha256, size: cur.size, stat: cur.stat, link: cur.link,
      units: fu.ids, cat: fu.cat, tok: this.tokOf(cur, fu), nexusHooks: fu.nexusHooks, history,
      acceptedAt: this.nowIso, acceptedBy: by, held: null,
    };
    this.setEntry(store, cur.key, next);
    this.emitLog({
      at: this.nowIso, event: o.tier === "NOTICE" ? "notice" : "advance", store: store.id, path: cur.path, tier: o.tier, by,
      added: o.added, removed: o.removed, old: sha8(prev.sha256), new: sha8(cur.sha256),
    });
    this.emitItem(this.result(store, cur, { ...o, flaggedUnits: [], next }));
  }

  /**
   * HOLD / SUSPECT: the baseline stays; `held` is set or updated, keeping the
   * earliest `since`. A first-run flag the baseline carries is persisted as it
   * was (`firstRunFlag`), whether or not the current file still holds it;
   * otherwise `held` keeps this change's reasons and no units. `screened`
   * records the verdicts this version's added text got, so that while the file
   * stays at this version (the same held id) it is not screened again. The
   * result reports every flagged unit.
   */
  private hold(store: Store, prev: StoreEntry, cur: SnapshotEntry, tier: HeldTier, flaggedUnits: string[], o: Outcome): void {
    const id = this.heldId(cur.key, cur);
    const flag = this.firstRunFlag(prev);
    const held: HeldItem = {
      id, tier, since: prev.held?.since ?? this.nowIso, reasons: flag ? flag.reasons : o.reasons, flaggedUnits: flag ? flag.units : [],
      ...(o.screened ? { screened: o.screened } : {}),
    };
    const base = prev.path === cur.path && prev.role === cur.role ? prev : { ...prev, path: cur.path, role: cur.role };
    const next: StoreEntry = base === prev && prev.held && sameHeld(prev.held, held) ? prev : { ...base, held };
    this.setEntry(store, cur.key, next);
    if (prev.held?.id !== id || prev.held.tier !== tier) {
      this.emitLog({
        at: this.nowIso, event: tier === "SUSPECT" ? "suspect" : "hold", store: store.id, path: cur.path, tier, by: "unknown",
        added: o.added, removed: o.removed, old: sha8(prev.sha256), new: sha8(cur.sha256),
      });
    }
    this.emitItem(this.result(store, cur, { ...o, flaggedUnits, next }));
  }

  // ── A store under TAMPER (§5.6) ──

  private tamperStore(kind: StoreKind, s: StoreInput, snap: StoreSnapshot): StoreOutcome {
    const reason = s.tamper!;
    const doc = s.doc;
    const comparable = !!doc && !!this.hasher && reason !== "key";
    const fragment = TAMPER_FRAGMENTS[reason];
    const place = this.at;
    this.emitLog({ at: this.nowIso, event: "tamper", store: snap.id });
    for (const [i, cur] of Object.values(snap.entries).entries()) {
      if (this.stop()) break;
      this.at = place + 1 + i;
      const prev = doc?.entries[cur.key];
      if (!doc) {
        if (cur.state !== "file" && cur.state !== "oversize") continue;
        this.emitItem(this.result({ kind, id: snap.id }, cur, {
          tier: "SUSPECT", rule: "S1", rules: ["S1"], reasons: [fragment], change: "listed", firstRun: false, tamper: reason,
          hunks: [], unquoted: true, added: 0, removed: 0, flaggedUnits: [], next: null, novel: [], scanTruncated: false,
          heldId: this.heldId(cur.key, cur),
        }));
        continue;
      }
      const base = prev ?? missingEntry(cur.path, cur.role, EPOCH);
      if (cur.state === "unhashed") continue;
      const changed = base.state !== cur.state || base.sha256 !== cur.sha256 || (base.link ?? null) !== (cur.link ?? null);
      if (!changed) continue;
      const change: ChangeKind = !present(base.state) && present(cur.state)
        ? "created"
        : present(base.state) && !present(cur.state) ? "deleted" : cur.link !== null && cur.link !== base.link ? "retargeted" : "modified";
      const fu = comparable && (cur.state !== "file" || cur.content) ? this.unitsNow({ acceptedServers: new Set() }, cur) : null;
      let hunks: Hunk[] = [];
      let added = 0;
      let removed = 0;
      if (fu) {
        const baseSet = new Set(base.units);
        const nowSet = new Set(fu.ids);
        const addedUnits = fu.ids.filter((u) => !baseSet.has(u));
        added = addedUnits.length;
        removed = base.units.filter((u) => !nowSet.has(u)).length;
        hunks = buildHunks(fu, new Set(addedUnits), () => UNKNOWN, isJsonRole(cur.role));
      }
      this.emitItem(this.result({ kind, id: snap.id }, cur, {
        tier: "SUSPECT", rule: "S1", rules: ["S1"], reasons: [fragment], change, firstRun: false, tamper: reason,
        hunks, unquoted: !fu && change !== "deleted", added, removed, flaggedUnits: [], next: prev ?? null,
        // the quoted lines' tokens arm the tripwire (S1 is SUSPECT); this store's own
        // `tok` lists are untrusted, so only a verified store's make a token known
        novel: fu ? this.novelIn(hunks, fu, isJsonRole(cur.role)) : [],
        scanTruncated: false, heldId: this.heldId(cur.key, cur),
      }));
    }
    return { kind, id: snap.id, firstRun: false, tamper: reason, next: null, dirty: false, recomputed: [] };
  }

  private result(store: Pick<Store, "kind" | "id">, cur: SnapshotEntry, o: Outcome & { flaggedUnits: string[]; next: StoreEntry | null; tamper?: TamperReason; unquoted?: boolean; heldId?: string }): EntryResult {
    return {
      store: store.kind,
      storeId: store.id,
      key: cur.key,
      path: cur.path,
      role: cur.role,
      roleClass: ROLE_CLASS[cur.role],
      tier: o.tier,
      rule: o.rule,
      rules: o.rules,
      reasons: o.reasons,
      change: o.change,
      firstRun: o.firstRun ?? false,
      tamper: o.tamper ?? null,
      hunks: o.hunks,
      added: o.added,
      removed: o.removed,
      descriptions: o.descriptions ?? [],
      removedNexusHooks: o.removedNexusHooks ?? [],
      dangerous: o.dangerous ?? [],
      flaggedUnits: o.flaggedUnits,
      novel: o.novel ?? [],
      link: cur.link,
      unquoted: o.unquoted ?? false,
      scanTruncated: o.scanTruncated ?? false,
      inWindow: o.inWindow ?? null,
      agent: o.agent ?? null,
      heldId: o.heldId ?? o.next?.held?.id ?? null,
      next: o.next,
    };
  }
}
