/**
 * `nexus guard integrity` (spec §7, amendment A7): status, diff, accept, log,
 * baseline and config, over the library in src/guard/integrity/index.ts.
 *
 * Exit codes: 0 OK; 1 a usage or internal error, a declined confirmation, the
 * human gate refused, or a store that cannot be written; 3 attention needed
 * (M5) — for `status`, a HOLD, SUSPECT or TAMPER pending, integrity's hooks
 * missing or not running (`checkNexusHooks`: a script gone, a group missing)
 * while integrity is not turned off (also before it was ever set up),
 * `disableAllHooks: true` in a settings layer, or a store Nexus cannot write;
 * for `diff`, a SUSPECT or TAMPER item shown, or the store itself under TAMPER.
 *
 * The human gate (`refuseUnlessHuman`) stands before `accept`, `baseline`,
 * `config <key> <value>`, `guard install --no-integrity` and a `guard install`
 * whose tool lists drop a guarded tool: they run only with stdin and stdout on a
 * terminal and none of AGENT_ENV set (Claude Code sets its variables for its
 * Bash tool, `!` shell mode and hook processes; Codex sets its own for the
 * commands it runs, which can have a terminal). Past the gate three ask for a
 * typed confirmation: `accept` (when something is pending), a 6-letter random
 * challenge for `baseline --reset`, `yes` for a config change; `baseline`
 * without `--reset` and the two installs ask nothing more. There is no bypass,
 * for tests or anyone: tests call the library and check that the CLI refuses.
 * `accept` trusts only the versions it showed: a file that changes before the
 * answer is refused (`expect`). A writer that finds the store read-only or
 * another user's says so in plain words, before asking when it can tell.
 *
 * Every string a watched file or the integrity log can influence reaches the
 * terminal cleaned by the library or here (ANSI escapes and control characters
 * stripped, secrets masked, sentinels neutralised); this module adds colour
 * only when the stream is a terminal. The one subprocess is `diff`'s revert
 * hint: `git -C <R> ls-files --error-unmatch`, 2 s timeout, never via a shell.
 */

import { spawnSync } from "node:child_process";
import { randomInt } from "node:crypto";
import { homedir, userInfo } from "node:os";
import { isAbsolute, join, relative, sep } from "node:path";
import { createInterface } from "node:readline";
import {
  acceptChanges, CONFIG_VALUES, contextStoreIds, createBaseline, getConfig, IntegrityError, integrityDiff, integrityStatus,
  parseConfigSetting, readIntegrityLog, resetBaseline, setConfig, storeUnwritable, unwritableAt, unwritableCode,
  type BaselineResult, type IntegrityDiffItem, type IntegrityStatus, type StoreUnwritable,
} from "../guard/integrity/index.js";
import { realPathOrNull } from "../guard/integrity/paths.js";
import { cleanText, displayPath } from "../guard/integrity/render.js";
import { integrityPaths, TAMPER_FRAGMENTS } from "../guard/integrity/store.js";
import { CONFIG_KEYS, type ConfigKey, type LogEntry, type StoreKind, type TamperReason } from "../guard/integrity/types.js";
import { auditMemoryMarkers, type MemoryMarkerAudit } from "../memory-engine/nexus-memory.js";
import { nexusDataDir } from "../shared/data-dir.js";

// ── The human gate (A7) ─────────────────────────────────────────────────────

export const HUMAN_GATE_MESSAGE =
  "This command must be run by you in your own terminal, not inside Claude Code or Codex: an agent cannot approve its own changes.";

/**
 * The variables an agent sets for the commands it runs. Claude Code: its Bash
 * tool, `!` shell mode and hook processes. Codex: every command it runs (the
 * thread, session and tool-call ids, and the sandbox markers), which matters
 * because Codex can give a command a terminal and type into it, so the TTY
 * check alone does not stop it. Another agent CLI needs its own markers here.
 */
export const AGENT_ENV = [
  "CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_CHILD_SESSION",
  "CODEX_THREAD_ID", "CODEX_SESSION_ID", "CODEX_TOOL_CALL_ID", "CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED",
] as const;

/** Refuse unless stdin and stdout are a terminal and none of AGENT_ENV is set (to anything, even ""). */
export function humanGateRefuses(io: { stdinIsTTY: boolean; stdoutIsTTY: boolean; env: Readonly<Record<string, string | undefined>> }): boolean {
  return !io.stdinIsTTY || !io.stdoutIsTTY || AGENT_ENV.some((name) => io.env[name] !== undefined);
}

/** The gate for this process: prints the refusal (after `why`, when given) to stderr and returns true when the command must not run. */
export function refuseUnlessHuman(why?: string): boolean {
  const refused = humanGateRefuses({
    stdinIsTTY: process.stdin.isTTY === true, stdoutIsTTY: process.stdout.isTTY === true, env: process.env,
  });
  if (refused) process.stderr.write(`${why ? `${why}\n` : ""}${HUMAN_GATE_MESSAGE}\n`);
  return refused;
}

// ── Output ──────────────────────────────────────────────────────────────────

const SGR = { reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m", red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m", cyan: "\x1b[36m" };
type Tone = Exclude<keyof typeof SGR, "reset">;

/** `text` in a colour, when `stream` is a terminal; as is otherwise (pipes, files, tests). */
function paint(tone: Tone, text: string, stream: NodeJS.WriteStream = process.stdout): string {
  return stream.isTTY === true ? `${SGR[tone]}${text}${SGR.reset}` : text;
}

const out = (line = "") => process.stdout.write(`${line}\n`);

/**
 * Characters JSON.stringify leaves raw that a terminal may act on or that
 * reorder or hide text: C1 controls, bidi and zero-width marks, line and
 * paragraph separators, tag characters (U+E0000-E007F, as their surrogate
 * pairs). They only occur inside strings, so escaping them keeps the same JSON
 * value (paths and log fields stay exact for programs).
 */
const JSON_UNSAFE = /[\u007f-\u009f\u061c\u180e\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb]|\udb40[\udc00-\udc7f]/g;

/** `--json` output: pretty JSON with JSON_UNSAFE characters written as `\uXXXX` (each UTF-16 unit). */
function json(value: unknown): string {
  return JSON.stringify(value, null, 2).replace(JSON_UNSAFE, (ch) =>
    ch.split("").map((unit) => `\\u${unit.charCodeAt(0).toString(16).padStart(4, "0")}`).join(""));
}

function fail(message: string): 1 {
  process.stderr.write(`${paint("red", "Error:", process.stderr)} ${message}\n`);
  return 1;
}

const USAGE = "Usage: nexus guard integrity <status|diff|accept|log|baseline|config>  [--json] [--memory] [--all] [--reset] [--agent codex]";

function usage(problem?: string): 1 {
  return fail(problem ? `${problem}\n${USAGE}` : USAGE);
}

const LABEL_WIDTH = 11;

/** One `  Label:      text` line of `status`. */
function row(label: string, text: string, tone: Tone = "cyan"): void {
  out(`  ${paint(tone, label.padEnd(LABEL_WIDTH))} ${text}`);
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
/** A time read from a file, as `2026-10-23 09:12` (UTC). */
const minute = (iso: string) => cleanText(iso.slice(0, 64)).slice(0, 16).replace("T", " ");
const day = (iso: string | null) => (iso ? cleanText(iso.slice(0, 64)).slice(0, 10) : "?");
const count = (n: unknown) => (typeof n === "number" && Number.isFinite(n) ? n : 0);

/** A path outside any project: `~/…` under home, else absolute; cleaned and cut. */
function homePath(path: string): string {
  return displayPath(path, { root: "", home: homedir(), platform: process.platform });
}

const KIND_LABEL: Readonly<Record<StoreKind, string>> = { global: "global", project: "project", memory: "auto memory" };
/** A store's label in a count: Codex's user-level store is a `global` kind of its own. */
const kindLabel = (st: { id: string; kind: StoreKind }) => (st.id === "codex" ? "Codex" : KIND_LABEL[st.kind]);

function tamperText(reason: TamperReason | null): string {
  return reason ? TAMPER_FRAGMENTS[reason] : "the fingerprint failed verification";
}

/** The ids of the cwd's own stores, which `storeName` calls "this project" and "auto memory". */
type OwnStores = { project: string | null; memory: string | null };

/** What `status` and `log` call a store, by its id: global, Codex, this project, auto memory, or another project's. */
function storeName(id: string, own: OwnStores): string {
  if (id === "global") return "global";
  if (id === "codex") return "Codex";
  if (id === own.project) return "this project";
  if (id === own.memory) return "auto memory";
  if (id.startsWith("project-")) return "another project";
  if (id.startsWith("memory-")) return "another project's auto memory";
  return cleanText(id.slice(0, 64));
}

/** A log event in words (`log`, status `Recent:`, `diff --all`). */
const EVENT_WORDS: Readonly<Record<LogEntry["event"], string>> = {
  "first-run": "fingerprint taken",
  reset: "fingerprint retaken",
  advance: "updated",
  notice: "updated, reported",
  hold: "held for review",
  suspect: "held for review (suspect)",
  accept: "accepted",
  "cleared-revert": "cleared (reverted)",
  tamper: "failed verification",
};
const eventWords = (event: string) => (EVENT_WORDS as Record<string, string | undefined>)[event] ?? cleanText(event.slice(0, 32));

/**
 * Who or what made a logged change, in words; nothing for an unknown writer
 * (`auto`). `agent` is the writer of most of the change during a Claude
 * session, not necessarily through Claude's file tools; a `nexus` change that
 * only took lines out is an uninstall.
 */
function byWords(by: string | null, added: number, removed: number): string {
  switch (by) {
    case null:
    case "auto":
      return "";
    case "user":
      return "by you";
    case "nexus":
      return added === 0 && removed > 0 ? "by Nexus uninstall" : "by Nexus install";
    case "agent":
      return "during a Claude session";
    case "first-run":
      return "at the first fingerprint";
    default:
      return `by ${cleanText(by.slice(0, 64)).slice(0, 32)}`;
  }
}

/**
 * Consecutive store-wide entries (no path) of one event at one time by the same
 * writer — the first fingerprint of the global, project and memory stores,
 * taken together — merged into one, their stores named; others stay as they are.
 */
function mergeStoreEvents<T extends { at: string; event: string; by?: unknown }>(
  entries: readonly T[], hasPath: (e: T) => boolean, store: (e: T) => string | null,
): { entry: T; stores: string[] }[] {
  const merged: { entry: T; stores: string[] }[] = [];
  for (const e of entries) {
    const last = merged.at(-1);
    const name = store(e);
    if (last && !hasPath(e) && !hasPath(last.entry) && last.entry.at === e.at && last.entry.event === e.event && last.entry.by === e.by) {
      if (name !== null && !last.stores.includes(name)) last.stores.push(name);
      continue;
    }
    merged.push({ entry: e, stores: name === null ? [] : [name] });
  }
  return merged;
}

const currentUid = () => (typeof process.getuid === "function" ? process.getuid() : null);

/** Plain words for a store path Nexus cannot write: that it is read-only, or who owns it. */
function unwritableText(u: StoreUnwritable): string {
  const where = homePath(u.path);
  if (u.code === "EROFS") return `${where} is on a read-only file system`;
  const me = currentUid();
  if (u.owner !== null && me !== null && u.owner !== me) return `${where} belongs to ${u.owner === 0 ? "root" : `user id ${u.owner}`}, not to you`;
  return `${where} is not writable by you (permission denied)`;
}

/** `path` is D or inside it, not a directory above D that D is still to be created in. */
function inDataDir(path: string, dataDir: string): boolean {
  const rel = relative(dataDir, path);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * The command that hands a store another user owns (as after `sudo nexus …`)
 * back to you; null when that is not the problem. Only ever D: a directory
 * above it (D not created yet) is not Nexus's to take.
 */
function chownCommand(u: StoreUnwritable, dataDir: string): string | null {
  const me = currentUid();
  if (u.code === "EROFS" || u.owner === null || me === null || u.owner === me || !inDataDir(u.path, dataDir)) return null;
  let name: string;
  try {
    name = userInfo().username;
  } catch {
    name = String(me);
  }
  return `sudo chown -R ${shellArg(name)} ${shellArg(dataDir)}`;
}

/** What to make writable, when no chown gives the store back: D, or the directory D is to be created in. */
function unwritableRemedy(u: StoreUnwritable, dataDir: string): string {
  return inDataDir(u.path, dataDir)
    ? `make ${homePath(dataDir)} writable again`
    : `make ${homePath(u.path)} writable, or set NEXUS_DATA to a directory you can write`;
}

/** `status`'s next step for a store it cannot write. */
function unwritableNext(u: StoreUnwritable, dataDir: string): string {
  const chown = chownCommand(u, dataDir);
  return chown ? `run in your own terminal: ${chown}` : unwritableRemedy(u, dataDir);
}

/** A writer's failure on a store it cannot write: the reason and the fix, instead of a raw errno message. */
function unwritableFailure(u: StoreUnwritable): 1 {
  const dataDir = nexusDataDir();
  const chown = chownCommand(u, dataDir);
  const remedy = unwritableRemedy(u, dataDir);
  const fix = chown ? `To take it back, run in your own terminal: ${chown}` : `${remedy[0].toUpperCase()}${remedy.slice(1)}, then retry.`;
  return fail(`cannot change the integrity store: ${unwritableText(u)}. ${fix}`);
}

/** Before a writer asks anything: when the store is read-only or another user's, fail now and say so. */
function refuseIfUnwritable(): boolean {
  const u = storeUnwritable(integrityPaths(nexusDataDir()));
  if (u) unwritableFailure(u);
  return u !== null;
}

/**
 * A write that failed past `refuseIfUnwritable` (a file in D itself, as the
 * anchor `baseline --reset` writes; a change since the check) because the store
 * is read-only or another user's, as `unwritableAt` words it; null for any other
 * failure. A recursive mkdir reports ENOENT on a read-only file system, so that
 * counts when the directory it would create in refuses.
 */
function unwritableFrom(error: unknown): StoreUnwritable | null {
  const e = error as NodeJS.ErrnoException | null;
  const code = unwritableCode(error);
  if (code === null && !(e?.code === "ENOENT" && e.syscall === "mkdir")) return null;
  const at = typeof e?.path === "string" ? e.path : integrityPaths(nexusDataDir()).dir;
  return unwritableAt(at) ?? (code === null ? null : { path: at, code, owner: null });
}

/**
 * The `NEXUS_DATA` values Nexus ignored (not absolute paths), one warning each,
 * as both `guard status` and `guard integrity status` print them: this shell's
 * (`path` null), which the CLI ignores for `dataDir`, and the one the settings
 * layers hand the hooks, which they ignore for ~/.nexus.
 */
export function ignoredDataDirWarnings(ignored: readonly { path: string | null; value: string }[], dataDir: string): string[] {
  return ignored.map((x) => {
    const value = JSON.stringify(cleanText(x.value.slice(0, 200)).slice(0, 80));
    return x.path === null
      ? `NEXUS_DATA=${value} is not an absolute path, so Nexus ignores it and uses ${homePath(dataDir)}`
      : `${homePath(x.path)} sets NEXUS_DATA to ${value}, not an absolute path: the hooks ignore it and use ~/.nexus`;
  });
}

/** Reads one line from the terminal; null on end of input or Ctrl-C. */
function ask(question: string): Promise<string | null> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    let answered = false;
    rl.on("SIGINT", () => rl.close());
    rl.on("close", () => {
      if (answered) return;
      out();
      resolve(null);
    });
    rl.question(question, (answer) => {
      answered = true;
      rl.close();
      resolve(answer);
    });
  });
}

// ── status ──────────────────────────────────────────────────────────────────

/** M5: what makes `status` exit 3. */
function statusNeedsAttention(s: IntegrityStatus): boolean {
  return s.state === "tamper" || s.pending.length > 0 || s.hook.disableAllHooksIn.length > 0 || s.unwritable !== null
    || (s.state !== "disabled" && !s.hook.live);
}

function storeText(s: IntegrityStatus): string {
  const base = homePath(join(s.dataDir, "integrity"));
  if (s.state === "uninitialized") return `${base} (not set up yet: the first fingerprint is taken at the next session start)`;
  if (s.state === "disabled") return `${base} (off: nexus guard integrity config enabled true turns it back on)`;
  if (s.state === "tamper") return `${base} (TAMPER: ${tamperText(s.tamperReason)})`;
  const updated = s.stores.filter((st) => st.verified && st.updatedAt).map((st) => st.updatedAt as string).sort().at(-1);
  const fresh = s.stores.some((st) => st.kind === "project" && st.gen === null);
  return `${base} (signed, verified${updated ? `; updated ${minute(updated)}` : ""})${fresh ? "; this project has no fingerprint yet (taken at its next session start)" : ""}`;
}

function watchingText(s: IntegrityStatus): string {
  const total = s.stores.reduce((n, st) => n + st.files, 0);
  const unhashed = s.stores.reduce((n, st) => n + st.unhashed, 0);
  const memory = s.autoMemory.located && s.autoMemory.dir
    ? `auto memory: ${homePath(s.autoMemory.dir)}${s.autoMemory.writesObserved ? " (Claude's memory saves seen)" : ""}`
    : "auto memory: not located";
  return [
    `${plural(total, "file")} (${s.stores.map((st) => `${kindLabel(st)} ${st.files}`).join(", ")})`,
    ...(unhashed ? [`${unhashed} over the scan limits, not hashed`] : []),
    memory,
  ].join("; ");
}

/** One status `Recent:` item: a file's change, or a store-wide event with the stores it covered. */
function recentText({ entry: r, stores }: { entry: IntegrityStatus["recent"][number]; stores: string[] }): string {
  const what = r.display
    ? `${r.display} +${count(r.added)}/-${count(r.removed)} ${eventWords(r.event)}`
    : `${eventWords(r.event)}${stores.length ? `: ${stores.join(", ")}` : ""}`;
  const by = byWords(r.by, count(r.added), count(r.removed));
  return `${what}${by ? ` ${by}` : ""} (${day(r.at)})`;
}

function memoryText(m: MemoryMarkerAudit): string {
  const parts = [`${m.valid} valid`, `${m.missing} missing`, `${m.staleVersion} stale version`, `${m.mismatched} mismatched`];
  if (m.unverified) parts.push(`${m.unverified} not checked (memory key ${m.key})`);
  if (m.unreadable) parts.push(`${m.unreadable} unreadable`);
  return `${plural(m.records, "record")}: ${parts.join(", ")}`;
}

function nextStep(s: IntegrityStatus, flags: IntegrityFlags): string | null {
  // nothing else can be fixed while the store cannot be written
  if (s.unwritable) return unwritableNext(s.unwritable, s.dataDir);
  if (s.state === "tamper") return `review ${integrityCmd("diff", flags)}, then run ${integrityCmd("baseline --reset", flags)} in your own terminal`;
  if (s.pending.length) return integrityCmd("diff", flags);
  if (s.state !== "disabled" && !s.hook.live && s.hook.scope) return `nexus guard install${s.hook.scope === "project" ? " --project" : ""}`;
  if (s.state !== "disabled" && !s.hook.live) {
    const other = s.hook.otherConfigDirs[0];
    return other
      ? `run this with CLAUDE_CONFIG_DIR=${homePath(other)} to check that config dir, or nexus guard install to add the hook to ${homePath(s.hook.configDir)}`
      : "nexus guard install";
  }
  if (s.hook.disableAllHooksIn.length) return "remove disableAllHooks from the settings named above";
  return null;
}

async function status(args: string[], flags: IntegrityFlags): Promise<number> {
  if (args.length) return usage("status takes no arguments");
  const s = await integrityStatus({ ...agentOf(flags), ...(flags.memory ? { memoryAudit: auditMemoryMarkers } : {}) });
  const code = statusNeedsAttention(s) ? 3 : 0;
  if (flags.json) {
    out(json(s));
    return code;
  }
  out(paint("bold", "Instruction-file integrity"));
  row("Store:", storeText(s), s.state === "tamper" ? "red" : "cyan");
  if (s.unwritable) row("Warning:", `${unwritableText(s.unwritable)}: Nexus cannot save what it finds or your reviews`, "yellow");
  for (const line of ignoredDataDirWarnings(s.ignoredDataDir, s.dataDir)) row("Warning:", line, "yellow");
  if (s.hook.live) row("Hook:", `SessionStart installed (${s.hook.scope} settings)`);
  else if (s.state === "disabled") row("Hook:", "SessionStart not installed (integrity is off)");
  // present but dead or partial (`checkNexusHooks`): reported as missing
  else if (s.hook.scope) row("Hook:", `not working (${s.hook.scope} settings): ${s.hook.problems.join("; ")}`, "yellow");
  else if (s.hook.otherConfigDirs.length) {
    // the fingerprint saw Nexus installed in another config dir: a shell without the CLAUDE_CONFIG_DIR Claude was started with
    const where = s.hook.otherConfigDirs.map((dir) => homePath(join(dir, "settings.json"))).join(", ");
    row("Hook:", `SessionStart hook not in ${homePath(join(s.hook.configDir, "settings.json"))} (the config dir this shell's CLAUDE_CONFIG_DIR selects) or this project's settings; it is in ${where}`, "yellow");
  } else row("Hook:", "SessionStart hook missing: run nexus guard install", "yellow");
  for (const path of s.hook.disableAllHooksIn) row("Warning:", `disableAllHooks is set in ${homePath(path)}: no Nexus hook runs`, "yellow");
  if (s.hook.staleDefaultSettings) {
    row("Warning:", `${homePath(s.hook.staleDefaultSettings)} still holds Nexus hooks, which Claude Code does not run while CLAUDE_CONFIG_DIR points elsewhere`, "yellow");
  }
  if (s.hook.missingNexusHooks.length) {
    row("Missing:", `Nexus ${s.hook.missingNexusHooks.join(", ")} hook removed, with no nexus guard uninstall on record`, "yellow");
  }
  row("Watching:", watchingText(s));
  for (const p of s.pending) row(p.tier === "SUSPECT" ? "Suspect:" : "Waiting:", p.summary, p.tier === "SUSPECT" ? "red" : "yellow");
  const own: OwnStores = { project: s.stores.find((st) => st.kind === "project")?.id ?? null, memory: s.stores.find((st) => st.kind === "memory")?.id ?? null };
  const recent = mergeStoreEvents(s.recent, (r) => r.display !== null, (r) => (r.store === null ? null : storeName(r.store, own)));
  if (recent.length) row("Recent:", recent.map(recentText).join("; "));
  if (s.taintedSessions.length) {
    const shown = s.taintedSessions.slice(0, 3).map((t) => `${t.sid}: ${t.reason}`).join("; ");
    row("Sessions:", `${s.taintedSessions.length} tainted in the last 7 days (${shown}${s.taintedSessions.length > 3 ? "; …" : ""})`);
  }
  row("Unwatched:", s.notWatched.join(", "), "dim");
  if (flags.memory && s.memory) row("Memory:", memoryText(s.memory as MemoryMarkerAudit));
  const next = nextStep(s, flags);
  if (next) row("Next:", next);
  return code;
}

// ── diff ────────────────────────────────────────────────────────────────────

const GIT_TIMEOUT_MS = 2000;

/** `arg` for a POSIX shell (cmd.exe on Windows), quoted only when it needs it. */
function shellArg(arg: string): string {
  if (/^[A-Za-z0-9._/@%+=:,-]+$/.test(arg)) return arg;
  return process.platform === "win32" ? `"${arg}"` : `'${arg.replace(/'/g, `'\\''`)}'`;
}

/**
 * `revert: git checkout -- <path>` for each item git tracks under R, the path
 * relative to the CLI's cwd (where the user runs it). One
 * `git -C <R> ls-files --error-unmatch -- <rel>` per item, 2 s timeout, no
 * shell; `core.fsmonitor` is forced off, so a hook planted in the repository's
 * config does not run. Missing git, or one that hangs, ends the hints.
 */
function revertHints(root: string, items: readonly IntegrityDiffItem[]): Map<string, string> {
  const hints = new Map<string, string>();
  // canonical like item.path: on win32 a shell's cwd may spell a directory by its 8.3 short name
  const cwd = realPathOrNull(process.cwd()) ?? process.cwd();
  for (const item of items) {
    const rel = relative(root, item.path);
    if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel) || cleanText(rel) !== rel) continue;
    const r = spawnSync("git", ["-C", root, "-c", "core.fsmonitor=false", "ls-files", "--error-unmatch", "--", rel], {
      stdio: "ignore", timeout: GIT_TIMEOUT_MS, windowsHide: true,
    });
    if (r.error) break;
    if (r.status !== 0) continue;
    const shown = relative(cwd, item.path).split(sep).join("/");
    if (shown && cleanText(shown) === shown) hints.set(item.path, `git checkout -- ${shellArg(shown)}`);
  }
  return hints;
}

const isHeldItem = (i: IntegrityDiffItem) => i.tier === "HOLD" || i.tier === "SUSPECT";
const TIER_TONE: Readonly<Record<IntegrityDiffItem["tier"], Tone>> = { SILENT: "dim", NOTICE: "cyan", HOLD: "yellow", SUSPECT: "red" };

async function diff(args: string[], flags: IntegrityFlags): Promise<number> {
  const d = await integrityDiff({ paths: args, all: flags.all, ...agentOf(flags) });
  const hints = revertHints(d.root, d.items);
  const items = d.items.map((i) => ({ ...i, revert: hints.get(i.path) ?? null }));
  const code = d.attention || d.state === "tamper" ? 3 : 0;
  if (flags.json) {
    out(json({ ...d, items }));
    return code;
  }
  if (d.state === "uninitialized") {
    out("Instruction-file integrity is not set up yet: there is no fingerprint to compare with.");
    return code;
  }
  if (d.state === "tamper") {
    out(paint("red", `TAMPER: ${tamperText(d.tamperReason)}. Nothing below could be verified; after reviewing it, run ${integrityCmd("baseline --reset", flags)} in your own terminal.`));
  } else if (d.state === "disabled") {
    out(paint("dim", "Instruction-file integrity is off (nexus guard integrity config enabled true turns it back on)."));
  }
  if (items.length === 0) out(args.length ? "No changes to these files since the last fingerprint." : "No changes since the last fingerprint.");
  for (const item of items) {
    const [head, ...rest] = item.text;
    out();
    out(paint(TIER_TONE[item.tier], head));
    for (const line of rest) out(line);
    if (item.revert) out(`  revert: ${item.revert}`);
  }
  if (flags.all) {
    out();
    out(d.advanced.length ? "Recent changes taken in without a review (line counts only):" : "No recent changes were taken in without a review.");
    for (const a of d.advanced) {
      const by = byWords(a.by, count(a.added), count(a.removed));
      out(`  ${minute(a.at)}  ${a.display ?? "?"}  +${count(a.added)}/-${count(a.removed)}  ${eventWords(a.event)}${by ? ` ${by}` : ""}`);
    }
  }
  if (d.state !== "tamper" && items.some(isHeldItem)) {
    out();
    out(`To trust these files as they are now, run in your own terminal: ${integrityCmd("accept", flags)}`);
  }
  return code;
}

// ── accept ──────────────────────────────────────────────────────────────────

async function accept(args: string[], flags: IntegrityFlags): Promise<number> {
  if (refuseUnlessHuman()) return 1;
  // first: a store Nexus cannot read reads as TAMPER, and baseline --reset cannot fix that either
  if (refuseIfUnwritable()) return 1;
  const d = await integrityDiff({ paths: args, ...agentOf(flags) });
  if (d.state === "uninitialized") return fail("there is no fingerprint to accept changes into yet");
  if (d.state === "tamper") {
    return fail(`the fingerprint failed verification (${tamperText(d.tamperReason)}); run ${integrityCmd("baseline --reset", flags)} in your own terminal`);
  }
  const pending = d.items.filter(isHeldItem);
  if (pending.length === 0) {
    out(args.length ? "Nothing to accept for these files." : "Nothing to accept.");
    return 0;
  }
  for (const item of pending) {
    out();
    for (const line of item.text) out(line);
  }
  out();
  const answer = await ask(`Type accept to trust these ${pending.length} file(s): `);
  if (answer?.trim() !== "accept") {
    out("Nothing accepted.");
    return 1;
  }
  const r = acceptChanges({ paths: args, expect: pending.map((i) => ({ path: i.path, heldId: i.heldId })), ...agentOf(flags) });
  out(`${paint("green", "OK")} Accepted ${plural(r.accepted.length, "file")}: ${r.accepted.map((a) => a.display).join(", ")}`);
  return 0;
}

// ── log ─────────────────────────────────────────────────────────────────────

/**
 * One `log` line: the time, the event in words, the file (or the stores a
 * store-wide event covered), its line counts and who made it. A store-wide
 * entry's own count is of the paths it checked, not files, so it is not shown.
 */
function logLine({ entry: e, stores }: { entry: LogEntry; stores: string[] }): string {
  const path = typeof e.path === "string" ? homePath(e.path) : null;
  const parts = [minute(e.at), eventWords(e.event).padEnd(17), path ?? stores.join(", ")];
  if (path !== null && (e.added !== undefined || e.removed !== undefined)) parts.push(`+${count(e.added)}/-${count(e.removed)}`);
  parts.push(byWords(typeof e.by === "string" ? e.by : null, count(e.added), count(e.removed)));
  return parts.filter(Boolean).join("  ");
}

function log(args: string[], flags: IntegrityFlags): number {
  if (args.length) return usage("log takes no arguments");
  const entries = readIntegrityLog();
  if (flags.json) {
    out(json(entries));
    return 0;
  }
  if (entries.length === 0) out("No integrity log entries yet.");
  const own: OwnStores = entries.length ? contextStoreIds() : { project: null, memory: null };
  const lines = mergeStoreEvents(entries, (e) => typeof e.path === "string", (e) => (typeof e.store === "string" ? storeName(e.store, own) : null));
  for (const line of lines) out(logLine(line));
  return 0;
}

// ── baseline ────────────────────────────────────────────────────────────────

/** Six random capital letters: `baseline --reset` asks for them typed back. */
function challenge(): string {
  return Array.from({ length: 6 }, () => String.fromCharCode(65 + randomInt(26))).join("");
}

function reportBaseline(verb: string, r: BaselineResult): void {
  const total = r.stores.reduce((n, st) => n + st.files, 0);
  out(`${paint("green", "OK")} ${verb} ${plural(total, "file")}: ${r.stores.map((st) => `${kindLabel(st)} ${st.files}`).join(", ")}.`);
  if (r.createdKey) out("   A new integrity key was created.");
  if (r.replacedConfig) out("   config.json did not verify and was replaced with the defaults.");
  if (r.dropped.length) out(`   Deleted ${plural(r.dropped.length, "fingerprint")} that could not be verified (first-run at their next session): ${r.dropped.join(", ")}`);
}

async function baseline(args: string[], flags: IntegrityFlags): Promise<number> {
  if (args.length) return usage("baseline takes no arguments");
  if (refuseUnlessHuman()) return 1;
  if (refuseIfUnwritable()) return 1;
  if (!flags.reset) {
    reportBaseline("Fingerprinted", createBaseline(agentOf(flags)));
    return 0;
  }
  const s = await integrityStatus(agentOf(flags));
  out(paint("bold", "Re-fingerprint instruction-file integrity"));
  row("Store:", storeText(s), s.state === "tamper" ? "red" : "cyan");
  row("Watching:", watchingText(s));
  if (s.pending.length) {
    row("Pending:", `${plural(s.pending.length, "change")} not reviewed will be trusted as they are now (${integrityCmd("diff", flags)} shows them)`, "yellow");
  }
  row("Also:", "a missing or untrusted integrity key is replaced; other projects' fingerprints that cannot be verified are deleted (they get a first-run fingerprint at their next session)");
  const code = challenge();
  const answer = await ask(`Type ${code} to re-fingerprint every watched file: `);
  if (answer?.trim().toUpperCase() !== code) {
    out("Nothing changed.");
    return 1;
  }
  reportBaseline("Re-fingerprinted", resetBaseline(agentOf(flags)));
  return 0;
}

// ── config ──────────────────────────────────────────────────────────────────

const isConfigKey = (key: string): key is ConfigKey => (CONFIG_KEYS as readonly string[]).includes(key);
const choicesOf = (key: ConfigKey) => (key in CONFIG_VALUES ? CONFIG_VALUES[key as keyof typeof CONFIG_VALUES] : ["true", "false"]);
const unknownKey = (key: string) => `unknown key ${JSON.stringify(key).slice(0, 80)} (one of ${CONFIG_KEYS.join(", ")})`;

async function changeConfig(key: string, value: string): Promise<number> {
  if (refuseUnlessHuman()) return 1;
  const setting = parseConfigSetting(key, value);
  if (refuseIfUnwritable()) return 1;
  out(`${setting.key}: ${String(getConfig().config[setting.key])} -> ${String(setting.value)}`);
  const answer = await ask(`Type yes to change ${setting.key}: `);
  if (answer?.trim() !== "yes") {
    out("Nothing changed.");
    return 1;
  }
  const view = setConfig({}, setting.key, setting.value);
  out(`${paint("green", "OK")} ${setting.key} = ${String(view.config[setting.key])}`);
  return 0;
}

async function config(args: string[], flags: IntegrityFlags): Promise<number> {
  if (args.length > 2) return usage("config takes a key and, to change it, a value");
  if (args.length === 2) return changeConfig(args[0], args[1]);
  const view = getConfig();
  if (args.length === 1) {
    const key = args[0];
    if (!isConfigKey(key)) return fail(unknownKey(key));
    out(flags.json ? json({ key, value: view.config[key] }) : `${key} = ${String(view.config[key])}`);
    return 0;
  }
  if (flags.json) {
    out(json(view));
    return 0;
  }
  const where = homePath(join(nexusDataDir(), "integrity", "config.json"));
  const state = view.state === "ok" ? "signed" : view.state === "missing" ? "defaults; no config.json yet" : "NOT VERIFIED: defaults apply until baseline --reset";
  out(paint("bold", "Instruction-file integrity config"));
  row("File:", `${where} (${state})`, view.state === "unverified" ? "red" : "cyan");
  const width = Math.max(...CONFIG_KEYS.map((k) => k.length));
  for (const key of CONFIG_KEYS) {
    out(`  ${key.padEnd(width)}  ${String(view.config[key]).padEnd(13)}  ${paint("dim", choicesOf(key).join(" | "))}`);
  }
  if (view.disabled) out(paint("yellow", "  Integrity is off (.disabled marker)."));
  out(paint("dim", "Change one in your own terminal: nexus guard integrity config <key> <value>"));
  return 0;
}

// ── Entry ───────────────────────────────────────────────────────────────────

/**
 * The switches `nexus guard integrity` reads (src/cli/index.ts reads them from
 * the parsed flags); `agent`: `--agent`'s value, `codex` for Codex's
 * user-level files instead of Claude Code's.
 */
export type IntegrityFlags = { json: boolean; all: boolean; reset: boolean; memory: boolean; agent?: string };

/** The library option `--agent codex` selects (checked by `cmdIntegrity`). */
const agentOf = (flags: IntegrityFlags): { agent?: "codex" } => (flags.agent?.toLowerCase() === "codex" ? { agent: "codex" } : {});

/**
 * `nexus guard integrity <sub>` as the next command to run: for `--agent codex`
 * with the flag kept (as the SessionStart text words it, render.ts `Voice`), since
 * without it the command reads Claude Code's user-level store instead.
 */
const integrityCmd = (sub: string, flags: IntegrityFlags): string => `nexus guard integrity ${sub}${agentOf(flags).agent ? " --agent codex" : ""}`;

/** `nexus guard integrity <action> [args…]`; returns the exit code. */
export async function cmdIntegrity(action: string | undefined, args: string[], flags: IntegrityFlags): Promise<number> {
  if (flags.agent !== undefined && !/^(?:claude|codex)$/i.test(flags.agent)) return usage("--agent takes claude or codex");
  try {
    switch (action) {
      case "status":
        return await status(args, flags);
      case "diff":
        return await diff(args, flags);
      case "accept":
        return await accept(args, flags);
      case "log":
        return log(args, flags);
      case "baseline":
        return await baseline(args, flags);
      case "config":
        return await config(args, flags);
      default:
        return usage(action === undefined ? undefined : `unknown integrity command ${JSON.stringify(action).slice(0, 40)}`);
    }
  } catch (error) {
    if (error instanceof IntegrityError) return fail(error.message);
    const unwritable = unwritableFrom(error);
    if (unwritable) return unwritableFailure(unwritable);
    throw error;
  }
}
