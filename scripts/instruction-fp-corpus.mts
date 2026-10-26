/**
 * False-positive measurement for the instruction-file integrity screen.
 *
 * Fingerprints every instruction file under a directory (AGENTS.md, CLAUDE.md,
 * copilot instructions, … downloaded from public repositories, say) the way a
 * first SessionStart does, through the real classify(), and prints how many
 * each tier flags, the rate by file size, and every flagged file with the
 * reason and line range its verdict shows. The corpus is not vendored: it is
 * other people's text, and the point is to re-run the measurement on a fresh one.
 *
 *   npx tsx scripts/instruction-fp-corpus.mts <dir> [--json <out.json>] [--attacks]
 *
 * <dir> is a directory of files (every regular file under it; symlinks, one-line
 * link stubs and byte-identical duplicates are skipped), or a corpus whose
 * index.json lists `{ file, repo?, path?, kind?, symlinkStub?, duplicateOf? }`.
 * The files are read as UTF-8 text and handed to the detectors; nothing in them
 * is run. Use a throwaway HOME and NEXUS_DATA: classify() itself touches no
 * store, but the habit keeps a stray run away from real state.
 *
 * Per file:
 *  - first fingerprint: no stores yet, so classify's first-run scan screens the
 *    whole file (SILENT, NOTICE for a soft verdict, SUSPECT for a strong one);
 *  - created after a baseline: the baseline lists the path as missing, then the
 *    file appears and every line is an added unit (the tier and rules);
 *  - markdownVerdict on the first 200 KB: the reason and line range shown.
 * --attacks also screens the repo's adaptive attack corpora: the content and
 * Markdown file-write attacks through markdownVerdict (caught, strong), every
 * payload through the content capabilities (deny), and every file write
 * through inspectFileWrite (deny) — the numbers a narrowing must keep.
 */

import { createHash } from "node:crypto";
import { closeSync, constants, existsSync, openSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { classify, type ClassifyInput, type ClassifyResult, type StoreInput } from "../src/guard/integrity/classify.js";
import type { Snapshot, SnapshotEntry } from "../src/guard/integrity/enumerate.js";
import { markdownVerdict, SCAN_CAP_CHARS, type Verdict } from "../src/guard/integrity/screen.js";
import { signerFor, type UnsignedStoreDoc } from "../src/guard/integrity/store.js";
import type { StoreDoc, WatchedRole } from "../src/guard/integrity/types.js";
import { sha256Hex, unitHasher } from "../src/guard/integrity/units.js";
import { detectContentCapabilities } from "../src/guard/capability.js";
import { inspectFileWrite } from "../src/guard/command.js";

const args = process.argv.slice(2);
const flag = (name: string) => args.includes(name);
const option = (name: string) => {
  const at = args.indexOf(name);
  return at >= 0 ? args[at + 1] : undefined;
};
const DIR = args.find((a, i) => !a.startsWith("--") && args[i - 1] !== "--json");
if (!DIR || !existsSync(DIR)) {
  console.error("usage: npx tsx scripts/instruction-fp-corpus.mts <dir> [--json <out.json>] [--attacks]");
  process.exit(2);
}

// ── The corpus ──────────────────────────────────────────────────────────────

type Doc = { id: string; name: string; text: string; size: number };

/** A git symlink fetched as a file: one short line naming another path (an `@path` import is a real file). */
const isLinkStub = (text: string) => text.length < 256 && /^[^\s@]\S*\s*$/.test(text) && /[./]/.test(text);

function walk(dir: string, out: string[]): void {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.isFile()) out.push(p);
  }
}

function loadCorpus(dir: string): Doc[] {
  const docs: Doc[] = [];
  const seen = new Set<string>();
  const add = (id: string, path: string) => {
    // a symlink is not read (opened with O_NOFOLLOW where the platform has it, so nothing changes between a check and the read)
    let bytes: Buffer;
    try {
      const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      try {
        bytes = readFileSync(fd);
      } finally {
        closeSync(fd);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ELOOP") return;
      throw error;
    }
    const sha = createHash("sha256").update(bytes).digest("hex");
    const text = bytes.toString("utf-8");
    if (seen.has(sha) || isLinkStub(text)) return;
    seen.add(sha);
    docs.push({ id, name: basename(path), text, size: bytes.length });
  };
  let index: string | null = null;
  try {
    index = readFileSync(join(dir, "index.json"), "utf-8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; // no index: every file under the directory
  }
  if (index !== null) {
    type Entry = { file: string; repo?: string; path?: string; symlinkStub?: boolean; duplicateOf?: string };
    for (const e of (JSON.parse(index) as { files: Entry[] }).files) {
      if (e.symlinkStub || e.duplicateOf) continue;
      add(e.repo && e.path ? `${e.repo} ${e.path}` : e.file, join(dir, e.file));
    }
  } else {
    const files: string[] = [];
    walk(dir, files);
    for (const f of files.sort()) add(relative(dir, f), f);
  }
  return docs;
}

// ── classify() drivers (as classify.test.ts drives it) ──────────────────────

const KEY = Buffer.alloc(32, 5);
const signer = signerFor(KEY);
const hashers = { unit: unitHasher(KEY), nonce: (t: string) => signer.hmac16("nonce", t) };
const HOME = "/home/u";
const ROOT = "/home/u/app";
const T0 = new Date("2026-10-20T09:00:00.000Z");
const T1 = Date.parse("2026-10-21T09:00:00.000Z");
const NOW = new Date("2026-10-23T09:00:00.000Z");
type Stores = ClassifyInput["stores"];
const NONE: Stores = { global: { doc: null, tamper: null }, project: { doc: null, tamper: null }, memory: { doc: null, tamper: null } };

function entry(path: string, role: WatchedRole, content: string | null): SnapshotEntry {
  if (content === null) return { path, key: path, role, state: "missing", sha256: null, size: null, stat: null, link: null, content: null, reused: false };
  const bytes = Buffer.from(content);
  return { path, key: path, role, state: "file", sha256: sha256Hex(bytes), size: bytes.length, stat: [bytes.length, T1, T1, 1, 1], link: null, content: bytes, reused: false };
}

function snapshot(e: SnapshotEntry): Snapshot {
  const store = (kind: "global" | "project" | "memory", id: Snapshot["global"]["id"], root: string | null, entries: SnapshotEntry[]) =>
    ({ kind, id, root, entries: Object.fromEntries(entries.map((x) => [x.key, x])) });
  return {
    global: store("global", "global", null, []),
    project: store("project", "project-0123456789abcdef", ROOT, [e]),
    memory: store("memory", "memory-0123456789abcdef", `${HOME}/.claude/projects/-home-u-app/memory`, []),
    globalScope: { dirs: ["/etc/claude-code", `${HOME}/.claude`], files: [`${HOME}/.claude.json`] },
    unstableCodexDirs: [], prefixScopes: {},
    unhashed: [], unreached: [], incomplete: false, hashedBytes: 0, files: 0,
  };
}

const run = (stores: Stores, snap: Snapshot, now = NOW): ClassifyResult =>
  classify({ stores, snapshot: snap, ledger: [], windows: () => [], config: { agentWindowEscalation: true }, now, hashers, home: HOME, platform: "linux" });

function committed(r: ClassifyResult): Stores {
  const doc = (d: UnsignedStoreDoc | null | undefined) => (d ? (JSON.parse(JSON.stringify(d)) as StoreDoc) : null);
  const memory: StoreInput | null = r.stores.memory ? { doc: doc(r.stores.memory.next), tamper: null } : null;
  return { global: { doc: doc(r.stores.global.next), tamper: null }, project: { doc: doc(r.stores.project.next), tamper: null }, memory };
}

type Tier = { tier: string; rules: string[]; reasons: string[] };
function tierOf(r: ClassifyResult, path: string): Tier {
  const it = r.items.find((i) => i.path === path);
  return it ? { tier: it.tier, rules: it.rules, reasons: it.reasons } : { tier: "SILENT", rules: [], reasons: [] };
}

// ── Measure ─────────────────────────────────────────────────────────────────

type Row = { id: string; size: number; lines: number; first: Tier; created: Tier; verdict: { reason: string; strong: boolean; lines?: Verdict["lines"] } | null };

const docs = loadCorpus(DIR);
const rows: Row[] = [];
const started = performance.now();
for (const d of docs) {
  const agents = /agents\.md$/i.test(d.name);
  const role: WatchedRole = agents ? "ancestor-agents-md" : "ancestor-claude-md";
  const path = `${ROOT}/${agents ? "AGENTS.md" : "CLAUDE.md"}`;
  const first = tierOf(run(NONE, snapshot(entry(path, role, d.text))), path);
  const base = committed(run(NONE, snapshot(entry(path, role, null)), T0));
  const created = tierOf(run(base, snapshot(entry(path, role, d.text))), path);
  const v = markdownVerdict(d.text.length > SCAN_CAP_CHARS ? d.text.slice(0, SCAN_CAP_CHARS) : d.text);
  // `lines` is not enumerable (see Verdict): copy it so --json keeps it.
  const verdict = v && { reason: v.reason, strong: v.strong, ...(v.lines ? { lines: v.lines } : {}) };
  rows.push({ id: d.id, size: d.size, lines: d.text.split("\n").length, first, created, verdict });
}
const elapsed = performance.now() - started;

const pct = (n: number, of: number) => `${of ? ((100 * n) / of).toFixed(1) : "0.0"}%`;
const flagged = rows.filter((r) => r.first.tier !== "SILENT");
const count = (tier: string) => rows.filter((r) => r.first.tier === tier).length;
console.log(`${rows.length} files (${(rows.reduce((n, r) => n + r.size, 0) / 1024).toFixed(0)} KB), screened in ${(elapsed / 1000).toFixed(1)} s`);
console.log(`first fingerprint: ${flagged.length} flagged (${pct(flagged.length, rows.length)}): NOTICE ${count("NOTICE")}, SUSPECT ${count("SUSPECT")}`);
console.log(`created after a baseline: ${rows.filter((r) => r.created.tier === "SUSPECT").length} SUSPECT, ${rows.filter((r) => r.created.tier === "NOTICE").length} NOTICE`);
console.log("flagged by size:");
for (const [lo, hi, label] of [[0, 2048, "under 2 KB"], [2048, 5120, "2-5 KB"], [5120, 10240, "5-10 KB"], [10240, 20480, "10-20 KB"], [20480, Infinity, "over 20 KB"]] as const) {
  const of = rows.filter((r) => r.size >= lo && r.size < hi);
  const hit = of.filter((r) => r.first.tier !== "SILENT").length;
  console.log(`  ${label.padEnd(11)} ${String(hit).padStart(4)}/${String(of.length).padEnd(4)} ${pct(hit, of.length)}`);
}
const byReason = new Map<string, number>();
for (const r of flagged) {
  const reason = (r.first.reasons[0] ?? r.verdict?.reason ?? "?").replace(/\([^)]*\)/g, "(…)");
  byReason.set(reason, (byReason.get(reason) ?? 0) + 1);
}
console.log("flagged by reason shown:");
for (const [reason, n] of [...byReason].sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(4)}  ${reason}`);
console.log("hits (first-fingerprint tier, lines of the deciding text, file, reason):");
for (const r of flagged) {
  const at = r.verdict?.lines ? `L${r.verdict.lines.from}-L${r.verdict.lines.to}` : "-";
  console.log(`  ${r.first.tier.padEnd(7)} ${at.padEnd(12)} ${r.id}: ${r.first.reasons[0] ?? r.verdict?.reason ?? ""}`);
}

// ── The attack corpora ──────────────────────────────────────────────────────

let attacks: Record<string, unknown> | null = null;
if (flag("--attacks")) {
  type Attack = { kind: string; payload?: string; filePath?: string };
  const files = ["adaptive-corpus.json", "adaptive-corpus-heldout.json", "adaptive-corpus-round3.json", "adaptive-corpus-round4.json"];
  let all = 0, screened = 0, caught = 0, strong = 0, capDeny = 0, writeDeny = 0;
  const missed: string[] = [];
  for (const f of files) {
    const list = (JSON.parse(readFileSync(new URL(`../src/guard/${f}`, import.meta.url), "utf-8")) as { attacks: Attack[] }).attacks;
    list.forEach((a, i) => {
      const payload = a.payload ?? "";
      all++;
      if (detectContentCapabilities(payload).some((c) => c.decision === "deny")) capDeny++;
      if (a.kind === "filewrite" && a.filePath && inspectFileWrite(a.filePath, payload).decision === "deny") writeDeny++;
      if (a.kind !== "content" && !(a.kind === "filewrite" && /\.(?:md|mdc)$|cursorrules$/i.test(a.filePath ?? ""))) return;
      screened++;
      const v = markdownVerdict(payload);
      if (!v) return void missed.push(`${f}#${i}`);
      caught++;
      if (v.strong) strong++;
    });
  }
  attacks = { attacks: all, screened, caught, strong, missed, contentCapabilityDenials: capDeny, fileWriteDenials: writeDeny };
  console.log(`attack corpora: content and Markdown file-write attacks caught ${caught}/${screened} (${strong} strong); ` +
    `content-capability denials ${capDeny}/${all}; file-write denials ${writeDeny}`);
}

const out = option("--json");
if (out) writeFileSync(out, JSON.stringify({ files: rows.length, flagged: flagged.length, rows, attacks }, null, 1));
