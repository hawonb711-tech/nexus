/**
 * Zero-dependency secret scanner.
 *
 * Two surfaces:
 *   1. Working tree — walks the project and scans every text file (including
 *      dotfiles like .env / .npmrc, which generic code walkers skip but which
 *      are the single most common place real secrets leak).
 *   2. Git history — parses `git log -p` so a secret that was committed and
 *      later removed is still surfaced; it remains exposed in history even
 *      though the working tree no longer shows it. This is the high-value case
 *      for a credential-leak audit.
 *
 * Detection = high-precision vendor/assignment regexes (always on) plus an
 * optional Shannon-entropy heuristic for unrecognized high-randomness strings.
 * Every reported secret is redacted — the raw value is never stored or printed.
 */

import { readFile, readdir, stat } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join, relative, resolve } from "node:path";
import { createHash } from "node:crypto";
import { shannonEntropy } from "../promptguard/entropy.js";
import { SECRET_RULES } from "./patterns.js";
import type {
  SecretFinding,
  SecretScanOptions,
  SecretScanResult,
  SecretSeverity,
} from "./types.js";

// ── Tunables ──────────────────────────────────────────────────────────────────
const DEFAULT_MAX_FILE_SIZE = 1024 * 1024; // 1 MiB
const DEFAULT_MAX_COMMITS = 1000;
const DEFAULT_MAX_FINDINGS = 1000;
const MAX_FILES = 50_000;
const GIT_MAX_BUFFER = 512 * 1024 * 1024; // 512 MiB cap on `git log -p` output

/** Directories never worth scanning for secrets. .git is excluded here because
 *  history is scanned separately and structurally, not as raw files. */
const DEFAULT_IGNORE_DIRS = new Set([
  ".git", "node_modules", "dist", "build", "out", "coverage",
  ".next", ".nuxt", ".cache", ".venv", "venv", "__pycache__", "target", "vendor",
]);

/** Files that are almost always machine-generated high-entropy noise. Pattern
 *  detection still runs on them (a real key in a lockfile is still a key), but
 *  the entropy heuristic is suppressed to avoid drowning in hashes. */
const ENTROPY_SKIP_RE = /(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Cargo\.lock|\.min\.js|\.map|\.snap)$/i;

// ── Entropy heuristic ──────────────────────────────────────────────────────────
const SECRET_CHARSET = /^[A-Za-z0-9+/_\-=.]+$/;
const ENTROPY_THRESHOLD = 3.8; // bits/char for a 20+ char mixed-class token
const PLACEHOLDER_RE =
  /(your[_-]?|example|sample|placeholder|change[_-]?me|dummy|redacted|xxxx|todo|fixme|insert[_-]|fake|foobar|lorem|test[_-]?(?:key|token|secret|password)|<[^>]+>)/i;

/** True for values that look like a stand-in rather than a live credential. */
function isPlaceholder(secret: string): boolean {
  const s = secret.trim();
  if (!s) return true;
  if (/^\$\{?[A-Za-z0-9_]+\}?$/.test(s)) return true;          // $ENV or ${ENV}
  if (/\b(?:process\.env|os\.environ|getenv|ENV\[)/i.test(s)) return true;
  if (/^[*x._\-]+$/i.test(s)) return true;                      // all mask chars
  if (PLACEHOLDER_RE.test(s)) return true;
  if (new Set(s.replace(/[-_./+=]/g, "")).size <= 2) return true; // e.g. "aaaaaaaa"
  return false;
}

/**
 * Extra shape guard for `generic` (key-name-based) rule captures, whose value
 * carries no vendor prefix to anchor on. Rejects the common false positives:
 * URLs, filesystem paths, and bare version/number strings; requires the value
 * to actually look credential-like (mixed character classes or real entropy).
 */
function looksLikeSecretValue(s: string): boolean {
  if (s.length < 8) return false;                       // too short to be a credential
  if (/^https?:\/\//i.test(s)) return false;            // URL
  if ((s.match(/\//g) ?? []).length >= 2) return false; // path-like a/b/c (real keys rarely have 2+ slashes)
  if (/^v?\d[\d.\-_]*$/.test(s)) return false;          // pure version / number
  const classes =
    (/[a-z]/.test(s) ? 1 : 0) + (/[A-Z]/.test(s) ? 1 : 0) + (/[0-9]/.test(s) ? 1 : 0);
  return classes >= 2 || shannonEntropy(s) >= 3.5;
}

/** Candidate high-entropy tokens on a line (entropy mode only). */
function entropyTokens(line: string): string[] {
  const out: string[] = [];
  for (const tok of line.split(/[\s"'`=:;,()[\]{}<>|/\\]+/)) {
    if (tok.length < 20 || tok.length > 128) continue;
    if (!SECRET_CHARSET.test(tok)) continue;
    if (isPlaceholder(tok)) continue;
    const classes =
      (/[A-Z]/.test(tok) ? 1 : 0) + (/[a-z]/.test(tok) ? 1 : 0) + (/[0-9]/.test(tok) ? 1 : 0);
    if (classes < 2) continue;             // pure words / pure hex-lowercase excluded
    if (shannonEntropy(tok) >= ENTROPY_THRESHOLD) out.push(tok);
  }
  return out;
}

// ── Redaction ───────────────────────────────────────────────────────────────────
export function redactSecret(secret: string): string {
  const s = secret.trim();
  if (s.length <= 8) return s.slice(0, 1) + "*".repeat(Math.max(3, s.length - 1));
  return `${s.slice(0, 4)}${"*".repeat(Math.min(12, s.length - 6))}${s.slice(-2)}`;
}

/** Replace a raw secret inside its surrounding line with the redacted form. */
function redactEvidence(line: string, secret: string, redacted: string): string {
  const replaced = line.split(secret).join(redacted).trim();
  return replaced.length > 160 ? replaced.slice(0, 157) + "..." : replaced;
}

// ── Line-level detection ─────────────────────────────────────────────────────────
type RawHit = { rule: string; detector: "pattern" | "entropy"; severity: SecretSeverity; secret: string };

function scanLine(line: string, entropy: boolean, entropyAllowed: boolean): RawHit[] {
  const hits: RawHit[] = [];
  const claimed = new Set<string>(); // secrets already flagged on this line (dedupe across rules)

  for (const rule of SECRET_RULES) {
    rule.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.re.exec(line)) !== null) {
      if (m[0].length === 0) { rule.re.lastIndex++; continue; } // avoid zero-width loop
      const secret = (rule.group != null ? m[rule.group] : m[0]) ?? "";
      if (!secret || isPlaceholder(secret) || claimed.has(secret)) continue;
      if (rule.generic && !looksLikeSecretValue(secret)) continue; // shape guard for key-name rules
      claimed.add(secret);
      hits.push({ rule: rule.label, detector: "pattern", severity: rule.severity, secret });
    }
  }

  // Entropy runs independently of pattern matches — a real high-entropy secret
  // can share a line with a low-value pattern hit. `claimed` dedupes so the same
  // token is never reported twice.
  if (entropy && entropyAllowed) {
    for (const tok of entropyTokens(line)) {
      if (claimed.has(tok)) continue;
      claimed.add(tok);
      hits.push({ rule: "high-entropy string", detector: "entropy", severity: "medium", secret: tok });
    }
  }
  return hits;
}

const SUGGESTION =
  "Rotate this credential immediately, then move it to an environment variable or secrets manager. " +
  "If it appears in git history, the secret is still exposed even after deletion — rotate, don't just remove.";

function makeFinding(
  base: Omit<SecretFinding, "id" | "redacted" | "evidence" | "suggestion" | "fingerprint"> & { rawLine: string; secret: string },
): SecretFinding {
  const redacted = redactSecret(base.secret);
  const fingerprint = createHash("sha256").update(base.secret).digest("hex").slice(0, 16);
  const id = createHash("sha256")
    .update(`${base.source}:${base.file}:${base.line}:${base.commit ?? ""}:${base.rule}:${fingerprint}`)
    .digest("hex").slice(0, 12);
  return {
    id,
    rule: base.rule,
    detector: base.detector,
    severity: base.severity,
    source: base.source,
    file: base.file,
    line: base.line,
    redacted,
    evidence: redactEvidence(base.rawLine, base.secret, redacted),
    commit: base.commit,
    commitDate: base.commitDate,
    author: base.author,
    stillPresent: base.stillPresent,
    fingerprint,
    suggestion: SUGGESTION,
  };
}

// ── Working-tree scan ────────────────────────────────────────────────────────────
function isProbablyBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 65536); // 64 KiB sniff window
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true; // NUL byte ⇒ binary
  return false;
}

/** Returns true if the hard MAX_FILES cap was hit (some files left unwalked). */
async function walkFiles(
  root: string,
  ignore: Set<string>,
  acc: string[],
): Promise<boolean> {
  if (acc.length >= MAX_FILES) return true;
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch {
    return false;
  }
  let capped = false;
  for (const entry of entries) {
    if (acc.length >= MAX_FILES) return true;
    if (ignore.has(entry.name)) continue;            // skip ignored dirs by name
    const full = join(root, entry.name);
    if (entry.isDirectory()) {
      if (await walkFiles(full, ignore, acc)) capped = true;
    } else if (entry.isFile()) {
      // NOTE: dotfiles (.env, .npmrc, ...) are intentionally NOT skipped.
      acc.push(full);
    }
  }
  return capped;
}

async function scanWorkingTree(
  rootDir: string,
  opts: { entropy: boolean; maxFileSize: number; ignore: Set<string> },
): Promise<{ findings: SecretFinding[]; filesScanned: number; filesSkipped: number; filesUnreadable: number; capped: boolean }> {
  const files: string[] = [];
  const capped = await walkFiles(rootDir, opts.ignore, files);

  const findings: SecretFinding[] = [];
  let scanned = 0;
  let skipped = 0;       // too large / binary
  let unreadable = 0;    // existed but could not be read

  for (const path of files) {
    let info;
    try {
      info = await stat(path);
    } catch {
      unreadable++;
      continue;
    }
    if (info.size > opts.maxFileSize) { skipped++; continue; }

    let buf: Buffer;
    try {
      buf = await readFile(path);
    } catch {
      unreadable++;       // e.g. EACCES — surface it; the user must know a file went unscanned
      continue;
    }
    if (isProbablyBinary(buf)) { skipped++; continue; }

    const rel = relative(rootDir, path) || path;
    const entropyAllowed = !ENTROPY_SKIP_RE.test(rel);
    const lines = buf.toString("utf-8").split("\n");
    scanned++;
    for (let i = 0; i < lines.length; i++) {
      for (const hit of scanLine(lines[i], opts.entropy, entropyAllowed)) {
        findings.push(makeFinding({
          rule: hit.rule, detector: hit.detector, severity: hit.severity,
          source: "working-tree", file: rel, line: i + 1,
          rawLine: lines[i], secret: hit.secret,
        }));
      }
    }
  }
  return { findings, filesScanned: scanned, filesSkipped: skipped, filesUnreadable: unreadable, capped };
}

// ── Git-history scan ─────────────────────────────────────────────────────────────
function isGitRepo(rootDir: string): boolean {
  const r = spawnSync("git", ["-C", rootDir, "rev-parse", "--is-inside-work-tree"], {
    encoding: "utf-8",
  });
  return r.status === 0 && r.stdout.trim() === "true";
}

const HUNK_RE = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/;
const COMMIT_MARKER = "@@NXCOMMIT@@";

function scanGitHistory(
  rootDir: string,
  opts: { entropy: boolean; maxCommits: number },
): { findings: SecretFinding[]; commitsScanned: number; truncatedCommits: boolean; unavailable?: string } {
  if (!isGitRepo(rootDir)) {
    return { findings: [], commitsScanned: 0, truncatedCommits: false, unavailable: "not a git repository (or git not installed)" };
  }

  // The format ARG stays plain ASCII — "%x09" is a git token (not a control
  // byte: Node rejects args containing NUL, and a space delimiter would corrupt
  // multi-word author names). git expands %x09 into a TAB in its OUTPUT, which
  // we split on. The @@NXCOMMIT@@ marker makes commit boundaries unambiguous
  // even if a diff line happens to resemble a header. -U0 drops context lines.
  const res = spawnSync("git", [
    "-C", rootDir, "log", "-p", "-U0", "--no-color", "--no-merges",
    `--max-count=${opts.maxCommits + 1}`,
    `--pretty=format:${COMMIT_MARKER}%x09%H%x09%ad%x09%an`,
    "--date=short",
  ], { encoding: "utf-8", maxBuffer: GIT_MAX_BUFFER });

  if (res.status !== 0 || typeof res.stdout !== "string") {
    const reason = res.error?.message ?? `git exited with status ${res.status}`;
    return { findings: [], commitsScanned: 0, truncatedCommits: false, unavailable: reason };
  }

  const findings: SecretFinding[] = [];
  let commit = "", date = "", author = "", file = "", newLineNo = 0;
  const seenCommits = new Set<string>();
  let capped = false;

  for (const line of res.stdout.split("\n")) {
    if (line.startsWith(COMMIT_MARKER)) {
      const parts = line.split("\t"); // [marker, hash, date, author]
      commit = (parts[1] ?? "").slice(0, 10);
      date = parts[2] ?? "";
      author = parts[3] ?? "";
      file = "";
      if (commit && !seenCommits.has(commit)) {
        if (seenCommits.size >= opts.maxCommits) { capped = true; break; }
        seenCommits.add(commit);
      }
      continue;
    }
    if (line.startsWith("+++ b/")) { file = line.slice(6); newLineNo = 0; continue; }
    if (line.startsWith("+++ ") || line.startsWith("--- ")) continue;
    const hunk = HUNK_RE.exec(line);
    if (hunk) { newLineNo = parseInt(hunk[1], 10); continue; }
    if (line.startsWith("diff --git")) { file = ""; continue; }

    if (line.startsWith("+")) {
      const added = line.slice(1);
      const lineNo = newLineNo > 0 ? newLineNo++ : 0;
      const entropyAllowed = !ENTROPY_SKIP_RE.test(file);
      for (const hit of scanLine(added, opts.entropy, entropyAllowed)) {
        findings.push(makeFinding({
          rule: hit.rule, detector: hit.detector, severity: hit.severity,
          source: "git-history", file: file || "(unknown)", line: lineNo,
          commit, commitDate: date, author,
          rawLine: added, secret: hit.secret,
        }));
      }
    }
  }

  return { findings, commitsScanned: seenCommits.size, truncatedCommits: capped };
}

// ── Orchestration ────────────────────────────────────────────────────────────────
const SEVERITY_ORDER: Record<SecretSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export async function scanForSecrets(
  root: string,
  options: SecretScanOptions = {},
): Promise<SecretScanResult> {
  const start = performance.now();
  const rootDir = resolve(root);
  const entropy = options.entropy ?? false;
  const maxFileSize = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const maxCommits = options.maxCommits ?? DEFAULT_MAX_COMMITS;
  const maxFindings = options.maxFindings ?? DEFAULT_MAX_FINDINGS;
  const ignore = new Set([...DEFAULT_IGNORE_DIRS, ...(options.ignore ?? [])]);

  const wt = await scanWorkingTree(rootDir, { entropy, maxFileSize, ignore });

  let history: { findings: SecretFinding[]; commitsScanned: number; truncatedCommits: boolean; unavailable?: string } =
    { findings: [], commitsScanned: 0, truncatedCommits: false };
  if (options.includeHistory) {
    history = scanGitHistory(rootDir, { entropy, maxCommits });

    // Mark which historical secrets still live in the working tree. Keyed on the
    // raw-secret fingerprint, not the lossy redaction, to avoid false matches.
    const present = new Set(wt.findings.map((f) => f.fingerprint));
    for (const f of history.findings) f.stillPresent = present.has(f.fingerprint);
  }

  // Merge, dedupe (same secret + location + source), then sort by severity. At
  // equal severity, working-tree (a live exposure) ranks above git-history.
  const byKey = new Map<string, SecretFinding>();
  for (const f of [...wt.findings, ...history.findings]) {
    const key = `${f.source}:${f.file}:${f.line}:${f.commit ?? ""}:${f.rule}:${f.fingerprint}`;
    if (!byKey.has(key)) byKey.set(key, f);
  }
  const sourceRank = (s: SecretFinding["source"]) => (s === "working-tree" ? 0 : 1);
  let findings = [...byKey.values()].sort((a, b) =>
    SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
    sourceRank(a.source) - sourceRank(b.source) ||
    a.file.localeCompare(b.file) ||
    a.line - b.line,
  );

  const truncated: SecretScanResult["truncated"] = {};
  if (wt.filesSkipped > 0) truncated.files = wt.filesSkipped;
  if (wt.filesUnreadable > 0) truncated.unreadable = wt.filesUnreadable;
  if (wt.capped) truncated.filesCapped = MAX_FILES;
  if (history.truncatedCommits) truncated.commits = maxCommits;
  if (history.unavailable) truncated.historyUnavailable = history.unavailable;
  if (findings.length > maxFindings) {
    truncated.findings = findings.length - maxFindings;
    findings = findings.slice(0, maxFindings);
  }

  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  const summary = findings.length === 0
    ? "No secrets detected."
    : `${findings.length} potential secret(s): ` +
      (["critical", "high", "medium", "low"] as SecretSeverity[])
        .filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(", ");

  return {
    findings,
    filesScanned: wt.filesScanned,
    commitsScanned: history.commitsScanned,
    durationMs: Math.round(performance.now() - start),
    truncated,
    summary,
  };
}
