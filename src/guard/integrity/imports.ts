/**
 * Instruction-file integrity — the `@path` imports of CLAUDE.md-style files
 * (spec §3.5). Claude Code inlines an imported file into the instructions, so
 * each target is watched like the file that imports it.
 *
 * - Tokens: Claude Code's grammar, per line, outside fenced blocks and inline
 *   code spans: `@`, then characters other than whitespace and `\`, or `\ `
 *   (an escaped space); a `#fragment` is cut off and `\ ` unescaped. Claude
 *   Code runs its `(?:^|\s)@` scan on each text token of the parsed Markdown,
 *   so inside inline markup a token starts right after it (`**@x.md**`,
 *   `[@x.md](…)`, `<b>@x.md</b>`) and ends where the markup closes. Without a
 *   Markdown parser this module over-collects instead: a token may also start
 *   after one of `* _ ~ [ ( > " ' |`, and one ending in closing markup or
 *   punctuation also yields the token cut there (at a `<` or `]`, then trailing
 *   `* _ ~ ) ] " ' | . , ; : ! ?` dropped). Watching a few extra files is the
 *   cost; missing one Claude Code loads is not. A token counts when Claude Code
 *   would load it: it starts with `./`, `~/`, `/` (plus more) or one of
 *   `[A-Za-z0-9._-]`.
 * - Resolution: `~/` from home, absolute as is, anything else from the importing
 *   file's directory.
 * - Recursion: targets import further targets, to depth 4; cycles are cut by
 *   real path; at most 50 targets and 500 distinct paths looked up (then the
 *   result is marked truncated). A repeated token costs no lookup.
 * - A target that does not exist is kept, as `missing`, only when its token was
 *   explicitly a path (`./`, `../`, `~/` or `/`) and does not itself end in
 *   markup (its cut form is recorded instead), so a later file planted there
 *   shows up; any other token that names no regular file (an `@mention`) is not
 *   an import.
 * - Role: `import` under the project root R or the config directory U,
 *   `external-import` anywhere else.
 */

import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { codeSpans, forEachMarkdownLine, maskCodeSpans } from "./markdown.js";
import { canonicalPath, isUnder, realPathOrNull } from "./paths.js";
import { MAX_FILE_BYTES } from "./types.js";

/** Imports nested deeper than this are not followed. */
export const MAX_IMPORT_DEPTH = 4;
/** Import targets per run. */
export const MAX_IMPORT_TARGETS = 50;
/**
 * Distinct token paths looked up per run, found or not. `@mentions` that name no
 * file are not targets, so without this one instruction file of them would cost
 * a filesystem call each, unbounded.
 */
export const MAX_IMPORT_LOOKUPS = 500;

/**
 * Claude Code's token grammar (2.1.309), with this module's 512-unit cap; a
 * token may also start right after inline markup (see the module comment).
 */
const IMPORT_TOKEN = /(?:^|[\s*_~[(>"'|])@((?:[^\s\\]|\\ ){1,512})/g;
/** Tokens Claude Code tries to load. */
const LOADABLE = /^(?:\.\/|~\/|\/.|[A-Za-z0-9._-])/;
const EXPLICIT_PATH = /^(?:\.{1,2}\/|~\/|\/)/;
/** Characters inline markup or a sentence may close a token with. */
const CLOSING = new Set([..."*_~)]\"'|.,;:!?"]);

/**
 * `token` cut where inline markup around it would close: before the first `<`
 * (an HTML tag) or `]` (a link text's end), then without trailing closing
 * markup or punctuation. Linear, no regex.
 */
export function trimMarkup(token: string): string {
  let end = token.length;
  for (let i = 0; i < token.length; i++) {
    const c = token.charCodeAt(i);
    if (c === 60 || c === 93) { // < ]
      end = i;
      break;
    }
  }
  while (end > 0 && CLOSING.has(token[end - 1])) end--;
  return token.slice(0, end);
}

/** Does the token grammar continue at `i`? (A match that stopped there hit its cap.) */
function tokenContinues(s: string, i: number): boolean {
  if (i >= s.length) return false;
  return s.charCodeAt(i) === 92 ? s.charCodeAt(i + 1) === 32 : !/\s/.test(s[i]);
}

/**
 * The `@path` tokens of a Markdown text that count as imports, in order. A
 * token that ends in markup comes as its cut form (`trimMarkup`) first, then
 * as written.
 */
export function importTokens(text: string): string[] {
  const out: string[] = [];
  forEachMarkdownLine(text, (line, kind) => {
    if (kind !== "text" || !line.includes("@")) return;
    const masked = maskCodeSpans(line, codeSpans(line));
    for (const m of masked.matchAll(IMPORT_TOKEN)) {
      if (tokenContinues(masked, m.index + m[0].length)) continue; // longer than 512
      const hash = m[1].indexOf("#");
      const token = (hash < 0 ? m[1] : m[1].slice(0, hash)).replace(/\\ /g, " ");
      const cut = trimMarkup(token);
      // a cut form that names a directory (`@a/<b>` → `a/`) or nothing is no import
      if (cut !== token && cut !== "" && !cut.endsWith("/") && !cut.endsWith("\\") && LOADABLE.test(cut)) out.push(cut);
      if (LOADABLE.test(token)) out.push(token);
    }
  });
  return out;
}

/** Where a token points, seen from the file that holds it. */
export function resolveImportToken(token: string, fromFile: string, home: string): string {
  if (token.startsWith("~/")) return join(home, token.slice(2));
  if (isAbsolute(token)) return resolve(token);
  return resolve(dirname(fromFile), token);
}

export type ImportRole = "import" | "external-import";

/** `import` when the target is under R or U, `external-import` otherwise. */
export function importRoleOf(path: string, ctx: { root: string; configDir: string; platform: NodeJS.Platform }): ImportRole {
  return isUnder(path, ctx.root, ctx.platform) || isUnder(path, ctx.configDir, ctx.platform) ? "import" : "external-import";
}

/** A file to scan: its path and Markdown text. */
export type ImportSource = { path: string; text: string };

export type ImportTarget = {
  /** Canonical path (see `canonicalPath`). */
  path: string;
  role: ImportRole;
  state: "file" | "missing";
  /** The file whose token named it. */
  from: string;
  /** 1 for a source's own imports, up to MAX_IMPORT_DEPTH. */
  depth: number;
};

/**
 * Reads an import target: null when no regular file is there; otherwise its real
 * path (for the cycle cut) and its text, or null text when it is too large or
 * unreadable to scan for further imports.
 */
export type ImportLoader = (path: string) => { real: string; text: string | null } | null;

/** Reads up to MAX_FILE_BYTES of a regular file without following it into a FIFO. */
const readImportTarget: ImportLoader = (path) => {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch {
    return null;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return null;
    const real = realPathOrNull(path) ?? path;
    if (st.size > MAX_FILE_BYTES) return { real, text: null };
    const buf = Buffer.alloc(st.size);
    let n = 0;
    while (n < buf.length) {
      const r = readSync(fd, buf, n, buf.length - n, null);
      if (r === 0) break;
      n += r;
    }
    return { real, text: buf.subarray(0, n).toString("utf-8") };
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
};

export type ImportOptions = {
  home: string;
  root: string;
  configDir: string;
  platform: NodeJS.Platform;
  load?: ImportLoader;
  maxDepth?: number;
  maxTargets?: number;
  maxLookups?: number;
};

export type ImportResult = {
  targets: ImportTarget[];
  /** A cap (targets or lookups) cut the walk. */
  truncated: boolean;
  /** Paths `load` was asked about. */
  lookups: number;
};

/**
 * Every import reachable from `sources`, breadth first (so the shallowest
 * imports win the target cap). `truncated` is set when a cap cut the walk.
 * Repeats are recognised on the resolved token path, before any filesystem
 * call; only a token that names a file, or an explicit path recorded as
 * missing, is canonicalised.
 */
export function resolveImports(sources: readonly ImportSource[], opts: ImportOptions): ImportResult {
  const load = opts.load ?? readImportTarget;
  const maxDepth = opts.maxDepth ?? MAX_IMPORT_DEPTH;
  const maxTargets = opts.maxTargets ?? MAX_IMPORT_TARGETS;
  const maxLookups = opts.maxLookups ?? MAX_IMPORT_LOOKUPS;
  const visited = new Set<string>(sources.map((s) => realPathOrNull(s.path) ?? s.path));
  /** Canonical paths already recorded (or cut as a cycle). */
  const recorded = new Set<string>();
  /** Resolved token paths with nothing left to do. */
  const handled = new Set<string>();
  /** Resolved token paths found to hold no regular file (`@mentions` repeat). */
  const absent = new Set<string>();
  const targets: ImportTarget[] = [];
  let lookups = 0;
  let level: ImportSource[] = [...sources];
  for (let depth = 1; depth <= maxDepth && level.length > 0; depth++) {
    const next: ImportSource[] = [];
    for (const source of level) {
      for (const token of importTokens(source.text)) {
        const abs = resolveImportToken(token, source.path, opts.home);
        if (handled.has(abs)) continue;
        const explicit = EXPLICIT_PATH.test(token);
        if (!explicit && absent.has(abs)) continue;
        if (targets.length >= maxTargets) return { targets, truncated: true, lookups };
        let found: ReturnType<ImportLoader> = null;
        if (!absent.has(abs)) {
          if (lookups >= maxLookups) return { targets, truncated: true, lookups };
          lookups++;
          found = load(abs);
          if (!found) absent.add(abs);
        }
        // an explicit token that ends in markup is recorded missing only in its cut form
        if (!found && (!explicit || trimMarkup(token) !== token)) continue;
        handled.add(abs);
        const path = canonicalPath(abs);
        if (recorded.has(path)) continue;
        recorded.add(path);
        if (!found) {
          targets.push({ path, role: importRoleOf(path, opts), state: "missing", from: source.path, depth });
          continue;
        }
        if (visited.has(found.real)) continue; // a cycle back to a file already scanned
        visited.add(found.real);
        targets.push({ path, role: importRoleOf(path, opts), state: "file", from: source.path, depth });
        if (found.text !== null) next.push({ path, text: found.text });
      }
    }
    level = next;
  }
  return { targets, truncated: false, lookups };
}
