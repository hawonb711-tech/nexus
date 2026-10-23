/**
 * Instruction-file integrity — the `@path` imports of CLAUDE.md-style files
 * (spec §3.5). Claude Code inlines an imported file into the instructions, so
 * each target is watched like the file that imports it.
 *
 * - Tokens: `(?:^|\s)@path` per line, outside fenced blocks and inline code
 *   spans; a token counts only if it contains `/` or ends in `.ext` (1-8 word
 *   characters), which leaves `@mentions` alone.
 * - Resolution: `~/` from home, absolute as is, anything else from the importing
 *   file's directory.
 * - Recursion: targets import further targets, to depth 4; cycles are cut by
 *   real path; at most 50 targets (then the result is marked truncated).
 * - A target that does not exist is kept, as `missing`, only when its token was
 *   explicitly a path (`./`, `../`, `~/` or `/`), so a later file planted there
 *   shows up; a bare token that resolves to nothing is not an import.
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

const IMPORT_TOKEN = /(?:^|\s)@((?:~\/|\.{1,2}\/|\/)?[^\s`'"<>()[\]]{1,512})/g;
/** Characters a token may continue with: a match that stops at its 512 cap on one of these was cut short. */
const TOKEN_CHAR = /[^\s`'"<>()[\]]/;
const HAS_EXTENSION = /\.\w{1,8}$/;
const EXPLICIT_PATH = /^(?:\.{1,2}\/|~\/|\/)/;

/** The `@path` tokens of a Markdown text that count as imports, in order. */
export function importTokens(text: string): string[] {
  const out: string[] = [];
  forEachMarkdownLine(text, (line, kind) => {
    if (kind !== "text" || !line.includes("@")) return;
    const masked = maskCodeSpans(line, codeSpans(line));
    for (const m of masked.matchAll(IMPORT_TOKEN)) {
      const token = m[1];
      const end = m.index + m[0].length;
      if (end < masked.length && TOKEN_CHAR.test(masked[end])) continue; // longer than 512
      if (token.includes("/") || HAS_EXTENSION.test(token)) out.push(token);
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
};

/**
 * Every import reachable from `sources`, breadth first (so the shallowest
 * imports win the target cap). `truncated` is set when the cap cut the walk.
 */
export function resolveImports(sources: readonly ImportSource[], opts: ImportOptions): { targets: ImportTarget[]; truncated: boolean } {
  const load = opts.load ?? readImportTarget;
  const maxDepth = opts.maxDepth ?? MAX_IMPORT_DEPTH;
  const maxTargets = opts.maxTargets ?? MAX_IMPORT_TARGETS;
  const visited = new Set<string>(sources.map((s) => realPathOrNull(s.path) ?? s.path));
  const recorded = new Set<string>();
  const targets: ImportTarget[] = [];
  let level: ImportSource[] = [...sources];
  for (let depth = 1; depth <= maxDepth && level.length > 0; depth++) {
    const next: ImportSource[] = [];
    for (const source of level) {
      for (const token of importTokens(source.text)) {
        const abs = resolveImportToken(token, source.path, opts.home);
        const path = canonicalPath(abs);
        if (recorded.has(path)) continue;
        if (targets.length >= maxTargets) return { targets, truncated: true };
        const found = load(abs);
        if (!found) {
          if (!EXPLICIT_PATH.test(token)) continue;
          recorded.add(path);
          targets.push({ path, role: importRoleOf(path, opts), state: "missing", from: source.path, depth });
          continue;
        }
        recorded.add(path);
        if (visited.has(found.real)) continue; // a cycle back to a file already scanned
        visited.add(found.real);
        targets.push({ path, role: importRoleOf(path, opts), state: "file", from: source.path, depth });
        if (found.text !== null) next.push({ path, text: found.text });
      }
    }
    level = next;
  }
  return { targets, truncated: false };
}
