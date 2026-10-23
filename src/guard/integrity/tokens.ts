/**
 * Instruction-file integrity — actionable tokens (spec §5.2): the URLs, hosts,
 * emails, home/system paths and command arguments a line of instructions could
 * make an agent act on. A token no accepted instruction file already carries is
 * *novel*; novel tokens in held lines become session indicators (the tripwire),
 * and novel tokens in a memory write after web/MCP exposure ask first.
 *
 * Extraction is regex-only with bounded quantifiers (one linear pass per token
 * type); the email domain's TLD is checked by a scan instead of a backtracking
 * suffix. Tokens are compared as `hmac16("unit", "t\0" + lower(token))`, the
 * hashes the store's `tok` lists hold. Pure; no I/O.
 */

import { codeSpans, forEachMarkdownLine, spanText } from "./markdown.js";
import { isUnder } from "./paths.js";
import type { UnitHasher } from "./units.js";

/** Hosts too common to be an indicator. */
export const COMMON_HOSTS: ReadonlySet<string> = new Set([
  "github.com", "gitlab.com", "bitbucket.org", "registry.npmjs.org", "npmjs.com", "pypi.org",
  "files.pythonhosted.org", "crates.io", "localhost", "127.0.0.1", "example.com", "example.org",
]);

/** Commands whose argument (a package, script or target) is an actionable token. */
export const CMD_HEADS: ReadonlySet<string> = new Set([
  "curl", "wget", "sh", "bash", "zsh", "python", "python3", "node", "npx", "bunx", "pnpm", "yarn",
  "pip", "pip3", "npm", "uvx", "iwr", "irm", "invoke-webrequest", "invoke-expression", "iex", "ssh",
  "scp", "nc", "ncat", "socat", "base64", "eval", "powershell", "pwsh",
]);

/**
 * Words skipped between a command head and its argument: the spec's `dlx`,
 * `exec` (and `-y`, a flag anyway), plus the package-manager verbs `install`,
 * `i`, `add`, `run` and `x`, so `pip install <pkg>` yields the package, not the verb.
 */
const SKIP_WORDS = new Set(["dlx", "exec", "install", "i", "add", "run", "x"]);
/** Words that end a simple command: its argument cannot come after them. */
const SHELL_OPERATOR = /^(?:\|{1,2}|&{1,2}|;|[<>]{1,2}|\d?>{1,2}|&>)/;

const URL_TOKEN = /https?:\/\/[^\s"'`<>)\]]{1,2048}/gi;
const GIT_HOST = /\bgit@([A-Za-z0-9.-]{1,253}):/g;
const SSH_HOST = /\bssh[ \t]{1,8}(?:[A-Za-z0-9._-]{1,64}@)?([A-Za-z0-9][A-Za-z0-9.-]{0,252})/g;
/** The local part only starts a match at the start of a run (lookbehind), so a long run is scanned once. */
const EMAIL_CANDIDATE = /(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]{1,278})/g;
const PATH_TOKEN =
  /(?<![^\s"'`(=[,:])(?:~\/|\$HOME\/|\$\{HOME\}\/|\/etc\/|\/root\/|\/home\/[^\s/"'`]{1,64}\/|\/Users\/[^\s/"'`]{1,64}\/|%USERPROFILE%|[A-Za-z]:\\Users\\)[^\s"'`<>()[\]]{0,1024}/gi;
const TRAILING_URL_PUNCT = /[.,;:]{1,64}$/;
const TRAILING_PATH_PUNCT = /[.,;:)]{1,64}$/;

const MIN_URL = 12;
const MIN_OTHER = 6;

export type TokenType = "url" | "host" | "email" | "path" | "cmd";
export type ActionableToken = { type: TokenType; value: string };

export type TokenOptions = {
  /** R: paths under the project root are not actionable. */
  root?: string | null;
  /** For expanding `~/`, `$HOME/` and `%USERPROFILE%` before the R check. */
  home?: string;
  platform?: NodeJS.Platform;
  /** Treat every line as a command line (for command strings from JSON units), not as Markdown. */
  commands?: boolean;
};

/** A URL with its query and fragment cut, trailing `.,;:` stripped and scheme + authority lower-cased, plus its host. */
function normalizeUrl(raw: string): { url: string; host: string } {
  let u = raw;
  for (const sep of ["?", "#"]) {
    const at = u.indexOf(sep);
    if (at >= 0) u = u.slice(0, at);
  }
  u = u.replace(TRAILING_URL_PUNCT, "");
  const schemeEnd = u.indexOf("://") + 3;
  const slash = u.indexOf("/", schemeEnd);
  const authorityEnd = slash < 0 ? u.length : slash;
  const authority = u.slice(schemeEnd, authorityEnd).toLowerCase();
  const url = u.slice(0, schemeEnd).toLowerCase() + authority + u.slice(authorityEnd);
  return { url, host: hostOf(authority) };
}

/** The host of a URL authority: no userinfo, no port, no IPv6 brackets. */
function hostOf(authority: string): string {
  const at = authority.lastIndexOf("@");
  let h = at >= 0 ? authority.slice(at + 1) : authority;
  if (h.startsWith("[")) {
    const close = h.indexOf("]");
    return close > 0 ? h.slice(1, close) : h.slice(1);
  }
  const colon = h.indexOf(":");
  if (colon >= 0) h = h.slice(0, colon);
  return h.replace(/\.$/, "");
}

const isLetter = (c: number) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122);

/**
 * `local@domain` cut where `[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}` would match:
 * the rightmost dot (after at least one character) followed by 2-24 letters.
 */
function email(local: string, domain: string): string | null {
  for (let i = Math.min(domain.length - 1, 253); i >= 1; i--) {
    if (domain[i] !== ".") continue;
    let j = i + 1;
    while (j < domain.length && j - i - 1 < 24 && isLetter(domain.charCodeAt(j))) j++;
    if (j - i - 1 >= 2) return `${local}@${domain.slice(0, j)}`;
  }
  return null;
}

/** The token a command line names: the first non-flag, non-URL argument after a CMD_HEADS head. */
export function commandToken(line: string): string | null {
  const words = line.trim().split(/[ \t]{1,64}/).filter((w) => w !== "");
  const head = words[0]?.replace(/^.*[\\/]/, "").toLowerCase();
  if (!head || !CMD_HEADS.has(head)) return null;
  for (const word of words.slice(1)) {
    if (SHELL_OPERATOR.test(word)) return null;
    if (word.startsWith("-") || SKIP_WORDS.has(word.toLowerCase())) continue;
    const arg = word.replace(/^["']{1,8}|["']{1,8}$/g, "");
    if (/^[a-z][a-z0-9+.-]{0,16}:\/\//i.test(arg)) continue;
    return arg.length >= MIN_OTHER ? arg : null;
  }
  return null;
}

/** Lines that hold commands: fenced code, inline code spans, and lines starting with `$ `. */
function commandLines(text: string, all: boolean): string[] {
  if (all) return text.split("\n");
  const out: string[] = [];
  forEachMarkdownLine(text, (line, kind) => {
    if (kind === "fence") return;
    if (kind === "code") {
      out.push(line.replace(/^[ \t]{0,16}\$[ \t]/, ""));
      return;
    }
    const trimmed = line.trimStart();
    if (trimmed.startsWith("$ ")) out.push(trimmed.slice(2));
    if (line.includes("`")) for (const span of codeSpans(line)) out.push(spanText(line, span));
  });
  return out;
}

function expandHome(path: string, home: string | undefined): string {
  if (!home) return path;
  if (path.startsWith("~/")) return `${home}/${path.slice(2)}`;
  if (path.startsWith("$HOME/")) return `${home}/${path.slice(6)}`;
  if (path.startsWith("${HOME}/")) return `${home}/${path.slice(8)}`;
  if (/^%USERPROFILE%/i.test(path)) return home + path.slice(13);
  return path;
}

/** Every actionable token in `text`, deduplicated case-insensitively, grouped by type. */
export function extractTokens(text: string, opts: TokenOptions = {}): ActionableToken[] {
  const out: ActionableToken[] = [];
  const seen = new Set<string>();
  const push = (type: TokenType, value: string) => {
    const k = value.toLowerCase();
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ type, value });
  };
  const hosts: string[] = [];

  for (const m of text.matchAll(URL_TOKEN)) {
    const { url, host } = normalizeUrl(m[0]);
    if (url.length >= MIN_URL) push("url", url);
    hosts.push(host);
  }
  for (const m of text.matchAll(GIT_HOST)) hosts.push(m[1].toLowerCase());
  for (const m of text.matchAll(SSH_HOST)) hosts.push(m[1].toLowerCase().replace(/\.$/, ""));
  for (const host of hosts) if (host.length >= MIN_OTHER && !COMMON_HOSTS.has(host)) push("host", host);

  for (const m of text.matchAll(EMAIL_CANDIDATE)) {
    const e = email(m[1], m[2]);
    if (e) push("email", e);
  }

  const platform = opts.platform ?? "linux";
  for (const m of text.matchAll(PATH_TOKEN)) {
    const path = m[0].replace(TRAILING_PATH_PUNCT, "");
    if (path.length < MIN_OTHER) continue;
    if (opts.root && isUnder(expandHome(path, opts.home), opts.root, platform)) continue;
    push("path", path);
  }

  for (const line of commandLines(text, opts.commands === true)) {
    const token = commandToken(line);
    if (token) push("cmd", token);
  }
  return out;
}

/** `hmac16("unit", "t\0" + lower(token))`. */
export function tokenHash(hash: UnitHasher, token: string): string {
  return hash(`t\0${token.toLowerCase()}`);
}

/** The sorted, unique token hashes of `tokens` — an entry's `tok` list. */
export function tokenHashes(tokens: readonly ActionableToken[], hash: UnitHasher): string[] {
  return [...new Set(tokens.map((t) => tokenHash(hash, t.value)))].sort();
}

/** The tokens no accepted entry carries (`accepted`: the union of the `tok` lists of this context's stores). */
export function novelTokens(tokens: readonly ActionableToken[], accepted: ReadonlySet<string>, hash: UnitHasher): ActionableToken[] {
  return tokens.filter((t) => !accepted.has(tokenHash(hash, t.value)));
}
