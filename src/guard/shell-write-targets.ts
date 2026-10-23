/**
 * Shell-write-target extraction for the command guard.
 *
 * A prompt-injected agent can steer every future Claude session not only through
 * the Write/Edit tools (which the integrity layer tracks) but by shelling out —
 * `echo … >> CLAUDE.md`, `tee .claude/settings.json`, `sed -i … AGENTS.md`,
 * `python -c 'open("CLAUDE.md","w")…'`. Those shell writes bypass edit tracking,
 * so they are surfaced here: a write whose target is a watched instruction/config
 * file is an `ask`, and any write or delete touching Nexus's own trust store is a
 * `deny`.
 *
 * This is pure and context-free (the PreToolUse hook, the MCP `nexus_guard` tool
 * and library callers all get it). It segments the command, pulls the write
 * target out of each segment per the table below, and matches it against
 * WATCHED_NAME / the store paths. Everything is bounded: the scanner is a single
 * linear pass, every regex uses bounded quantifiers, and a pathological segment
 * is short-circuited by the 20,000-character rule.
 */

export type ShellWriteDecision = { decision: "deny" | "ask" | "allow"; rule: string | null; target: string | null };

/**
 * A watched instruction/config path, matched on forward-slash text (callers
 * normalise backslashes first). Anchored on a path boundary so the TARGET of a
 * write must BE the file, not merely mention it.
 */
export const WATCHED_NAME =
  /(?:^|\/)(?:CLAUDE(?:\.local)?\.md|AGENTS\.md|\.mcp\.json|\.claude\.json)$|(?:^|\/)\.claude\/(?:settings(?:\.local)?\.json$|(?:rules|agents|commands|skills|hooks|agent-memory(?:-local)?)(?:\/|$))|\/projects\/[^/]{1,255}\/memory(?:\/|$)/i;

/** Loose "mentions a watched name" check for the oversize-segment short circuit:
 *  no `$` anchor, and the name may follow any character that cannot be part of a
 *  file name (a space, quote, `>`, `=`, `/`). The capture is the name, for the
 *  `ask` reason's label. */
const WATCHED_CONTAINS =
  /(?:^|[^\w.-])((?:CLAUDE(?:\.local)?\.md|AGENTS\.md|\.mcp\.json|\.claude\.json)\b|\.claude\/(?:settings(?:\.local)?\.json|rules|agents|commands|skills|hooks|agent-memory))|(\/projects\/[^/]{1,255}\/memory)/i;

/** A path inside Nexus's own trust store (default `.nexus/` location) or one of
 *  its key files, anywhere in the token. Writes/deletes here are a hard deny. */
const STORE_PATH =
  /(?:^|\/)\.nexus\/(?:integrity|observations)(?:\/|$)|\.(?:integrity-key|sanitation-key|integrity-anchor)\b/i;

/** The over-length guard: beyond this a segment is not tokenised, it only gets a
 *  cheap "mentions a watched name?" ask. */
const MAX_SEGMENT = 20_000;

const INTERP = /^(?:python3?|node|ruby|perl|php|deno|bun)$/;
/** A shell or interpreter, as any word of a segment (`bash <<EOF`, `| sh`,
 *  `docker exec -i c sh`): a heredoc fed to one is code, not data. Matched on a
 *  word's lower-cased basename. */
const SHELL_FED = /^(?:(?:ba|z|da|k|mk|a|fi|c|tc)?sh|pwsh|powershell|cmd|ssh|python[\d.]{0,4}|node|ruby|perl|php|deno|bun|osascript)(?:\.exe)?$/;
/** A command that runs its input as code, as a segment's first word only (so a
 *  later `git add .` does not count). */
const SHELL_FED_HEAD = /^(?:\.|source|eval|su|sudo|doas|at|batch|crontab|make)$/;
/** A write call inside an interpreter one-liner body (run on the RAW segment, so
 *  the string literals and mode flag are intact). */
const WRITE_CALL = /open\s*\([^)]{0,200}['"][wa]|write_text|writeFileSync|writeFile|appendFile|File\.write|fs\.write/;

type Tok = { kind: "word" | "op"; value: string };

/** Strip surrounding quotes and map backslashes to forward slashes, so a native
 *  Windows target (`C:\Users\me\CLAUDE.md`) is matched by the `/`-written rules. */
function normPath(tok: string): string {
  return tok.replace(/^['"]+|['"]+$/g, "").replace(/\\+/g, "/");
}

function basenameLower(tok: string): string {
  const p = normPath(tok);
  return (p.split("/").pop() ?? p).toLowerCase();
}

type Heredoc = { delim: string; strip: boolean; literal: boolean };

/**
 * Split a command into segments on `;`, `&&`, `||`, `|`, `&` and newline, outside
 * single/double quotes. A `&` or `|` that is part of a redirect (`&>`, `>&`, `>|`)
 * does not split. With `heredocs`, the body lines of a heredoc (`<<WORD` up to the
 * line `WORD`) are dropped rather than split into commands: they are data for the
 * command, so a doc heredoc that shows `echo … >> CLAUDE.md` does not write to it.
 * `dropped` says a body was dropped; `live` that an unquoted body runs `$(…)` or
 * backticks. One linear pass.
 */
function scanSegments(command: string, heredocs: boolean): { segs: string[]; dropped: boolean; live: boolean } {
  const segs: string[] = [];
  let cur = "";
  let quote: "'" | '"' | null = null;
  let escaped = -1; // index of the last character taken by an escape pair: a `\>` is no redirect
  // No heredoc starts inside a `#` comment (to the newline), or once the command
  // has arithmetic or a parameter expansion, where `<<` is a shift or plain text.
  let comment = false, noHeredoc = false;
  const pending: Heredoc[] = [];
  let dropped = false, live = false;
  // Read the source, not `cur`: reading the end of a growing `cur` would flatten
  // it on every call, which is quadratic on one long segment.
  const afterRedirect = (i: number) => command[i - 1] === ">" && escaped !== i - 1;
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (quote) {
      cur += c;
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') { quote = c; cur += c; continue; }
    if (c === "\\" && i + 1 < command.length) { cur += c + command[i + 1]; i++; escaped = i; continue; }
    if (c === "\n") {
      segs.push(cur); cur = ""; comment = false;
      if (pending.length) {
        const body = skipHeredocBodies(command, i + 1, pending);
        dropped = true;
        live ||= body.live;
        i = body.end - 1;
        pending.length = 0;
      }
      continue;
    }
    if (c === ";") { segs.push(cur); cur = ""; continue; }
    if (c === "&") {
      if (command[i + 1] === ">" || afterRedirect(i)) { cur += c; continue; } // &> / >& redirect
      if (command[i + 1] === "&") i++; // &&
      segs.push(cur); cur = ""; continue;
    }
    if (c === "|") {
      if (afterRedirect(i)) { cur += c; continue; } // >| redirect
      if (command[i + 1] === "|") i++; // ||
      segs.push(cur); cur = ""; continue;
    }
    if (c === "<" && command[i + 1] === "<") {
      if (command[i + 2] === "<") { cur += "<<<"; i += 2; continue; } // here-string
      if (heredocs && !comment && !noHeredoc) {
        const end = heredocWord(command, i + 2, pending);
        cur += command.slice(i, end); i = end - 1; continue;
      }
    }
    if (c === "#" && (cur === "" || /[\s(]/.test(command[i - 1]))) comment = true;
    else if ((c === "(" && command[i + 1] === "(") || (c === "$" && (command[i + 1] === "[" || command[i + 1] === "{")) || c === "`") noHeredoc = true;
    cur += c;
  }
  segs.push(cur);
  return { segs: segs.filter((s) => s.trim()), dropped, live };
}

/** Read the heredoc word after `<<` (from `j`): `[-] [blanks] WORD`, quotes and
 *  backslashes removed as the shell does. Queues it and returns the index after. */
function heredocWord(command: string, j: number, pending: Heredoc[]): number {
  const strip = command[j] === "-";
  if (strip) j++;
  while (command[j] === " " || command[j] === "\t") j++;
  let delim = "", q: string | null = null, literal = false;
  for (; j < command.length; j++) {
    const ch = command[j];
    if (q) { if (ch === q) q = null; else delim += ch; continue; }
    if (ch === "'" || ch === '"') { q = ch; literal = true; }
    else if (ch === "\\" && j + 1 < command.length) { delim += command[++j]; literal = true; }
    else if (/[ \t\n;&|<>()]/.test(ch)) break; // the shell's metacharacters only: a `\r` or backtick stays in WORD
    else delim += ch;
  }
  if (delim && !q && !delim.includes("\n")) pending.push({ delim, strip, literal });
  return j;
}

/** Skip the bodies of the queued heredocs, in order, from `pos` (the line after
 *  the heredoc's own line). Returns the index after the last terminator line. */
function skipHeredocBodies(command: string, pos: number, pending: Heredoc[]): { end: number; live: boolean } {
  let live = false;
  for (const { delim, strip, literal } of pending) {
    while (pos < command.length) {
      let eol = command.indexOf("\n", pos);
      if (eol < 0) eol = command.length;
      let line = command.slice(pos, eol);
      pos = eol + 1;
      if (strip) line = line.replace(/^\t+/, "");
      if (line === delim) break;
      if (!literal && (line.includes("$(") || line.includes("`"))) live = true;
    }
  }
  return { end: Math.min(pos, command.length), live };
}

/** A segment that runs a shell or interpreter (`bash`, `| sh`, `(… ) | bash`). */
function feedsShell(seg: string): boolean {
  const words = tokenize(seg).filter((t) => t.kind === "word")
    .map((t) => basenameLower(t.value.replace(/^[$({`!]{1,8}|[)}`]{1,8}$/g, "")));
  const head = words.find((w) => w !== "");
  return (head !== undefined && SHELL_FED_HEAD.test(head)) || words.some((w) => SHELL_FED.test(w));
}

/**
 * The command's segments, heredoc bodies dropped. A body a shell or interpreter
 * runs (`bash <<EOF`, `cat <<EOF | sh`), or an unquoted one with `$(…)`, is
 * code, so then the body lines stay segments, as in a plain split.
 */
function splitSegments(command: string): string[] {
  const { segs, dropped, live } = scanSegments(command, true);
  if (dropped && (live || segs.some(feedsShell))) return scanSegments(command, false).segs;
  return segs;
}

const OP_RE = /^(?:&>>|&>|>>|\d{0,3}>\||\d{0,3}>&\d{0,3}|\d{0,3}>)/;

/** Tokenise one segment into words (quote-stripped) and redirect operators. */
function tokenize(seg: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  while (i < seg.length) {
    const c = seg[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === ">" || c === "&" || (/\d/.test(c) && OP_RE.test(seg.slice(i, i + 8)))) {
      const m = OP_RE.exec(seg.slice(i, i + 8));
      if (m) { toks.push({ kind: "op", value: m[0] }); i += m[0].length; continue; }
    }
    if (c === "<") { i++; continue; } // input redirect operator — read the target as a plain word next
    let out = "", j = i;
    while (j < seg.length) {
      const ch = seg[j];
      if (/\s/.test(ch) || ch === ">" || ch === "<") break;
      if (ch === "'") { j++; while (j < seg.length && seg[j] !== "'") out += seg[j++]; j++; continue; }
      if (ch === '"') {
        // Inside double quotes a backslash escapes only `"`, `\`, `$`, a backtick or
        // a newline (bash; PowerShell never escapes with it), so the separators of
        // a quoted Windows path ("C:\proj\CLAUDE.md") survive for normPath.
        j++;
        while (j < seg.length && seg[j] !== '"') {
          if (seg[j] === "\\" && j + 1 < seg.length && /["\\$`\n]/.test(seg[j + 1])) { out += seg[j + 1]; j += 2; } else out += seg[j++];
        }
        j++;
        continue;
      }
      out += ch; j++;
    }
    toks.push({ kind: "word", value: out });
    i = j;
  }
  return toks;
}

/** A redirect that writes its next word to a file (not an fd-dup like `2>&1`). */
function isWriteRedirect(op: string): boolean {
  return op.includes(">") && !/>&\d/.test(op);
}

const isFlag = (w: string) => w.startsWith("-");

/** The files a segment WRITES, per the target table in the spec. Returns
 *  normalised (forward-slash, unquoted) paths. */
function writeTargets(seg: string): string[] {
  const toks = tokenize(seg);
  const words = toks.filter((t) => t.kind === "word").map((t) => t.value);
  const head = basenameLower(words[0] ?? "");
  const args = words.slice(1);
  const targets: string[] = [];

  // Redirects: the word after a write redirect is the target.
  for (let k = 0; k < toks.length; k++) {
    if (toks[k].kind === "op" && isWriteRedirect(toks[k].value)) {
      const next = toks[k + 1];
      if (next && next.kind === "word") targets.push(normPath(next.value));
    }
  }

  const nonFlag = args.filter((a) => !isFlag(a));
  const flagValue = (names: RegExp): string | null => {
    for (let k = 0; k < args.length; k++) {
      const eq = args[k].indexOf("=");
      if (eq > 0 && names.test(args[k].slice(0, eq))) return normPath(args[k].slice(eq + 1));
      if (names.test(args[k]) && args[k + 1]) return normPath(args[k + 1]);
    }
    return null;
  };

  if (head === "tee") {
    targets.push(...nonFlag.map(normPath));
  } else if (head === "truncate") {
    targets.push(...nonFlag.map(normPath));
  } else if (head === "sed") {
    if (args.some((a) => a === "-i" || a === "--in-place" || /^--in-place=/.test(a) || /^-[A-Za-z]{0,8}i/.test(a))) {
      // files come after the script (the first non-flag argument)
      targets.push(...nonFlag.slice(1).map(normPath));
    }
  } else if (head === "perl") {
    if (args.some((a) => /^-[A-Za-z]{0,8}i/.test(a))) targets.push(...nonFlag.map(normPath));
  } else if (head === "dd") {
    for (const a of args) if (/^of=/.test(a)) targets.push(normPath(a.slice(3)));
  } else if (head === "cp" || head === "mv" || head === "install" || head === "rsync" || head === "ln") {
    const t = flagValue(/^(?:-t|--target-directory)$/);
    if (t) targets.push(t);
    else if (nonFlag.length >= 1) targets.push(normPath(nonFlag[nonFlag.length - 1]));
  } else if (head === "set-content" || head === "add-content" || head === "out-file" || head === "new-item" ||
             head === "tee-object" || head === "copy-item" || head === "move-item") {
    const t = flagValue(/^-(?:Path|LiteralPath|FilePath|Destination)$/i);
    if (t) targets.push(t);
    else {
      const positional = nonFlag.filter((a) => a.indexOf("=") < 0);
      const idx = head === "copy-item" || head === "move-item" ? 1 : 0;
      if (positional[idx]) targets.push(normPath(positional[idx]));
    }
  } else if (INTERP.test(head) && args.some((a) => a === "-c" || a === "-e" || a === "--eval")) {
    // The body contains a write call AND names a watched file: pull the watched
    // path out of the body (split on quotes/brackets/commas, which bound the
    // string literal the path lives in). Run on the RAW segment so the literals
    // and the mode flag survive.
    if (WRITE_CALL.test(seg)) {
      for (const part of seg.split(/[\s'"(),;]+/)) {
        const lit = normPath(part);
        if (lit && (WATCHED_NAME.test(lit) || STORE_PATH.test(lit))) targets.push(lit);
      }
    }
  }
  return targets;
}

/** Arguments a destructive verb (rm/unlink/shred/chmod) operates on — for the
 *  store-mutation check, where deleting or chmod-ing a store file is a write. */
function destructiveArgs(seg: string): string[] {
  const words = tokenize(seg).filter((t) => t.kind === "word").map((t) => t.value);
  return words.slice(1).filter((a) => !isFlag(a)).map(normPath);
}

/** A write or delete that lands inside Nexus's store or names a key file. */
function storeMutation(seg: string): string | null {
  for (const t of writeTargets(seg)) if (STORE_PATH.test(t)) return t;
  const head = basenameLower(tokenize(seg).find((t) => t.kind === "word")?.value ?? "");
  if (/^(?:rm|unlink|shred|chmod)$/.test(head)) {
    for (const t of destructiveArgs(seg)) if (STORE_PATH.test(t)) return t;
  }
  return null;
}

/** A write whose target is a watched instruction/config file. */
function instructionWrite(seg: string): string | null {
  for (const t of writeTargets(seg)) if (WATCHED_NAME.test(t)) return t;
  return null;
}

/**
 * Most-severe shell-write verdict over a command: a store write/delete denies, a
 * write to a watched instruction/config file asks, otherwise allow.
 */
export function shellWriteTargets(command: string): ShellWriteDecision {
  let ask: string | null = null;
  for (const seg of splitSegments(command)) {
    if (seg.length > MAX_SEGMENT) {
      const m: RegExpExecArray | null = ask === null ? WATCHED_CONTAINS.exec(seg.replace(/\\+/g, "/")) : null;
      if (m) ask = m[1] ?? m[2];
      continue;
    }
    const store = storeMutation(seg);
    if (store) return { decision: "deny", rule: "nexus-store-write", target: store };
    if (ask === null) ask = instructionWrite(seg);
  }
  if (ask) return { decision: "ask", rule: "instruction-file-shell-write", target: ask };
  return { decision: "allow", rule: null, target: null };
}

export type NexusCliAction =
  | { rule: "integrity-self-approve"; decision: "deny" }
  | { rule: "guard-uninstall"; decision: "ask" }
  | null;

/** A path that is a Nexus CLI entry point run directly (`node …/cli/index.js`). */
const NEXUS_ENTRY = /(?:^|\/)(?:dist\/)?cli\/index\.js$|(?:^|\/)nexus(?:-mcp)?$/i;
/** A published-package spec for Nexus (`@hawon/nexus`, `nexus`, `@hawon/nexus@1`). */
const NEXUS_PKG = /^(?:@hawon\/)?nexus(?:@|$)/i;

/**
 * Detect an agent trying to run the self-approval / uninstall CLI commands, by
 * parsing each segment's COMMAND position — not by matching the words anywhere,
 * so `echo 'run nexus guard integrity accept'` or `grep "integrity accept"` do
 * not trip it, while every real invocation (the `nexus` binary, `npx
 * @hawon/nexus …`, `node <path>/cli/index.js …`) does.
 */
export function nexusCliAction(command: string): NexusCliAction {
  let uninstall: NexusCliAction = null;
  for (const seg of splitSegments(command)) {
    if (seg.length > MAX_SEGMENT) continue;
    const words = tokenize(seg).filter((t) => t.kind === "word").map((t) => t.value);
    let i = 0;
    while (i < words.length && (basenameLower(words[i]) === "sudo" || /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i]))) i++;
    if (i >= words.length) continue;
    const head = basenameLower(words[i]);
    let rest: string[] | null = null;
    if (head === "nexus") {
      rest = words.slice(i + 1);
    } else if (head === "npx" || head === "bunx" || head === "pnpm" || head === "yarn") {
      let k = i + 1;
      while (k < words.length && isFlag(words[k])) k++;
      if ((head === "pnpm" || head === "yarn") && (words[k] === "dlx" || words[k] === "exec")) k++;
      const pkg = words[k] ?? "";
      if (NEXUS_PKG.test(pkg) || basenameLower(pkg) === "nexus") rest = words.slice(k + 1);
    } else if (head === "node" || head === "bun" || head === "deno" || head === "tsx" || head === "ts-node") {
      let k = i + 1;
      while (k < words.length && (isFlag(words[k]) || words[k] === "run" || words[k] === "tsx")) k++;
      if (NEXUS_ENTRY.test(normPath(words[k] ?? ""))) rest = words.slice(k + 1);
    }
    if (!rest || rest[0] !== "guard") continue;
    const [, a, b] = rest;
    if (a === "integrity" && (b === "accept" || b === "baseline")) return { rule: "integrity-self-approve", decision: "deny" };
    if (a === "integrity" && b === "config" && rest[3] && /^[A-Za-z]/.test(rest[3])) return { rule: "integrity-self-approve", decision: "deny" };
    if (a === "install" && rest.includes("--no-integrity")) return { rule: "integrity-self-approve", decision: "deny" };
    if (a === "uninstall") uninstall ??= { rule: "guard-uninstall", decision: "ask" };
  }
  return uninstall;
}

/** A human label for a watched target, for the `ask` reason. */
export function watchedLabel(target: string): string {
  if (/(?:^|\/)\.claude\/settings(?:\.local)?\.json$/i.test(target)) return "Claude Code settings";
  if (/(?:^|\/)\.mcp\.json$/i.test(target)) return "MCP server config";
  if (/(?:^|\/)\.claude\.json$/i.test(target)) return "Claude Code settings";
  if (/(?:^|\/)\.claude\/hooks(?:\/|$)/i.test(target)) return "a hook script";
  if (/(?:^|\/)\.claude\/rules(?:\/|$)/i.test(target)) return "a rules file";
  if (/(?:^|\/)\.claude\/agents(?:\/|$)/i.test(target)) return "a subagent definition";
  if (/(?:^|\/)\.claude\/commands(?:\/|$)/i.test(target)) return "a slash command";
  if (/(?:^|\/)\.claude\/skills(?:\/|$)/i.test(target)) return "a skill";
  if (/(?:^|\/)\.claude\/agent-memory(?:-local)?(?:\/|$)/i.test(target) || /\/projects\/[^/]{1,255}\/memory(?:\/|$)/i.test(target)) return "agent memory";
  return "agent instructions";
}
