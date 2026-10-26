/**
 * Shell-write-target extraction for the command guard. A shell write to a watched
 * instruction/config file (`echo … >> CLAUDE.md`, past the integrity layer's edit
 * tracking) asks, a write or delete in Nexus's trust store denies, and the Nexus CLI
 * run to approve its own changes (`integrity-self-approve`) denies or to remove the
 * hooks (`guard-uninstall`) asks. This runs on every Bash/PowerShell PreToolUse call
 * and is defence in depth (SessionStart also reports a shell-written change), so a
 * hard linear bound beats precision: ambiguity resolves to the coarse verdict.
 *
 * Spec amendments (deliberate deviations from §6.7):
 * - Raw-text segmentation. resolveCommand drops the quoting that marks data, so one
 *   forward scan of the raw command cuts segments, outside quotes, at ; && || | &
 *   newline `$(` backticks, a group's `{ }` and a first word's `( )`. No nested frames:
 *   a closer restores its quote mode and, inside a word, the enclosing segment with `$_`
 *   (`cp x $(pwd)/CLAUDE.md`; past the first word `<(…)`, extglob, zsh's `(a|b)`).
 * - KEY_PATH split from SECRET_PATH (capability.ts): the key files are a secret path
 *   for commands only, or a doc naming one near a `curl` line reads as exfiltration.
 * - Quoted-string blanking. The self-approve and uninstall regexes read a segment's
 *   words with quoted phrases blanked, so `grep "integrity accept"` stays allow.
 * - Conservative heredoc ownership. Bodies (<<, <<-, <<~) are data unless a segment
 *   runs code (a shell or interpreter as command word, a shell as a later word, a
 *   script path, `make`, `at`); then all are commands, which covers a heredoc writing
 *   a script the command runs. An unquoted body's `$(…)` and backticks always are.
 * - Single-level shell-string reading. The quoted words of a segment that runs code
 *   (else its here-string), the rest of an `eval`/`pwsh`/`cmd` line and what `echo`
 *   pipes into a shell are scanned as commands once; a shell's string inside them
 *   gets the coarse check only.
 * - Work budget and coarse fallback. Scan steps, tokens and regex input count against
 *   16 × length + 20,000. Past it, on an open quote or past MAX_NEST, the verdict is
 *   coarse (also on the text with quotes dropped): ask on a watched name, deny on a store
 *   path beside a write verb or call, the CLI regexes unblanked; an oversize segment gets
 *   it untokenised. In a heredoc body, read as usual up to its open quote, the store deny
 *   needs a line's write verb, a `>` before the path or a call, not prose's `install` or
 *   `->`. A command starting like PowerShell (Verb-Noun, pwsh) keeps `\` literal.
 * - Codex's apply_patch. `apply_patch` / `applypatch` as a command word (Codex runs
 *   `apply_patch <<'EOF' … EOF` itself, and puts the command on the shell's PATH)
 *   writes every file its patch names: the patch is read from the command's heredoc
 *   bodies, its here-strings and quoted words, and those of an `echo`/`printf` piped
 *   into it (codex/patch.ts). Each Add, Update, Move-to and Delete path is a write
 *   target, under a `cd` earlier in the command when it is relative; a watched one asks
 *   (SHELL_PATCH_RULE: under Codex, a deny pointing to the apply_patch tool, which Nexus
 *   can check and record), and the files with the text they add are returned for the
 *   static file-write guard. More than MAX_TARGETS of them is `patchOverflow`.
 */

import { addedText, opPaths, parsePatch, type PatchWrite } from "./codex/patch.js";
import { headUnits, tailFrom } from "./codex/utf16.js";

export type ShellWriteDecision = { decision: "deny" | "ask" | "allow"; rule: string | null; target: string | null };

/** The rule of an ask for a watched file written by a patch fed to `apply_patch` in the shell. */
export const SHELL_PATCH_RULE = "instruction-file-shell-patch";
export type NexusCliAction = { rule: "integrity-self-approve"; decision: "deny" } | { rule: "guard-uninstall"; decision: "ask" } | null;

/**
 * `re` as the platform's default file systems compare names: as written (case-insensitive)
 * on win32 and darwin, exactly elsewhere, where neither agent loads a `claude.md` as its
 * CLAUDE.md (the integrity layer's role tables do the same: paths.ts `foldsCase`).
 */
export const asFileNames = (re: RegExp, platform: NodeJS.Platform = process.platform): RegExp =>
  platform === "win32" || platform === "darwin" ? re : new RegExp(re.source, re.flags.replace("i", ""));

/** A watched instruction/config path, on forward-slash text, anchored on a path boundary
 *  (a write's target must BE the file); names compared as `asFileNames` says. Codex's:
 *  AGENTS.override.md, a `.codex` (or `$CODEX_HOME`) directory's config, profiles, hooks,
 *  rules, skills and memory files, `.agents/skills`, and the system layer's config. */
export const WATCHED_NAME = asFileNames(
  /(?:^|\/)(?:CLAUDE(?:\.local)?\.md|AGENTS(?:\.override)?\.md|\.mcp\.json|\.claude\.json)$|(?:^|\/)\.claude\/(?:settings(?:\.local)?\.json$|(?:rules|agents|commands|skills|hooks|agent-memory(?:-local)?)(?:\/|$))|(?:^|\/)\.claude\/projects\/[^/]{1,255}\/memory(?:\/|$)|(?:^|\/)(?:\.codex|\$\{?CODEX_HOME\}?)\/(?:(?:[^/]{1,255}\.)?config\.toml$|hooks\.json$|memories(?:_v2)?\/(?:memory_summary|MEMORY)\.md$|(?:rules|skills)(?:\/|$))|(?:^|\/)\.agents\/skills(?:\/|$)|^\/etc\/codex\/(?:config|requirements|managed_config)\.toml$/i);
/** A watched name anywhere in free text (the coarse verdict); captures the name. */
const WATCHED_CONTAINS = asFileNames(
  /(?:^|[^\w.-])((?:CLAUDE(?:\.local)?\.md|AGENTS(?:\.override)?\.md|\.mcp\.json|\.claude\.json)\b|\.claude\/(?:settings(?:\.local)?\.json|rules|agents|commands|skills|hooks|agent-memory|projects\/[^/]{1,255}\/memory)|\.codex\/(?:config\.toml|hooks\.json|rules|skills)|\.agents\/skills)/i);
/** A path in Nexus's trust store (default `.nexus/`) or a key file, in a word / in free text. */
const STORE_PATH = /(?:^|\/)\.nexus\/(?:integrity|observations)(?:\/|$)|\.(?:integrity-key|sanitation-key|integrity-anchor)\b/i;
const STORE_CONTAINS = /\.nexus\/(?:integrity|observations)\b|\.(?:integrity-key|sanitation-key|integrity-anchor)\b/i;
/** A write call in code: `open(…, "w"|"a")`, perl's `open(F, ">>", …)`, a write function. */
export const WRITE_CALL =
  /open\s{0,8}\([^)]{0,200}['"](?:[wa]|\+?>)|\bopen\s{1,8}(?:my\s{1,8})?\$?\w{1,64}\s{0,8},\s{0,8}['"]\+?>|write_text|writeFileSync|writeFile|appendFile|File\.write|fs\.write/;
/** The spec's integrity-self-approve and guard-uninstall rules (§6.7). */
const SELF_APPROVE_RE = /\bintegrity\s{1,8}(?:accept|baseline)\b|\bintegrity\s{1,8}config\s{1,8}[A-Za-z]|\bguard\s{1,8}install\b[^\n]{0,200}--no-integrity\b/;
const UNINSTALL_RE = /\bguard\s{1,8}uninstall\b/;

/** A longer segment is not tokenised; past MAX_NEST open quotes, `${`, `$((`, subshells and
 *  substitutions the scan gives up; MAX_HOPS caps what is skipped before a command word. */
const MAX_SEGMENT = 20_000, MAX_NEST = 64, MAX_HOPS = 16;
const SH = "(?:ba|z|da|k|mk|a|fi|c|tc)?sh|pwsh|powershell|cmd|iex|invoke-expression";
/** A shell as a later word (`xargs sh -c`, `find -exec bash -c`) or after `|`. */
const SHELL = new RegExp(`^(?:${SH})(?:\\.exe)?$`);
/** A command word that runs a string as shell commands; one that runs other code. */
const SHELL_HEAD = new RegExp(`^(?:${SH}|eval|su|runuser|script|flock)(?:\\.exe)?$`);
const RUNNER = /^(?:ssh|source|\.|python[\d.]{0,4}|node|perl|ruby|php|deno|bun|osascript|make|at|batch|crontab)(?:\.exe)?$/;
/** Commands that run the rest of their line; those that use PowerShell/cmd quoting. */
const REST_RUNNER = /^(?:eval|iex|invoke-expression|pwsh|powershell|cmd)(?:\.exe)?$/;
const PS_RUNNER = /^(?:pwsh|powershell|cmd|iex|invoke-expression)(?:\.exe)?$/;
/** A command word that is a script the command runs (`./setup.sh`, `/tmp/x.py`). */
const SCRIPT = /^\.{1,2}\/|\.(?:sh|bash|zsh|ps1|py|js|mjs|cjs|rb|pl|php)$/i;
const PRINTER = /^(?:echo|printf|write-output|write-host)$/;
/** A command that writes or deletes its operands: a store path among them denies. */
const WRITE_VERB = /^(?:rm|unlink|shred|mv|cp|ln|chmod|chown|truncate|tee|sed|dd|install|rsync|remove-item|move-item|copy-item|del|rmdir)$/;
/** A command that deletes or moves its operands (each one, not only a destination): listed for the integrity layer's store check. */
const DELETE_VERB = /^(?:rm|unlink|shred|mv|remove-item|del|rmdir|move-item)$/;
const COARSE_VERB = /\b(?:rm|unlink|shred|mv|cp|ln|chmod|chown|truncate|tee|sed|perl|dd|install|rsync|remove-item|move-item|copy-item|set-content|add-content|out-file|new-item|del|rmdir)\b|>/i;
const BODY_WRITE = /(?:^|\n)[ \t]{0,64}(?:sudo[ \t]{1,8})?(?:rm|unlink|shred|mv|cp|ln|chmod|chown|truncate|tee|sed|perl|dd|install|rsync|remove-item|move-item|copy-item|set-content|add-content|out-file|new-item|del|rmdir)\b|>[ \t]{0,8}[^\s>]{0,256}\.(?:nexus\/(?:integrity|observations)|integrity-key|sanitation-key|integrity-anchor)\b/i;
const LOOKS_PS = /^\s{0,64}(?:[A-Z][a-z]{1,16}-[A-Z][A-Za-z]{1,40}|[Pp](?:wsh|ower[Ss]hell)(?:\.exe)?)(?:\s|$)/;
const ASSIGN = /^[A-Za-z_][A-Za-z0-9_]{0,127}=/, RESERVED = /^(?:!|if|then|else|elif|do|while|until)$/;
/** Launchers that run the rest of the line, and their options that take a value. */
const LAUNCHERS = new Map<string, RegExp | null>([
  ["sudo", /^-[ughpCrtUDT]$/], ["doas", /^-[uC]$/], ["env", /^-[uCS]$/], ["nohup", null], ["time", null], ["command", null],
  ["builtin", null], ["exec", /^-a$/], ["nice", /^-n$/], ["ionice", /^-[cnp]$/], ["stdbuf", /^-[ioe]$/], ["timeout", /^-[sk]$/], ["xargs", /^-[aEdIiLlnPs]$/]]);

type Work = { left: number };
const OVER = new Error("shell-write analysis over budget"), spend = (w: Work, n: number) => { if ((w.left -= n) < 0) throw OVER; };

/** A segment's words (unquoted; no redirect operands), write-redirect targets, indices of
 *  words with a quoted part (`-c 'a '\''b'` is one), here-strings, words with phrases blanked. */
type Words = { words: string[]; bare: string; redir: string[]; quoted: number[]; here: string[] };
/** `runs`: 2 when the command runs a string as shell commands, 1 for other code. */
type Seg = { text: string; start: number; end: number; pipeFrom: Seg | null; t?: Words | null; at?: number; head?: string; runs?: number };
type Body = [start: number, end: number, quoted: boolean]; // a heredoc body, and whether its delimiter was quoted
type Builder = { parts: string[]; from: number; start: number; data: boolean; pipeFrom: Seg | null; word: boolean };
type Ctx = { m: "cmd" | "dq" | "hd" | "param" | "arith"; close: string; outer: Builder | null; parens: number };

/** How a scan ended: parsed, inside an open quote, or gave up (nesting past MAX_NEST, or a
 *  PowerShell-ambiguous `\'` / `\"`). */
type ScanEnd = true | "open-quote" | "unsure";

/** Cut src[from, to) into segments and heredoc bodies. `hd`: a data body, where only `$(…)`,
 *  backticks and `${…}` are code; `ps`: a backtick escapes, a backslash is literal. */
function scan(src: string, from: number, to: number, ps: boolean, hd: boolean, segs: Seg[], bodies: Body[], w: Work): ScanEnd {
  spend(w, to - from);
  const esc = ps ? "`" : "\\";
  const ctx = (m: Ctx["m"], close = "", outer: Builder | null = null): Ctx => ({ m, close, outer, parens: 0 });
  const stack = [ctx(hd ? "hd" : "cmd")], pending: { delim: string; strip: string; quoted: boolean }[] = [];
  const begin = (at: number, data = false, pipeFrom: Seg | null = null): Builder => ({ parts: [], from: at, start: at, data, pipeFrom, word: false });
  let cur = begin(from, hd), escAt = -1, joinAt = -1; // the last escaped character; where a word resumes after a `)`
  const wordStart = (i: number) => i === from || (escAt !== i - 1 && /[\s;&|()]/.test(src[i - 1])); // after a blank or a metacharacter
  /** No word yet in the current segment (cached once one is seen): a `}` ends a group, a `(` opens a subshell. */
  const fresh = (i: number) => !(cur.word ||= cur.parts.length > 0 || /\S/.test(src.slice(cur.from, i)));
  const emit = (at: number): Seg | null => {
    const text = cur.parts.join("") + src.slice(cur.from, at);
    return cur.data || !/\S/.test(text) ? null : segs[segs.push({ text, start: cur.start, end: at, pipeFrom: cur.pipeFrom }) - 1];
  };
  const split = (at: number, next: number, pipe = false) => { const s = emit(at); cur = begin(next, false, pipe ? s : null); };
  const close = (i: number) => { emit(i); const o = stack.pop()!.outer; if (o) joinAt = i + 1; cur = o ?? begin(i + 1); cur.from = i + 1; };
  /** A substitution from i to `closer`, its body from `next`: the enclosing segment resumes after it with `$_`. */
  const nest = (i: number, closer: string, next: number) => { cur.parts.push(src.slice(cur.from, i), "$_"); stack.push(ctx("cmd", closer, cur)); cur = begin(next); };
  /** `$(`, `$((`, `${` or a backtick at i; returns the last index consumed. */
  const open = (i: number): number => {
    const dollar = src[i] === "$", n = src[i + 1];
    if (dollar && n === "(" && src[i + 2] === "(") { stack.push(ctx("arith")); return i + 2; }
    if (dollar && n !== "(") { if (n === "{") stack.push(ctx("param")); return n === "{" ? i + 1 : i; }
    nest(i, dollar ? ")" : "`", dollar ? i + 2 : i + 1);
    return dollar ? i + 1 : i;
  };
  /** Queue the heredoc whose word follows `<<` at j (an unclosed quote is none); returns the index after it. */
  const heredoc = (j: number): number => {
    HEREDOC_WORD.lastIndex = j;
    const m = HEREDOC_WORD.exec(src), delim = m?.[2].replace(/\\(.)|['"]/g, "$1") ?? "";
    if (m) pending.push({ delim, strip: m[1], quoted: delim !== m[2] }); // a quote or `\` in it: a literal body
    return m ? j + m[0].length : j;
  };
  /** Find the queued heredocs' bodies, in order, from `pos` (the scan's charge covers it). */
  const locate = (pos: number): number => {
    for (const h of pending) {
      const start = pos; let end = to;
      for (let term = false; pos < to && !term; ) {
        const nl = src.indexOf("\n", pos), eol = nl < 0 || nl > to ? to : nl;
        let p = pos;
        while (h.strip && p < eol && (src[p] === "\t" || (h.strip === "~" && src[p] === " "))) p++;
        if ((term = eol - p === h.delim.length && src.startsWith(h.delim, p))) end = pos;
        pos = Math.min(eol + 1, to);
      }
      bodies.push([start, end, h.quoted]);
    }
    pending.length = 0;
    return pos;
  };

  for (let i = from; i < to; i++) {
    if (stack.length > MAX_NEST) return "unsure";
    const c = src[i], top = stack[stack.length - 1], n = src[i + 1];
    if (top.m === "dq" || top.m === "hd" || top.m === "param") {
      if (c === esc) i++;
      else if ((c === '"' && top.m === "dq") || (c === "}" && top.m === "param")) stack.pop();
      else if (c === "$" || (c === "`" && !ps)) i = open(i);
      continue;
    }
    // Outside quotes `\'` / `\"` is bash's escape but a PowerShell path's end: ambiguous.
    if (ps && c === "\\" && (n === "'" || n === '"')) return "unsure";
    const glued = i > from && src[i - 1] === ">" && escAt !== i - 1; // `>&`, `>|`
    if (c === esc) escAt = ++i;
    else if (c === "'" || (c === "$" && n === "'")) {
      let j = i + (c === "$" ? 2 : 1);
      while (j < to && src[j] !== "'") j += c === "$" && src[j] === "\\" ? 2 : 1;
      if (j >= to) return "open-quote";
      i = j;
    } else if (c === '"') stack.push(ctx("dq"));
    else if (c === "`" && !ps && top.close === "`") close(i);
    else if (c === "$" || (c === "`" && !ps)) i = open(i);
    else if (top.m === "arith") {
      if (c === "(") top.parens++;
      else if (c === ")" && top.parens > 0) top.parens--;
      else if (c === ")") { stack.pop(); if (n === ")") i++; }
      else if (c === "\n") { stack.pop(); i--; } // `((` across lines is a nested subshell
    } else if (c === "#" && wordStart(i) && joinAt !== i) { // `$(a)#b` is one word
      const f = src.indexOf("\n", i), nl = f < 0 || f > to ? to : f;
      cur.parts.push(src.slice(cur.from, i)); // a comment is not part of the command
      cur.from = nl; i = nl - 1;
    } else if (c === "\n") {
      const blank = emit(i) === null; // a blank line after `|` continues the pipeline
      if (pending.length) i = locate(i + 1) - 1;
      cur = begin(i + 1, false, blank ? cur.pipeFrom : null);
    } else if (c === ";" || (c === "{" && /\s/.test(n ?? "") && wordStart(i)) || (c === "}" && /^[\s;&|)<>]?$/.test(n ?? "") && fresh(i))) split(i, i + 1);
    else if (c === "&" && n !== ">" && !glued) { split(i, n === "&" ? i + 2 : i + 1); if (n === "&") i++; }
    else if (c === "|" && !glued) { split(i, n === "|" || n === "&" ? i + 2 : i + 1, n !== "|"); if (n === "|" || n === "&") i++; }
    // A bare `((` is not skipped as arithmetic: dash (Debian's and Ubuntu's /bin/sh) runs it as
    // two subshells, so it is read as two. Only `$((…))` is arithmetic in every shell.
    else if (c === "(" && !fresh(i) && !/(?:^|\s)in[ \t]{1,8}$/.test(src.slice(Math.max(cur.from, i - 12), i)))
      nest(i, ")", i + 1); // past the first word, unless a case pattern: `<(…)`, extglob, `f()`, a PowerShell argument
    else if (c === "(") { split(i, i + 1); stack.push(ctx("cmd", ")")); }
    else if (c === ")") { if (top.close === ")") close(i); else split(i, i + 1); }
    else if (c === "<" && n === "<") i = src[i + 2] === "<" ? i + 2 : heredoc(i + 2) - 1;
  }
  if (stack.some((x) => x.m === "dq" || x.m === "param")) return "open-quote";
  for (const h of pending) bodies.push([to, to, h.quoted]); // a heredoc on the last line has an empty body
  emit(to);
  for (let k = stack.length - 1; k > 0; k--) { const o = stack[k].outer; if (o) { cur = o; cur.from = to; emit(to); } }
  return true;
}

const OP = /&>>?|>>|>\||>&(?:\d{1,3}|-)?|>|<<<|<<[-~]?|<&(?:\d{1,3}|-)?|<>?/y;
/** A heredoc's `[-~] WORD`, which must end at a blank or a metacharacter. */
const HEREDOC_WORD = /([-~]?)[ \t]{0,64}((?:'[^'\n]{0,256}'|"[^"\n]{0,256}"|\\[^\n]|[^\s;&|<>()'"\\]){1,256})(?![^\s;&|<>()])/y;
const isBlank = (c: string) => c === " " || c === "\t" || c === "\n" || c === "\r";
const wordEnd = (s: string, j: number) => isBlank(s[j]) || s[j] === ">" || s[j] === "<" || (s[j] === "&" && s[j + 1] === ">");

/** Tokenise one segment (see Words). */
function tokenize(text: string, ps: boolean): Words {
  const r: Words = { words: [], bare: "", redir: [], quoted: [], here: [] }, bare: string[] = [], esc = ps ? "`" : "\\";
  let op = ""; // the next word is the operand of a w(rite), r(ead) or h(ere-string) redirect
  for (let i = 0; i < text.length; ) {
    OP.lastIndex = i;
    const m = text[i] === ">" || text[i] === "<" || text[i] === "&" ? OP.exec(text) : null;
    if (m) op = m[0] === "<<<" ? "h" : m[0][0] === "<" ? (m[0][1] === "&" ? "" : "r") : /&[\d-]/.test(m[0]) ? "" : "w";
    if (m || isBlank(text[i])) { i += m ? m[0].length : 1; continue; }
    let val = "", plain = "", j = i, quoted = false;
    while (j < text.length && !wordEnd(text, j)) {
      const ch = text[j];
      if (ch === "'" || ch === '"' || (ch === "$" && text[j + 1] === "'")) {
        const ansi = ch === "$", q = ansi ? "'" : ch, e = ansi ? "\\" : q === '"' ? esc : "";
        let part = "";
        // In "…" bash's `\` escapes only `"`, `\`, `$`, a backtick and a newline; PowerShell's backtick, anything.
        for (j += ansi ? 2 : 1; j < text.length && text[j] !== q; j++) part += text[j] === e && j + 1 < text.length && (ps || ansi || /["\\$`\n]/.test(text[j + 1])) ? text[++j] : text[j];
        j++;
        val += part;
        if (!/\s/.test(part)) plain += part;
        quoted = true;
        continue;
      }
      // An escaped metacharacter is literal; any other backslash stays, for a Windows path.
      if (ch === esc && j + 1 < text.length && (ps || /[\s()<>;&|'"`$\\]/.test(text[j + 1]))) j++;
      val += text[j];
      plain += text[j++];
    }
    if (op === "w") r.redir.push(val);
    else if (op === "h") r.here.push(val);
    else if (!op && !(/^\d{1,3}$/.test(val) && (text[j] === ">" || text[j] === "<"))) { // not an fd number
      if (quoted) r.quoted.push(r.words.length);
      r.words.push(val);
      bare.push(plain);
    }
    op = ""; i = j;
  }
  return Object.assign(r, { bare: bare.join(" ") });
}

const slash = (p: string) => p.replace(/\\+/g, "/"), isFlag = (w: string) => w.startsWith("-");
const base = (w: string) => { const p = slash(w); return p.slice(p.lastIndexOf("/") + 1).toLowerCase(); };
/** The words after the command word and its switches (`-x`, cmd's `/c`), joined. */
const tail = (words: string[], at: number) => {
  while (++at < words.length && /^(?:-|\/[A-Za-z]{1,16}(?::\w{0,16})?$)/.test(words[at]));
  return words.slice(at).join(" ");
};

/** Tokenise a segment once and find its command word, after assignments, reserved
 *  words and launchers; a launcher with no command (`sudo -s`) reads as a shell. */
function describe(seg: Seg, ps: boolean, w: Work): Seg {
  if (seg.t !== undefined) return seg;
  spend(w, seg.text.length);
  if (seg.text.length > MAX_SEGMENT) return Object.assign(seg, { t: null, runs: 0 });
  const t = (seg.t = tokenize(seg.text, ps)), words = t.words;
  let at = 0, hops = 0, launched = false;
  for (; at < words.length && hops <= MAX_HOPS; hops++) {
    if (ASSIGN.test(words[at]) || RESERVED.test(words[at])) { at++; continue; }
    const b = base(words[at]), takes = LAUNCHERS.get(b);
    if (takes === undefined) break;
    launched = true;
    for (at++; at < words.length && (isFlag(words[at]) || (b === "env" && ASSIGN.test(words[at]))); ) at += takes?.test(words[at]) ? 2 : 1;
    if (b === "timeout") at++; // the duration
  }
  const found = at < words.length && hops <= MAX_HOPS, head = found ? base(words[at]) : launched || hops > MAX_HOPS ? "sh" : "";
  const runs = SHELL_HEAD.test(head) || (!PRINTER.test(head) && words.some((x, k) => k > at && SHELL.test(base(x)))) ? 2
    : RUNNER.test(head) || (found && SCRIPT.test(slash(words[at]))) ? 1 : 0;
  return Object.assign(seg, { at, head, runs });
}

/** PowerShell switches (no value), rsync options whose value is a separate word, PowerShell writers. */
const PS_SWITCH = /^-(?:Force|Append|NoNewline|Recurse|NoClobber|PassThru|WhatIf|Confirm|Verbose|Debug|AsByteStream)$/i;
const RSYNC_VALUE = /^(?:-[efBMT]|--(?:exclude|include|exclude-from|include-from|filter|files-from|rsh|rsync-path|temp-dir|partial-dir|backup-dir|suffix|compare-dest|copy-dest|link-dest|chmod|chown|log-file|log-file-format|password-file|out-format|max-size|min-size|bwlimit|timeout|contimeout|port|block-size|remote-option|info|debug|iconv|usermap|groupmap|max-delete|modify-window|sockopts))$/;
const PS_WRITER = /^(?:copy-item|move-item|set-content|add-content|out-file|tee-object|new-item)$/;
/** Codex's patch command (and its alias), which applies the patch on its stdin or in its argument. */
const PATCH_HEAD = /^(?:apply_patch|applypatch)(?:\.exe)?$/;

/** The files a segment writes, per the §6.7 target table (redirects aside). sed and
 *  perl in place: every operand (a sed script ending in a watched path is a `w`). */
function targets(words: string[], at: number, head: string): (string | undefined)[] {
  const args = words.slice(at + 1), ops = args.filter((a) => !isFlag(a));
  if (head === "tee" || head === "truncate") return ops;
  if (head === "sed") return args.some((a) => /^-[A-Za-z]{0,8}i|^--in-place\b/.test(a)) ? ops : [];
  if (head === "perl") return args.some((a) => /^-(?![MmI])[A-Za-z]{0,8}i/.test(a)) ? ops : []; // -M… is a module
  if (head === "dd") return args.filter((a) => a.startsWith("of=")).map((a) => a.slice(3));
  if (head === "cp" || head === "mv" || head === "install" || head === "ln") {
    for (let k = 0; k < args.length; k++) {
      const a = args[k], t = /^-[A-Za-z]{0,16}?t/.exec(a); // -t DIR, also in a cluster (-st DIR)
      if (t || a.startsWith("--target-directory")) return [t ? a.slice(t[0].length) || args[k + 1] : a[18] === "=" ? a.slice(19) : args[k + 1]];
    }
    return ops.slice(-1);
  }
  if (head === "rsync") {
    let last: string | undefined;
    for (let k = 0; k < args.length; k++) if (!isFlag(args[k])) last = args[k]; else if (RSYNC_VALUE.test(args[k])) k++;
    return [last];
  }
  if (!PS_WRITER.test(head)) return [];
  // PowerShell: named values (`-Name v`, `-Name:v`; a switch takes none) and positionals.
  const named = new Map<string, string | undefined>(), pos: string[] = [];
  for (let k = 0; k < args.length; k++) {
    const a = args[k], sep = a.indexOf(":");
    if (!isFlag(a)) pos.push(a);
    else if (sep > 0) named.set(a.slice(0, sep).toLowerCase(), a.slice(sep + 1) || args[++k]);
    else if (!PS_SWITCH.test(a)) named.set(a.toLowerCase(), args[++k]);
  }
  if (head === "copy-item" || head === "move-item") // -Path/-LiteralPath name the source
    return [named.get("-destination") ?? pos[named.has("-path") || named.has("-literalpath") ? 0 : 1]];
  const path = named.get("-path") ?? named.get("-literalpath") ?? named.get("-filepath") ?? pos[0], name = named.get("-name");
  return [head !== "new-item" || name === undefined ? path : `${path ?? "."}/${name}`];
}

/** A word of interpreter code that may name a file: it has a slash or an extension. */
const PATHISH = /[/\\]|\.\w{1,8}$/;
/** Interpreter code that makes a write call: the paths it names (every watched or store path among them). */
const interpTargets = (code: string) =>
  WRITE_CALL.test(code) ? code.split(/[\s'"`(),;]+/).filter((p) => PATHISH.test(p) || STORE_PATH.test(slash(p))) : [];

/** Distinct write targets kept for the integrity layer's `watch-prefixes.json` match, per kind
 *  (redirect and command operands; paths named in interpreter code); the rest are not listed. */
const MAX_TARGETS = 64;
type Acc = {
  deny: string | null; ask: string | null; cli: NexusCliAction; w: Work; coarse: boolean; targets: string[]; code: string[]; operands: string[];
  /** The ask is for a patch's target; the patch files (and their added text), and whether there were more than MAX_TARGETS. */
  askPatch: boolean; patches: PatchWrite[]; patchOverflow: boolean;
};
const note = (acc: Acc, target: string | undefined, list = acc.targets, patch = false) => {
  const p = slash(target ?? "");
  if (p && list.length < MAX_TARGETS && !list.includes(target!)) list.push(target!);
  if (p && STORE_PATH.test(p)) acc.deny ??= p;
  else if (p && WATCHED_NAME.test(p) && acc.ask === null) {
    acc.ask = p;
    acc.askPatch = patch;
  }
};

/** `path` under the directory an earlier `cd` moved to, when it is relative (Codex resolves a patch's paths against the shell's cwd). */
function underCd(path: string, cd: string | null): string {
  if (cd === null || /^(?:[\\/~]|[A-Za-z]:|\$)/.test(path)) return path;
  let end = cd.length;
  while (end > 0 && (cd[end - 1] === "/" || cd[end - 1] === "\\")) end--;
  return `${cd.slice(0, end)}/${path}`;
}

/** The files a patch in `text` writes, noted as write targets and kept with the text they add (see the header). */
function notePatch(acc: Acc, text: string, cd: string | null): void {
  if (!text.includes("*** Begin Patch")) return;
  spend(acc.w, text.length);
  const parsed = parsePatch(text);
  if (parsed.overflow) acc.patchOverflow = true;
  for (const op of parsed.ops) {
    const added = addedText(op);
    for (const p of opPaths(op)) {
      // Codex joins a patch's relative path to the cwd as written: `~` and `$X` are directory names there.
      const path = underCd(p[0] === "~" || p[0] === "$" ? `./${p}` : p, cd);
      if (acc.patches.length >= MAX_TARGETS) {
        acc.patchOverflow = true;
        return;
      }
      acc.patches.push({ path, added });
      note(acc, path, acc.targets, true);
    }
  }
}
const cliCheck = (acc: Acc, text: string) => {
  if (SELF_APPROVE_RE.test(text)) acc.cli = { rule: "integrity-self-approve", decision: "deny" };
  else if (!acc.cli && UNINSTALL_RE.test(text)) acc.cli = { rule: "guard-uninstall", decision: "ask" };
};

/** The coarse verdict on free text, or on a heredoc `body` that ended in an open quote (its store deny needs BODY_WRITE; see the header). */
function coarse(acc: Acc, text: string, body = false): void {
  const s = slash(text), b = s.replace(/['"`]/g, ""); // also with quotes dropped: `".nexus"/integrity`, `integrity "accept"`
  const watched = WATCHED_CONTAINS.exec(s) ?? WATCHED_CONTAINS.exec(b), store = STORE_CONTAINS.exec(s) ?? STORE_CONTAINS.exec(b);
  if (store && ((body ? BODY_WRITE.test(s) : COARSE_VERB.test(text)) || WRITE_CALL.test(text))) acc.deny ??= store[0];
  if (watched) acc.ask ??= watched[1];
  for (const x of [text, b]) cliCheck(acc, x);
}

/** Analyse `src` into acc: the command at level 0, a string it runs at level 1. */
function analyze(src: string, level: number, ps: boolean, acc: Acc): void {
  const segs: Seg[] = [], bodies: Body[] = [], w = acc.w;
  if (scan(src, 0, src.length, ps, false, segs, bodies, w) !== true) { acc.coarse ||= level === 0; return coarse(acc, src); }
  const code = level > 0 || segs.some((s) => (describe(s, ps, w).runs ?? 0) > 0);
  for (let k = 0; k < bodies.length; k++) {
    const [a, b, quoted] = bodies[k];
    if (code) { spend(w, b - a); for (const t of interpTargets(src.slice(a, b))) note(acc, t, acc.code); }
    // Only an apostrophe in prose earns the narrow store check; a body the scan gave up on gets the full coarse one.
    const end = (code || !quoted) && b > a ? scan(src, a, b, ps, !code, segs, bodies, w) : true;
    if (end !== true) coarse(acc, src.slice(a, b), end === "open-quote");
  }
  let cd: string | null = null, patchBodies = false;
  for (const seg of segs) {
    if (acc.deny) return;
    const { t, at = 0, head = "", runs } = describe(seg, ps, w);
    if (!t) { coarse(acc, seg.text); continue; }
    spend(w, 2 * t.bare.length + t.words.length);
    cliCheck(acc, t.bare);
    if (head === "cd") {
      const dir = t.words.slice(at + 1).find((x) => !isFlag(x));
      cd = dir === undefined ? null : underCd(dir, cd);
    }
    if (PATCH_HEAD.test(head)) {
      // The patch: any heredoc body of the command (read once), a here-string or quoted word, or what an echo pipes in.
      if (!patchBodies) for (const [a, b] of bodies) notePatch(acc, src.slice(a, b), cd);
      patchBodies = true;
      const fedWords = seg.pipeFrom?.t && PRINTER.test(seg.pipeFrom.head ?? "") ? seg.pipeFrom.t.quoted.map((k) => seg.pipeFrom!.t!.words[k]) : [];
      for (const text of [...t.here, ...t.quoted.map((k) => t.words[k]), ...fedWords]) notePatch(acc, text, cd);
    }
    for (const r of [...t.redir, ...targets(t.words, at, head)]) note(acc, r);
    if (WRITE_VERB.test(head)) for (let k = at + 1; k < t.words.length; k++) if (STORE_PATH.test(slash(t.words[k]))) acc.deny ??= slash(t.words[k]);
    if (DELETE_VERB.test(head)) {
      for (let k = at + 1; k < t.words.length && acc.operands.length < MAX_TARGETS; k++) {
        const word = t.words[k];
        if (!isFlag(word) && word !== "" && !acc.operands.includes(word)) acc.operands.push(word);
      }
    }
    if (runs) { spend(w, seg.end - seg.start); for (const r of interpTargets(src.slice(seg.start, seg.end))) note(acc, r, acc.code); }
    // A string the command runs is read as commands, one level deep; in one, a shell's string gets the coarse check.
    const run = (q: string) => { spend(w, q.length); if (level === 0) analyze(q, 1, PS_RUNNER.test(head) || LOOKS_PS.test(q), acc); else if (runs === 2) coarse(acc, q); };
    const strings = t.quoted.filter((k) => k > at).map((k) => t.words[k]), fed = seg.pipeFrom;
    if (runs) for (const q of strings.length ? strings : t.here) run(q);
    if (REST_RUNNER.test(head)) run(tail(t.words, at));
    // What an echo prints into a shell that has no string of its own.
    if (fed?.t && PRINTER.test(fed.head ?? "") && SHELL.test(head) && !strings.length) run(tail(fed.t.words, fed.at ?? 0));
  }
}

/** The context-free shell rules in one pass: the most severe shell-write verdict, the Nexus
 *  CLI action, whether the whole command got the coarse verdict (over `budget`, open quote),
 *  the write targets found (as written, at most 64 operands and 64 paths named in
 *  interpreter code; the integrity layer matches them against `watch-prefixes.json`) and
 *  the operands of delete and move commands (at most 64; the integrity layer checks them,
 *  with the targets, against the Nexus data directory in use). */
export function analyzeShellCommand(
  command: string, budget = 16 * command.length + 20_000,
): {
  write: ShellWriteDecision; cli: NexusCliAction; coarse: boolean; targets: string[]; operands: string[];
  /** Files a patch fed to `apply_patch` writes (at most MAX_TARGETS; `patchOverflow` when there were more). */
  patches: PatchWrite[]; patchOverflow: boolean;
} {
  const acc: Acc = {
    deny: null, ask: null, cli: null, w: { left: budget }, coarse: false, targets: [], code: [], operands: [],
    askPatch: false, patches: [], patchOverflow: false,
  };
  try { analyze(command, 0, LOOKS_PS.test(command), acc); }
  catch (e) { if (e !== OVER) throw e; acc.coarse = true; coarse(acc, command); }
  const write: ShellWriteDecision = acc.deny ? { decision: "deny", rule: "nexus-store-write", target: acc.deny }
    : acc.ask ? { decision: "ask", rule: acc.askPatch ? SHELL_PATCH_RULE : "instruction-file-shell-write", target: acc.ask }
    : { decision: "allow", rule: null, target: null };
  return {
    write, cli: acc.cli, coarse: acc.coarse, targets: [...acc.targets, ...acc.code], operands: acc.operands,
    patches: acc.patches, patchOverflow: acc.patchOverflow,
  };
}

/** `~/.claude/CLAUDE.md` by any home spelling, or `$CLAUDE_CONFIG_DIR/CLAUDE.md`. */
const USER_CLAUDE_MD =
  /^(?:(?:~|\$HOME|\$\{HOME\}|\$env:(?:USERPROFILE|HOME)|%USERPROFILE%|(?:[A-Za-z]:)?\/(?:home|Users)\/[^/]{1,64}|\/root)\/\.claude|\$\{?CLAUDE_CONFIG_DIR\}?)\/CLAUDE\.md$/i;
/** The label of a Codex home's AGENTS.md (or AGENTS.override.md). */
export const CODEX_USER_INSTRUCTIONS = "Codex user instructions";
/**
 * A Codex home's AGENTS.md (or AGENTS.override.md) by a path that names the home:
 * `$CODEX_HOME/…`, or `~/.codex/…`, its default, by any home spelling. Codex reads
 * AGENTS.md as user instructions only in its home, so one in any other `.codex`
 * directory (a project's, which holds its config, hooks, rules and skills) is named as
 * any AGENTS.md is, as the integrity layer names it (`writeRoleOf`) when it does not
 * know that directory as a Codex home: the same write is named the same with integrity
 * on or off (handler.ts `relabeledShellWrite`).
 */
const CODEX_HOME_AGENTS_MD =
  /^(?:\$\{?CODEX_HOME\}?|(?:~|\$HOME|\$\{HOME\}|\$env:(?:USERPROFILE|HOME)|%USERPROFILE%|(?:[A-Za-z]:)?\/(?:home|Users)\/[^/]{1,64}|\/root)\/\.codex)\/AGENTS(?:\.override)?\.md$/i;
/** Codex's other files, in any `.codex` (or `$CODEX_HOME`) directory, by the label a reason gives them (checked before the generic ones). */
const CODEX_LABELS: [RegExp, string][] = [
  [/(?:^|\/)(?:\.codex|\$\{?CODEX_HOME\}?)\/(?:[^/]{1,255}\.)?config\.toml$|^\/etc\/codex\//i, "Codex config"],
  [/(?:^|\/)(?:\.codex|\$\{?CODEX_HOME\}?)\/hooks\.json$/i, "Codex hooks"],
  [/(?:^|\/)(?:\.codex|\$\{?CODEX_HOME\}?)\/rules(?:\/|$)/i, "Codex exec-policy rules"],
  [/(?:^|\/)(?:\.codex|\$\{?CODEX_HOME\}?|\.agents)\/skills(?:\/|$)/i, "a Codex skill"],
  [/(?:^|\/)(?:\.codex|\$\{?CODEX_HOME\}?)\/memories/i, "Codex memory"],
];
const LABELS: [RegExp, string][] = [
  [/(?:^|\/)CLAUDE\.local\.md$/i, "personal project instructions"], [/(?:^|\/)(?:CLAUDE|AGENTS(?:\.override)?)\.md$/i, "project instructions"],
  [/(?:^|\/)\.claude\/settings(?:\.local)?\.json$/i, "Claude Code settings"], [/(?:^|\/)(?:\.mcp|\.claude)\.json$/i, "MCP server config"],
  [/(?:^|\/)\.claude\/hooks(?:\/|$)/i, "a hook script"], [/(?:^|\/)\.claude\/rules(?:\/|$)/i, "a rules file"],
  [/(?:^|\/)\.claude\/agents(?:\/|$)/i, "a subagent definition"], [/(?:^|\/)\.claude\/commands(?:\/|$)/i, "a slash command"], [/(?:^|\/)\.claude\/skills(?:\/|$)/i, "a skill"]];

/** AGENTS.md or AGENTS.override.md directly in a directory, on forward-slash text: the directory. */
const AGENTS_FILE_DIR = /^(.*)\/AGENTS(?:\.override)?\.md$/i;

/**
 * Is `t` (forward slashes) an AGENTS.md in `codexHome`, the absolute
 * `$CODEX_HOME` the hook's environment names, by that path? Compared as
 * written (a Windows drive path ignoring case): the integrity layer, when on,
 * names the file by its real path (handler.ts `relabeledShellWrite`).
 */
function inCodexHome(t: string, codexHome: string): boolean {
  const dir = AGENTS_FILE_DIR.exec(t)?.[1];
  const home = slash(codexHome).replace(/\/+$/, "");
  if (dir === undefined || home === "") return false;
  return dir === home || (/^[A-Za-z]:\//.test(home) && dir.toLowerCase() === home.toLowerCase());
}

/**
 * A human label for a watched target, for the `ask` reason (the §6.6 set).
 * `codexHome`: an absolute `$CODEX_HOME`, whose AGENTS.md is Codex's user
 * instructions by its path as well as by the `$CODEX_HOME` spelling.
 */
export const watchedLabel = (target: string, codexHome?: string) => {
  const t = slash(target);
  if (USER_CLAUDE_MD.test(t)) return "user instructions";
  if (CODEX_HOME_AGENTS_MD.test(t) || (codexHome !== undefined && inCodexHome(t, codexHome))) return CODEX_USER_INSTRUCTIONS;
  return CODEX_LABELS.find(([re]) => re.test(t))?.[1] ?? LABELS.find(([re]) => re.test(t))?.[1] ?? "agent memory";
};

/** ANSI escapes: CSI, OSC (to BEL or ST) and two-character ones. */
const ANSI_ESCAPE = /\u001b(?:\[[0-?]{0,64}[ -/]{0,16}[@-~]|\][^\u0007\u001b]{0,512}(?:\u0007|\u001b\\)?|[@-Z\\-_])/g;

/** Characters of a target a reason shows. */
const SHOWN_TARGET = 120;
const cleanTarget = (target: string) => target.replace(ANSI_ESCAPE, "").replace(/[\u0000-\u001f\u007f-\u009f]/g, "");

/** A target as echoed in a reason: ANSI escapes and control characters stripped, ≤ 120 characters (a surrogate pair kept whole). */
export function displayTarget(target: string): string {
  const clean = cleanTarget(target);
  return clean.length > SHOWN_TARGET ? headUnits(clean, SHOWN_TARGET - 1) + "…" : clean;
}

/**
 * A target as a reason shows it when the file it names matters (the trust
 * store's, a patch's): like `displayTarget`, but a long path loses its start
 * (a long home or project directory), so the file name stays in view, and the
 * part that names the store (`.nexus/integrity/…`, a key file) with it; when
 * even the end would cut that part away, the text from it is shown.
 */
export function displayPathTarget(target: string): string {
  const clean = cleanTarget(target);
  if (clean.length <= SHOWN_TARGET) return clean;
  const from = clean.length - (SHOWN_TARGET - 1);
  const store = STORE_CONTAINS.exec(clean.replace(/\\/g, "/"));
  if (!store || store.index >= from) return `…${tailFrom(clean, from)}`;
  return `…${headUnits(clean.slice(store.index, store.index + SHOWN_TARGET - 1), SHOWN_TARGET - 2)}…`;
}
