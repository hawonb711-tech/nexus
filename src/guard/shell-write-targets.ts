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
 *   it untokenised. A command starting like PowerShell (Verb-Noun, pwsh) keeps `\` literal.
 */

export type ShellWriteDecision = { decision: "deny" | "ask" | "allow"; rule: string | null; target: string | null };
export type NexusCliAction = { rule: "integrity-self-approve"; decision: "deny" } | { rule: "guard-uninstall"; decision: "ask" } | null;

/** A watched instruction/config path, on forward-slash text, anchored on a path boundary
 *  (a write's target must BE the file); case-insensitive, like macOS and Windows. */
export const WATCHED_NAME =
  /(?:^|\/)(?:CLAUDE(?:\.local)?\.md|AGENTS\.md|\.mcp\.json|\.claude\.json)$|(?:^|\/)\.claude\/(?:settings(?:\.local)?\.json$|(?:rules|agents|commands|skills|hooks|agent-memory(?:-local)?)(?:\/|$))|(?:^|\/)\.claude\/projects\/[^/]{1,255}\/memory(?:\/|$)/i;
/** A watched name anywhere in free text (the coarse verdict); captures the name. */
const WATCHED_CONTAINS =
  /(?:^|[^\w.-])((?:CLAUDE(?:\.local)?\.md|AGENTS\.md|\.mcp\.json|\.claude\.json)\b|\.claude\/(?:settings(?:\.local)?\.json|rules|agents|commands|skills|hooks|agent-memory|projects\/[^/]{1,255}\/memory))/i;
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
const COARSE_VERB = /\b(?:rm|unlink|shred|mv|cp|ln|chmod|chown|truncate|tee|sed|perl|dd|install|rsync|remove-item|move-item|copy-item|set-content|add-content|out-file|new-item|del|rmdir)\b|>/i;
const LOOKS_PS = /^\s{0,64}(?:[A-Z][a-z]{1,16}-[A-Z][A-Za-z]{1,40}|[Pp](?:wsh|ower[Ss]hell)(?:\.exe)?)(?:\s|$)/;
const ASSIGN = /^[A-Za-z_][A-Za-z0-9_]{0,127}=/, RESERVED = /^(?:!|if|then|else|elif|do|while|until)$/;
/** Launchers that run the rest of the line, and their options that take a value. */
const LAUNCHERS = new Map<string, RegExp | null>([
  ["sudo", /^-[ughpCrtUDT]$/], ["doas", /^-[uC]$/], ["env", /^-[uCS]$/], ["nohup", null], ["time", null], ["command", null],
  ["builtin", null], ["exec", /^-a$/], ["nice", /^-n$/], ["ionice", /^-[cnp]$/], ["stdbuf", /^-[ioe]$/], ["timeout", /^-[sk]$/], ["xargs", /^-[aEdIiLlnPs]$/]]);

type Work = { left: number };
const OVER = new Error("shell-write analysis over budget");
const spend = (w: Work, n: number) => { if ((w.left -= n) < 0) throw OVER; };

/** A segment's words (unquoted; no redirect operands), write-redirect targets, indices of
 *  words with a quoted part (`-c 'a '\''b'` is one), here-strings, words with phrases blanked. */
type Words = { words: string[]; bare: string; redir: string[]; quoted: number[]; here: string[] };
/** `runs`: 2 when the command runs a string as shell commands, 1 for other code. */
type Seg = { text: string; start: number; end: number; pipeFrom: Seg | null; t?: Words | null; at?: number; head?: string; runs?: number };
type Body = [start: number, end: number, quoted: boolean]; // a heredoc body, and whether its delimiter was quoted
type Builder = { parts: string[]; from: number; start: number; data: boolean; pipeFrom: Seg | null; word: boolean };
type Ctx = { m: "cmd" | "dq" | "hd" | "param" | "arith"; close: string; outer: Builder | null; parens: number };

/** Cut src[from, to) into segments and heredoc bodies. `hd`: a data body, where only `$(…)`,
 *  backticks and `${…}` are code; `ps`: a backtick escapes, a backslash is literal. False
 *  when the scan ends inside a quote or nests past MAX_NEST. */
function scan(src: string, from: number, to: number, ps: boolean, hd: boolean, segs: Seg[], bodies: Body[], w: Work): boolean {
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
    if (stack.length > MAX_NEST) return false;
    const c = src[i], top = stack[stack.length - 1], n = src[i + 1];
    if (top.m === "dq" || top.m === "hd" || top.m === "param") {
      if (c === esc) i++;
      else if ((c === '"' && top.m === "dq") || (c === "}" && top.m === "param")) stack.pop();
      else if (c === "$" || (c === "`" && !ps)) i = open(i);
      continue;
    }
    // Outside quotes `\'` / `\"` is bash's escape but a PowerShell path's end: ambiguous.
    if (ps && c === "\\" && (n === "'" || n === '"')) return false;
    const glued = i > from && src[i - 1] === ">" && escAt !== i - 1; // `>&`, `>|`
    if (c === esc) escAt = ++i;
    else if (c === "'" || (c === "$" && n === "'")) {
      let j = i + (c === "$" ? 2 : 1);
      while (j < to && src[j] !== "'") j += c === "$" && src[j] === "\\" ? 2 : 1;
      if (j >= to) return false;
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
    else if (c === "(" && n === "(") { stack.push(ctx("arith")); i++; }
    else if (c === "(" && !fresh(i) && !/(?:^|\s)in[ \t]{1,8}$/.test(src.slice(Math.max(cur.from, i - 12), i)))
      nest(i, ")", i + 1); // past the first word, unless a case pattern: `<(…)`, extglob, `f()`, a PowerShell argument
    else if (c === "(") { split(i, i + 1); stack.push(ctx("cmd", ")")); }
    else if (c === ")") { if (top.close === ")") close(i); else split(i, i + 1); }
    else if (c === "<" && n === "<") i = src[i + 2] === "<" ? i + 2 : heredoc(i + 2) - 1;
  }
  if (stack.some((x) => x.m === "dq" || x.m === "param")) return false;
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

const slash = (p: string) => p.replace(/\\+/g, "/");
const base = (w: string) => { const p = slash(w); return p.slice(p.lastIndexOf("/") + 1).toLowerCase(); };
const isFlag = (w: string) => w.startsWith("-");
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

/** Interpreter code that makes a write call: the watched or store paths it names. */
const interpTargets = (code: string) =>
  WRITE_CALL.test(code) ? code.split(/[\s'"`(),;]+/).filter((p) => WATCHED_NAME.test(slash(p)) || STORE_PATH.test(slash(p))) : [];

type Acc = { deny: string | null; ask: string | null; cli: NexusCliAction; w: Work; coarse: boolean };

const note = (acc: Acc, target: string | undefined) => {
  const p = slash(target ?? "");
  if (p && STORE_PATH.test(p)) acc.deny ??= p;
  else if (p && WATCHED_NAME.test(p)) acc.ask ??= p;
};
const cliCheck = (acc: Acc, text: string) => {
  if (SELF_APPROVE_RE.test(text)) acc.cli = { rule: "integrity-self-approve", decision: "deny" };
  else if (!acc.cli && UNINSTALL_RE.test(text)) acc.cli = { rule: "guard-uninstall", decision: "ask" };
};

/** The coarse verdict on free text (see the header). */
function coarse(acc: Acc, text: string): void {
  const s = slash(text), b = s.replace(/['"`]/g, ""); // also with quotes dropped: `".nexus"/integrity`, `integrity "accept"`
  const watched = WATCHED_CONTAINS.exec(s) ?? WATCHED_CONTAINS.exec(b), store = STORE_CONTAINS.exec(s) ?? STORE_CONTAINS.exec(b);
  if (store && (COARSE_VERB.test(text) || WRITE_CALL.test(text))) acc.deny ??= store[0];
  if (watched) acc.ask ??= watched[1];
  for (const x of [text, b]) cliCheck(acc, x);
}

/** Analyse `src` into acc: the command at level 0, a string it runs at level 1. */
function analyze(src: string, level: number, ps: boolean, acc: Acc): void {
  const segs: Seg[] = [], bodies: Body[] = [], w = acc.w;
  if (!scan(src, 0, src.length, ps, false, segs, bodies, w)) { acc.coarse ||= level === 0; return coarse(acc, src); }
  const code = level > 0 || segs.some((s) => (describe(s, ps, w).runs ?? 0) > 0);
  for (let k = 0; k < bodies.length; k++) {
    const [a, b, quoted] = bodies[k];
    if (code) { spend(w, b - a); for (const t of interpTargets(src.slice(a, b))) note(acc, t); }
    if ((code || !quoted) && b > a && !scan(src, a, b, ps, !code, segs, bodies, w)) coarse(acc, src.slice(a, b));
  }
  for (const seg of segs) {
    if (acc.deny) return;
    const { t, at = 0, head = "", runs } = describe(seg, ps, w);
    if (!t) { coarse(acc, seg.text); continue; }
    spend(w, 2 * t.bare.length + t.words.length);
    cliCheck(acc, t.bare);
    for (const r of [...t.redir, ...targets(t.words, at, head)]) note(acc, r);
    if (WRITE_VERB.test(head)) for (let k = at + 1; k < t.words.length; k++) if (STORE_PATH.test(slash(t.words[k]))) acc.deny ??= slash(t.words[k]);
    if (runs) { spend(w, seg.end - seg.start); for (const r of interpTargets(src.slice(seg.start, seg.end))) note(acc, r); }
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
 *  CLI action, and whether the whole command got the coarse verdict (over `budget`, open quote). */
export function analyzeShellCommand(command: string, budget = 16 * command.length + 20_000): { write: ShellWriteDecision; cli: NexusCliAction; coarse: boolean } {
  const acc: Acc = { deny: null, ask: null, cli: null, w: { left: budget }, coarse: false };
  try { analyze(command, 0, LOOKS_PS.test(command), acc); }
  catch (e) { if (e !== OVER) throw e; acc.coarse = true; coarse(acc, command); }
  const write: ShellWriteDecision = acc.deny ? { decision: "deny", rule: "nexus-store-write", target: acc.deny }
    : acc.ask ? { decision: "ask", rule: "instruction-file-shell-write", target: acc.ask } : { decision: "allow", rule: null, target: null };
  return { write, cli: acc.cli, coarse: acc.coarse };
}

/** `~/.claude/CLAUDE.md` by any home spelling, or `$CLAUDE_CONFIG_DIR/CLAUDE.md`. */
const USER_CLAUDE_MD =
  /^(?:(?:~|\$HOME|\$\{HOME\}|\$env:(?:USERPROFILE|HOME)|%USERPROFILE%|(?:[A-Za-z]:)?\/(?:home|Users)\/[^/]{1,64}|\/root)\/\.claude|\$\{?CLAUDE_CONFIG_DIR\}?)\/CLAUDE\.md$/i;
const LABELS: [RegExp, string][] = [
  [/(?:^|\/)CLAUDE\.local\.md$/i, "personal project instructions"], [/(?:^|\/)(?:CLAUDE|AGENTS)\.md$/i, "project instructions"],
  [/(?:^|\/)\.claude\/settings(?:\.local)?\.json$/i, "Claude Code settings"], [/(?:^|\/)(?:\.mcp|\.claude)\.json$/i, "MCP server config"],
  [/(?:^|\/)\.claude\/hooks(?:\/|$)/i, "a hook script"], [/(?:^|\/)\.claude\/rules(?:\/|$)/i, "a rules file"],
  [/(?:^|\/)\.claude\/agents(?:\/|$)/i, "a subagent definition"], [/(?:^|\/)\.claude\/commands(?:\/|$)/i, "a slash command"], [/(?:^|\/)\.claude\/skills(?:\/|$)/i, "a skill"]];

/** A human label for a watched target, for the `ask` reason (the §6.6 set). */
export const watchedLabel = (target: string) =>
  USER_CLAUDE_MD.test(slash(target)) ? "user instructions" : LABELS.find(([re]) => re.test(slash(target)))?.[1] ?? "agent memory";

/** ANSI escapes: CSI, OSC (to BEL or ST) and two-character ones. */
const ANSI_ESCAPE = /\u001b(?:\[[0-?]{0,64}[ -/]{0,16}[@-~]|\][^\u0007\u001b]{0,512}(?:\u0007|\u001b\\)?|[@-Z\\-_])/g;

/** A target as echoed in a reason: ANSI escapes and control characters stripped, ≤ 120 characters. */
export function displayTarget(target: string): string {
  const clean = target.replace(ANSI_ESCAPE, "").replace(/[\u0000-\u001f\u007f-\u009f]/g, "");
  return clean.length > 120 ? clean.slice(0, 119) + "…" : clean;
}
