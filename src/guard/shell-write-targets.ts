/**
 * Shell-write-target extraction for the command guard.
 *
 * A prompt-injected agent can steer every future Claude session not only through
 * the Write/Edit tools (which the integrity layer tracks) but by shelling out —
 * `echo … >> CLAUDE.md`, `tee .claude/settings.json`, `sed -i … AGENTS.md`,
 * `python -c 'open("CLAUDE.md","w")…'`. Those shell writes bypass edit tracking,
 * so they are surfaced here: a write whose target is a watched instruction/config
 * file is an `ask`, and any write or delete touching Nexus's own trust store is a
 * `deny`. The same pass finds the agent running the Nexus CLI to approve its own
 * changes (`integrity-self-approve`, deny) or to remove the hooks
 * (`guard-uninstall`, ask).
 *
 * Spec amendments (deliberate deviations from §6.7):
 * - Raw-text segmentation. The spec segments the resolveCommand-normalised text,
 *   but resolveCommand strips quotes and newlines, which merges a heredoc body
 *   into its command and loses the quoting that says what is data. Segments are
 *   cut from the raw command instead, outside quotes, with subshells, `{ …; }`
 *   groups, `$(…)` and backticks opened as nested commands and heredoc bodies
 *   kept as data unless the command that owns them runs them.
 * - KEY_PATH split from SECRET_PATH (capability.ts). The key files are a secret
 *   path for commands only: in SECRET_PATH they also fed the content windows,
 *   where a doc naming a key file near a `curl` install line became an exfil deny.
 * - Quoted-string blanking for the self-approve rules. integrity-self-approve and
 *   guard-uninstall fire when a segment's command-position parser finds the Nexus
 *   CLI, or when the spec regex matches the segment with the contents of '…' and
 *   "…" blanked, so a quoted mention (`grep "integrity accept"`, a commit
 *   message) stays allow while an unquoted CLI call behind any launcher is still
 *   caught. A quoted string is read as commands only when a shell runs it (see
 *   innerCommand): `sh -c` / `bash -o x -c` as the command or an argument
 *   (`xargs sh -c`, `find -exec bash -c`), `su|runuser -c`, `script -c`,
 *   `flock -c`, `pwsh -c|-Command`, `powershell "…"`, `cmd /c|/k`, `eval`,
 *   `iex`, a `<<<` here-string, or an `echo`/`printf` piped into a shell or
 *   `iex`. A string another program runs (`ssh host '…'`, `watch '…'`,
 *   `python -c "os.system('…')"`, `expect -c`) is not read, and a quoted CLI
 *   call there stays allow: this rule is defence in depth against an agent
 *   that can run code (spec §2.3 item 5), beside the CLI's own TTY /
 *   CLAUDECODE gate on the approval commands (PR3).
 *
 * This is pure and context-free (the PreToolUse hook, the MCP `nexus_guard` tool
 * and library callers all get it). The command is split once (a second time with
 * PowerShell quoting when bash quoting leaves a quote open) and each segment
 * tokenised once; the store, watched-file and CLI checks read the same tokens.
 * Everything is bounded: the scanner is one linear pass per nesting level (with
 * capped nesting and depth), every regex uses bounded quantifiers, and a
 * pathological segment is short-circuited by the 20,000-character rule.
 */

export type ShellWriteDecision = { decision: "deny" | "ask" | "allow"; rule: string | null; target: string | null };

export type NexusCliAction =
  | { rule: "integrity-self-approve"; decision: "deny" }
  | { rule: "guard-uninstall"; decision: "ask" }
  | null;

/**
 * A watched instruction/config path, matched on forward-slash text (callers
 * normalise backslashes first). Anchored on a path boundary so the TARGET of a
 * write must BE the file, not merely mention it. Case-insensitive, as the macOS
 * and Windows filesystems are.
 */
export const WATCHED_NAME =
  /(?:^|\/)(?:CLAUDE(?:\.local)?\.md|AGENTS\.md|\.mcp\.json|\.claude\.json)$|(?:^|\/)\.claude\/(?:settings(?:\.local)?\.json$|(?:rules|agents|commands|skills|hooks|agent-memory(?:-local)?)(?:\/|$))|(?:^|\/)\.claude\/projects\/[^/]{1,255}\/memory(?:\/|$)/i;

/** Loose "mentions a watched name" check for the oversize-segment short circuit:
 *  no `$` anchor, and the name may follow any character that cannot be part of a
 *  file name (a space, quote, `>`, `=`, `/`). The capture is the name, for the
 *  `ask` reason's label. */
const WATCHED_CONTAINS =
  /(?:^|[^\w.-])((?:CLAUDE(?:\.local)?\.md|AGENTS\.md|\.mcp\.json|\.claude\.json)\b|\.claude\/(?:settings(?:\.local)?\.json|rules|agents|commands|skills|hooks|agent-memory|projects\/[^/]{1,255}\/memory))/i;

/** A path inside Nexus's own trust store (default `.nexus/` location) or one of
 *  its key files, anywhere in the token. Writes/deletes here are a hard deny. */
const STORE_PATH =
  /(?:^|\/)\.nexus\/(?:integrity|observations)(?:\/|$)|\.(?:integrity-key|sanitation-key|integrity-anchor)\b/i;

/** The over-length guard: beyond this a segment is not tokenised, it only gets a
 *  cheap "mentions a watched name?" ask. */
const MAX_SEGMENT = 20_000;
/** Nested commands (subshells, groups, `$(…)`, backticks) opened at once; past
 *  this an opener is plain text, which the tokeniser still splits words on. */
const MAX_NEST = 32;
/** Heredoc bodies and `sh -c` strings read as commands inside one another; past
 *  this a `<<` is plain text, so a deeper body reads as commands. */
const MAX_DEPTH = 6;

/** A write call inside an interpreter one-liner body (run on the RAW segment, so
 *  the string literals and mode flag are intact): an `open(…, "w"|"a")`, perl's
 *  `open(F, ">>", …)` / `open my $f, ">", …`, or a write function. */
export const WRITE_CALL =
  /open\s{0,8}\([^)]{0,200}['"](?:[wa]|\+?>)|\bopen\s{1,8}(?:my\s{1,8})?\$?\w{1,64}\s{0,8},\s{0,8}['"]\+?>|write_text|writeFileSync|writeFile|appendFile|File\.write|fs\.write/;

const INTERP = /^(?:python[\d.]{0,4}|node|ruby|perl|php|deno|bun)(?:\.exe)?$/;
/** A shell, as any command word of the pipeline that owns a heredoc: its body is
 *  commands (`bash <<EOF`, `cat <<EOF | sh`, `docker exec -i c sh <<EOF`). */
const SHELLS = /^(?:(?:ba|z|da|k|mk|a|fi|c|tc)?sh|pwsh|powershell|cmd|ssh)(?:\.exe)?$/;
/** A command that runs its input as code, as the command word only. */
const SHELL_FED_HEAD = /^(?:\.|source|eval|su|at|batch|crontab|make)$/;
/** An interpreter that runs its stdin when it has no script operand (or `-`). */
const INTERP_FEED = /^(?:python[\d.]{0,4}|node|ruby|perl|php|deno|bun|osascript)(?:\.exe)?$/;
/** An interpreter flag that takes the program inline (`-c`, `-e`, `-le`, `--eval`). */
const INLINE_CODE = /^-[A-Za-z]{0,8}[ceE]$|^-[ce].|^--(?:eval|print)(?:=|$)/;

type Tok = { kind: "word" | "op"; value: string };
type Feed = "shell" | "interp";
/** One segment's tokens, its command words (redirect operands left out), the
 *  index of the command word after any launcher (`sudo`, `env X=1`, `nohup` …)
 *  and that word's lower-cased basename. */
type Parsed = { toks: Tok[]; words: string[]; at: number; head: string; sudoShell: boolean };
/** A simple command: its text (a `$(…)` replaced by `$_`; comments and heredoc
 *  bodies cut out) and its parse (null over MAX_SEGMENT). An `interp` segment is
 *  a heredoc body an interpreter reads, which only the interpreter row inspects.
 *  `stdin` is what an `echo`/`printf` before it in the pipeline prints, when
 *  this segment runs its input (`echo '…' | sh`, `… | iex`). */
type Seg = { text: string; parsed: Parsed | null; depth: number; interp?: boolean; stdin?: string };

/** Strip surrounding quotes and map backslashes to forward slashes, so a native
 *  Windows target (`C:\Users\me\CLAUDE.md`) is matched by the `/`-written rules. */
function normPath(tok: string): string {
  return tok.replace(/^['"]+|['"]+$/g, "").replace(/\\+/g, "/");
}

function basenameLower(tok: string): string {
  const p = normPath(tok);
  return (p.split("/").pop() ?? p).toLowerCase();
}

const isFlag = (w: string) => w.startsWith("-");

// ── Segmenting ─────────────────────────────────────────────────────────────────

type Heredoc = {
  delim: string; strip: boolean; literal: boolean; start: number; end: number;
  decided: boolean; feed: Feed | null; done: boolean; owner: Seg | null;
};
/** A data heredoc body and the command that owns it: if that command writes a
 *  file the same command line later runs (`cat > s.sh <<EOF … EOF; bash s.sh`),
 *  the body is code after all. */
type Written = { src: string; start: number; end: number; owner: Seg; depth: number };
/** Where a scan puts its segments. `ps` scans PowerShell quoting: a backtick
 *  escapes and a backslash is a path separator. */
type Sink = { segs: Seg[]; written: Written[]; ps: boolean };

/** A nested command: it owns the segments cut inside it. `open` holds the
 *  heredocs whose output flows into its current pipeline; `carry`, those of its
 *  finished pipelines, handed to the enclosing command when it closes (a group's
 *  and a substitution's output is the enclosing command's input or argument).
 *  `last` is its last segment, the one a segment after `|` reads. */
type Frame = {
  kind: "root" | "group" | "brace" | "subst" | "bq" | "arith";
  pieces: string[]; from: number;
  open: Heredoc[]; carry: Heredoc[]; mine: Heredoc[];
  parens: number; closer: string; pipe: boolean; last: Seg | null;
};
type Ctx = { kind: "cmd"; frame: Frame } | { kind: "sq" } | { kind: "ansi" } | { kind: "dq" } | { kind: "hd" } | { kind: "param"; inDq: boolean };

/**
 * Cut `src[start, end)` into simple-command segments, appended to `sink`.
 * Returns false when it ends inside a quote (the caller then rescans with the
 * other shell's quoting).
 *
 * Separators are `;`, `&&`, `||`, `|`, `&` and newline outside quotes (a `&` or
 * `|` that is part of a redirect, `&>` `>&` `>|`, does not split), and the
 * unquoted `(`/`)` of a subshell, a standalone `{`/`}`, `$(…)`, `$((…))` and
 * backticks, whose contents are segments of their own. Inside double quotes a
 * `$(…)` is still a command; a backtick there is text (PowerShell's escape).
 *
 * A heredoc body (`<<WORD` to the line `WORD`) is cut out of the command. It is
 * read as commands only when the pipeline that owns the heredoc runs it — a
 * shell or `ssh` anywhere in it, `sudo -s`, `source`/`eval`/`make`… as the
 * command, an interpreter with no script operand, or the command a group or
 * `$(…)` around it feeds (`(cat <<EOF …) | bash`, `bash -c "$(cat <<EOF …)"`).
 * Otherwise it is data, and only an unquoted body's `$(…)`/backticks are read.
 * `mode: "hd"` scans such a body. `<<` in a comment, arithmetic or `${…}` is no
 * heredoc. One linear pass per nesting level.
 */
function scan(src: string, start: number, end: number, mode: "cmd" | "hd", depth: number, sink: Sink): boolean {
  const heredocs = depth < MAX_DEPTH;
  const pending: Heredoc[] = [];
  const stack: Ctx[] = [];
  const frames: Frame[] = [];
  let escaped = -1; // index of the last character taken by an escape pair: a `\>` is no redirect
  const ch = (k: number) => (k < end ? src[k] : "");

  const out = sink.segs;
  const readBody = (h: Heredoc) => {
    if (h.feed === "shell") { scan(src, h.start, h.end, "cmd", depth + 1, sink); return; }
    if (h.feed === "interp") out.push({ text: src.slice(h.start, h.end), parsed: null, depth, interp: true });
    else if (h.owner) sink.written.push({ src, start: h.start, end: h.end, owner: h.owner, depth });
    if (!h.literal) scan(src, h.start, h.end, "hd", depth + 1, sink);
  };
  const settle = (h: Heredoc) => { if (h.decided && h.end >= 0 && !h.done) { h.done = true; readBody(h); } };
  const decide = (h: Heredoc, feed: Feed | null) => { if (!h.decided) { h.decided = true; h.feed = feed; settle(h); } };

  const top = () => frames[frames.length - 1] as Frame | undefined;
  const openFrame = (kind: Frame["kind"], at: number, from: number, placeholder: string, closer = "") => {
    const parent = top();
    if (parent) parent.pieces.push(src.slice(parent.from, at) + placeholder);
    const f: Frame = { kind, pieces: [], from, open: [], carry: [], mine: [], parens: 0, closer, pipe: false, last: null };
    // A group after `|` reads the pipe: the heredocs flowing in flow into it.
    if (parent?.pipe && (kind === "group" || kind === "brace")) { for (const h of parent.open) f.open.push(h); parent.open.length = 0; }
    frames.push(f);
    stack.push({ kind: "cmd", frame: f });
  };
  /** Emit the frame's current segment (text up to `at`); a shell or interpreter
   *  in it runs the heredocs flowing into it, and the text an `echo` before it
   *  in the pipeline prints. Returns whether it was non-blank. */
  const emit = (f: Frame, at: number): boolean => {
    const text = f.pieces.length ? f.pieces.join("") + src.slice(f.from, at) : src.slice(f.from, at);
    f.pieces.length = 0;
    if (!/\S/.test(text)) { f.mine.length = 0; return false; }
    const parsed = text.length > MAX_SEGMENT ? null : parse(text);
    const seg: Seg = { text, parsed, depth };
    if (f.pipe && parsed && f.last?.parsed) {
      const fed = printed(f.last.parsed);
      if (fed && (feedOf(parsed) === "shell" || PS_EVAL.test(parsed.head))) seg.stdin = fed;
    }
    f.last = seg;
    out.push(seg);
    for (const h of f.mine) h.owner = seg;
    f.mine.length = 0;
    const feed = !f.open.length ? null : parsed ? feedOf(parsed) : "shell";
    if (feed) { for (const h of f.open) decide(h, feed); f.open.length = 0; }
    return true;
  };
  const endPipeline = (f: Frame) => {
    f.pipe = false;
    if (!f.open.length) return;
    if (f.kind === "root") for (const h of f.open) decide(h, null);
    else for (const h of f.open) f.carry.push(h);
    f.open.length = 0;
  };
  const separate = (f: Frame, at: number, from: number) => { emit(f, at); endPipeline(f); f.from = from; };
  /** Close the innermost frame at `at`; the enclosing one resumes at `resume`. */
  const closeFrame = (at: number, resume: number) => {
    const f = frames.pop()!;
    while (stack.length && (stack[stack.length - 1] as { frame?: Frame }).frame !== f) stack.pop();
    stack.pop();
    emit(f, at);
    endPipeline(f);
    const parent = top();
    if (parent) { parent.from = resume; for (const h of f.carry) parent.open.push(h); }
    else for (const h of f.carry) decide(h, null);
  };
  /** Find the queued heredoc bodies, in order, from `pos` (the line after the
   *  heredoc's own line). Returns the index after the last terminator line. */
  const locate = (pos: number): number => {
    for (const h of pending) {
      h.start = Math.min(pos, end);
      h.end = end;
      while (pos < end) {
        let eol = src.indexOf("\n", pos);
        if (eol < 0 || eol > end) eol = end;
        let p = pos;
        if (h.strip) while (p < eol && src[p] === "\t") p++;
        const terminator = eol - p === h.delim.length && src.startsWith(h.delim, p);
        if (terminator) h.end = pos;
        pos = Math.min(eol + 1, end);
        if (terminator) break;
      }
      settle(h);
    }
    pending.length = 0;
    return pos;
  };
  const atWordStart = (i: number) => i === start || (escaped !== i - 1 && /[\s;&|()]/.test(src[i - 1]));
  /** `$(`, `$((`, `$[` and `${` (from a command, a double quote, a body or a `${`). */
  const dollar = (i: number, inDq: boolean): number => {
    const n1 = ch(i + 1);
    if (n1 === "(" && frames.length < MAX_NEST) {
      if (ch(i + 2) === "(") { openFrame("arith", i, i + 3, "$_", ")"); return i + 2; }
      openFrame("subst", i, i + 2, "$_");
      return i + 1;
    }
    if (n1 === "[" && frames.length < MAX_NEST) { openFrame("arith", i, i + 2, "$_", "]"); return i + 1; }
    if (n1 === "{") { stack.push({ kind: "param", inDq }); return i + 1; }
    return i;
  };

  if (mode === "cmd") openFrame("root", start, start, "");
  else stack.push({ kind: "hd" });

  for (let i = start; i < end; i++) {
    const c = src[i];
    const ctx = stack[stack.length - 1];
    if (ctx.kind === "sq") { if (c === "'") stack.pop(); continue; }
    if (ctx.kind === "ansi") { if (c === "\\") i++; else if (c === "'") stack.pop(); continue; }
    if (ctx.kind === "dq" || ctx.kind === "hd") {
      // bash: a backslash escapes `$`, a backtick, itself or a newline (and `"`
      // inside double quotes). PowerShell: a backtick escapes.
      if (sink.ps && ctx.kind === "dq") { if (c === "`") { i++; continue; } }
      else if (c === "\\" && (ctx.kind === "dq" ? /[$`\\"\n]/ : /[$`\\\n]/).test(ch(i + 1))) { i++; continue; }
      if (c === '"' && ctx.kind === "dq") { stack.pop(); continue; }
      if (c === "$") { i = dollar(i, true); continue; }
      if (c === "`" && ctx.kind === "hd" && frames.length < MAX_NEST) openFrame("bq", i, i + 1, "$_");
      continue;
    }
    if (ctx.kind === "param") {
      if (c === "\\") { i++; continue; }
      if (c === "}") { stack.pop(); continue; }
      if (c === "'" && !ctx.inDq) stack.push({ kind: "sq" });
      else if (c === '"') stack.push({ kind: "dq" });
      else if (c === "$") i = dollar(i, ctx.inDq);
      continue;
    }

    // A command frame.
    const f = ctx.frame;
    if (c === (sink.ps ? "`" : "\\")) { i++; escaped = i; continue; }
    if (c === "'") { stack.push({ kind: "sq" }); continue; }
    if (c === '"') { stack.push({ kind: "dq" }); continue; }
    if (c === "$") {
      if (ch(i + 1) === "'") { stack.push({ kind: "ansi" }); i++; continue; }
      i = dollar(i, false);
      continue;
    }
    if (c === "`" && !sink.ps) {
      if (f.kind === "bq") closeFrame(i, i + 1);
      else if (frames.length < MAX_NEST) openFrame("bq", i, i + 1, "$_");
      continue;
    }
    if (c === "#" && f.kind !== "arith" && atWordStart(i)) {
      // A comment runs to the newline and is not part of the command.
      let nl = src.indexOf("\n", i);
      if (nl < 0 || nl > end) nl = end;
      f.pieces.push(src.slice(f.from, i));
      f.from = nl;
      i = nl - 1;
      continue;
    }
    if (c === "\n") {
      const pos = pending.length ? locate(i + 1) : i + 1;
      const nonBlank = emit(f, i);
      if (nonBlank || !f.pipe) endPipeline(f); // a blank line after `|` continues the pipeline
      f.from = pos;
      i = pos - 1;
      continue;
    }
    if (c === ";") { separate(f, i, i + 1); continue; }
    if (c === "&") {
      if (ch(i + 1) === ">" || (src[i - 1] === ">" && escaped !== i - 1)) continue; // &> / >& redirect
      const two = ch(i + 1) === "&";
      separate(f, i, i + (two ? 2 : 1));
      if (two) i++;
      continue;
    }
    if (c === "|") {
      if (src[i - 1] === ">" && escaped !== i - 1) continue; // >| redirect
      if (ch(i + 1) === "|") { separate(f, i, i + 2); i++; continue; }
      emit(f, i);
      f.pipe = true;
      if (ch(i + 1) === "&") i++; // |& pipes stderr too
      f.from = i + 1;
      continue;
    }
    if (c === "<" && ch(i + 1) === "<") {
      if (ch(i + 2) === "<") { i += 2; continue; } // here-string
      if (heredocs && f.kind !== "arith") {
        const h = heredocWord(src, i + 2, end);
        if (h.doc) { pending.push(h.doc); f.open.push(h.doc); f.mine.push(h.doc); }
        i = h.next - 1;
        continue;
      }
    }
    if (f.kind === "arith") {
      if (c === "(") f.parens++;
      else if (c === ")" && f.closer === ")") {
        if (f.parens > 0) f.parens--;
        else if (ch(i + 1) === ")") { closeFrame(i, i + 2); i++; }
        else closeFrame(i, i + 1);
      } else if (c === "]" && f.closer === "]") closeFrame(i, i + 1);
      continue;
    }
    if (c === "(") {
      if (frames.length >= MAX_NEST) continue;
      if (ch(i + 1) === "(") { openFrame("arith", i, i + 2, "", ")"); i++; }
      else openFrame("group", i, i + 1, "");
      continue;
    }
    if (c === ")") {
      if (f.kind === "group" || f.kind === "subst") closeFrame(i, i + 1);
      else separate(f, i, i + 1);
      continue;
    }
    if (c === "{" && atWordStart(i) && /\s/.test(ch(i + 1)) && frames.length < MAX_NEST) { openFrame("brace", i, i + 1, ""); continue; }
    if (c === "}" && f.kind === "brace" && atWordStart(i) && /^[\s;&|)<>]?$/.test(ch(i + 1))) { closeFrame(i, i + 1); continue; }
  }
  for (const h of pending) h.start = h.end = end; // a heredoc on the last line has an empty body
  pending.length = 0;
  const balanced = !stack.some((x) => x.kind === "sq" || x.kind === "dq" || x.kind === "ansi");
  while (frames.length) closeFrame(end, end);
  return balanced;
}

/** Read the heredoc word after `<<` (from `j`): `[-] [blanks] WORD`, quotes and
 *  backslashes removed as the shell does. Returns it and the index after. */
function heredocWord(src: string, j: number, end: number): { doc: Heredoc | null; next: number } {
  const strip = src[j] === "-";
  if (strip) j++;
  while (j < end && (src[j] === " " || src[j] === "\t")) j++;
  let delim = "", q: string | null = null, literal = false;
  for (; j < end; j++) {
    const c = src[j];
    if (q) { if (c === q) q = null; else delim += c; continue; }
    if (c === "'" || c === '"') { q = c; literal = true; }
    else if (c === "\\" && j + 1 < end) { delim += src[++j]; literal = true; }
    else if (/[ \t\n;&|<>()]/.test(c)) break; // the shell's metacharacters only: a `\r` or backtick stays in WORD
    else delim += c;
  }
  const ok = delim && !q && !delim.includes("\n");
  return { doc: ok ? { delim, strip, literal, start: -1, end: -1, decided: false, feed: null, done: false, owner: null } : null, next: j };
}

// ── Tokens and command words ───────────────────────────────────────────────────

const OP_RE = /^(?:&>>|&>|>>|\d{0,3}>\||\d{0,3}>&\d{0,3}|\d{0,3}>)/;

/** Tokenise one segment into words (quote-stripped) and redirect operators.
 *  Unquoted `(` and `)` end a word and are dropped, as is a standalone `{`/`}`. */
function tokenize(seg: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  while (i < seg.length) {
    const c = seg[i];
    if (/\s/.test(c) || c === "(" || c === ")") { i++; continue; }
    if (c === ">" || c === "&" || (/\d/.test(c) && OP_RE.test(seg.slice(i, i + 8)))) {
      const m = OP_RE.exec(seg.slice(i, i + 8));
      if (m) { toks.push({ kind: "op", value: m[0] }); i += m[0].length; continue; }
    }
    if (c === "<") { toks.push({ kind: "op", value: "<" }); i++; continue; } // input redirect: its operand is no argument
    let out = "", j = i, quoted = false;
    while (j < seg.length) {
      const ch = seg[j];
      if (/\s/.test(ch) || ch === ">" || ch === "<" || ch === "(" || ch === ")") break;
      // An escaped metacharacter is literal; any other backslash is kept, for a
      // native Windows path.
      if (ch === "\\" && j + 1 < seg.length && /[\s()<>;&|'"]/.test(seg[j + 1])) { out += seg[j + 1]; j += 2; continue; }
      if (ch === "'") { quoted = true; j++; while (j < seg.length && seg[j] !== "'") out += seg[j++]; j++; continue; }
      if (ch === '"') {
        // Inside double quotes a backslash escapes only `"`, `\`, `$`, a backtick or
        // a newline (bash; PowerShell never escapes with it), so the separators of
        // a quoted Windows path ("C:\proj\CLAUDE.md") survive for normPath.
        quoted = true;
        j++;
        while (j < seg.length && seg[j] !== '"') {
          if (seg[j] === "\\" && j + 1 < seg.length && /["\\$`\n]/.test(seg[j + 1])) { out += seg[j + 1]; j += 2; } else out += seg[j++];
        }
        j++;
        continue;
      }
      out += ch; j++;
    }
    if (quoted || (out !== "{" && out !== "}")) toks.push({ kind: "word", value: out });
    i = j;
  }
  return toks;
}

/** A redirect that writes its next word to a file (not an fd-dup like `2>&1`). */
function isWriteRedirect(op: string): boolean {
  return op.includes(">") && !/>&\d/.test(op);
}

const ASSIGN = /^[A-Za-z_][A-Za-z0-9_]{0,127}=/;
/** Reserved words that can stand before a command (`then tee …`, `do cp …`). */
const RESERVED = /^(?:!|if|then|else|elif|do|while|until)$/;
/** Launchers that run the rest of the line as the command, and their options
 *  that take a separate value. */
const LAUNCHERS = new Map<string, RegExp | null>([
  ["sudo", /^-[ughpCrtUDT]$/], ["doas", /^-[uC]$/], ["env", /^-[uCS]$/], ["nohup", null], ["time", null],
  ["command", null], ["builtin", null], ["exec", /^-a$/], ["nice", /^-n$/], ["ionice", /^-[cnp]$/], ["stdbuf", /^-[ioe]$/], ["timeout", /^-[sk]$/],
]);

function parse(text: string): Parsed {
  const toks = tokenize(text);
  const words: string[] = [];
  for (let k = 0; k < toks.length; k++) {
    if (toks[k].kind !== "word") continue;
    const prev = k > 0 ? toks[k - 1] : null;
    if (prev?.kind === "op" && (prev.value === "<" || isWriteRedirect(prev.value))) continue; // a redirect's operand
    words.push(toks[k].value);
  }
  // Skip assignments, reserved words and launchers to the command word.
  let at = 0, sudoShell = false;
  while (at < words.length) {
    const w = words[at];
    if (ASSIGN.test(w) || RESERVED.test(w)) { at++; continue; }
    const b = basenameLower(w);
    if (!LAUNCHERS.has(b)) break;
    const takesValue = LAUNCHERS.get(b);
    at++;
    while (at < words.length && (isFlag(words[at]) || (b === "env" && ASSIGN.test(words[at])))) {
      const f = words[at];
      if (f === "--") { at++; break; }
      if ((b === "sudo" || b === "doas") && (/^-[A-Za-z]{0,8}[si][A-Za-z]{0,8}$/.test(f) || f === "--shell" || f === "--login")) sudoShell = true;
      at += takesValue?.test(f) ? 2 : 1;
    }
    if (b === "timeout" && at < words.length) at++; // the duration
  }
  return { toks, words, at, head: basenameLower(words[at] ?? ""), sudoShell };
}

/** Whether the interpreter at `words[k]` reads its program from stdin: no script
 *  operand, or `-` / `/dev/stdin`, and no inline program. */
function readsStdin(words: string[], k: number): boolean {
  const deno = /^(?:deno|bun)/.test(basenameLower(words[k]));
  for (let q = k + 1; q < words.length; q++) {
    const a = words[q];
    if (a === "-" || a === "/dev/stdin") return true;
    if (isFlag(a)) { if (INLINE_CODE.test(a) || a === "-m") return false; continue; }
    if (deno && q === k + 1 && a === "run") continue;
    return false;
  }
  return true;
}

/** Whether this command runs the heredocs flowing into it, and as what. */
function feedOf(p: Parsed): Feed | null {
  if (p.sudoShell || SHELL_FED_HEAD.test(p.head)) return "shell";
  for (let k = p.at; k < p.words.length; k++) {
    const b = basenameLower(p.words[k]);
    if (SHELLS.test(b)) return "shell";
    if (INTERP_FEED.test(b) && readsStdin(p.words, k)) return "interp";
  }
  return null;
}

// ── Write targets ──────────────────────────────────────────────────────────────

/** PowerShell switch parameters: they take no value, so the next word may be a
 *  positional argument. */
const PS_SWITCH = /^-(?:Force|Append|NoNewline|Recurse|NoClobber|PassThru|WhatIf|Confirm|Verbose|Debug|AsByteStream)$/i;
/** rsync options whose value is a separate word. */
const RSYNC_VALUE = /^(?:-[efBMT]|--(?:exclude|include|exclude-from|include-from|filter|files-from|rsh|rsync-path|temp-dir|partial-dir|backup-dir|suffix|compare-dest|copy-dest|link-dest|chmod|chown|log-file|log-file-format|password-file|out-format|max-size|min-size|bwlimit|timeout|contimeout|port|block-size|remote-option|info|debug|iconv|usermap|groupmap|max-delete|modify-window|sockopts))$/;
/** A perl switch letter after which the rest of the cluster is its argument. */
const PERL_ARG_SWITCH = "MmIeExdDCF";

/** PowerShell `-Name value` / `-Name:value`. `at` is the index of a separate
 *  value word (-1 when inline). */
function psValue(args: string[], names: RegExp): { value: string; at: number } | null {
  for (let k = 0; k < args.length; k++) {
    const sep = isFlag(args[k]) ? args[k].search(/[:=]/) : -1;
    if (!names.test(sep > 0 ? args[k].slice(0, sep) : args[k])) continue;
    if (sep > 0 && sep < args[k].length - 1) return { value: normPath(args[k].slice(sep + 1)), at: -1 };
    if (args[k + 1]) return { value: normPath(args[k + 1]), at: k + 1 };
  }
  return null;
}

/** PowerShell positional arguments: a named parameter that is not a known
 *  switch takes the next word as its value. */
function psPositional(args: string[]): string[] {
  const pos: string[] = [];
  for (let k = 0; k < args.length; k++) {
    const a = args[k];
    if (isFlag(a)) { if (a.search(/[:=]/) < 0 && !PS_SWITCH.test(a)) k++; continue; }
    if (a.indexOf("=") < 0) pos.push(a);
  }
  return pos;
}

/** The files `sed` edits in place, or null without -i / --in-place. The script
 *  is the first operand unless -e / --expression / -f / --file gave it. */
function sedInPlaceFiles(args: string[]): string[] | null {
  let inPlace = false, script = false;
  const operands: string[] = [];
  for (let k = 0; k < args.length; k++) {
    const a = args[k];
    if (a === "--") { for (k++; k < args.length; k++) operands.push(args[k]); break; }
    if (a.startsWith("--")) {
      const name = a.split("=", 1)[0];
      if (name === "--in-place") inPlace = true;
      else if (name === "--expression" || name === "--file") { script = true; if (name === a) k++; }
      else if (name === "--line-length" && name === a) k++;
      continue;
    }
    if (a.length > 1 && a[0] === "-") {
      for (let c = 1; c < a.length; c++) {
        const s = a[c];
        if (s === "i") { inPlace = true; break; } // -i[SUFFIX]
        if (s === "e" || s === "f") { script = true; if (c === a.length - 1) k++; break; }
        if (s === "l") { if (c === a.length - 1) k++; break; }
      }
      continue;
    }
    operands.push(a);
  }
  return inPlace ? (script ? operands : operands.slice(1)) : null;
}

/** Whether perl's switches include -i (in-place); `-MFile::Copy` is a module. */
function perlInPlace(args: string[]): boolean {
  for (let k = 0; k < args.length; k++) {
    const a = args[k];
    if (a === "--") return false;
    if (a.length < 2 || a[0] !== "-" || a[1] === "-") continue;
    for (let c = 1; c < a.length; c++) {
      const s = a[c];
      if (s === "i") return true;
      if (PERL_ARG_SWITCH.includes(s)) { if ((s === "e" || s === "E") && c === a.length - 1) k++; break; }
    }
  }
  return false;
}

/** cp/mv/install/ln: the -t / --target-directory value (also in a short
 *  cluster such as `-st DIR`), or null. */
function targetDirectory(args: string[]): string | null {
  for (let k = 0; k < args.length; k++) {
    const a = args[k];
    if (a.startsWith("--target-directory")) {
      if (a[18] === "=") return normPath(a.slice(19));
      if (a.length === 18 && args[k + 1]) return normPath(args[k + 1]);
      continue;
    }
    if (a.length < 2 || a[0] !== "-" || a[1] === "-") continue;
    const t = a.indexOf("t");
    if (t > 0 && /^[A-Za-z]{0,16}$/.test(a.slice(1, t))) return normPath(t < a.length - 1 ? a.slice(t + 1) : args[k + 1] ?? "") || null;
  }
  return null;
}

/** rsync's destination: the last operand, skipping trailing options and the
 *  values of options that take one (`--exclude CLAUDE.md`). */
function rsyncDestination(args: string[]): string | null {
  let last: string | null = null;
  for (let k = 0; k < args.length; k++) {
    if (isFlag(args[k])) { if (RSYNC_VALUE.test(args[k])) k++; continue; }
    last = args[k];
  }
  return last === null ? null : normPath(last);
}

/** An interpreter body that both makes a write call and names a watched or store
 *  path: those paths (the body split on quotes/brackets/commas, which bound the
 *  string literal the path lives in). */
function interpTargets(body: string): string[] {
  if (!WRITE_CALL.test(body)) return [];
  const out: string[] = [];
  for (const part of body.split(/[\s'"`(),;]+/)) {
    const lit = normPath(part);
    if (lit && (WATCHED_NAME.test(lit) || STORE_PATH.test(lit))) out.push(lit);
  }
  return out;
}

/** The files a segment WRITES, per the target table in the spec. Returns
 *  normalised (forward-slash, unquoted) paths. */
function writeTargets(p: Parsed, raw: string): string[] {
  const { toks, words, at, head } = p;
  const targets: string[] = [];
  // Redirects: the word after a write redirect is the target.
  for (let k = 0; k + 1 < toks.length; k++) {
    if (toks[k].kind === "op" && isWriteRedirect(toks[k].value) && toks[k + 1].kind === "word") targets.push(normPath(toks[k + 1].value));
  }
  const args = words.slice(at + 1);
  const nonFlag = () => args.filter((a) => !isFlag(a)).map(normPath);

  if (head === "tee" || head === "truncate") {
    targets.push(...nonFlag());
  } else if (head === "sed") {
    const files = sedInPlaceFiles(args);
    if (files) targets.push(...files.map(normPath));
  } else if (head === "perl" && perlInPlace(args)) {
    targets.push(...nonFlag());
  } else if (head === "dd") {
    for (const a of args) if (/^of=/.test(a)) targets.push(normPath(a.slice(3)));
  } else if (head === "cp" || head === "mv" || head === "install" || head === "ln") {
    const t = targetDirectory(args);
    const operands = nonFlag();
    if (t) targets.push(t);
    else if (operands.length) targets.push(operands[operands.length - 1]);
  } else if (head === "rsync") {
    const t = rsyncDestination(args);
    if (t) targets.push(t);
  } else if (head === "copy-item" || head === "move-item") {
    // These write only their destination: -Destination, else position 1, or the
    // first positional when the source is named. -Path/-LiteralPath name the
    // source, which is a read (`Copy-Item -Path CLAUDE.md -Destination /tmp/x`).
    const dest = psValue(args, /^-Destination$/i);
    if (dest) targets.push(dest.value);
    else {
      const named = psValue(args, /^-(?:Path|LiteralPath)$/i) !== null;
      const t = psPositional(args)[named ? 0 : 1];
      if (t) targets.push(normPath(t));
    }
  } else if (head === "set-content" || head === "add-content" || head === "out-file" || head === "new-item" || head === "tee-object") {
    const t = psValue(args, /^-(?:Path|LiteralPath|FilePath)$/i);
    if (t) targets.push(t.value);
    else {
      const first = psPositional(args)[0];
      if (first) targets.push(normPath(first));
    }
  } else if (INTERP.test(head) && args.some((a, k) => INLINE_CODE.test(a) || (k === 0 && a === "eval" && /^(?:deno|bun)/.test(head)))) {
    // The body contains a write call AND names a watched file: pull the watched
    // path out of the body. Run on the RAW segment so the literals and the mode
    // flag survive.
    targets.push(...interpTargets(raw));
  }
  return targets;
}

// ── The Nexus CLI ──────────────────────────────────────────────────────────────

/** A path that is a Nexus CLI entry point run directly (`node …/cli/index.js`). */
const NEXUS_ENTRY = /(?:^|\/)(?:dist\/)?cli\/index\.js$|(?:^|\/)nexus(?:-mcp)?$/i;
/** A published-package spec for Nexus (`@hawon/nexus`, `nexus`, `@hawon/nexus@1`). */
const NEXUS_PKG = /^(?:@hawon\/)?nexus(?:@|$)/i;
/** The spec's integrity-self-approve and guard-uninstall rules (§6.7), run on
 *  the segment with quoted text blanked. */
const SELF_APPROVE_RE = /\bintegrity\s{1,8}(?:accept|baseline)\b|\bintegrity\s{1,8}config\s{1,8}[A-Za-z]|\bguard\s{1,8}install\b[^\n]{0,200}--no-integrity\b/;
const UNINSTALL_RE = /\bguard\s{1,8}uninstall\b/;

const isNexusBin = (w: string) => basenameLower(w).replace(/\.(?:exe|cmd|ps1|bat)$/, "") === "nexus";

/** The arguments after the Nexus CLI when the segment's command runs it — the
 *  `nexus` binary, a package runner (`npx [-p @hawon/nexus] nexus`, `npm exec`,
 *  `pnpm|yarn dlx|exec`) or `node <path>/cli/index.js` — else null. */
function nexusArgs({ words, at, head }: Parsed): string[] | null {
  if (head.replace(/\.(?:exe|cmd|ps1|bat)$/, "") === "nexus") return words.slice(at + 1);
  if (head === "npx" || head === "bunx" || head === "pnpm" || head === "yarn" || head === "npm") {
    let k = at + 1;
    if (head !== "npx" && head !== "bunx") {
      while (k < words.length && isFlag(words[k])) k++;
      if (/^(?:exec|x|dlx)$/.test(words[k] ?? "")) k++;
      else if (head === "npm") return null;
    }
    // Runner options; -p/--package name the package, and the command follows.
    while (k < words.length && isFlag(words[k])) {
      if (words[k] === "--") { k++; break; }
      k += /^(?:-p|--package)$/.test(words[k]) ? 2 : 1;
    }
    const pkg = words[k] ?? "";
    if (!NEXUS_PKG.test(pkg) && !isNexusBin(pkg)) return null;
    let rest = words.slice(k + 1);
    if (rest[0] === "--") rest = rest.slice(1);
    if (rest[0] !== "guard" && isNexusBin(rest[0] ?? "")) rest = rest.slice(1);
    return rest;
  }
  if (head === "node" || head === "bun" || head === "deno" || head === "tsx" || head === "ts-node") {
    let k = at + 1;
    while (k < words.length && (isFlag(words[k]) || words[k] === "run" || words[k] === "tsx")) k++;
    if (NEXUS_ENTRY.test(normPath(words[k] ?? ""))) return words.slice(k + 1);
  }
  return null;
}

/** The text with the contents of '…', "…" and $'…' strings removed (quotes kept). */
function blankQuoted(s: string): string {
  if (s.indexOf("'") < 0 && s.indexOf('"') < 0) return s;
  const parts: string[] = [];
  let from = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\") { i++; continue; }
    if (c !== "'" && c !== '"') continue;
    const esc = c === '"' || s[i - 1] === "$";
    let j = i + 1;
    while (j < s.length && s[j] !== c) j += esc && s[j] === "\\" ? 2 : 1;
    parts.push(s.slice(from, i + 1));
    from = j; // the closing quote (if any) is kept
    i = j;
  }
  parts.push(s.slice(from));
  return parts.join("");
}

function cliAction(seg: Seg): NexusCliAction {
  const p = seg.parsed;
  const rest = p ? nexusArgs(p) : null;
  if (rest && rest[0] === "guard") {
    const [, a, b] = rest;
    if (a === "integrity" && (b === "accept" || b === "baseline")) return { rule: "integrity-self-approve", decision: "deny" };
    if (a === "integrity" && b === "config" && rest[3] && /^[A-Za-z]/.test(rest[3])) return { rule: "integrity-self-approve", decision: "deny" };
    if (a === "install" && rest.includes("--no-integrity")) return { rule: "integrity-self-approve", decision: "deny" };
  }
  const uninstall: NexusCliAction = { rule: "guard-uninstall", decision: "ask" };
  const parsedUninstall = rest !== null && rest[0] === "guard" && rest[1] === "uninstall";
  // Both regexes need one of these words; skip the blanking without them.
  if (seg.text.indexOf("integrity") < 0 && seg.text.indexOf("guard") < 0) return parsedUninstall ? uninstall : null;
  const blank = blankQuoted(seg.text);
  if (SELF_APPROVE_RE.test(blank)) return { rule: "integrity-self-approve", decision: "deny" };
  return parsedUninstall || UNINSTALL_RE.test(blank) ? uninstall : null;
}

// ── The verdict ────────────────────────────────────────────────────────────────

type Acc = { deny: string | null; ask: string | null; cli: NexusCliAction };

/** PowerShell's eval (`Invoke-Expression`), as the command or after `|`. */
const PS_EVAL = /^(?:iex|invoke-expression)$/;
/** A command that prints its operands: they are data, unless piped into a shell. */
const PRINTER = /^(?:echo|printf|write-output)$/;
const SH_FAMILY = /^(?:ba|z|da|k|mk|a|fi|c|tc)?sh(?:\.exe)?$/;

/** The command string after a sh-family shell's (or su's) `-c`, which may stand
 *  in a cluster (`-lc`, `-ec`) and before or after other options; `-o`/`-O`
 *  (`-eo`, `+o`), `--rcfile` and `--init-file` take a value. su's user name may
 *  come first, and su also takes `--command`. Null without `-c` (a script
 *  operand). */
function shCommand(words: string[], k: number, su: boolean): string | null {
  let c = false;
  for (let j = k + 1; j < words.length; j++) {
    const w = words[j];
    if (w === "--") return c ? words[j + 1] ?? null : null;
    if (su && (w === "--command" || w.startsWith("--command="))) return w.length > 10 ? w.slice(10) : words[j + 1] ?? null;
    if (/^[-+][A-Za-z]{1,8}$/.test(w)) {
      if (w[0] === "-" && w.includes("c")) c = true;
      if (/[oO]$/.test(w)) j++;
      continue;
    }
    if (w === "--rcfile" || w === "--init-file") { j++; continue; }
    if (isFlag(w)) continue;
    if (c) return w;
    if (!su) return null;
  }
  return null;
}

/** A pwsh/powershell parameter (`-x`, `--x` or `/x`, a `:value` cut off) that is
 *  `name` or an abbreviation of it, as the PowerShell CLI accepts. */
function psParam(w: string, name: string): boolean {
  const m = /^(?:-{1,2}|\/)([A-Za-z]{1,32})(?::|$)/.exec(w);
  return m !== null && name.startsWith(m[1].toLowerCase());
}
/** The Windows PowerShell CLI's switches; its other parameters take a value. */
const PS_CLI_SWITCH = /^(?:-{1,2}|\/)(?:nologo|noexit|sta|mta|noprofile|noninteractive|nol|noe|nop|noni)$/i;

/** The command a pwsh/powershell runs: the rest of the line after -Command (any
 *  prefix: `-c`, `-Command:…`). Windows PowerShell also takes a first operand as
 *  -Command; pwsh takes it as -File. -File and -EncodedCommand carry no command. */
function psCommand(words: string[], k: number, implicit: boolean): string | null {
  for (let j = k + 1; j < words.length; j++) {
    const w = words[j];
    if (psParam(w, "command")) {
      const colon = w.indexOf(":");
      const rest = words.slice(j + 1);
      if (colon > 0 && colon < w.length - 1) rest.unshift(w.slice(colon + 1));
      return rest.join(" ") || null;
    }
    if (psParam(w, "file") || psParam(w, "encodedcommand") || /^(?:-{1,2}|\/)ec$/i.test(w)) return null;
    if (/^(?:-{1,2}|\/)[A-Za-z]{1,32}(?::|$)/.test(w)) {
      if (!PS_CLI_SWITCH.test(w) && !w.includes(":") && j + 1 < words.length && !isFlag(words[j + 1])) j++;
      continue;
    }
    return implicit ? words.slice(j).join(" ") : null;
  }
  return null;
}

/** The `-c CMD` / `--command CMD` that `script` and `flock` run through the
 *  shell (`script -qc '…' /dev/null` fakes a TTY). */
function dashCCommand(words: string[], k: number): string | null {
  for (let j = k + 1; j < words.length; j++) {
    const w = words[j];
    if (w === "--") return null;
    if (w === "--command" || /^-[A-Za-z]{0,8}c$/.test(w)) return words[j + 1] ?? null;
    if (w.startsWith("--command=")) return w.slice(10);
  }
  return null;
}

/** The command `cmd /c` or `/k` runs: the rest of the line, which may start in
 *  the switch's own word (`/c"…"`), after other switches (`/s`, `/q`, `/v:on`). */
function cmdCommand(words: string[], k: number): string | null {
  for (let j = k + 1; j < words.length; j++) {
    const w = words[j];
    if (/^\/[ck]/i.test(w)) return [w.slice(2), ...words.slice(j + 1)].join(" ").trim() || null;
    if (!/^\/[A-Za-z](?::\w{1,8})?$/.test(w)) return null;
  }
  return null;
}

/** The command string a segment's shell runs: `eval …` / `iex …`, `su -c …`,
 *  `runuser -c …`, `script -c …`, `flock … -c …`, or the first shell word's
 *  (the command or an argument, as in `xargs sh -c`,
 *  `find -exec bash -c` or `docker exec c sh -c`): `sh -c`, `bash -o x -c`,
 *  `pwsh -c|-Command`, `powershell "…"`, `cmd /c|/k`. Else a here-string a
 *  shell reads (`bash <<< '…'`). An `echo`'s operands are only printed (piped
 *  into a shell they are the next segment's `stdin`). */
function innerCommand(p: Parsed): string | null {
  const { words, at, head, toks } = p;
  if (PRINTER.test(head)) return null;
  if (head === "eval" || PS_EVAL.test(head)) return words.slice(at + 1).join(" ") || null;
  if (head === "su" || head === "runuser") return shCommand(words, at, true);
  const viaShell = head === "script" || head === "flock" ? dashCCommand(words, at) : null;
  if (viaShell) return viaShell;
  for (let k = at; k < words.length; k++) {
    const b = basenameLower(words[k]);
    if (SH_FAMILY.test(b)) return shCommand(words, k, false) ?? hereString(p, toks);
    if (/^(?:pwsh|powershell)(?:\.exe)?$/.test(b)) return psCommand(words, k, b.startsWith("powershell"));
    if (/^cmd(?:\.exe)?$/.test(b)) return cmdCommand(words, k);
  }
  return hereString(p, toks);
}

/** The word of a `<<<` here-string, when the segment runs its input. */
function hereString(p: Parsed, toks: Tok[]): string | null {
  const lt = (k: number) => toks[k].kind === "op" && toks[k].value === "<";
  for (let k = 0; k + 3 < toks.length; k++) {
    if (lt(k) && lt(k + 1) && lt(k + 2) && toks[k + 3].kind === "word") return feedOf(p) === "shell" ? toks[k + 3].value : null;
  }
  return null;
}

/** What an `echo`/`printf`/`Write-Output` segment prints: its operands, joined
 *  (echo's -n/-e/-E dropped). */
function printed(p: Parsed): string | null {
  if (!PRINTER.test(p.head)) return null;
  let k = p.at + 1;
  if (p.head === "echo") while (k < p.words.length && /^-[neE]{1,3}$/.test(p.words[k])) k++;
  return p.words.slice(k).join(" ") || null;
}

/** The script file a command runs (`bash s.sh`, `source s.sh`, `python3 x.py`,
 *  `./s.sh`), keyed like scriptKey, and what reads it. */
function runsScript(p: Parsed): { key: string; feed: Feed } | null {
  const w = p.words[p.at];
  if (!w) return null;
  // The first operand, unless the program is inline (`sh -c`, `python3 -c`).
  const operand = (inline: RegExp) => {
    for (let k = p.at + 1; k < p.words.length; k++) {
      const a = p.words[k];
      if (inline.test(a)) return null;
      if (!isFlag(a)) return a;
    }
    return null;
  };
  let path: string | null = null, feed: Feed = "shell";
  if (p.head === "source" || p.head === "." || /^(?:ba|z|da|k|mk|a)?sh(?:\.exe)?$/.test(p.head)) path = operand(/^-[A-Za-z]{0,8}c$/);
  else if (INTERP_FEED.test(p.head)) { path = operand(INLINE_CODE); feed = "interp"; }
  else if (/[\\/]/.test(w)) path = w;
  return path ? { key: scriptKey(path), feed } : null;
}

const scriptKey = (path: string) => normPath(path).replace(/^(?:\.\/){1,16}/, "");

/** The data heredoc bodies whose owner wrote a file the command line runs, read
 *  as that file's runner would (one round: a script written by such a body is
 *  not followed further). */
function writtenScripts(sink: Sink): Seg[] {
  if (!sink.written.length) return [];
  const runs = new Map<string, Feed>();
  for (const seg of sink.segs) {
    const r = seg.parsed ? runsScript(seg.parsed) : null;
    if (r) runs.set(r.key, r.feed);
  }
  if (!runs.size) return [];
  const out: Sink = { segs: [], written: [], ps: sink.ps };
  const files = new Map<Seg, string[]>();
  for (const w of sink.written) {
    if (!w.owner.parsed) continue;
    let written = files.get(w.owner);
    if (!written) files.set(w.owner, (written = writeTargets(w.owner.parsed, w.owner.text).map(scriptKey)));
    const feed = written.map((k) => runs.get(k)).find((x) => x !== undefined);
    if (feed === "shell" && w.depth < MAX_DEPTH) scan(w.src, w.start, w.end, "cmd", w.depth + 1, out);
    else if (feed === "interp") out.segs.push({ text: w.src.slice(w.start, w.end), parsed: null, depth: w.depth, interp: true });
  }
  return out.segs;
}

function analyze(command: string, depth: number, acc: Acc): void {
  const sink: Sink = { segs: [], written: [], ps: false };
  // Ending inside a quote under bash quoting suggests PowerShell's (a quoted
  // path ending in `\"`, a backtick escape): read it that way as well.
  if (!scan(command, 0, command.length, "cmd", depth, sink)) {
    sink.ps = true;
    scan(command, 0, command.length, "cmd", depth, sink);
  }
  const segs = sink.segs.concat(writtenScripts(sink));
  for (const seg of segs) {
    if (acc.deny) return;
    const note = (t: string) => {
      if (STORE_PATH.test(t)) acc.deny ??= t;
      else if (acc.ask === null && WATCHED_NAME.test(t)) acc.ask = t;
    };
    if (seg.interp) { for (const t of interpTargets(seg.text)) note(t); continue; }
    const cli = cliAction(seg);
    if (cli && (cli.decision === "deny" || !acc.cli)) acc.cli = cli;
    const p = seg.parsed;
    if (!p) {
      const m = acc.ask === null ? WATCHED_CONTAINS.exec(seg.text.replace(/\\+/g, "/")) : null;
      if (m) acc.ask = m[1];
      continue;
    }
    for (const t of writeTargets(p, seg.text)) note(t);
    // Deleting, moving or chmod-ing a store file is a write too (a move deletes
    // its source). A PowerShell `-Path:value` carries its operand inline.
    if (/^(?:rm|unlink|shred|chmod|mv|move-item)$/.test(p.head)) {
      for (let k = p.at + 1; k < p.words.length && !acc.deny; k++) {
        const a = p.words[k];
        const colon = isFlag(a) ? a.indexOf(":") : -1;
        const operand = !isFlag(a) ? normPath(a) : colon > 0 && colon < a.length - 1 ? normPath(a.slice(colon + 1)) : "";
        if (STORE_PATH.test(operand)) acc.deny = operand;
      }
    }
    // A shell given a `-c` string reads its stdin as data. Each segment's text
    // is read again at most once (an `echo` has no inner command), so the
    // nested reads stay linear per level.
    const inner = seg.depth < MAX_DEPTH ? innerCommand(p) ?? seg.stdin ?? null : null;
    if (inner) analyze(inner, seg.depth + 1, acc);
  }
}

/**
 * One pass over a command for the context-free shell rules: the most severe
 * shell-write verdict (a store write/delete denies, a write to a watched
 * instruction/config file asks) and the Nexus CLI action
 * (integrity-self-approve deny, guard-uninstall ask), per segment from the same
 * tokens. The CLI rules fire on the command-position parser, or on the spec
 * regexes over the segment with quoted text blanked, so `echo 'run nexus guard
 * integrity accept'` or `grep "integrity accept"` do not trip them while an
 * unquoted invocation (`nexus`, `npx @hawon/nexus`, `node <path>/cli/index.js`,
 * behind `env`, `nohup`, `npm exec` or any other launcher) does. The string a
 * shell runs (`sh -c`, `xargs sh -c`, `pwsh -Command`, `cmd /c`, `eval`, a
 * here-string, an `echo` piped into `sh`; the list is at innerCommand), and a
 * script a heredoc writes that the same command line then runs, are read as
 * commands too. A string any other program runs is not.
 */
export function analyzeShellCommand(command: string): { write: ShellWriteDecision; cli: NexusCliAction } {
  const acc: Acc = { deny: null, ask: null, cli: null };
  analyze(command, 0, acc);
  const write: ShellWriteDecision = acc.deny
    ? { decision: "deny", rule: "nexus-store-write", target: acc.deny }
    : acc.ask
      ? { decision: "ask", rule: "instruction-file-shell-write", target: acc.ask }
      : { decision: "allow", rule: null, target: null };
  return { write, cli: acc.cli };
}

/** The user's own instruction file: `~/.claude/CLAUDE.md` by any home spelling,
 *  or `$CLAUDE_CONFIG_DIR/CLAUDE.md`. Any other CLAUDE.md is a project's. */
const USER_CLAUDE_MD =
  /^(?:(?:~|\$HOME|\$\{HOME\}|\$env:(?:USERPROFILE|HOME)|%USERPROFILE%|(?:[A-Za-z]:)?\/(?:home|Users)\/[^/]{1,64}|\/root)\/\.claude|\$\{?CLAUDE_CONFIG_DIR\}?)\/CLAUDE\.md$/i;

/** A human label for a watched target, for the `ask` reason (the §6.6 set). */
export function watchedLabel(target: string): string {
  const t = target.replace(/\\+/g, "/");
  if (/(?:^|\/)CLAUDE\.local\.md$/i.test(t)) return "personal project instructions";
  if (/(?:^|\/)CLAUDE\.md$/i.test(t)) return USER_CLAUDE_MD.test(t) ? "user instructions" : "project instructions";
  if (/(?:^|\/)AGENTS\.md$/i.test(t)) return "project instructions";
  if (/(?:^|\/)\.claude\/settings(?:\.local)?\.json$/i.test(t)) return "Claude Code settings";
  if (/(?:^|\/)(?:\.mcp|\.claude)\.json$/i.test(t)) return "MCP server config";
  if (/(?:^|\/)\.claude\/hooks(?:\/|$)/i.test(t)) return "a hook script";
  if (/(?:^|\/)\.claude\/rules(?:\/|$)/i.test(t)) return "a rules file";
  if (/(?:^|\/)\.claude\/agents(?:\/|$)/i.test(t)) return "a subagent definition";
  if (/(?:^|\/)\.claude\/commands(?:\/|$)/i.test(t)) return "a slash command";
  if (/(?:^|\/)\.claude\/skills(?:\/|$)/i.test(t)) return "a skill";
  return "agent memory";
}

/** ANSI escape sequences: CSI, OSC (to BEL or ST) and two-character escapes. */
const ANSI_ESCAPE = /\u001b(?:\[[0-?]{0,64}[ -/]{0,16}[@-~]|\][^\u0007\u001b]{0,512}(?:\u0007|\u001b\\)?|[@-Z\\-_])/g;

/** A target as echoed in a reason: ANSI escapes and control characters
 *  stripped, at most 120 characters. */
export function displayTarget(target: string): string {
  const clean = target.replace(ANSI_ESCAPE, "").replace(/[\u0000-\u001f\u007f-\u009f]/g, "");
  return clean.length > 120 ? clean.slice(0, 119) + "…" : clean;
}
