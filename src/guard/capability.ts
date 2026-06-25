/**
 * Structural capability analysis — the firewall's answer to adaptive attacks.
 *
 * Pattern matching anchors on literal tokens; attackers defer those tokens to
 * runtime (`c?rl` globs to curl, `$p$q` concatenates to curl, `$(printf 's\x64a')`
 * builds `sda`). So instead of matching surface text we (1) RESOLVE the command
 * symbolically — undo the shell tricks the way the shell would — and then (2)
 * judge by CAPABILITY: does this *do* a fetch-and-execute, open a reverse shell,
 * read a secret and send it somewhere? Capabilities survive token-level evasion
 * because they describe behaviour, not spelling.
 *
 * This is still not a sandbox (shell is Turing-complete), but it closes the whole
 * family of "rename the tool / split the token / build it at runtime" bypasses
 * that defeat regex, and it generalizes to variants it has never seen.
 */

export type Cap = { id: string; decision: "deny" | "ask"; label: string };

// ── Symbolic resolution ────────────────────────────────────────────────────────

/** Interpret C-style escapes in a printf argument: \x64→d, \144→d, \n, \t … */
function interpretEscapes(s: string): string {
  return s
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\([0-7]{1,3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)))
    .replace(/\\t/g, "\t").replace(/\\n/g, "\n").replace(/\\r/g, "\r");
}

/** Binaries whose appearance (however spelled) is security-relevant. A glob token
 *  is "resolved" to one of these if it could expand to it. */
const DANGEROUS_BINS = [
  "curl", "wget", "fetch", "nc", "ncat", "socat", "bash", "sh", "zsh", "dash",
  "python", "python2", "python3", "perl", "ruby", "php", "node", "dig", "nslookup",
  "host", "scp", "sftp", "ftp", "tftp", "telnet", "openssl",
];

/** Resolve a single glob word to a dangerous binary if it unambiguously could be
 *  one. Conservative: only `?`/character-class wildcards (NOT `*`, which matches
 *  arbitrary length and would over-match), and at least 3 literal characters, so
 *  benign globs like `*.log` or `*` are never mistaken for `curl`. */
function resolveGlobToken(token: string): string | null {
  const base = token.split("/").pop() ?? token;
  // Only short, filename-shaped tokens with `?`/balanced `[..]` wildcards — never
  // `*` (matches arbitrary length) and never prose like `[Desktop`.
  if (base.length > 12 || base.includes("*") || !/^[A-Za-z0-9?\[\].:_-]+$/.test(base)) return null;
  if (!/\?|\[[^\]]+\]/.test(base)) return null;
  const literals = base.replace(/\[[^\]]*\]|\?/g, "").length;
  if (literals < 3) return null;
  try {
    const re = new RegExp("^" + base.replace(/[.+^${}()|]/g, "\\$&").replace(/\?/g, ".") + "$");
    for (const bin of DANGEROUS_BINS) if (re.test(bin)) return token.replace(base, bin);
  } catch { return null; }
  return null;
}

/** Collect simple `name=value` assignments so `$name` references can be inlined. */
function collectAssignments(s: string): Map<string, string> {
  const vars = new Map<string, string>();
  const re = /(?:^|[;|&]|\bthen\b|\bdo\b)\s*([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;|&]*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) vars.set(m[1], m[2].replace(/^['"]|['"]$/g, ""));
  return vars;
}

/**
 * Reveal a command's true intent past the shell tricks adaptive attackers use:
 * variable concatenation, globbed binary names, parameter expansion of `$HOME`,
 * `$(printf '\xNN')` byte-building, quote/backslash/IFS splitting. Best-effort and
 * bounded — it models the common evasions, not the whole shell grammar.
 */
export function resolveCommand(cmd: string): string {
  let s = cmd;
  // $(printf '...') → its literal bytes (builds device names, tool names, etc.)
  s = s.replace(/\$\(\s*printf\s+(['"]?)([^)]*?)\1\s*\)/g, (_, _q, body) => interpretEscapes(body));
  // Parameter expansion of rooted vars: ${HOME:0:1} is the single char '/'.
  s = s.replace(/"?\$\{HOME:0:1\}"?/g, "/");
  s = s.replace(/\$\{(?:HOME|PWD|ROOT)[^}]*\}/g, "/__ROOTED__");
  // Inline variable assignments (fixed point, bounded) — kills `p=cur;q=l;$p$q`.
  const vars = collectAssignments(s);
  for (let pass = 0; pass < 6 && vars.size; pass++) {
    let changed = false;
    for (const [name, val] of vars) {
      const before = s;
      s = s.replace(new RegExp("\\$\\{" + name + "\\}|\\$" + name + "\\b", "g"), val);
      if (s !== before) changed = true;
    }
    if (!changed) break;
  }
  // Glob → dangerous binary, token by token.
  s = s.split(/(\s+)/).map((tok) => resolveGlobToken(tok) ?? tok).join("");
  // Finally strip the quoting/escapes the shell would collapse.
  s = s
    .replace(/\\([A-Za-z0-9/.:_-])/g, "$1")
    .replace(/['"`]/g, "")
    .replace(/\$\{IFS\}|\$IFS/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return s;
}

// ── Capability detectors (run on RESOLVED command text) ─────────────────────────

const SHELL = /\b(?:ba|z|da)?sh\b/;
const FETCH = /\b(?:curl|wget|fetch)\b/;
/** Sensitive files an injected agent might read and leak. */
const SECRET_PATH =
  /\.ssh\b|id_rsa\b|id_ed25519\b|id_ecdsa\b|id_dsa\b|\.aws\b|\.gnupg\b|\.config\/gh\b|\.npmrc\b|\.netrc\b|\.kube\/config|credentials\.json|\.git-credentials|\/etc\/shadow|\.docker\/config\.json|\.env\b/i;
/** Channels that move bytes off the machine. */
const HTTP_EGRESS = /\b(?:curl|wget)\b|\bn(?:c|cat)\b|\bsocat\b|\b(?:dig|nslookup|host)\b|\burlopen\b|\brequests\.(?:get|post)\b|\bfetch\s*\(|\bNet::HTTP\b|\bLWP\b|\bfile_get_contents\b|\bmail\b|\bsendmail\b|git\s+[^\n]*push\s+https?:\/\//i;
const FILE_EGRESS = /\bscp\b|\bsftp\b|\bftp\b|\btftp\b/i;
/** Secret-shaped environment variable names. */
const SECRET_VAR = /\$\{?[A-Z0-9_]*(?:AWS|GITHUB|GH_|OPENAI|ANTHROPIC|NPM|SECRET|TOKEN|API[_-]?KEY|APIKEY|PASSWORD|PRIVATE|ACCESS_KEY)[A-Z0-9_]*\}?/;

function detectFetchExec(s: string): Cap | null {
  if (new RegExp(FETCH.source + "[^|\\n]*\\|\\s*(?:sudo\\s+)?(?:\\S*\\/)?(?:ba|z|da)?sh\\b", "i").test(s))
    return { id: "fetch-exec-pipe", decision: "deny", label: "pipes a network download straight into a shell" };
  if (/\$\(\s*(?:curl|wget|fetch)\b/i.test(s) || /(?:eval|exec)\b[^\n]*(?:curl|wget|fetch)\b/i.test(s))
    return { id: "fetch-exec-subst", decision: "deny", label: "executes the output of a network fetch" };
  // Interpreter that both fetches and executes remote content.
  const fetches = /\b(?:urlopen|urllib|requests\.(?:get|post)|fetch\s*\(|Net::HTTP|LWP|file_get_contents|http\.(?:get|request))\b/i.test(s) ||
    /\.get\s*\(\s*['"]?https?:\/\//i.test(s) || /require\(\s*['"]?https?['"]?\s*\)/i.test(s);
  const execs = /\b(?:os\.system|subprocess|popen|system\s*\(|spawn|child_process|\beval\b|\bexec\b)\b/i.test(s) || /\/bin\/(?:ba)?sh\b/.test(s);
  if (fetches && execs)
    return { id: "fetch-exec-interp", decision: "deny", label: "downloads and runs remote code through an interpreter" };
  return null;
}

function detectReverseShell(s: string): Cap | null {
  if (/\/dev\/(?:tcp|udp)\//.test(s) && (SHELL.test(s) || /\beval\b/.test(s) || /[<>]&?\s*\d/.test(s)))
    return { id: "revshell-devtcp", decision: "deny", label: "opens a reverse shell over a raw TCP/UDP socket" };
  if (/\bn(?:c|cat)\b[^\n]*\s-[a-z]*[ec]\b[^\n]*(?:ba|z)?sh\b/i.test(s) || /mkfifo\b[^\n]*\bn(?:c|cat)\b/i.test(s))
    return { id: "revshell-nc", decision: "deny", label: "spawns a reverse shell with netcat" };
  if (/\bsocat\b[^\n]*(?:EXEC|SYSTEM):/i.test(s) && /\b(?:TCP|UDP|OPENSSL|SSL)\d?:/i.test(s))
    return { id: "revshell-socat", decision: "deny", label: "spawns a shell bound to a socket with socat" };
  const sock = /\b(?:IO::Socket|socket\.socket|SOCK_STREAM|PeerAddr|TCPSocket|fsockopen|Socket::INET)\b/i.test(s);
  const spawn = /\b(?:system\s*\(|exec|spawn|popen)\b/i.test(s) || /\/bin\/(?:ba)?sh\b/.test(s) || /\bsh\s+-i\b/.test(s);
  if (sock && spawn)
    return { id: "revshell-interp", decision: "deny", label: "spawns a reverse shell via an interpreter socket" };
  return null;
}

function detectSecretExfil(s: string): Cap | null {
  if (SECRET_PATH.test(s)) {
    if (HTTP_EGRESS.test(s)) return { id: "exfil-secret-net", decision: "deny", label: "reads a secret file and sends it off the machine" };
    if (FILE_EGRESS.test(s) && /\b\w+@?[\w.-]+:/.test(s)) return { id: "exfil-secret-copy", decision: "deny", label: "copies a secret file to a remote host" };
  }
  // Secret-named variable posted to the network (after assignment inlining).
  if (SECRET_VAR.test(s) && /\b(?:curl|wget)\b[^\n]*(?:-d|--data\S*|-F|--form|-T|--upload|-G\b)/i.test(s))
    return { id: "exfil-secret-var", decision: "deny", label: "posts a secret-looking value to a URL" };
  return null;
}

function detectEnvExfil(s: string): Cap | null {
  if (/\b(?:env|printenv|set|export\s+-p)\b\s*\|\s*(?:curl|wget|n(?:c|cat)|socat|python\d?|perl|ruby|node|php|dig|mail|sendmail|nc)\b/i.test(s))
    return { id: "exfil-env", decision: "deny", label: "ships environment variables (secrets) off the machine" };
  // Dump-to-file then upload (printenv > f && curl -F @f) — not a pipe, same intent.
  if (/\b(?:printenv|env|export\s+-p)\b/i.test(s) && /\b(?:curl|wget|n(?:c|cat)|socat)\b[^\n]*(?:-F\b|--data\S*|--upload|-T\b|@\/|@-|@\$)/i.test(s))
    return { id: "exfil-env", decision: "deny", label: "dumps environment variables to a file and uploads it" };
  return null;
}

function detectDestructive(s: string): Cap | null {
  // rm of a filesystem-root / home target (resolved `${HOME:0:1}*` → `/*`).
  if (/\brm\b(?:\s+-{1,2}[A-Za-z-]+)*\s+(?:--\s+)?(?:\/|\/\*|~\/?|\$HOME|\/__ROOTED__)(?:\s|$|\*|;|&|\|)/.test(s) &&
      /\brm\b[^\n]*-[A-Za-z]*r/i.test(s))
    return { id: "destroy-rm-root", decision: "deny", label: "recursively deletes the filesystem root or home" };
  if (/\bdd\b[^\n]*\bof=\/dev\/(?:sd|nvme|hd|vd|disk|mmcblk)/i.test(s) || /\bmkfs(?:\.\w+)?\s+\/dev\//i.test(s))
    return { id: "destroy-disk", decision: "deny", label: "writes raw data over a disk device" };
  if (/>\s*\/dev\/(?:sd|nvme|hd)[a-z]/i.test(s))
    return { id: "destroy-overwrite-dev", decision: "deny", label: "redirects into a raw disk device" };
  return null;
}

function detectForkBomb(s: string): Cap | null {
  if (/:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/.test(s)) return { id: "forkbomb-classic", decision: "deny", label: "is a fork bomb" };
  // Renamed fork bomb: a function whose body recurses into itself across a pipe and backgrounds.
  const m = /([A-Za-z_]\w*)\s*\(\)\s*\{([^}]*)\}/.exec(s);
  if (m) {
    const name = m[1], body = m[2];
    const calls = (body.match(new RegExp("\\b" + name + "\\b", "g")) ?? []).length;
    if (calls >= 2 && body.includes("|") && body.includes("&")) return { id: "forkbomb-renamed", decision: "deny", label: "is a fork bomb (recursive self-pipe)" };
  }
  return null;
}

const COMMAND_DETECTORS = [detectFetchExec, detectReverseShell, detectSecretExfil, detectEnvExfil, detectDestructive, detectForkBomb];

/** Run every capability detector over a RESOLVED command (or file content). */
export function detectCommandCapabilities(resolved: string): Cap[] {
  const caps: Cap[] = [];
  for (const d of COMMAND_DETECTORS) { const c = d(resolved); if (c) caps.push(c); }
  return caps;
}

/** Source content that POSTs a credential/token to a hard-coded plain-`http://`
 *  host — the shape of a backdoor smuggled into otherwise-normal-looking code.
 *  `ask` (not `deny`): legitimate API clients exist, but they use https and a
 *  configured base URL, not a literal http:// address carrying a token. */
function detectContentExfil(s: string): Cap | null {
  const posts = /\bfetch\s*\(\s*['"]http:\/\//i.test(s) || /\b(?:axios|XMLHttpRequest|\.post)\b[^\n]{0,60}http:\/\//i.test(s);
  const carriesSecret = /\b(?:token|password|secret|credential|authorization|api[_-]?key|cookie|session)\b/i.test(s);
  const sends = /method\s*:\s*['"]?POST\b/i.test(s) || /\.post\b/i.test(s) || /\bbody\s*:/i.test(s);
  if (posts && carriesSecret && sends)
    return { id: "content-exfil-http", decision: "ask", label: "sends a token/credential to a hard-coded external http:// address" };
  return null;
}

/** Capabilities embedded in file CONTENT (a build file / config / script the
 *  agent is asked to write). Fetch-and-execute or a reverse shell baked into a
 *  file is persistence/RCE regardless of the file's path. Scans both the raw
 *  content and its resolved form so neither quote-stripping nor obfuscation hides
 *  the behaviour. */
export function detectContentCapabilities(content: string): Cap[] {
  const resolved = resolveCommand(content);
  const seen = new Set<string>();
  const caps: Cap[] = [];
  for (const text of [content, resolved]) {
    for (const d of [detectFetchExec, detectReverseShell, detectEnvExfil, detectSecretExfil, detectContentExfil]) {
      const c = d(text);
      if (c && !seen.has(c.id)) { seen.add(c.id); caps.push(c); }
    }
  }
  return caps;
}
