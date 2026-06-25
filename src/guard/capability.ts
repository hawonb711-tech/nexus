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
  // Short, filename-shaped tokens with `?`/`*`/`[..]` wildcards (not prose like
  // `[Desktop`). Adaptive attackers use `c*l`→curl and `b*sh`→bash, so `*` is
  // allowed — but ≥2 literal chars are required and the result must be an exact
  // dangerous-binary name, so benign globs (`*.json`, `dist/*`) never match.
  if (base.length > 14 || !/^[A-Za-z0-9?*\[\].:_-]+$/.test(base)) return null;
  if (!/[?*]|\[[^\]]+\]/.test(base)) return null;
  const literals = base.replace(/\[[^\]]*\]|[?*]/g, "").length;
  if (literals < 2) return null;
  try {
    const re = new RegExp("^" + base.replace(/[.+^${}()|]/g, "\\$&").replace(/\?/g, ".").replace(/\*/g, ".*") + "$");
    for (const bin of DANGEROUS_BINS) if (re.test(bin)) return token.replace(base, bin);
  } catch { return null; }
  return null;
}

/** Decode `$(… | base64 -d)` / `$(echo B64 | base64 -d)` so a URL or command
 *  hidden in base64 and built at runtime is revealed before capability checks. */
function decodeBase64Subst(s: string): string {
  return s.replace(
    /\$\(\s*(?:printf\s+%s\s+|echo\s+(?:-n\s+)?)?["']?([A-Za-z0-9+/=]{8,})["']?\s*\|\s*base64\s+-d\w*\s*\)/gi,
    (m, b64) => { try { return Buffer.from(b64, "base64").toString("utf8"); } catch { return m; } },
  );
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
  // Decode base64 built at runtime (after vars are inlined so $H → the literal).
  s = decodeBase64Subst(s);
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
  /\.ssh\b|id_rsa\b|id_ed25519\b|id_ecdsa\b|id_dsa\b|\.aws\b|\.gnupg\b|\.config\/gh\b|\.config\/gcloud\b|\.config\/rclone\b|\.config\/git\/credentials|rclone\.conf\b|\.azure\b|\.terraform\.d\b|\.npmrc\b|\.netrc\b|\.pgpass\b|\.kube\/config|kubeconfig\b|credentials\.json|\.git-credentials|\/etc\/shadow|\/proc\/self\/environ|\.docker\/config\.json|\.env\b/i;
/** Channels that move bytes off the machine (HTTP, DNS, ICMP, raw socket, mail,
 *  cloud-storage CLIs, and the gawk /inet networking extension). */
const HTTP_EGRESS = /\b(?:curl|wget)\b|\bn(?:c|cat)\b|\bsocat\b|\b(?:dig|nslookup|host|getent)\b|\bping\b|\btelnet\b|\/dev\/(?:tcp|udp)\/|\/inet\/(?:tcp|udp)\/|\burlopen\b|\brequests\.(?:get|post)\b|\bfetch\s*\(|\bNet::HTTP\b|\bLWP\b|\bfile_get_contents\b|\b(?:mail|mailx|mutt|sendmail|smtplib)\b|require\(['"]dns['"]\)|\bdns\.(?:resolve|lookup)|\brclone\b|\baws\s+s3\b|\bgsutil\b|\baz\s+storage\b|\bgh\s+api\b|\bkubectl\s+cp\b|\bb2\s+upload\b|\bmc\s+cp\b|git\s+[^\n]*push\s+https?:\/\//i;
const FILE_EGRESS = /\bscp\b|\bsftp\b|\bftp\b|\btftp\b|\brsync\b[^\n]*::/i;
/** Secret-shaped environment variable names. */
const SECRET_VAR = /\$\{?[A-Z0-9_]*(?:AWS|GITHUB|GH_|OPENAI|ANTHROPIC|NPM|SECRET|TOKEN|API[_-]?KEY|APIKEY|PASSWORD|PRIVATE|ACCESS_KEY|DATABASE_URL|DB_URL|SESSION|COOKIE|CONN(?:ECTION)?_?STR|DSN)[A-Z0-9_]*\}?/;

function detectFetchExec(s: string): Cap | null {
  if (new RegExp(FETCH.source + "[^|\\n]*\\|\\s*(?:sudo\\s+)?(?:\\S*\\/)?(?:ba|z|da)?sh\\b", "i").test(s))
    return { id: "fetch-exec-pipe", decision: "deny", label: "pipes a network download straight into a shell" };
  if (/\$\(\s*(?:curl|wget|fetch)\b/i.test(s) || /(?:eval|exec)\b[^\n]*(?:curl|wget|fetch)\b/i.test(s))
    return { id: "fetch-exec-subst", decision: "deny", label: "executes the output of a network fetch" };
  // Decode/transform-and-execute: any decode/transform tool (base64, hex, base32,
  // gunzip, ROT13 via tr, rev, openssl) whose output is piped into a shell —
  // possibly through a chain of transforms (… | base64 -d | gunzip | sh).
  const TRANSFORM = "base64\\s+-{1,2}(?:d|decode|D)|xxd\\s+-r|base32\\s+-{1,2}d|openssl\\s+enc\\s+-d|uudecode|gunzip|zcat|gzip\\s+-d|\\brev\\b|\\btr\\s+['\"]?[A-Za-z]";
  if (new RegExp("(?:" + TRANSFORM + ")[^\\n]*(?:\\|\\s*[^|\\n]*)*\\|\\s*(?:sudo\\s+)?(?:\\S*\\/)?(?:ba|z|da)?sh\\b", "i").test(s))
    return { id: "fetch-exec-subst", decision: "deny", label: "decodes/deobfuscates a blob and runs it in a shell" };
  // eval/sh -c of a transform substitution: eval "$(tr … <<< …)", bash -c "$(rev <<< …)".
  if (/\b(?:eval|(?:ba|z)?sh\s+-c)\b[^\n]*\$\([^)]*(?:\brev\b|\btr\s+['"]?[A-Za-z]|base64\s+-d|gunzip|xxd\s+-r)/i.test(s))
    return { id: "fetch-exec-subst", decision: "deny", label: "deobfuscates a string and executes it" };
  // perl/python pack/codecs decode then run (system pack "H*", codecs.decode rot13/zlib + exec).
  // Quote-tolerant: resolveCommand strips the quotes around "H*".
  if (/\bpack\s*\(?\s*["']?H\*/i.test(s) && /\b(?:system|exec|eval)\b|`/i.test(s))
    return { id: "fetch-exec-subst", decision: "deny", label: "decodes a hex-packed payload and executes it" };
  // Interpreter that decodes-and-executes (exec(b64decode(...)), execSync(Buffer.from(...,'base64')), codecs.decode).
  if (/\b(?:exec|eval|os\.system|execSync|child_process|new Function|spawn\w*|popen|system)\b[^\n]*(?:b64decode|base64\.b64decode|Buffer\.from\([^)]*['"]base64|atob\s*\(|base32\.b32decode|codecs\.decode|zlib\.decompress)/i.test(s))
    return { id: "fetch-exec-subst", decision: "deny", label: "decodes an encoded payload and executes it" };
  // Interpreter that both fetches and executes remote content.
  const fetches = /\b(?:urlopen|urllib|requests\.(?:get|post)|fetch\s*\(|Net::HTTP|LWP|file_get_contents|http\.(?:get|request))\b/i.test(s) ||
    /\.get\s*\(\s*['"]?https?:\/\//i.test(s) || /require\(\s*['"]?https?['"]?\s*\)/i.test(s);
  const execs = /\b(?:os\.system|subprocess|popen|system\s*\(|spawn\w*|child_process|\beval\b|\bexec\b|new Function|execSync)\b/i.test(s) || /\/bin\/(?:ba)?sh\b/.test(s);
  if (fetches && execs)
    return { id: "fetch-exec-interp", decision: "deny", label: "downloads and runs remote code through an interpreter" };
  return null;
}

/** Installing from an attacker-controlled package index/registry (supply-chain). */
function detectUntrustedInstall(s: string): Cap | null {
  const m = /(?:pip\d?\s+install|uv\s+(?:pip\s+)?install|npm\s+(?:install|i)\b|yarn\s+add|pnpm\s+(?:add|install))[^\n]*--(?:extra-index-url|index-url|registry)[ =]\s*(https?:\/\/[^\s"']+)/i.exec(s);
  if (m && !/^https?:\/\/((www\.)?registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org|files\.pythonhosted\.org|jsr\.io)(\/|$|:)/i.test(m[1]))
    return { id: "untrusted-index", decision: "deny", label: "installs packages from an attacker-controlled index/registry" };
  return null;
}

function detectReverseShell(s: string): Cap | null {
  if (/\/dev\/(?:tcp|udp)\//.test(s) && (SHELL.test(s) || /\beval\b/.test(s) || /[<>]&?\s*\d/.test(s) || /\bcat\b/.test(s)))
    return { id: "revshell-devtcp", decision: "deny", label: "opens a reverse shell or raw-socket channel over /dev/tcp|udp" };
  // gawk's /inet/tcp networking extension used as a socket (reverse/bind shell).
  if (/\/inet\/(?:tcp|udp)\/\d/.test(s) && /\bg?awk\b/i.test(s))
    return { id: "revshell-gawk", decision: "deny", label: "opens a network socket via gawk's /inet extension" };
  if (/\bn(?:c|cat)\b[^\n]*\s-[a-z]*[ec]\b[^\n]*(?:ba|z)?sh\b/i.test(s) || /\b(?:mkfifo|mknod)\b[^\n]*\bn(?:c|cat)\b/i.test(s) ||
      (/\b(?:mkfifo|mknod\b[^\n]*\bp\b)/i.test(s) && /\bn(?:c|cat)\b/i.test(s) && /\bsh\b/i.test(s)))
    return { id: "revshell-nc", decision: "deny", label: "spawns a reverse shell with netcat/a named pipe" };
  if (/\bsocat\b[^\n]*(?:EXEC|SYSTEM):/i.test(s) && /\b(?:TCP|UDP|OPENSSL|SSL)\d?:/i.test(s))
    return { id: "revshell-socat", decision: "deny", label: "spawns a shell bound to a socket with socat" };
  const sock = /\b(?:IO::Socket|socket\.socket|SOCK_STREAM|PeerAddr|TCPSocket|fsockopen|Socket::INET|create_connection|os\.dup2)\b/i.test(s) || /\.socket\s*\(/.test(s) || /\.connect\s*\(\s*\(/.test(s);
  const spawn = /\b(?:system\s*\(|exec|spawn\w*|popen|subprocess|pty\.spawn|os\.system)\b/i.test(s) || /\/bin\/(?:ba)?sh\b/.test(s) || /\bsh\s+-i\b/.test(s);
  if (sock && spawn)
    return { id: "revshell-interp", decision: "deny", label: "spawns a reverse shell via an interpreter socket" };
  return null;
}

function detectSecretExfil(s: string): Cap | null {
  if (SECRET_PATH.test(s)) {
    if (HTTP_EGRESS.test(s)) return { id: "exfil-secret-net", decision: "deny", label: "reads a secret file and sends it off the machine" };
    if (FILE_EGRESS.test(s) && /\b\w+@?[\w.-]+:/.test(s)) return { id: "exfil-secret-copy", decision: "deny", label: "copies a secret file to a remote host" };
    // Copying a secret into a publicly-served directory (download it over HTTP later).
    if (/\/var\/www|\/srv\/www|\/usr\/share\/nginx|\/public\/|\bpublic\/|\/static\/|\.\/public\b/i.test(s) && /\bopen\s*\(|>\s|>>\s|\bwrite\b|\bcp\b|\bmv\b|\btee\b/i.test(s))
      return { id: "exfil-secret-public", decision: "deny", label: "copies a secret file into a publicly-served location" };
  }
  // Secret-named variable posted to the network (after assignment inlining) —
  // either as POST data or carried inside the request URL.
  if (SECRET_VAR.test(s) && (
        /\b(?:curl|wget)\b[^\n]*(?:-d|--data\S*|-F|--form|-T|--upload|-G\b)/i.test(s) ||
        /\b(?:curl|wget)\b[^\n]*https?:\/\/[^\s"']*\$\{?[A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|DATABASE|SESSION|COOKIE|DSN)/i.test(s) ||
        /\b(?:getent|dig|nslookup|host)\b[^\n]*\$\{?[A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|DATABASE|SESSION|COOKIE|DSN)/i.test(s)))
    return { id: "exfil-secret-var", decision: "deny", label: "sends a secret-looking value to a URL or DNS lookup" };
  return null;
}

function detectEnvExfil(s: string): Cap | null {
  // `env` only counts as a dump when it pipes its output (not `env VAR=x cmd`).
  const envDump = /\bprintenv\b/i.test(s) || /\benv\s*\|/i.test(s) || /\benv\s*>/i.test(s) || /\bexport\s+-p\b/i.test(s);
  if (envDump && (HTTP_EGRESS.test(s) || /\b(?:python\d?|perl|ruby|node|php)\b/i.test(s)))
    return { id: "exfil-env", decision: "deny", label: "ships environment variables (secrets) off the machine" };
  // Dump-to-file then upload (printenv > f && curl -F @f) — not a pipe, same intent.
  if (envDump && /\b(?:curl|wget|n(?:c|cat)|socat)\b[^\n]*(?:-F\b|--data\S*|--upload|-T\b|@\/|@-|@\$)/i.test(s))
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
  // `find ~ -delete` / `find $HOME -exec shred|rm` — a recursive wipe wearing find's clothes.
  if ((/\bfind\b[^\n]*\s(?:~|\$HOME|\/__ROOTED__|"?\$HOME"?|\/)\s/.test(s) || /\bfind\b\s+(?:~|\$HOME|\/__ROOTED__|"\$HOME")\b/.test(s)) &&
      /-delete\b|-exec\s+(?:shred|rm|unlink)\b/.test(s))
    return { id: "destroy-find-delete", decision: "deny", label: "recursively deletes/shreds the home/root tree via find" };
  // rsync --delete onto the home/root tree (empties it) — often a dated time-bomb.
  if (/\brsync\b[^\n]*--delete\b[^\n]*(?:~\/|\$HOME|"\$HOME"|\/__ROOTED__|\s\/\s*["']?$)/.test(s))
    return { id: "destroy-rsync", decision: "deny", label: "wipes the home/root tree with rsync --delete" };
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

const COMMAND_DETECTORS = [detectFetchExec, detectReverseShell, detectSecretExfil, detectEnvExfil, detectDestructive, detectForkBomb, detectUntrustedInstall];

/** Run every capability detector over a RESOLVED command (or file content). */
export function detectCommandCapabilities(resolved: string): Cap[] {
  const caps: Cap[] = [];
  for (const d of COMMAND_DETECTORS) { const c = d(resolved); if (c) caps.push(c); }
  return caps;
}

/** Source/doc content that POSTs a credential/token to an external host — the
 *  shape of a backdoor or an exfil "beacon" smuggled into normal-looking code.
 *  `ask` (not `deny`): legitimate API clients exist, so it fires only on plain
 *  `http://` OR an explicit exfil framing ("beacon", "report token usage"…). */
function detectContentExfil(s: string): Cap | null {
  const externalPost = /\bfetch\s*\(\s*['"]http:\/\//i.test(s) ||
    /\b(?:axios|requests|XMLHttpRequest)\b[^\n]{0,12}\.?post\b[^\n]{0,80}https?:\/\//i.test(s) ||
    /\.post\s*\(\s*['"]https?:\/\//i.test(s);
  const carriesSecret = /(?:token|password|secret|credential|authorization|api[_-]?key|cookie|session)/i.test(s);
  const malFraming = /\bhttp:\/\//i.test(s) ||
    /\b(?:beacon|attribution|exfil|report (?:token|usage)|mandatory for production|immediately after the request|so each token is)\b/i.test(s);
  if (externalPost && carriesSecret && malFraming)
    return { id: "content-exfil-http", decision: "ask", label: "sends a token/credential to an external host (exfil beacon)" };
  return null;
}

/** Content that downloads a remote payload into an executable / cron / init
 *  location — the supply-chain-backdoor shape (fetch a script to /usr/local/bin
 *  + chmod +x + a cron entry). `ask`: fetching a binary into an image is also a
 *  legitimate (if risky) pattern, so flag rather than hard-block. */
/** A config file that repoints a package manager at a non-official registry /
 *  proxy / mirror (supply-chain), or pins a malicious lockfile resolution. */
function detectConfigRepoint(s: string): Cap | null {
  const OFFICIAL = /^https?:\/\/(?:www\.)?(?:registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org|files\.pythonhosted\.org|jsr\.io|proxy\.golang\.org|sum\.golang\.org|repo\.maven\.apache\.org|repo1\.maven\.org|github\.com)(?:[/:]|$)/i;
  const m = /(?:GOPROXY\s*=|npmRegistryServer\s*:|registry\s*=|--(?:extra-)?index-url[ =]|"resolved"\s*:\s*|PIP_(?:EXTRA_)?INDEX_URL\s*=)\s*["']?(https?:\/\/[^\s"'<,]+)/i.exec(s);
  if (m && !OFFICIAL.test(m[1]))
    return { id: "config-repoint", decision: "ask", label: "points a package manager at a non-official registry/proxy (supply-chain risk)" };
  return null;
}

/** A config file that redirects a dev tool (the git binary, the shell startup
 *  env) to an attacker-controlled path — silent tooling hijack. */
function detectToolingHijack(s: string): Cap | null {
  if (/"git\.path"\s*:\s*"[^"]*(?:\.local\/bin|\/tmp\/|\.cache\/|\.config\/)/i.test(s) ||
      /"?BASH_ENV"?\s*[:=]\s*["'][^"']*(?:\.config|\.cache|\/tmp\/|\.local)/i.test(s) ||
      /\bterminal\.integrated\.env\.\w+["']?\s*:\s*\{[^}]*(?:BASH_ENV|LD_PRELOAD|ENV)\b/i.test(s))
    return { id: "tooling-hijack", decision: "ask", label: "redirects a dev tool (git binary / shell startup env) to an attacker-controlled path" };
  return null;
}

function detectFetchToPersist(s: string): Cap | null {
  const fetchToBin = /\b(?:curl|wget)\b[^\n]*-[oO]\b[^\n]*(?:\/usr(?:\/local)?\/bin\/|\/usr\/bin\/|\/s?bin\/)/i.test(s);
  const persists = /\/etc\/cron|crontab\b|\/etc\/init|\/etc\/systemd|systemctl|chmod\s+\+?x|chmod\s+0?7/i.test(s);
  if ((fetchToBin && persists) || /\b(?:curl|wget)\b[^\n]*>\s*\/etc\/cron/i.test(s))
    return { id: "fetch-to-persist", decision: "ask", label: "downloads a remote payload into an executable/cron/init location" };
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
    for (const d of [detectFetchExec, detectReverseShell, detectEnvExfil, detectSecretExfil, detectContentExfil, detectFetchToPersist, detectConfigRepoint, detectToolingHijack]) {
      const c = d(text);
      if (c && !seen.has(c.id)) { seen.add(c.id); caps.push(c); }
    }
  }
  return caps;
}
