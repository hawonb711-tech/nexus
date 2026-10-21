import { test } from "node:test";
import assert from "node:assert/strict";
import { LINE_RULES } from "./capability.js";
import { RULES } from "./command.js";

/**
 * The line-scan.ts rules must give exactly the verdicts of the plain
 * `TOOL[^\n]*SUFFIX` regexes they replace (and, for the ones read with `.exec()`,
 * the same match and captures). Each rule is fuzzed against its pre-change
 * literal as an oracle over a vocabulary of its own heads, tails and the
 * characters its gaps stop at — repeated heads, several tails, newlines inside
 * heads, tokens glued together without a separator.
 */

/** mulberry32: small, fast, and every bit is usable (an LCG's low bits cycle). */
function rng(seed: number): () => number {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SEPARATORS = [" ", " ", " ", "", "", "\n", "\t", "|", ";", "'", '"', ")", "=", "x"];

function corpus(words: readonly string[], count: number, seed: number): string[] {
  const r = rng(seed);
  const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    let s = "";
    const n = 1 + Math.floor(r() * 12);
    for (let j = 0; j < n; j++) s += pick(words) + pick(SEPARATORS);
    out.push(s);
  }
  return out;
}

type Case = { name: string; oracle: RegExp; rule: RegExp; words: string[]; exec?: boolean };

const CURL = ["curl", "wget", "curlx", "CURL", "curl:"];
const SECRET_REF = ["$TOKEN", "${GH_TOKEN}", "$x", "$DB_PASSWORD", "$A_KEY_B", "$"];

const CASES: Case[] = [
  { name: "EVAL_OF_FETCH", oracle: /(?:eval|exec)\b[^\n]*(?:curl|wget|fetch)\b/i, rule: LINE_RULES.EVAL_OF_FETCH,
    words: ["eval", "exec", "reexec", "evalx", "EVAL", "fetch", "fetchx", ...CURL] },
  { name: "EVAL_OF_TRANSFORM", oracle: /\b(?:eval|(?:ba|z)?sh\s+-c)\b[^\n]*\$\([^)]*(?:\brev\b|\btr\s+['"]?[A-Za-z]|base64\s+-d|gunzip|xxd\s+-r)/i,
    rule: LINE_RULES.EVAL_OF_TRANSFORM,
    words: ["eval", "bash -c", "sh -c", "zsh -c", "sh\n-c", "$(", "$(", ")", "rev", "revx", "tr 'a", "tr x", "tr 1", "base64 -d", "gunzip", "xxd -r", "$", "(", "<<<"] },
  { name: "EXEC_OF_DECODE", oracle: /\b(?:exec|eval|os\.system|execSync|child_process|new Function|spawn\w*|popen|system)\b[^\n]*(?:b64decode|base64\.b64decode|Buffer\.from\([^)]*['"]base64|atob\s*\(|base32\.b32decode|codecs\.decode|zlib\.decompress)/i,
    rule: LINE_RULES.EXEC_OF_DECODE,
    words: ["exec", "eval", "os.system", "execSync", "child_process", "new Function", "spawnSync", "spawn", "popen", "system", "b64decode", "Buffer.from(", "base64", "atob(", "atob\n(", "base32.b32decode", "codecs.decode", "zlib.decompress", "("] },
  { name: "INSTALL_FROM_INDEX", exec: true,
    oracle: /(?:pip\d?\s+install|uv\s+(?:pip\s+)?install|npm\s+(?:install|i)\b|yarn\s+add|pnpm\s+(?:add|install))[^\n]*--(?:extra-index-url|index-url|registry)[ =]\s*(https?:\/\/[^\s"']+)/i,
    rule: LINE_RULES.INSTALL_FROM_INDEX,
    words: ["pip install", "pip3 install", "uv pip install", "uv install", "npm install", "npm i", "yarn add", "pnpm add", "pip\ninstall", "--index-url", "--extra-index-url", "--registry", "--registry=", "https://a.b/c", "http://x", "http://"] },
  { name: "INSTALL_FROM_URL", exec: true,
    oracle: /(?:pip\d?\s+install|npm\s+(?:install|i)\b|uv\s+(?:pip\s+)?install)[^\n]*\s(https?:\/\/[^\s"']+\.(?:tar\.gz|tgz|whl|zip))/i,
    rule: LINE_RULES.INSTALL_FROM_URL,
    words: ["pip install", "npm i", "npm install", "uv pip install", "https://e.x/p.whl", "http://x/a.tar.gz", "https://y/z.tgz", ".zip", "http://q/", "https://"] },
  { name: "FIFO_THEN_NC", oracle: /\b(?:mkfifo|mknod)\b[^\n]*\bn(?:c|cat)\b/i, rule: LINE_RULES.FIFO_THEN_NC,
    words: ["mkfifo", "mknod", "mkfifox", "nc", "ncat", "netcat", "xnc"] },
  { name: "FIFO", oracle: /\b(?:mkfifo|mknod\b[^\n]*\bp\b)/i, rule: LINE_RULES.FIFO,
    words: ["mkfifo", "mknod", "mknodx", "p", "pp", "xmkfifo"] },
  { name: "SOCAT_EXEC", oracle: /\bsocat\b[^\n]*(?:EXEC|SYSTEM):/i, rule: LINE_RULES.SOCAT_EXEC,
    words: ["socat", "socatx", "EXEC:", "SYSTEM:", "exec", ":", "TCP:"] },
  { name: "OPENSSL_CONNECT", oracle: /\bopenssl\s+s_client\b[^\n]*-connect\b/i, rule: LINE_RULES.OPENSSL_CONNECT,
    words: ["openssl s_client", "openssl\ts_client", "openssl\ns_client", "s_client", "-connect", "-connectx", "openssl"] },
  { name: "NAMED_SECRET_SENT", oracle: /\b(?:curl|wget)\b[^\n]*(?:-d\b|--data\S*|-F\b|--form|-T\b|--upload|-G\b)|\|\s*(?:curl|wget|n(?:c|cat)|logger)\b/i,
    rule: LINE_RULES.NAMED_SECRET_SENT,
    words: [...CURL, "-d", "-dx", "--data-raw", "-F", "--form", "-T", "--upload-file", "-G", "nc", "logger", "|"] },
  { name: "FETCH_POSTS_DATA", oracle: /\b(?:curl|wget)\b[^\n]*(?:-d|--data\S*|-F|--form|-T|--upload|-G\b)/i,
    rule: LINE_RULES.FETCH_POSTS_DATA,
    words: [...CURL, "-d", "--data", "-F", "--form", "-T", "--upload", "-G", "-Gx", "-x"] },
  { name: "FETCH_URL_CARRIES_SECRET",
    oracle: /\b(?:curl|wget)\b[^\n]*https?:\/\/[^\s"']*\$\{?[A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|DATABASE|SESSION|COOKIE|DSN)/i,
    rule: LINE_RULES.FETCH_URL_CARRIES_SECRET,
    words: [...CURL, "http://", "https://", "http:/", "a/", "?q=", ...SECRET_REF] },
  { name: "DNS_CARRIES_SECRET", oracle: /\b(?:getent|dig|nslookup|host)\b[^\n]*\$\{?[A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|DATABASE|SESSION|COOKIE|DSN)/i,
    rule: LINE_RULES.DNS_CARRIES_SECRET,
    words: ["getent", "dig", "nslookup", "host", "hostx", ...SECRET_REF] },
  { name: "ENV_DUMP_PIPE", exec: true, oracle: /\b(?:printenv|env|export\s+-p)\b[^\n|=]*\|/i, rule: LINE_RULES.ENV_DUMP_PIPE,
    words: ["printenv", "env", "envx", "export -p", "export\n-p", "|", "=", "X=1", "sort"] },
  { name: "ENV_DUMP_REDIRECT", oracle: /\bprintenv\b[^\n|]*>|\benv\s*>|\bexport\s+-p\b[^\n|]*>/i, rule: LINE_RULES.ENV_DUMP_REDIRECT,
    words: ["printenv", "env", "export -p", ">", " >", "|", "f"] },
  { name: "RM_RECURSIVE", oracle: /\brm\b[^\n]*-[A-Za-z]*r/i, rule: LINE_RULES.RM_RECURSIVE,
    words: ["rm", "rmx", "-rf", "-r", "-R", "-x", "-", "r", "-fv"] },
  { name: "DD_TO_DISK", oracle: /\bdd\b[^\n]*\bof=\/dev\/(?:sd|nvme|hd|vd|disk|mmcblk)/i, rule: LINE_RULES.DD_TO_DISK,
    words: ["dd", "ddx", "of=/dev/sda", "of=/dev/mmcblk0", "of=/dev/x", "of=", "xof=/dev/sd"] },
  { name: "FIND_FROM_ROOT", oracle: /\bfind\b[^\n]*\s(?:~|\$HOME|\/__ROOTED__|"?\$HOME"?|\/)\s/, rule: LINE_RULES.FIND_FROM_ROOT,
    words: ["find", "FIND", "~", "$HOME", "/", '"$HOME"', "/__ROOTED__", " ", "\t", "."] },
  { name: "RSYNC_DELETE_ROOT", oracle: /\brsync\b[^\n]*--delete\b[^\n]*(?:~\/|\$HOME|"\$HOME"|\/__ROOTED__|\s\/\s*["']?$)/,
    rule: LINE_RULES.RSYNC_DELETE_ROOT,
    words: ["rsync", "--delete", "--deletex", "~/", "$HOME", "/", '"$HOME"', "/__ROOTED__", "src/"] },
  { name: "REGISTRY_URL", exec: true,
    oracle: /(?:GOPROXY\s*=|npmRegistryServer\s*:|registry\s*=|--(?:extra-)?index-url[ =]|\bindex-url\s*=|"resolved"\s*:\s*|PIP_(?:EXTRA_)?INDEX_URL\s*=|replace-with\b[^\n]*registry\s*=)\s*["']?(?:sparse\+|git\+)?(https?:\/\/[^\s"'<,]+)/i,
    rule: LINE_RULES.REGISTRY_URL,
    words: ["replace-with", "replace-withx", "registry =", "registry=", "registry", "GOPROXY=", "index-url =", "https://evil.x", "http://y", "sparse+", "git+"] },
  { name: "FETCH_TO_CRON", oracle: /\b(?:curl|wget)\b[^\n]*>\s*\/etc\/cron/i, rule: LINE_RULES.FETCH_TO_CRON,
    words: [...CURL, ">", "> /etc/cron.d/x", ">/etc/cron", "/etc/cron"] },
];

const cmdRule = (id: string): RegExp => {
  const rule = RULES.find((r) => r.id === id);
  assert.ok(rule, `no command rule ${id}`);
  return rule.re;
};
CASES.push(
  { name: "revshell-devtcp", oracle: /(?:ba|z)?sh\s+-i\b[^\n]*>&?\s*\/dev\/tcp\/|\/dev\/tcp\/\d/i, rule: cmdRule("revshell-devtcp"),
    words: ["bash -i", "sh -i", "zsh\n-i", "-ix", ">&", "> ", "/dev/tcp/", "/dev/tcp/1", "/dev/tcp/x"] },
  { name: "revshell-interp", oracle: /(?:python\d?|perl|ruby|php)\b[^\n]*socket\b[^\n]*(?:connect|SOCK_STREAM)[^\n]*(?:exec|spawn|\/bin\/(?:ba)?sh)/i,
    rule: cmdRule("revshell-interp"),
    words: ["python", "python3", "perl", "ruby", "php", "socket", "socketx", "connect", "SOCK_STREAM", "exec", "spawn", "/bin/sh", "/bin/bash"] },
  { name: "destroy-dd-disk", oracle: /\bdd\b[^\n]*\bof=\/dev\/(?:sd|nvme|hd|disk|vd)|\bmkfs(?:\.\w+)?\s+\/dev\//i, rule: cmdRule("destroy-dd-disk"),
    words: ["dd", "of=/dev/sda", "of=/dev/vd", "of=/dev/x", "mkfs", "mkfs.ext4", "/dev/"] },
  { name: "weaken-disable-history", oracle: /\bhistory\s+-c\b|\brm\b[^\n]*\.bash_history|\bunset\s+HISTFILE\b|\bexport\s+HISTSIZE=0\b/i,
    rule: cmdRule("weaken-disable-history"),
    words: ["history -c", "rm", "rmx", ".bash_history", "~/.bash_history", "unset HISTFILE", "export HISTSIZE=0"] },
);

const view = (m: RegExpExecArray | null) => (m ? [m.index, m[0], m[1]] : null);

for (const c of CASES) {
  test(`${c.name} matches exactly what its plain \`[^\\n]*\` form matched`, () => {
    let positives = 0;
    for (const s of corpus(c.words, 6000, c.name.length * 7919)) {
      const want = c.oracle.test(s);
      if (want) positives++;
      assert.equal(c.rule.test(s), want, `${c.name} on ${JSON.stringify(s)}`);
      if (c.exec) assert.deepEqual(view(c.rule.exec(s)), view(c.oracle.exec(s)), `${c.name} exec on ${JSON.stringify(s)}`);
    }
    // A corpus that never matches would make the comparison vacuous.
    assert.ok(positives >= 100, `${c.name}: only ${positives} positives in the corpus`);
  });
}
