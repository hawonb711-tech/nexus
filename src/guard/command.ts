/**
 * Dangerous-command inspection for the PreToolUse side of the agent firewall.
 *
 * A prompt-injected agent's most dangerous capability is running shell commands.
 * This screens a command the agent is ABOUT to execute and decides deny / ask /
 * allow. Patterns are deliberately HIGH-confidence (remote-code execution,
 * reverse shells, disk/destructive ops, credential exfiltration, persistence) so
 * that everyday commands pass untouched — a guard that cries wolf gets disabled.
 *
 * Layer 1 (primary) is STRUCTURAL: the command is resolved symbolically and
 * judged by capability (see ./capability.ts), so adaptive evasions — globbed
 * binary names, variable concatenation, runtime byte-building — are caught by
 * behaviour, not spelling. Layer 2 is the high-confidence regex set below, kept
 * as defense-in-depth.
 */

import { posix, win32 } from "node:path";
import { resolveCommand, detectCommandCapabilities, detectContentCapabilities } from "./capability.js";
import { lineSeq, oneOf } from "./line-scan.js";
import { hooksOffSwitches, isCodexRequirements, type ConfigBoolean } from "./codex/hooks-switch.js";
import type { PatchWrite } from "./codex/patch.js";
import { analyzeShellCommand, asFileNames, CODEX_USER_INSTRUCTIONS, watchedLabel, displayPathTarget, displayTarget, SHELL_PATCH_RULE } from "./shell-write-targets.js";

export type CommandDecision = "deny" | "ask" | "allow";

export type CommandResult = {
  decision: CommandDecision;
  /** Human reason (shown to the agent / user). */
  reason: string;
  /** Rule id that fired, if any. */
  rule: string | null;
};

export type CmdRule = { id: string; decision: "deny" | "ask"; label: string; re: RegExp; reason?: string };

export const RULES: CmdRule[] = [
  // ── Remote code execution: fetch-and-run ────────────────────────────────────
  { id: "rce-pipe-shell", decision: "deny", label: "pipes a download straight into a shell",
    re: /\b(?:curl|wget|fetch)\b[^\n|]{0,400}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i },
  { id: "rce-eval-fetch", decision: "deny", label: "evaluates the output of a network fetch",
    re: /(?:eval|exec)\s*[("'`$]*\s*(?:curl|wget)\b|\$\(\s*(?:curl|wget)\b/i },
  { id: "rce-base64-shell", decision: "deny", label: "decodes a blob and pipes it into a shell",
    re: /base64\s+(?:-d|--decode|-D)\b[^\n|]{0,400}\|\s*(?:ba|z)?sh\b/i },

  // ── Reverse shells ──────────────────────────────────────────────────────────
  { id: "revshell-devtcp", decision: "deny", label: "opens a reverse shell via /dev/tcp",
    re: oneOf("i", lineSeq(/(?:ba|z)?sh\s+-i\b/, />&?\s*\/dev\/tcp\//), /\/dev\/tcp\/\d/) },
  { id: "revshell-nc", decision: "deny", label: "spawns a reverse shell with netcat",
    re: /\bn(?:c|cat)\b[^\n]{0,200}\s-[a-z]*e\b[^\n]{0,200}\b(?:ba|z)?sh\b|mkfifo\b[^\n]{0,200}\bn(?:c|cat)\b/i },
  { id: "revshell-interp", decision: "deny", label: "spawns a reverse shell via an interpreter socket",
    re: new RegExp(lineSeq(/(?:python\d?|perl|ruby|php)\b/, /socket\b/, /(?:connect|SOCK_STREAM)/, /(?:exec|spawn|\/bin\/(?:ba)?sh)/), "i") },

  // ── Destructive / disk ──────────────────────────────────────────────────────
  { id: "destroy-rm-root", decision: "deny", label: "recursively deletes a root/home path",
    re: /\brm\s+(?:-\w+\s+)*-?\w*[rf]\w*[rf]?\w*\s+(?:--no-preserve-root\s+)?(?:\/(?:\s|$|\*)|~(?:\/\s*)?(?:\s|$)|\$HOME\b|\/\*)/i },
  { id: "destroy-forkbomb", decision: "deny", label: "is a fork bomb",
    re: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/ },
  { id: "destroy-dd-disk", decision: "deny", label: "writes raw data over a disk device",
    re: oneOf("i", lineSeq(/\bdd\b/, /\bof=\/dev\/(?:sd|nvme|hd|disk|vd)/), /\bmkfs(?:\.\w+)?\s+\/dev\//) },
  { id: "destroy-overwrite-dev", decision: "deny", label: "redirects into a raw disk device",
    re: />\s*\/dev\/(?:sd|nvme|hd)[a-z]/i },

  // ── Credential / data exfiltration ──────────────────────────────────────────
  { id: "exfil-secret-file", decision: "deny", label: "ships a secret file to the network",
    re: /(?:cat|head|tail|cp|tar|base64)\b[^\n|]{0,300}(?:\.env\b|id_rsa\b|id_ed25519\b|\.aws\/credentials|\.ssh\/|\.npmrc\b|\.netrc\b|\.kube\/config|credentials\.json)[^\n]{0,300}\|\s*(?:curl|wget|n(?:c|cat))\b/i },
  { id: "exfil-env-network", decision: "deny", label: "ships environment variables to the network",
    re: /\b(?:env|printenv|set)\b\s*\|\s*(?:curl|wget|n(?:c|cat))\b/i },
  { id: "exfil-secret-var", decision: "deny", label: "posts a secret-looking variable to a URL",
    re: /(?:curl|wget)\b[^\n]{0,300}(?:-d|--data\S*|-F|--form|-T|--upload)\b[^\n]{0,300}\$\{?(?:[A-Z0-9_]*(?:AWS|GITHUB|GH|OPENAI|ANTHROPIC|NPM|SECRET|TOKEN|API[_-]?KEY|PASSWORD|PRIVATE)[A-Z0-9_]*)\}?/i },

  // ── Persistence / backdoor ──────────────────────────────────────────────────
  { id: "persist-authorized-keys", decision: "deny", label: "writes an SSH authorized_keys entry",
    re: />>?\s*(?:~|\$HOME|\/root|\/home\/[^\s/]+)?\/?\.ssh\/authorized_keys/i },
  { id: "persist-cron-fetch", decision: "ask", label: "installs a cron job that fetches from the network",
    re: /\bcrontab\b[^\n]{0,300}(?:curl|wget)|(?:curl|wget)[^\n]{0,300}\|\s*crontab\b/i },
  { id: "persist-shellrc-fetch", decision: "ask", label: "appends a network fetch to a shell rc file",
    re: />>\s*~?\/?\.(?:bashrc|zshrc|profile|bash_profile)\b[^\n]{0,300}&&[^\n]{0,300}(?:curl|wget)|(?:curl|wget)[^\n]{0,300}>>\s*~?\/?\.(?:bashrc|zshrc|profile)/i },

  // ── Tampering / anti-forensics / weakening ──────────────────────────────────
  { id: "weaken-chmod-777", decision: "ask", label: "makes a path world-writable (chmod 777)",
    re: /\bchmod\s+(?:-R\s+)?0?777\b/i },
  { id: "weaken-disable-history", decision: "ask", label: "disables or wipes shell history",
    re: oneOf("i", /\bhistory\s+-c\b/, lineSeq(/\brm\b/, /\.bash_history/), /\bunset\s+HISTFILE\b|\bexport\s+HISTSIZE=0\b/) },
  { id: "weaken-disable-security", decision: "ask", label: "disables a host security control",
    re: /\bsetenforce\s+0\b|\bsystemctl\s+(?:stop|disable)\s+(?:firewalld|ufw|apparmor)\b|\bufw\s+disable\b/i },

  // ── Nexus instruction-file integrity (context-free static rules, §6.7) ────────
  // A read of a Nexus key file: an agent never needs one (a read-and-send is a
  // hard deny via SECRET_PATH; this catches the bare read).
  { id: "nexus-key-read", decision: "ask", label: "reads a Nexus key file",
    re: /\.integrity-key\b|\.sanitation-key\b|\.integrity-anchor\b/i,
    reason: "Caution: this command reads a Nexus key file. An agent never needs it." },
  // Turning off every hook (including this firewall) via a settings mention.
  { id: "disable-all-hooks", decision: "ask", label: "mentions disableAllHooks",
    re: /\bdisableAllHooks\b/,
    reason: "Caution: this command mentions disableAllHooks, which turns off every hook including this firewall." },
  // integrity-self-approve (deny) and guard-uninstall (ask) are detected in
  // inspectCommand through analyzeShellCommand, per segment: the spec regexes on
  // the segment's words with quoted phrases blanked, so the words inside a string
  // do not trip them (unless a shell runs the string: `sh -c`, `pwsh -c`, `cmd /c`
  // …, read as commands).
];

// ── File-write guard (PreToolUse on Write/Edit/NotebookEdit) ────────────────────
// An injected agent's other dangerous move is writing a backdoor or leaking a
// secret into a file it then commits. Screen the path + the content being written.

/** The `agent-instructions` label, naming the agent whose sessions the file steers. */
function instructionsLabel(agent: string): string {
  return `changes instructions every future ${agent} session will follow`;
}

/** AGENTS.md: read by Codex, and watched for Claude Code too. */
const AGENTS_MD = /(?:^|[\\/])AGENTS\.md$/i;
/** Files only Codex reads: AGENTS.override.md, anything in a `.codex` (or `$CODEX_HOME`) directory or `.agents/skills`, its system config. */
const CODEX_ONLY = /(?:^|[\\/])AGENTS\.override\.md$|(?:^|[\\/])(?:\.codex|\$\{?CODEX_HOME\}?)[\\/]|(?:^|[\\/])\.agents[\\/]skills[\\/]|^[\\/]etc[\\/]codex[\\/]/i;

/**
 * The agent a reason says a watched file steers. `agent` is the one writing it
 * or running the command (a context's `agent`: "Codex" under Codex's dialect);
 * without one the text is Claude Code's as it always was, and names Claude.
 * A file only Codex reads steers Codex whoever writes it; AGENTS.md steers the
 * agent writing it under Codex, and every other watched file (CLAUDE.md,
 * `.claude/…`, Claude Code's settings and memory) steers Claude.
 */
export function steeredBy(path: string, agent?: string): string {
  if (CODEX_ONLY.test(path)) return "Codex";
  return agent !== undefined && AGENTS_MD.test(path) ? agent : "Claude";
}

/** Codex's config files: config.toml and `<profile>.config.toml`, hooks.json, rules/*.rules in a `.codex` directory; the system layer's TOML files. */
const CODEX_CONFIG_PATH = asFileNames(
  /(?:^|\/)\.codex\/(?:(?:[^/]{1,255}\.)?config\.toml|hooks\.json|rules\/[^/]{1,255}\.rules)$|^\/etc\/codex\/(?:config|requirements|managed_config)\.toml$|(?:^|\/)OpenAI\/Codex\/(?:config|requirements)\.toml$/i);
const CODEX_CONFIG_LABEL = "changes Codex config, hooks or exec-policy rules, which run code and set the sandbox and approvals in future sessions";

const SENSITIVE_PATHS: { id: string; decision: "deny" | "ask"; label: string; re: RegExp }[] = [
  { id: "ssh-authorized-keys", decision: "deny", label: "writes to ~/.ssh/authorized_keys (SSH backdoor)", re: /\.ssh\/authorized_keys\d*\b/i },
  { id: "etc-sudoers", decision: "deny", label: "writes to the sudoers config", re: /\/etc\/sudoers\b/i },
  { id: "git-hooks", decision: "deny", label: "writes an executable git hook", re: /(?:^|\/)\.git\/hooks\/(?!.*\.sample$)/i },
  // Git config (repo or global) can run commands via fsmonitor/sshCommand/pager/hooksPath.
  { id: "git-config", decision: "ask", label: "modifies a git config (can run commands via fsmonitor/sshCommand)", re: /(?:^|\/)\.gitconfig$|(?:^|\/)\.git\/config$/i },
  // Auto-run-on-login / shell-entry surfaces.
  { id: "autostart", decision: "ask", label: "writes an autostart/desktop entry (runs on login)", re: /\/(?:autostart\/[^/]+\.desktop|Library\/LaunchAgents\/[^/]+\.plist)$/i },
  { id: "direnv", decision: "ask", label: "writes a .envrc (direnv auto-runs it on cd)", re: /(?:^|\/)\.envrc$/i },
  { id: "editor-tasks", decision: "ask", label: "writes an editor task/launch config (auto-run surface)", re: /\/\.vscode\/(?:tasks|launch|settings)\.json$/i },
  { id: "bin-path", decision: "ask", label: "writes an executable onto PATH (could shadow a real tool)", re: /^(?:\/usr(?:\/local)?\/bin|\/bin|\/sbin)\/[^/]+$/i },
  { id: "shell-rc", decision: "ask", label: "modifies a shell startup file", re: /(?:^|\/)\.(?:bashrc|zshrc|profile|bash_profile|zprofile)\b/i },
  { id: "ssh-config", decision: "ask", label: "modifies your SSH client config", re: /\.ssh\/config\b/i },
  { id: "ci-workflow", decision: "ask", label: "edits a CI workflow (supply-chain surface)", re: /\.github\/workflows\/[^/]+\.ya?ml$/i },
  { id: "npmrc", decision: "ask", label: "writes an .npmrc (registry/token surface)", re: /(?:^|\/)\.npmrc$/i },
  { id: "cron", decision: "ask", label: "writes a cron/systemd unit", re: /\/(?:etc\/cron|crontab|systemd\/system)\b/i },

  // ── Nexus instruction-file integrity (context-free static path rules, §6.6) ───
  // A write into Nexus's own trust store — fingerprints, keys or memory records.
  { id: "nexus-store", decision: "deny", label: "targets Nexus's own trust store (integrity fingerprints, keys or memory records)",
    re: /(?:^|\/)\.nexus\/(?:integrity\/|observations\/|\.sanitation-key$|\.integrity-anchor$)/i },
  // Claude Code settings / MCP config — these run code in future sessions. These and the rules below
  // compare names as the platform's file systems do (`asFileNames`): `docs/claude.md` is no CLAUDE.md on Linux.
  { id: "claude-settings", decision: "ask", label: "changes Claude Code settings, hooks or MCP servers, which run code in future sessions",
    re: asFileNames(/(?:^|\/)\.claude\/settings(?:\.local)?\.json$|(?:^|\/)\.mcp\.json$|(?:^|\/)\.claude\.json$|(?:^|\/)managed-settings(?:\.d\/[^/]+)?\.json$|(?:^|\/)managed-mcp\.json$/i) },
  // A script Claude Code hooks run on future tool calls.
  { id: "claude-hook-script", decision: "ask", label: "changes a script Claude Code hooks run on future tool calls",
    re: asFileNames(/(?:^|\/)\.claude\/hooks\//i) },
  // Codex's config (and profiles), hooks and exec-policy rules, user, project or system — they run code and
  // set the sandbox and approvals in future sessions.
  { id: "codex-config", decision: "ask", label: CODEX_CONFIG_LABEL, re: CODEX_CONFIG_PATH },
  // Instructions every future Claude (or Codex) session will follow (`FileWriteContext.agent`, `steeredBy`).
  { id: "agent-instructions", decision: "ask", label: instructionsLabel("Claude"),
    re: asFileNames(/(?:^|\/)(?:CLAUDE(?:\.local)?|AGENTS(?:\.override)?)\.md$|(?:^|\/)\.claude\/(?:rules|agents|commands|skills)\/|(?:^|\/)\.(?:codex|agents)\/skills\//i) },
];

/** The body that turns off every Claude Code hook — escalates `claude-settings`
 *  from `ask` to `deny` (the integrity layer also tests the file an edit leaves). */
export const DISABLE_ALL_HOOKS = /"disableAllHooks"\s{0,8}:\s{0,8}true/;
/** The answer to a settings write that turns off every Claude Code hook. */
export const DISABLE_ALL_HOOKS_DENY: Readonly<CommandResult> = {
  decision: "deny",
  rule: "claude-settings",
  reason: "Blocked: this write turns off every Claude Code hook, including this firewall. If you meant to, change it yourself.",
};

/**
 * A Codex config body that may turn off every Codex hook: `hooks = false` or
 * the legacy `codex_hooks = false` (a `[features]` key, dotted, or in an
 * inline table), or requirements' `allow_managed_hooks_only = true`, which
 * ignores the user's hooks. Context-free: the pre-test of `codexHooksOffIn`,
 * which places what it matches.
 */
export const CODEX_HOOKS_OFF = /(?:^|[\s{,.])["']?(?:codex_)?hooks["']?[ \t]{0,8}=[ \t]{0,8}false\b|\ballow_managed_hooks_only["']?[ \t]{0,8}=[ \t]{0,8}true\b/;

/** A key part as a plain line writes it: bare, or a basic or literal string without escapes. */
const KEY_PART = String.raw`(?:[A-Za-z0-9_-]+|"[^"\\\r\n]*"|'[^'\r\n]*')`;
const DOTTED_KEY = String.raw`${KEY_PART}(?:[ \t]*\.[ \t]*${KEY_PART})*`;
/** A table header on a line of its own: `[a.b]`, `[[a.b]]`. */
const HEADER_LINE = new RegExp(String.raw`^\[\[?[ \t]*(${DOTTED_KEY})[ \t]*\]\]?$`);
/** A key set to a boolean on a line of its own: `a.b = false`. */
const BOOLEAN_LINE = new RegExp(String.raw`^(${DOTTED_KEY})[ \t]*=[ \t]*(true|false)$`);
const KEY_PARTS = new RegExp(KEY_PART, "g");
const keyParts = (dotted: string) => Array.from(dotted.matchAll(KEY_PARTS), ([part]) => (part[0] === '"' || part[0] === "'" ? part.slice(1, -1) : part));

/**
 * Does a Codex config's text (a whole file, or an edit's new text) turn off
 * every Codex hook? The coarse write-time check of the static rule, which
 * agrees with the install's reading of a real config (hooks-switch.ts
 * `hooksOffSwitches`, given the booleans the text sets): `codex_hooks = false`
 * with `hooks = true` after it, `hooks = false` in a profile's or an MCP
 * server's table, and `allow_managed_hooks_only` outside requirements
 * (`managed`) leave the hooks on. Each line is read up to its first `#`
 * outside a quoted string, so a note that mentions `hooks = false` is not the
 * switch; a table header and a key set to a boolean place the switch, and a
 * top-level one may sit under `[features]` in the file an edit lands in. Where
 * it cannot tell, it errs toward the deny: a switch it cannot place (an inline
 * table, a header it cannot read), and any text with a multi-line string,
 * whose lines would read as keys. Linear: the whole text is tested first, so
 * text without the pattern costs one scan.
 */
export function codexHooksOffIn(text: string, where: { managed?: boolean } = {}): boolean {
  if (!CODEX_HOOKS_OFF.test(text)) return false;
  const placed = !text.includes('"""') && !text.includes("'''");
  const sets: ConfigBoolean<null>[] = [];
  /** The table the lines are in: [] before any header, null after one this check cannot read. */
  let table: string[] | null = [];
  for (let start = 0; start <= text.length; ) {
    const nl = text.indexOf("\n", start);
    const end = nl < 0 ? text.length : nl;
    const code = text.slice(start, codeEnd(text, start, end)).trim();
    start = end + 1;
    if (!placed) {
      if (CODEX_HOOKS_OFF.test(code)) return true;
      continue;
    }
    const header = HEADER_LINE.exec(code);
    const set = header ? null : BOOLEAN_LINE.exec(code);
    if (header) table = keyParts(header[1]);
    else if (code.startsWith("[")) table = null;
    else if (set && table) sets.push({ path: [...table, ...keyParts(set[1])], value: set[2] === "true", at: null });
    else if (CODEX_HOOKS_OFF.test(code)) return true;
  }
  return hooksOffSwitches(sets, { fragment: true, managed: where.managed }).length > 0;
}

/** Where the code of the line `text[start, end)` ends: at its first `#` outside a basic or literal string, else `end`. */
function codeEnd(text: string, start: number, end: number): number {
  let quote = 0;
  for (let i = start; i < end; i++) {
    const c = text.charCodeAt(i);
    if (quote === 0) {
      if (c === 0x23) return i; // #
      if (c === 0x22 || c === 0x27) quote = c; // " '
    } else if (c === 0x5c && quote === 0x22) {
      i++; // an escape in a basic string
    } else if (c === quote) {
      quote = 0;
    }
  }
  return end;
}
/** The answer to a Codex config write that turns off every Codex hook. */
export const CODEX_HOOKS_OFF_DENY: Readonly<CommandResult> = {
  decision: "deny",
  rule: "codex-config",
  reason: "Blocked: this write turns off every Codex hook, including this firewall. If you meant to, change it yourself.",
};

/** Network-fetch binaries: the file-write escalation detection (a fetch landing in a
 *  shell rc, CI or cron file). The integrity layer's exposure tracking uses the
 *  narrower `fetchesWebContent`. */
export const NETWORK_FETCH = /\b(?:curl|wget|fetch|Invoke-WebRequest|iwr)\b/i;

/** Commands that fetch from the network (not `git fetch`, not a package that only has the word). */
const WEB_FETCHER = /\b(?:curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b/i;
const WEB_URL = /\bhttps?:\/\//i;

/**
 * Does this command read web content into the session? A real network fetcher —
 * curl, wget, Invoke-WebRequest / iwr, Invoke-RestMethod / irm — with an http(s)
 * URL. `git fetch`, installing curl or `curl --version` are not. The integrity
 * layer marks the session exposed by it (§6.7 step 2); no guard rule uses it.
 */
export function fetchesWebContent(command: string): boolean {
  return WEB_FETCHER.test(command) && WEB_URL.test(command);
}
const SECRET_IN_CONTENT = /\b(?:AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|sk-ant-[A-Za-z0-9_-]{20,}|sk-(?:proj-)?[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AIza[0-9A-Za-z\-_]{35})\b/;

/**
 * Where a file write is screened: `dataDir`, the Nexus data directory (any write
 * inside it denies), and `cwd`, the directory a relative path resolves against
 * for that check (the hook payload's). `agent`: the agent writing it, as the
 * reasons name it (`steeredBy`; absent for Claude Code, "Codex" under Codex).
 */
export type FileWriteContext = { dataDir?: string; cwd?: string; agent?: string };

export function inspectFileWrite(path: string, content: string, ctx?: FileWriteContext): CommandResult {
  const p = (path ?? "").trim();
  const body = content ?? "";
  if (!p) return { decision: "allow", reason: "No path.", rule: null };
  // Match path rules against a forward-slash form so native Windows paths
  // (`C:\Users\me\.ssh\authorized_keys`) are screened by the same `/`-written
  // SENSITIVE_PATHS rules; the original `p` is kept for the message to the user.
  const matchPath = p.replace(/\\+/g, "/");

  // ── Structural: a fetch-and-execute / reverse shell baked into ANY file the
  // agent is asked to write is persistence/RCE, regardless of the file's path
  // (Makefile $(shell curl|sh), .gitconfig fsmonitor, conftest.py urllib boot…). ──
  const contentCaps = detectContentCapabilities(body);
  const denyCap = contentCaps.find((c) => c.decision === "deny");
  if (denyCap) {
    return {
      decision: "deny",
      rule: `content:${denyCap.id}`,
      reason: `Blocked: the content being written to ${p} ${denyCap.label}. Persisting that into a file means it runs later — a classic injection backdoor. If you truly meant to, write it yourself.`,
    };
  }

  // Both are evaluated and the stricter wins: content deny, then a path deny (the
  // trust store, a settings write that disables every hook, authorized_keys …),
  // then an ask, the content reason first.
  const pathHit = pathRule(p, matchPath, body, ctx);
  if (pathHit?.result.decision === "deny") return pathHit.result;
  const askCap = contentCaps.find((c) => c.decision === "ask");
  if (askCap) {
    return {
      decision: "ask",
      rule: `content:${askCap.id}`,
      reason: `Caution: the content being written to ${p} ${askCap.label}. Confirm this is intended and not a smuggled backdoor.${pathHit ? ` This write also ${pathHit.label}.` : ""}`,
    };
  }
  if (pathHit) return pathHit.result;
  if (SECRET_IN_CONTENT.test(body)) {
    return { decision: "ask", rule: "secret-in-write", reason: `Caution: this write puts a credential-shaped value into ${p}. Don't commit secrets — use an env var or secrets manager.` };
  }
  return { decision: "allow", reason: "No sensitive path or secret in write.", rule: null };
}

/** A win32-shaped path: a drive letter or a backslash. */
const WIN_SHAPED = /^[A-Za-z]:[\\/]|\\/;

/**
 * `path` as the write lands: `.` and `..` resolved, and a relative path against
 * `cwd` when that is absolute (a relative path with no such `cwd` is left as it
 * is). Win32-shaped paths resolve by win32 rules. Nothing touches the disk.
 */
function resolvedWritePath(path: string, cwd: string | undefined): string {
  const p = WIN_SHAPED.test(path) || (cwd !== undefined && WIN_SHAPED.test(cwd)) ? win32 : posix;
  if (p.isAbsolute(path)) return p.normalize(path);
  return cwd !== undefined && p.isAbsolute(cwd) ? p.join(cwd, path) : path;
}

/** Whether `path` is `dataDir` or inside it. Slashes are normalised; a
 *  win32-shaped path (drive letter or backslash) compares case-insensitively. */
function underDataDir(path: string, dataDir: string): boolean {
  const win = WIN_SHAPED.test(dataDir) || WIN_SHAPED.test(path);
  const norm = (s: string) => {
    const t = s.replace(/[\\/]+/g, "/").replace(/\/$/, "");
    return win ? t.toLowerCase() : t;
  };
  const d = norm(dataDir), q = norm(path);
  return d !== "" && (q === d || q.startsWith(d + "/"));
}

/** The first path rule a write matches (the Nexus data directory, then
 *  SENSITIVE_PATHS), with its label. */
function pathRule(path: string, matchPath: string, body: string, ctx?: FileWriteContext): { result: CommandResult; label: string } | null {
  const store = SENSITIVE_PATHS.find((r) => r.id === "nexus-store")!;
  // A write anywhere under the Nexus data directory targets the trust store,
  // like the `.nexus/` SENSITIVE_PATHS entry: the path as it lands (`..` and a
  // relative path resolved against the payload's cwd), and as written.
  if (ctx?.dataDir && (underDataDir(resolvedWritePath(path, ctx.cwd), ctx.dataDir) || underDataDir(path, ctx.dataDir))) {
    return { label: store.label, result: { decision: "deny", rule: "nexus-store", reason: `Blocked: this write ${store.label}. If a prompt injection put it here, that's what the firewall is for.` } };
  }
  for (const rule of SENSITIVE_PATHS) {
    if (!rule.re.test(matchPath)) continue;
    // A network fetch landing in a shell-rc / CI / cron file is supply-chain RCE → deny.
    const escalate = (rule.id === "shell-rc" || rule.id === "ci-workflow" || rule.id === "cron") && NETWORK_FETCH.test(body);
    // A settings write that turns off every Claude Code hook, or a Codex config
    // write that turns off Codex's, is a hard deny with its own reason — it
    // would disable this firewall.
    if (rule.id === "claude-settings" && DISABLE_ALL_HOOKS.test(body)) return { label: rule.label, result: { ...DISABLE_ALL_HOOKS_DENY } };
    if (rule.id === "codex-config" && /\.toml$/i.test(matchPath) && codexHooksOffIn(body, { managed: isCodexRequirements(matchPath) })) {
      return { label: rule.label, result: { ...CODEX_HOOKS_OFF_DENY } };
    }
    if (rule.decision === "deny" || escalate) {
      return { label: rule.label, result: { decision: "deny", rule: rule.id, reason: `Blocked: this write ${rule.label}${escalate ? " and fetches from the network" : ""}. If a prompt injection put it here, that's what the firewall is for.` } };
    }
    const label = rule.id === "agent-instructions" ? instructionsLabel(steeredBy(matchPath, ctx?.agent)) : rule.label;
    return { label, result: { decision: "ask", rule: rule.id, reason: `Caution: this write ${label}. Confirm you intended this.` } };
  }
  return null;
}

/** §6.7 `nexus-store-write`: a shell command writes or deletes `target` (as written) in
 *  Nexus's own trust store. A long target is cut from its start, so the store part shows. */
export function storeShellWriteDeny(target: string): CommandResult {
  return {
    decision: "deny",
    rule: "nexus-store-write",
    reason: `Blocked: this command changes Nexus's own trust store (${displayPathTarget(target)}). Only Nexus, or the user from their own terminal, should change it.`,
  };
}

/** §6.7 `instruction-file-shell-write`: a shell command writes to a watched file (`target` as
 *  written; `label` its role's noun, e.g. "project instructions"; `agent` the one running it, `steeredBy`). */
export function shellWriteAsk(target: string, label: string, agent?: string): CommandResult {
  return {
    decision: "ask",
    rule: "instruction-file-shell-write",
    reason: `Caution: this command writes to ${displayTarget(target)} (${label}), which steers future ${steeredBy(target, agent)} sessions. Shell writes bypass Nexus's edit tracking; confirm you asked for this.`,
  };
}

/** A watched file written by a patch fed to `apply_patch` in a shell command (Codex's heredoc form): `target` as written, `label` its role's noun. */
export function shellPatchAsk(target: string, label: string): CommandResult {
  return {
    decision: "ask",
    rule: SHELL_PATCH_RULE,
    reason: `Caution: this command applies a patch to ${displayPathTarget(target)} (${label}), which steers future agent sessions. A patch run in the shell bypasses Nexus's edit tracking; confirm you asked for this.`,
  };
}

/** A file's decision within a patch, its reason naming the file (a patch can name many): a long path is cut from its start, so the file name shows. */
export function patchFileResult(path: string, r: CommandResult): CommandResult {
  return { ...r, reason: `Patch to ${displayPathTarget(path)}: ${r.reason}` };
}

/**
 * A patch's decision from its files' (Codex's apply_patch, as a tool or run in
 * the shell): stricter wins — the first deny, else the first ask — with the
 * file named in the reason. `overflow`: the patch names more files than were
 * read, so with nothing stricter it asks (`apply-patch-unchecked`).
 */
export function strictestPatchResult(files: readonly { path: string; result: CommandResult }[], overflow: boolean): CommandResult {
  let ask: CommandResult | null = null;
  for (const f of files) {
    if (f.result.decision === "deny") return patchFileResult(f.path, f.result);
    if (f.result.decision === "ask") ask ??= patchFileResult(f.path, f.result);
  }
  if (ask) return ask;
  if (overflow) {
    return {
      decision: "ask",
      rule: "apply-patch-unchecked",
      // the remedy is a sentence of its own: under Codex, where nothing can confirm, the closing request goes (codex/output.ts)
      reason: "Caution: this patch names more files, or is longer, than Nexus checks in one call, so the rest went unchecked. Split it into smaller patches to have every file checked. Confirm you intended it.",
    };
  }
  return { decision: "allow", reason: "No sensitive path or secret in the patch.", rule: null };
}

/**
 * The static file-write guard on each file of a patch, in order, with the text
 * it adds: each file with its decision, up to and including the first deny
 * (nothing after it can be stricter).
 */
export function inspectPatchFiles<T extends PatchWrite>(files: Iterable<T>, ctx?: FileWriteContext): (T & { result: CommandResult })[] {
  const out: (T & { result: CommandResult })[] = [];
  for (const f of files) {
    const result = inspectFileWrite(f.path, f.added, ctx);
    out.push({ ...f, result });
    if (result.decision === "deny") break;
  }
  return out;
}

/** The static file-write guard over a patch: `inspectPatchFiles`, then `strictestPatchResult`. */
export function inspectPatchWrites(files: Iterable<PatchWrite>, overflow: boolean, ctx?: FileWriteContext): CommandResult {
  return strictestPatchResult(inspectPatchFiles(files, ctx), overflow);
}

/**
 * Reveal a command's intent past trivial shell obfuscation: strip in-word
 * backslash escapes (`cur\l` → `curl`) and quotes (`c"u"rl`, `c'u'rl` → `curl`),
 * which the shell collapses but a naive regex would miss. Used as a SECOND pass —
 * a normalized-only match is reported as "ask" (not "deny"), because stripping
 * quotes can also surface a benign string (`echo "rm -rf /tmp"`), so it raises a
 * flag rather than hard-blocking. The guard is a high-signal tripwire, not a
 * sandbox: a determined attacker can obfuscate further (env indirection, base64,
 * here-docs). It raises the bar and surfaces the obvious; pair it with real
 * sandboxing / least privilege for untrusted code.
 */
export function normalizeCommand(cmd: string): string {
  return cmd
    .replace(/\\([A-Za-z0-9/.:_-])/g, "$1") // drop in-word backslash escapes
    .replace(/['"`]/g, "")                   // drop quotes that split tokens
    .replace(/\$\{IFS\}|\$IFS/g, " ")        // $IFS used as a separator
    .replace(/\s+/g, " ");
}

/**
 * Where a command runs. `agent`: who runs it, as the reasons name it: absent
 * for Claude Code (the original wording), "Codex" under Codex's dialect.
 * `codexHome`: an absolute `$CODEX_HOME` the hook's environment names, so a
 * shell write to its AGENTS.md by that path is named as Codex's (`watchedLabel`).
 */
export type CommandContext = { agent?: string; codexHome?: string };

export function inspectCommand(command: string, ctx: CommandContext = {}): CommandResult {
  const cmd = (command ?? "").trim();
  if (!cmd) return { decision: "allow", reason: "Empty command.", rule: null };

  // ── Layer 1: structural. Resolve shell obfuscation, judge by capability. ──────
  const resolved = resolveCommand(cmd);
  const caps = detectCommandCapabilities(resolved);
  const deniedCap = caps.find((c) => c.decision === "deny");
  if (deniedCap) {
    return {
      decision: "deny",
      rule: deniedCap.id,
      reason: `Blocked: this command ${deniedCap.label}. The firewall resolved it past any obfuscation and judged it by what it does, not how it's spelled. If a prompt injection put it here, that's exactly what this is for — run it yourself if you truly intended it.`,
    };
  }

  // ── Shell writes to watched files / the Nexus store (context-free, §6.7). ─────
  // A write or delete inside the trust store denies; a write to a watched
  // instruction/config file asks. A store deny ranks with the capability denies.
  // One pass also finds the agent running the Nexus CLI.
  const { write: shell, cli, patches, patchOverflow } = analyzeShellCommand(cmd);
  if (shell.decision === "deny") return storeShellWriteDeny(shell.target!);
  // A patch fed to `apply_patch` (Codex): the static file-write guard on each file and the text it adds.
  const patched = patches.length || patchOverflow ? inspectPatchWrites(patches, patchOverflow, ctx.agent !== undefined ? { agent: ctx.agent } : undefined) : null;
  if (patched?.decision === "deny") return patched;

  // The agent approving its own instruction-file changes / disabling integrity.
  if (cli?.decision === "deny") {
    return {
      decision: "deny",
      rule: cli.rule,
      reason: `Blocked: only the user can approve instruction-file changes or turn the check off, by running this in their own terminal outside ${ctx.agent ?? "Claude Code"}.`,
    };
  }

  // ── Layer 2: high-confidence regex set, on the raw command. ───────────────────
  let asked: CmdRule | null = null;
  for (const rule of RULES) {
    if (rule.re.test(cmd)) {
      if (rule.decision === "deny") {
        return {
          decision: "deny",
          rule: rule.id,
          reason: rule.reason ?? `Blocked: this command ${rule.label}. If a prompt injection put it here, that's exactly what the agent firewall is for. Run it yourself if you truly intended it.`,
        };
      }
      asked ??= rule;
    }
  }

  // Second pass: catch obfuscation the shell would undo. Report as "ask" to avoid
  // false-denying a benign quoted string that merely contains the pattern.
  const norm = normalizeCommand(cmd);
  if (norm !== cmd) {
    for (const rule of RULES) {
      if (rule.decision === "deny" && rule.re.test(norm)) {
        return { decision: "ask", rule: `obfuscated:${rule.id}`, reason: `Caution: once shell quoting/escapes are removed, this command ${rule.label}. That obfuscation is a red flag — confirm you intended it.` };
      }
    }
  }

  const askedCap = caps.find((c) => c.decision === "ask");
  if (shell.decision === "ask") {
    const label = watchedLabel(shell.target!, ctx.codexHome);
    if (shell.rule === SHELL_PATCH_RULE) return shellPatchAsk(shell.target!, label);
    return shellWriteAsk(shell.target!, label, label === CODEX_USER_INSTRUCTIONS ? "Codex" : ctx.agent);
  }
  if (patched?.decision === "ask") return patched;
  if (cli?.decision === "ask") {
    return { decision: "ask", rule: cli.rule, reason: "Caution: this removes every Nexus hook, including the integrity check." };
  }
  if (asked) {
    return { decision: "ask", rule: asked.id, reason: asked.reason ?? `Caution: this command ${asked.label}. Confirm you intended this.` };
  }
  if (askedCap) {
    return { decision: "ask", rule: askedCap.id, reason: `Caution: this command ${askedCap.label}. Confirm you intended this.` };
  }
  return { decision: "allow", reason: "No dangerous command pattern.", rule: null };
}
