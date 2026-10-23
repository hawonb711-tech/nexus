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

import { resolveCommand, detectCommandCapabilities, detectContentCapabilities } from "./capability.js";
import { lineSeq, oneOf } from "./line-scan.js";
import { analyzeShellCommand, watchedLabel, displayTarget } from "./shell-write-targets.js";

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
  // Claude Code settings / MCP config — these run code in future sessions.
  { id: "claude-settings", decision: "ask", label: "changes Claude Code settings, hooks or MCP servers, which run code in future sessions",
    re: /(?:^|\/)\.claude\/settings(?:\.local)?\.json$|(?:^|\/)\.mcp\.json$|(?:^|\/)\.claude\.json$|(?:^|\/)managed-settings(?:\.d\/[^/]+)?\.json$|(?:^|\/)managed-mcp\.json$/i },
  // A script Claude Code hooks run on future tool calls.
  { id: "claude-hook-script", decision: "ask", label: "changes a script Claude Code hooks run on future tool calls",
    re: /(?:^|\/)\.claude\/hooks\//i },
  // Instructions every future Claude session will follow.
  { id: "agent-instructions", decision: "ask", label: "changes instructions every future Claude session will follow",
    re: /(?:^|\/)(?:CLAUDE(?:\.local)?|AGENTS)\.md$|(?:^|\/)\.claude\/(?:rules|agents|commands|skills)\//i },
];

/** The body that turns off every Claude Code hook — escalates `claude-settings`
 *  from `ask` to `deny`. */
const DISABLE_ALL_HOOKS = /"disableAllHooks"\s{0,8}:\s{0,8}true/;

/** Network-fetch binaries, exported for exposure tracking by the integrity layer.
 *  This is the existing file-write escalation detection, unchanged. */
export const NETWORK_FETCH = /\b(?:curl|wget|fetch|Invoke-WebRequest|iwr)\b/i;
const SECRET_IN_CONTENT = /\b(?:AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|sk-ant-[A-Za-z0-9_-]{20,}|sk-(?:proj-)?[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AIza[0-9A-Za-z\-_]{35})\b/;

export function inspectFileWrite(path: string, content: string, ctx?: { dataDir?: string }): CommandResult {
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

/** Whether `path` is `dataDir` or inside it. Slashes are normalised; a
 *  win32-shaped path (drive letter or backslash) compares case-insensitively. */
function underDataDir(path: string, dataDir: string): boolean {
  const win = /^[A-Za-z]:[\\/]|\\/.test(dataDir) || /^[A-Za-z]:[\\/]|\\/.test(path);
  const norm = (s: string) => {
    const t = s.replace(/[\\/]+/g, "/").replace(/\/$/, "");
    return win ? t.toLowerCase() : t;
  };
  const d = norm(dataDir), q = norm(path);
  return d !== "" && (q === d || q.startsWith(d + "/"));
}

/** The first path rule a write matches (the Nexus data directory, then
 *  SENSITIVE_PATHS), with its label. */
function pathRule(path: string, matchPath: string, body: string, ctx?: { dataDir?: string }): { result: CommandResult; label: string } | null {
  const store = SENSITIVE_PATHS.find((r) => r.id === "nexus-store")!;
  // A write anywhere under the Nexus data directory targets the trust store,
  // like the `.nexus/` SENSITIVE_PATHS entry.
  if (ctx?.dataDir && underDataDir(path, ctx.dataDir)) {
    return { label: store.label, result: { decision: "deny", rule: "nexus-store", reason: `Blocked: this write ${store.label}. If a prompt injection put it here, that's what the firewall is for.` } };
  }
  for (const rule of SENSITIVE_PATHS) {
    if (!rule.re.test(matchPath)) continue;
    // A network fetch landing in a shell-rc / CI / cron file is supply-chain RCE → deny.
    const escalate = (rule.id === "shell-rc" || rule.id === "ci-workflow" || rule.id === "cron") && NETWORK_FETCH.test(body);
    // A settings write that turns off every Claude Code hook is a hard deny with
    // its own reason — it would disable this firewall.
    if (rule.id === "claude-settings" && DISABLE_ALL_HOOKS.test(body)) {
      return { label: rule.label, result: { decision: "deny", rule: rule.id, reason: "Blocked: this write turns off every Claude Code hook, including this firewall. If you meant to, change it yourself." } };
    }
    if (rule.decision === "deny" || escalate) {
      return { label: rule.label, result: { decision: "deny", rule: rule.id, reason: `Blocked: this write ${rule.label}${escalate ? " and fetches from the network" : ""}. If a prompt injection put it here, that's what the firewall is for.` } };
    }
    return { label: rule.label, result: { decision: "ask", rule: rule.id, reason: `Caution: this write ${rule.label}. Confirm you intended this.` } };
  }
  return null;
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

export function inspectCommand(command: string): CommandResult {
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
  const { write: shell, cli } = analyzeShellCommand(cmd);
  if (shell.decision === "deny") {
    return {
      decision: "deny",
      rule: shell.rule,
      reason: `Blocked: this command changes Nexus's own trust store (${displayTarget(shell.target!)}). Only Nexus, or the user from their own terminal, should change it.`,
    };
  }

  // The agent approving its own instruction-file changes / disabling integrity.
  if (cli?.decision === "deny") {
    return {
      decision: "deny",
      rule: cli.rule,
      reason: "Blocked: only the user can approve instruction-file changes or turn the check off, by running this in their own terminal outside Claude Code.",
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
    return {
      decision: "ask",
      rule: shell.rule,
      reason: `Caution: this command writes to ${displayTarget(shell.target!)} (${watchedLabel(shell.target!)}), which steers future Claude sessions. Shell writes bypass Nexus's edit tracking; confirm you asked for this.`,
    };
  }
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
