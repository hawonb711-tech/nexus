/**
 * Dangerous-command inspection for the PreToolUse side of the agent firewall.
 *
 * A prompt-injected agent's most dangerous capability is running shell commands.
 * This screens a command the agent is ABOUT to execute and decides deny / ask /
 * allow. Patterns are deliberately HIGH-confidence (remote-code execution,
 * reverse shells, disk/destructive ops, credential exfiltration, persistence) so
 * that everyday commands pass untouched — a guard that cries wolf gets disabled.
 */

export type CommandDecision = "deny" | "ask" | "allow";

export type CommandResult = {
  decision: CommandDecision;
  /** Human reason (shown to the agent / user). */
  reason: string;
  /** Rule id that fired, if any. */
  rule: string | null;
};

type CmdRule = { id: string; decision: "deny" | "ask"; label: string; re: RegExp };

const RULES: CmdRule[] = [
  // ── Remote code execution: fetch-and-run ────────────────────────────────────
  { id: "rce-pipe-shell", decision: "deny", label: "pipes a download straight into a shell",
    re: /\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i },
  { id: "rce-eval-fetch", decision: "deny", label: "evaluates the output of a network fetch",
    re: /(?:eval|exec)\s*[("'`$]*\s*(?:curl|wget)\b|\$\(\s*(?:curl|wget)\b/i },
  { id: "rce-base64-shell", decision: "deny", label: "decodes a blob and pipes it into a shell",
    re: /base64\s+(?:-d|--decode|-D)\b[^\n|]*\|\s*(?:ba|z)?sh\b/i },

  // ── Reverse shells ──────────────────────────────────────────────────────────
  { id: "revshell-devtcp", decision: "deny", label: "opens a reverse shell via /dev/tcp",
    re: /(?:ba|z)?sh\s+-i\b[^\n]*>&?\s*\/dev\/tcp\/|\/dev\/tcp\/\d/i },
  { id: "revshell-nc", decision: "deny", label: "spawns a reverse shell with netcat",
    re: /\bn(?:c|cat)\b[^\n]*\s-[a-z]*e\b[^\n]*\b(?:ba|z)?sh\b|mkfifo\b[^\n]*\bn(?:c|cat)\b/i },
  { id: "revshell-interp", decision: "deny", label: "spawns a reverse shell via an interpreter socket",
    re: /(?:python\d?|perl|ruby|php)\b[^\n]*socket\b[^\n]*(?:connect|SOCK_STREAM)[^\n]*(?:exec|spawn|\/bin\/(?:ba)?sh)/i },

  // ── Destructive / disk ──────────────────────────────────────────────────────
  { id: "destroy-rm-root", decision: "deny", label: "recursively deletes a root/home path",
    re: /\brm\s+(?:-\w+\s+)*-?\w*[rf]\w*[rf]?\w*\s+(?:--no-preserve-root\s+)?(?:\/(?:\s|$|\*)|~(?:\/\s*)?(?:\s|$)|\$HOME\b|\/\*)/i },
  { id: "destroy-forkbomb", decision: "deny", label: "is a fork bomb",
    re: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/ },
  { id: "destroy-dd-disk", decision: "deny", label: "writes raw data over a disk device",
    re: /\bdd\b[^\n]*\bof=\/dev\/(?:sd|nvme|hd|disk|vd)|\bmkfs(?:\.\w+)?\s+\/dev\//i },
  { id: "destroy-overwrite-dev", decision: "deny", label: "redirects into a raw disk device",
    re: />\s*\/dev\/(?:sd|nvme|hd)[a-z]/i },

  // ── Credential / data exfiltration ──────────────────────────────────────────
  { id: "exfil-secret-file", decision: "deny", label: "ships a secret file to the network",
    re: /(?:cat|head|tail|cp|tar|base64)\b[^\n|]*(?:\.env\b|id_rsa\b|id_ed25519\b|\.aws\/credentials|\.ssh\/|\.npmrc\b|\.netrc\b|\.kube\/config|credentials\.json)[^\n]*\|\s*(?:curl|wget|n(?:c|cat))\b/i },
  { id: "exfil-env-network", decision: "deny", label: "ships environment variables to the network",
    re: /\b(?:env|printenv|set)\b\s*\|\s*(?:curl|wget|n(?:c|cat))\b/i },
  { id: "exfil-secret-var", decision: "deny", label: "posts a secret-looking variable to a URL",
    re: /(?:curl|wget)\b[^\n]*(?:-d|--data\S*|-F|--form|-T|--upload)\b[^\n]*\$\{?(?:[A-Z0-9_]*(?:AWS|GITHUB|GH|OPENAI|ANTHROPIC|NPM|SECRET|TOKEN|API[_-]?KEY|PASSWORD|PRIVATE)[A-Z0-9_]*)\}?/i },

  // ── Persistence / backdoor ──────────────────────────────────────────────────
  { id: "persist-authorized-keys", decision: "deny", label: "writes an SSH authorized_keys entry",
    re: />>?\s*(?:~|\$HOME|\/root|\/home\/[^\s/]+)?\/?\.ssh\/authorized_keys/i },
  { id: "persist-cron-fetch", decision: "ask", label: "installs a cron job that fetches from the network",
    re: /\bcrontab\b[^\n]*(?:curl|wget)|(?:curl|wget)[^\n]*\|\s*crontab\b/i },
  { id: "persist-shellrc-fetch", decision: "ask", label: "appends a network fetch to a shell rc file",
    re: />>\s*~?\/?\.(?:bashrc|zshrc|profile|bash_profile)\b[^\n]*&&[^\n]*(?:curl|wget)|(?:curl|wget)[^\n]*>>\s*~?\/?\.(?:bashrc|zshrc|profile)/i },

  // ── Tampering / anti-forensics / weakening ──────────────────────────────────
  { id: "weaken-chmod-777", decision: "ask", label: "makes a path world-writable (chmod 777)",
    re: /\bchmod\s+(?:-R\s+)?0?777\b/i },
  { id: "weaken-disable-history", decision: "ask", label: "disables or wipes shell history",
    re: /\bhistory\s+-c\b|\brm\b[^\n]*\.bash_history|\bunset\s+HISTFILE\b|\bexport\s+HISTSIZE=0\b/i },
  { id: "weaken-disable-security", decision: "ask", label: "disables a host security control",
    re: /\bsetenforce\s+0\b|\bsystemctl\s+(?:stop|disable)\s+(?:firewalld|ufw|apparmor)\b|\bufw\s+disable\b/i },
];

export function inspectCommand(command: string): CommandResult {
  const cmd = (command ?? "").trim();
  if (!cmd) return { decision: "allow", reason: "Empty command.", rule: null };

  let asked: CmdRule | null = null;
  for (const rule of RULES) {
    if (rule.re.test(cmd)) {
      if (rule.decision === "deny") {
        return {
          decision: "deny",
          rule: rule.id,
          reason: `Blocked: this command ${rule.label}. If a prompt injection put it here, that's exactly what the agent firewall is for. Run it yourself if you truly intended it.`,
        };
      }
      asked ??= rule; // remember the first "ask" but keep scanning for a "deny"
    }
  }
  if (asked) {
    return { decision: "ask", rule: asked.id, reason: `Caution: this command ${asked.label}. Confirm you intended this.` };
  }
  return { decision: "allow", reason: "No dangerous command pattern.", rule: null };
}
