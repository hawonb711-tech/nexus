# Security Policy

Nexus is a local-first tool: its analysis paths make no model API calls, and persistent
memory/models default to `~/.nexus` on your machine. Explicit commands write only to
their named local targets—for example, guard installation updates Claude Code's settings
or Codex's `hooks.json` and `config.toml` (only the trust entries of Nexus's own hooks:
added with `--trust`, removed on re-install and uninstall) and export/sync writes to
the selected vault. The optional collector performs explicit,
user-requested public HTTP(S) fetches behind SSRF and content-sanitization checks. That design removes whole classes of risk,
but the project still takes security seriously — it's built by a security researcher.

## Threat model

Nexus assumes an attacker may control text returned by a web page, search result,
issue, feed, document, or older memory entry. It also assumes that a compromised
or manipulated agent may propose a dangerous shell command or file write.

The default Claude Code hook places two boundaries around that path, plus a check
on the files that steer every future session (*Instruction files*, below):

- Every configured external PostToolUse result (WebFetch/WebSearch and every MCP
  tool — matcher `WebFetch|WebSearch|mcp__.*` — by default)
  is secret-redacted and framed as untrusted data, inside BEGIN/END lines that
  carry a per-call random nonce; boundary-marker look-alikes in the content are
  defanged. High-confidence injections are replaced before the model reads the
  payload; warning-level content remains visible inside the explicit data
  boundary. The rewrite keeps each tool's output shape: Claude Code applies it
  to built-in tools from v2.1.121 on and otherwise passes the original output
  through. For tools whose output Nexus cannot rewrite (for example `Read` or
  `Bash` added with `--tools`), it can only add a warning to the model's context,
  and secrets in that output are not masked. MCP tool output IS inspected by
  default (the `mcp__.*` matcher). Output of tools the hook does not match — by
  default anything that is not WebFetch, WebSearch, or an `mcp__*` tool (for
  example `Read` or `Bash` unless added with `--tools`) — is not inspected.
- PreToolUse resolves common command obfuscation and judges command/file-write
  capabilities before execution. High-confidence destructive, persistence,
  fetch-execute, reverse-shell, and secret-exfiltration actions are denied;
  ambiguous risk can require confirmation.

These controls do **not** make Nexus an operating-system sandbox. In particular:

- A direct process or tool invocation that bypasses the configured hook is out of
  reach. MCP clients other than Claude Code and Codex CLI must call
  `nexus_guard`; they are not intercepted automatically. Codex's hooks differ
  from Claude Code's (*Codex CLI*, below).
- Purely semantic instructions can evade deterministic detection. Always-on
  framing reduces that risk but depends on model behavior and is not enforcement.
- Command and file-write screening covers a maintained list of capabilities;
  anything not on it passes (the README's *Known limitations* lists examples
  such as `bash <(curl …)` and `openssl s_client` exfiltration).
- WebFetch output is Claude Code's summary of a page, not the raw page, and only
  the first 200,000 characters of any output are scanned (output Nexus can rewrite
  is framed in full; output from tools it cannot rewrite is not framed).
- Commands split across multiple independent tool calls, malicious local software,
  and a pre-compromised user account remain outside the guarantee.
- The hook runtime intentionally fails open on malformed hook input, an internal
  error, or a timeout (30 seconds) so a local guard failure cannot brick the
  coding agent. The exception is a write to a watched instruction or config
  file: if the integrity check fails on it, the write asks.

Warning/block content, and any chunk carrying a persistent exfil, fetch-and-run
or override directive aimed at future agent actions, are quarantined from durable
memory at ingest. Content classified as clean is redacted and may be stored, then
scanned again on retrieval unless it carries a current, valid integrity marker
(an HMAC under the per-store `.sanitation-key`, mode `0600`) proving Nexus
already sanitized it; a record with no/stale/mismatched marker is always
re-scanned. A signal-free semantic attack with none of those directive shapes can
therefore remain a residual memory-poisoning risk, and each stored observation's
`provenance` trust tier is advisory metadata, not a second sanitizer. Run agents
with least privilege (in Claude Code, inside its sandbox) and keep human approval
around sensitive credentials, production access, and irreversible operations.

### Instruction files

Claude Code loads `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, rules, settings,
hooks, MCP config, agent, command and skill files, and auto memory into every new
session, and settings and hooks run code; Codex CLI does the same with
`AGENTS.md` and its own config, hooks, rules, skills and memories. Nexus assumes
three kinds of writer may change them: an injected agent with Write/Edit/Bash/MCP
tools running as the user; another local program (an npm postinstall script,
another tool or agent); and a clone or pull. The trust root is the user's own
terminal: a TTY on stdin and stdout and none of the variables an agent sets for
the commands it runs — Claude Code's `CLAUDECODE`, `CLAUDE_CODE_SESSION_ID` and
`CLAUDE_CODE_CHILD_SESSION`, Codex's `CODEX_THREAD_ID`, `CODEX_SESSION_ID`,
`CODEX_TOOL_CALL_ID`, `CODEX_SANDBOX` and `CODEX_SANDBOX_NETWORK_DISABLED`.
Codex can give a command a PTY and type into it, so under Codex the variables
are the check; an agent CLI that sets none of them is not recognized.
`accept`, `baseline`, `config <key> <value>`, `guard install --no-integrity`,
a `guard install` whose `--tools` list drops a tool the current Nexus hooks
guard, `guard install --codex --trust`, and a Codex re-install that would change
or move hooks Codex trusts refuse without it (install records its settings
change as Nexus's own, so a narrowing an agent ran would otherwise pass the next
SessionStart in silence); `accept`, `baseline --reset` and
`config <key> <value>` then also ask for a typed confirmation (`accept`, a
random six-letter code, `yes`), while `baseline` without `--reset` and the
installs rely on that check alone.

**Stopped before the write lands** (PreToolUse `ask`, a prompt the user answers,
or `deny`). Claude Code shows the prompt in every permission mode, including
`acceptEdits` and `bypassPermissions`; under `claude -p` an `ask` is a denial.
Under Codex every `ask` is a denial. Subagents' tool calls run the same hooks
under the parent session.
- An agent Write/Edit/MultiEdit (or a file in a Codex `apply_patch`) to an
  instruction, settings, MCP, agent, command, skill or hook-script file → ask
  (an `@import` target inside the project or the Claude config dir: not
  prompted, see below). With `instructionGate: risky`
  (opt-in; the default is `always`), an instruction, settings, MCP, agent,
  command or skill file write asks only when it adds or removes code-running or
  permission config (category `e`/`a`/`r` units, a dangerous switch), carries
  a detector hit, a secret or a URL/host no reviewed file has, or the session is
  exposed or tainted; any other write is allowed, recorded, and reported once
  (N3) at the next session start. A plain-prose instruction line planted by an
  agent in a clean session is then not prompted: that is the trade this setting
  makes. The hook's reason previews the
  added text, but Claude Code 2.1.309's interactive Edit/Write confirmation
  dialog does not display it (its Bash dialog does); when the write is denied,
  the model receives the reason. A shell command that writes to one, or to a file Nexus knows by
  its path (a hook script settings run, a config or memory directory not named
  like Claude's, an `@import` target), asks too: redirects, `tee`, `sed -i`,
  `perl -i`, `cp`/`mv`/`ln`/`install`/`rsync`, `dd of=`, `truncate`, PowerShell
  content and item cmdlets, inline interpreter one-liners.
- A Write/Edit/MultiEdit that leaves `disableAllHooks: true` in a settings file
  (an Edit of the value alone included), or a write that turns Codex's hooks off
  in one of its config files → deny; a command that mentions `disableAllHooks`
  → ask.
- A write into the Nexus store (`integrity/`, `observations/`, `.sanitation-key`,
  `.integrity-anchor`) → deny. For the data directory in use (a custom
  `NEXUS_DATA` included) a file tool's path is resolved against the session's
  working directory, `..` included, before that check, and a shell write target
  or an operand of `rm`, `unlink`, `shred`, `mv`, `Remove-Item`, `del`, `rmdir` or
  `Move-Item` under its `integrity/` or `observations/`, or its
  `.integrity-anchor`, read from the working directory, `~`, `$HOME`, `$PWD` or
  `$NEXUS_DATA`, is denied as well. A command that reads a Nexus key file
  (`.integrity-key`, `.sanitation-key`, `.integrity-anchor`) → ask; one that
  reads it and sends it out → deny.
- A write to an instruction or memory file that repeats a URL, host or command
  from text a detector flagged at session start → deny; from text only held for
  review → ask.
- An auto-memory or subagent-memory save: content the content guard blocks →
  deny; a persistent exfiltration, fetch-and-run or override directive → ask;
  from a session that read flagged content → ask; with the default
  `memoryGate`, one that adds hosts, URLs or commands not seen before after the
  session read web or MCP output → ask.
- The agent running `nexus guard integrity accept`, `baseline`,
  `config <key> <value>` or `nexus guard install --no-integrity` → deny (the CLI
  also refuses them without a TTY or under Claude Code or Codex);
  `nexus guard uninstall` → ask.
- A Bash or PowerShell command that uses a new host, URL or command from text
  flagged at session start → ask, for the rest of the session.

**Detected at the next session start** (startup, resume, clear, compact):
- A change made outside the agent's file tools → NOTICE, once; HOLD if it
  happened while an agent was working (for a project's file: in that project, or
  one that had written into it). A HOLD stays until the user accepts or reverts
  it, also after the session records behind it age out, and a moved, renamed or
  copied project keeps its held and suspect files.
- New or changed code-running configuration from an unknown writer or an
  unprompted agent write → HOLD: hooks, status line and helper commands, MCP
  servers, plugins and marketplaces, unscoped allow rules,
  `additionalDirectories`, `autoMemoryDirectory`, `claudeMdExcludes`, the
  `tools`, `hooks`, `permissionMode` and `mcpServers` of agent and skill
  frontmatter, and the content of hook and skill scripts (a skill's Markdown and
  text documents are compared line by line instead); in Codex's config, MCP
  servers, hooks, `notify`, providers and base URLs, and sandbox, approval and
  permission settings.
- Added text that trips the detectors and was not approved in a Nexus prompt →
  SUSPECT: the model gets the lines inside a nonce-marked frame with "do not
  follow" instructions, the session is tainted, and output from an MCP server
  added in that change is withheld.
- A Nexus hook removed without a Nexus uninstall, or `disableAllHooks: true`,
  `defaultMode: bypassPermissions` or `env.NEXUS_DATA` added by an unknown or
  unprompted writer → SUSPECT; so are Codex's hooks turned off, a
  `dangerously_*` switch, and `approval_policy = "never"` with
  `danger-full-access`.
- A `CLAUDE.md`, `CLAUDE.local.md` or `AGENTS.md` planted in a parent directory,
  or a symlink retargeted.
- The first session in a new project (or after install) takes the files as they
  are as the baseline: a full detector scan, where a block-level hit is SUSPECT
  and any other hit a one-time NOTICE, and a one-time list of the hooks and MCP
  servers the project defines. Text that trips no detector is accepted silently.
- Agent writes from a tainted session: HOLD if unprompted, NOTICE if prompted.
- Tampering with the store by a writer without the key → TAMPER: a signature
  mismatch, an older copy restored, the store deleted while the anchor remains,
  the key replaced, or `NEXUS_DATA` redirected to an empty store.

**Not stopped or not detected:**
- **Loading.** `CLAUDE.md` is already read when SessionStart runs; Nexus cannot
  stop or change it. Its warning is placed ahead of the `CLAUDE.md` block and is
  advice to the model. Only the write gates, the tripwire and the MCP
  withholding are enforced.
- **Code-running additions made out of band have already taken effect.** A hook
  or MCP server added outside Claude has run or connected by the time it is
  reported, and a malicious SessionStart hook runs alongside Nexus's.
- **Mid-session changes** (hot-reloaded settings or hooks, on-demand files, topic
  memory) are reported only at the next session start, clear or compact.
- **Benign-sounding poison that passes the detectors:** written by the agent to
  auto memory in a clean session, or in one that read web or MCP content when it
  adds no new hosts, URLs or commands — silent, the largest residual gap; written
  out of band outside any agent activity (a delayed job such as
  `(sleep 900; …) &`, cron, launchd) — one NOTICE, then accepted; approved by the
  user in a Nexus prompt — accepted.
- **`@import` targets inside the project or the Claude config dir** are checked
  by the detectors only: an agent Write/Edit to one is not prompted, and a
  benign-looking change to one is accepted silently, unless the agent made it
  unprompted in a tainted session (HOLD) or prompted in one (NOTICE). An
  `@import` from outside both is watched like `CLAUDE.md`.
- **Shell write targets are read literally.** A shell write to a file Nexus knows
  only by its path asks only when the command names that path literally or from
  `~`, `$HOME` or `$PWD`; a target built from another variable or a
  substitution, or reached through `cd`, is left to the next session start's
  check.
- **Same-user code execution.** An agent that can run arbitrary code as the user
  can read `.integrity-key` and forge signatures, ledger records and session
  files; delete the store together with its anchor, which looks like a first
  run; remove every Nexus hook or set `disableAllHooks`, after which no
  SessionStart runs and only `nexus guard status` notices; or fake a TTY with
  `script` and unset the agent variables to run `accept`.
- Exposure is counted only from WebFetch and WebSearch results, `mcp__*` results
  other than Claude Code's own IDE server (`mcp__ide__*`), and Bash or
  PowerShell commands that run curl, wget, Invoke-WebRequest / iwr or
  Invoke-RestMethod / irm with an http(s) URL (not `git fetch`); not from `Read`
  or other output.
- A fork gets a new session id: tool-result taint does not carry over, but held
  and suspect items are armed again at the fork's SessionStart.
- WebFetch to a flagged URL is not gated (the install hooks WebFetch only after
  it runs).
- In a folder Claude Code does not trust yet, SessionStart runs only after the
  user accepts the trust dialog; if the user declines, Claude Code exits.
- Windows: no `O_NOFOLLOW`, no mode or owner checks on the key, a ctime the owner
  can set, and appends that are not guaranteed atomic.
- Not watched: nested `CLAUDE.md`, `AGENTS.md`, rules and skills below the working
  directory that Claude Code loads on demand (watched once Claude writes one
  through its file tools; agent writes to them are gated either way),
  `--add-dir` directories, plugin directories (changes to `enabledPlugins` and
  `extraKnownMarketplaces` are watched), `--settings` / `--agents`,
  server-managed settings that are not on disk, `~/.claude.json` keys outside
  its MCP servers, output styles, transcripts, Nexus memory observations
  (they carry their own HMAC markers, agent writes to them are denied, and
  `nexus guard integrity status --memory` audits them), and for Codex its
  `-c`/`--enable`/`--disable` command-line overrides, its bundled skills
  (`skills/.system`) and plugin caches.

**Candidates for v1.1**, so this does not look more complete than it is:
Claude Code's ConfigChange, InstructionsLoaded and FileChanged hooks (their
behaviour on current versions is unconfirmed, and unknown event keys may break
older Claude Code), and coverage of nested on-demand instruction files.

### Codex CLI

`nexus guard install --codex` puts the command, file-write, content and
integrity checks into Codex CLI's hooks (tested with Codex CLI 0.164.0). What
differs from Claude Code, and what Codex leaves out of reach:

- **No ask.** Codex hooks cannot ask, so every `ask` above is a `deny`, and the
  reason tells the model that the user can run the command or make the change
  themselves. Codex is therefore stricter: a legitimate edit to a watched file,
  `.envrc`, a CI workflow or similar must be made by the user (for a watched
  instruction file, `instructionGate: risky` lets an ordinary edit through).
- **No reframing.** Codex cannot rewrite a tool's output, only replace it. An
  MCP result the content guard blocks is replaced by the quarantine notice, one
  with a credential by a masked copy (at most 20,000 characters, which Codex
  may cut further to the model's tool-output budget), and a warn-level one gets
  a note. A clean result is not framed: the always-on untrusted-data boundary of
  the Claude Code hook does not exist under Codex.
- **Not seen.** Bash output (the install's PostToolUse covers MCP tools only),
  Codex's native `web_search` (it runs on OpenAI's side, out of any hook's
  reach), and input sent to an already running shell with `write_stdin` (no
  PreToolUse fires for it).
- **`apply_patch`.** Every file in a patch is screened and the strictest
  decides; a patch over 256 files or about 16 MB is denied whole. Codex applies
  a patch run through the shell (`apply_patch <<'EOF'`) with no PostToolUse, so
  it cannot be recorded; for a watched file it is denied.
- **Fails open.** A hook that times out (30 seconds), crashes or answers
  something Codex cannot parse lets the call run. Nexus's answers are checked
  against Codex's schemas and are well-formed UTF-16, but a timeout still fails
  open; a watched write that lands that way is reported at the next session
  start, after the fact.
- **Trust.** Codex runs a hook only while `config.toml` trusts it at its hash
  and position, and `codex exec` skips an untrusted or changed hook without a
  word. `--trust` writes trust only for the hooks that install just wrote, and
  runs only in the user's own terminal: trust is Codex's own check that nothing
  an agent or a package adds to hooks.json runs unseen. A re-install that would
  change hooks Codex trusts now, or move one of the user's trusted hooks, is
  gated the same way, since it would turn them off without a word. Uninstall
  is not gated: one of the user's hooks after a Nexus group moves up and loses
  its trust, and uninstall names each one it moved. Codex's "Trust all and
  continue" trusts every hook waiting for review, not only Nexus's.
- **Hooks turned off.** With `[features] hooks = false` (or the older
  `codex_hooks = false`) Codex runs no hook, and with
  `allow_managed_hooks_only = true` in managed requirements no user hook,
  Nexus's included, so no Codex session can report the change. A file-tool or
  `apply_patch` write that turns Codex's hooks off is denied (a shell write
  asks under Claude Code and is denied under Codex). `hooks = false` set
  another way in Codex's user `config.toml` is reported by
  `nexus guard status --codex` and `nexus guard integrity status`, and, once a
  Codex session has fingerprinted that file, at the next Claude Code session
  start; in a project's `.codex/config.toml`, at the next Claude Code session
  start in that project. Not detected: Codex's `--disable hooks` or
  `-c features.hooks=false`, a `--profile` run's profile file, `/etc/codex` and
  managed requirements.
- **Loading.** SessionStart runs after Codex has loaded `AGENTS.md`, so, as
  under Claude Code, Nexus warns but cannot keep a changed file out. Under
  `codex exec` the user sees no Nexus notice; the model still gets the SUSPECT
  and TAMPER warnings.
- **The human gate** relies on the `CODEX_*` variables inside Codex (see the
  trust root above); an agent that can run code as the user can unset them
  (*Same-user code execution*).
- Windows is untested for Codex: its paths and the trust keys `--trust` writes
  may not match what Codex expects there.

## Reporting a vulnerability

Please **do not** open a public issue for a security vulnerability. Instead, report it
privately via [GitHub Security Advisories](https://github.com/hawonb711-tech/nexus/security/advisories/new).

Include: affected version, a minimal reproduction, and the impact. Expect an initial
response within a few days.

**Never paste real credentials** in a report. If you need to demonstrate a secret-handling
issue, use obviously-fake placeholders — and note that `nexus secrets` redacts every finding
precisely so secrets never need to leave your machine.

## Scope

In scope:
- The injection-detection (`promptguard`) and secret-scanning (`secrets`) logic — false
  negatives that would let a real attack/secret through, or a redaction path that leaks a
  raw secret.
- Path-traversal or arbitrary-file-read in the CLI / MCP tools (paths are validated against
  an allow-list in the MCP server).
- Command injection in local parser/tool integrations.
- SSRF, redirect/DNS validation bypass, or any unexpected network call.
- Persistent-memory poisoning that bypasses the untrusted-content boundary.
- An instruction-file change that a Nexus write gate should have stopped, or that
  the next SessionStart should have reported, by the lists above.

Out of scope:
- Vulnerabilities in the **optional** `@huggingface/transformers` dependency and its
  transitive packages (it is not installed by default; `npm audit` findings there do not
  affect the core).
- Issues requiring a pre-compromised machine or write access to `~/.nexus`.

The instruction-file fingerprint is **tamper-evident** against writers that cannot
run shell code: a forged, rolled-back, deleted or redirected store is reported as
TAMPER instead of silently starting over. Against a shell-capable agent running
as the same user it is only **advisory**, since that agent can read the key (see
*Same-user code execution* above). The real boundary there is the operating
system: Claude Code's sandbox, or a separate user account.

## Supported versions

The latest published `0.x` release receives fixes. Nexus is pre-1.0; APIs may change.

Hook installs written by Nexus 0.7.4 or earlier set `"timeout": 15000`, which
Claude Code reads as seconds (~4 h 10 min), and do not screen `MultiEdit`; re-run `nexus guard install` (with the same
`--project` / `--tools`) to migrate them. `nexus guard status` reports such an
install as outdated.

Hook installs written by Nexus 0.8.0 or earlier have no SessionStart hook and no
`Write|Edit|MultiEdit` PostToolUse hook, so instruction-file integrity is not
active; `nexus guard status` reports them as outdated until `nexus guard install`
is re-run.

The default content-guard coverage widened from `WebFetch|WebSearch` to
`WebFetch|WebSearch|mcp__.*` (web plus every MCP tool's output). A stock web-only
install is migrated to the wider default by re-running `nexus guard install`; a
genuinely custom `--tools` list is preserved.
