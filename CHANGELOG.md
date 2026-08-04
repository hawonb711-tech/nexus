# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [Unreleased]

## [0.7.3] — 2026-08-04

### Security
- Refresh the locked core dependency tree to `fast-uri` 3.1.5, Hono 4.12.34
  or newer, and `ip-address` 10.4.0, closing the newly disclosed URI host
  confusion, CORS ReDoS, and IP-address parsing trust-boundary advisories.
- Publish the audited dependency tree as `npm-shrinkwrap.json` so CLI and
  registry installs enforce the fixed transitives instead of relying on
  root-only overrides or an unpublished development lockfile.

### Changed
- Supersede the unpublished v0.7.2 npm artifact after the release audit gate
  correctly stopped publication before `npm publish`; public APIs and product
  behavior are otherwise unchanged.

## [0.7.2] — 2026-08-04

### Changed
- Attempt a version-only npm publication recovery for v0.7.1. The GitHub
  release was created, but newly published dependency advisories caused the
  release audit gate to stop the npm publication.

## [0.7.1] — 2026-07-31

### Security
- Frame every configured external PostToolUse result as untrusted data even when
  deterministic injection detection returns `allow`; high-confidence attacks
  are still quarantined and surfaced credentials are masked.
- Make `nexus reorganize` operate only on the explicitly selected vault and move
  generated folders into a recoverable `.nexus-backups` snapshot instead of
  permanently deleting data or scanning guessed legacy vault paths.
- Override vulnerable MCP SDK transitives with fixed `@hono/node-server`,
  `body-parser`, and `fast-uri` releases; the full installed tree now audits clean.
- Route web, feed, document, manual-memory, and memory-search content through a
  shared full-input trust boundary. Secrets are redacted and prompt-injection
  warnings/blocks are quarantined instead of being persisted as active memory.
- Restrict the collector to public HTTP(S) destinations, with DNS and redirect
  revalidation to block loopback, private, link-local, and metadata-service SSRF.
- Replace shell-interpolated document converter commands with argument-array
  process execution, closing malicious-filename command injection.
- Canonicalize MCP paths against explicit roots, rejecting prefix and symlink
  escapes instead of allowing the entire home directory or `/mnt/c`.

### Fixed
- Remove cross-language promptguard rule collisions, several code-review and
  config-validator false positives, and misleading test-health coverage/import
  diagnostics found by running Nexus against its own repository.
- Restore native Windows installation and normalize codebase graph paths across
  Windows, macOS, and Linux.
- Source CLI and MCP versions from `package.json`; persist MCP memory tags.
- Replace observation and graph files atomically, update only dirty observations,
  and guard multi-file saves with an ownership-aware concurrent-save lock.

### Changed
- Pin external benchmark sources to explicit revisions, validate their row counts
  and labels, and fail clearly on HTTP, timeout, schema, or source drift.
- Add a real stdio MCP integration test and an installed-tarball smoke test that
  verifies the CLI, demo, 12 public imports, and all 17 MCP tools.
- Refresh CLI positioning and add a Korean research-presentation runbook.
- Refresh the lockfile to remove known core audit findings and declare the
  directly imported `zod` dependency.
- Expand CI to Node 20/22/24 on Linux, macOS, and Windows, add package/audit
  checks and CodeQL, and migrate npm publishing from a long-lived token to OIDC.

## [0.7.0] — 2026-07-07

### Changed — the firewall is now STRUCTURAL, and measured honestly
- **Resolve-then-judge command/file guard** (`src/guard/capability.ts`). Instead
  of matching literal tokens, a command is first *resolved* symbolically —
  variable concatenation (`p=cur;q=l;$p$q`→curl), globs (`c?rl`/`c*l`→curl),
  `${HOME:0:1}`, `$(printf '\xNN')`, runtime base64 — then judged by **capability**
  (fetch-and-execute, reverse shell, secret exfiltration, env dump, destruction,
  fork bomb, untrusted package index). Secret-exfil keys on "a sensitive path AND
  any egress channel", so it no longer enumerates reader tools an attacker can
  swap forever (od/sed/awk/xxd/dig/rclone/aws-s3/syslog… all caught). File writes
  are scanned for the same capabilities, so a backdoor in *any* file (Makefile
  `$(shell curl|sh)`, `.gitconfig` fsmonitor, `postinstall` hooks, `.pth` files)
  is denied regardless of path.
- **De-obfuscate-then-intent content guard** (`src/guard/content-directives.ts`).
  Untrusted content is normalized (NFKC, zero-width strip, Cyrillic/Greek
  homoglyph fold) and checked for agent-directed *intent* — override-instructions
  (8 languages), fetch-and-run directives, credential exposure, role hijack,
  registry repoint, TLS downgrade — not literal phrases.
- **Spotlighting backstop** (`spotlightUntrusted`). Flagged content the guard
  doesn't hard-block is wrapped in explicit "untrusted data, not instructions"
  boundaries, so injections detection misses are still defanged by framing.
- **Honest measurement.** Validated by 4 fresh adversarial red-team rounds
  (~290 attacks generated to evade the guard's own logic), not a self-made test:
  **~80% of novel attacks** and **~66% of adaptive attacks** (attacker given the
  full source) caught, **0 false positives**. The residual (purely-semantic
  prose, staged multi-file, time-bombs) is the spotlighting/sandboxing boundary —
  it's a high-coverage tripwire, **not a sandbox**; pair with least privilege.
- Adversarial corpora locked as CI ratchets (62/62, 88/88, plus round-3/4
  baselines). New evals: `scripts/adaptive-benchmark.ts`,
  `scripts/adaptive-generalization.ts`. `nexus guard demo` now showcases the
  obfuscation-evasion cases the structural guard catches.
- README / launch posts / website / package description relabeled from the old
  self-made "30/30" to the red-team numbers above.

## [0.6.0] — 2026-06-21

### Added
- **Agent firewall** (`src/guard/`, `nexus guard install`) — two layers of
  on-device defense for AI coding agents:
  - **Content guard** (PostToolUse): inspects untrusted tool output
    (WebFetch/WebSearch) and, on a prompt injection, rewrites the result to a
    redacted, defanged version via the hook `updatedToolOutput` mechanism — so
    the model never reads the payload — while warning the user.
  - **Command guard** (PreToolUse): screens every `Bash` command before it runs
    and **denies** high-confidence dangerous ones (`curl | sh`, reverse shells,
    `rm -rf /`, credential exfiltration, persistence) via `permissionDecision`.
    High-confidence patterns only, so ordinary commands pass untouched.
  - **File-write guard** (PreToolUse): screens `Write`/`Edit`/`NotebookEdit`
    before they land — denies backdoor writes (`~/.ssh/authorized_keys`,
    git hooks, sudoers), supply-chain edits (a CI workflow or shell rc that
    fetches from the network), and warns on writing a credential into a file.
  - `nexus_guard` MCP tool exposes the content + command guards to any
    MCP-capable agent (Cursor, Cline, …), not just Claude Code's hooks.
  - `nexus guard demo` shows all of it blocking real attacks in ~10s.
  `install` / `status` / `uninstall` merge non-destructively and idempotently
  into `~/.claude/settings.json`; the runtime fails open (a guard bug never
  bricks the agent). This reframes Nexus as a local trust layer for AI agents.
- Hardened multilingual prompt-injection detection from an audit (9/16 → 16/16):
  fixed an English false negative ("ignore all of your previous instructions")
  and added the "forget all rules" verb family across German/Chinese/Spanish/
  French plus Arabic.

## [0.5.0] — 2026-06-21 (GitHub release; npm pending)

### Added
- **Secret scanner** (`src/secrets/`, `nexus secrets`, `nexus_secrets` MCP tool). Scans the
  working tree (including dotfiles like `.env`) and, with `--history`, git history via
  `git log -p` — surfacing secrets that were committed then deleted (still exposed in history).
  Vendor + generic credential patterns and an optional entropy heuristic; every finding is
  **redacted** (the raw value is never stored or printed), with a `fingerprint` for
  cross-surface matching. Hardened after an adversarial multi-agent review.
- **Self-learning embeddings** (`src/ml/`, `nexus train` / `nexus neighbors`). Pure-TypeScript,
  deterministic SGNS word2vec trained on your own observation corpus, plus a Hangul jamo
  subword layer for the Korean long tail. Inference is plain typed-array math; artifacts are
  plain JSON under `~/.nexus/models`.
- **Search-quality evals** (`nexus eval-search`, `nexus dense-eval`) — reproducible A/Bs for
  query expansion and dense retrieval.
- **Optional multilingual encoder** (`src/encoder/`, `@huggingface/transformers` in
  `optionalDependencies`, lazy-imported). Real cross-lingual capability, off by default.
- Tests for the memory engine, promptguard, review, secrets, and ml kernel (105 total);
  `npm test` script; `CONTRIBUTING.md`; CI workflow.

### Changed
- **Resurrected the self-evolving skills feature** (was effectively dead): fixed O(n²)
  clustering via an inverted index (result-identical, far faster), a prototype-pollution crash
  on tokens like `constructor`, and unbounded cluster seeds. Skill names are now derived from
  the insight rather than keyword lists, with a junk filter. `nexus reorganize` went from a
  15-minute timeout to ~2 minutes, producing real skills.
- README rewritten for accuracy: real, reproducible benchmark numbers (including the ones that
  aren't 100% and the experiments that were rejected); corrected tool count (16) and feature
  list.

### Removed
- Vestigial `cost` CLI command (the cost module was removed in an earlier release).

### Honest negative results (kept, documented)
- Learned-embedding query expansion improves same-session recall by only ~1.2% → **off by default**.
- A pretrained multilingual encoder *loses* to BM25 by ~1.15 pts on this identifier-heavy
  corpus → kept **optional**, not the retrieval backbone.
