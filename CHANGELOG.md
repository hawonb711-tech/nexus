# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [Unreleased]

**Upgrade note:** if you installed the hook with Nexus 0.7.4 or earlier, re-run
`nexus guard install` (with the same `--project` / `--tools` you used). It
migrates the old entries in place; `nexus guard status` shows whether an
install is outdated and why.

### Security
- **The content guard's rewrites now reach the model.** The PostToolUse hook
  always emitted `updatedToolOutput: { result }`. Claude Code 2.1.121 and later
  validate a built-in tool's rewrite against that tool's output schema and fall
  back to the original output on a mismatch, so on WebFetch and WebSearch the
  untrusted-data framing, the injection quarantine and secret masking never
  reached the model — while the message shown to the user said "blocked". The
  rewrite now starts from the received `tool_response` and replaces only text
  fields: WebFetch keeps its response object with `result` rewritten; WebSearch
  keeps `query` / `durationSeconds` / `searchCount`, cleans string entries,
  titles and snippets (each snippet gets its own frame), and frames the list
  with a leading and a trailing entry; MCP output stays a string or a
  content-block array. A tool whose output shape Nexus does not know gets no
  rewrite (it would be dropped): it gets added context, plus `decision: "block"`
  with a reason on a block verdict. The user message says "blocked"/"masked"
  only when a rewrite was emitted, "flagged" otherwise. New opt-in
  `npm run e2e:claude` runs a real local Claude Code headless in an isolated
  config and checks what the model received (WebFetch allow and block,
  WebSearch, MCP).
- **Spotlight frames can't be closed from inside.** The frame used a fixed,
  public END line that fetched content could print to put text visually outside
  the data block. BEGIN/END lines now carry a per-call random nonce and the
  preamble says only that exact END line closes the block. Marker look-alikes in
  content (including homoglyph, width and zero-width variants) are rewritten
  before framing, always raise at least a warning, and are neutralized before
  anything is persisted to memory.
- The PreToolUse file guard screens every `edits[].new_string` of `MultiEdit`,
  and `nexus guard install` now hooks `MultiEdit`.
- Hook `timeout` is 30 (seconds). Earlier installs wrote `15000`, intended as
  milliseconds; Claude Code reads seconds, so a hung hook could stall the agent
  for ~4 h 10 min.
- Raise patched floors and refresh the lockfile; `npm run audit:core` was
  failing on six vulnerable packages and now reports 0 vulnerabilities:
  - `@modelcontextprotocol/sdk` ^1.31.0 — GHSA-6qxp-vccf-f47h (high)
  - `fast-uri` ^3.1.8 — GHSA-5jgf-p345-68v8, GHSA-f65p-4m7j-42xc,
    GHSA-fph4-wmhf-6fwf, GHSA-jqff-g426-hqxp, GHSA-qw65-cvwx-89v3 (high),
    GHSA-hrr3-gc8f-f4qj (moderate)
  - `hono` ^4.13.7 — GHSA-gqvv-2mrq-wpjv, GHSA-g6gw-c38x-mqfc,
    GHSA-crvj-82cr-hjcx, GHSA-hxh3-vqpv-xpqv (moderate)
  - `ip-address` ^10.7.1 — GHSA-rpw4-54j3-4h4q, GHSA-2vr4-cq9g-pvrc,
    GHSA-j6r3-76f7-8jcv, GHSA-h3mg-xc3c-68pw (moderate)
  - lockfile only: `proxy-addr` 2.0.8 — GHSA-jqcg-44mw-7w3h (critical);
    `qs` 6.16 — GHSA-x5fp-wj9c-mxmx, GHSA-4mjr-xmp4-gh2g (moderate)

### Fixed
- **Regex blow-ups on the hook's hot path.** Several promptguard rules and guard
  checks backtracked super-linearly on long or repetitive input, which the hook
  scans synchronously: `advanced-padding-injection` took 83 s on 25 KB of one
  repeated character; `inspectFileWrite` took 5 s on 6 KB and 33 s on 8 KB (one
  repository source file hung for more than 30 s); `inspectCommand` took 2 s on
  50 KB of repeated `curl `. Quantifiers are bounded, rules got cheap
  prefilters, and pipeline stages are split instead of matched with nested
  quantifiers. New `scripts/perf-audit.ts` times every rule and entry point on
  adversarial input families at 25–200 KB: every individual rule now grows
  linearly (the slowest takes ~50 ms at 200 KB). Whole-pipeline calls still take
  more than 50 ms at 200 KB, and `inspectCommand` on a pathological 200 KB
  command (repeated transforms) still grows super-linearly, to ~1.2 s.
  `src/guard/perf.test.ts` pins time budgets.
- **False positives on ordinary files and docs.** File-content capability checks
  scanned a whole file as one blob, so any two tokens anywhere counted as
  adjacent (a 3-line `process.env.PORT` + `host` server was denied as secret
  exfiltration). They now look at overlapping 512-character windows (256
  stride). `.env` no longer matches `process.env` / `.environ`; the DNS `host`
  tool matches only as a command; env-dump exfiltration needs an egress tool or
  interpreter at the head of a later pipeline stage (`env | grep NODE` and
  `printenv | sort` are allowed); two-signal content directives must co-occur
  within ~220 characters; `advanced-no-restrictions-apply` no longer fires on the
  MIT licence's "without restriction"; `advanced-markdown-exfil` word-bounds its
  keywords. Benign `node_modules` README/doc warn rate 15.1% → 3.4% with zero
  blocks (6 of 158 Markdown files, 3.8%, on the refreshed lockfile); repository source files denied by the file-write guard 13 → 6 (the six
  embed attack-pattern sources and are listed in `src/guard/benign.test.ts`).
  Two new precise detectors keep catches the narrowing would have lost (a secret
  file path inside a fetched URL, a secret env value appended to one). All local
  benchmarks are unchanged.
- **Installer could not see its own hooks.** `nexus guard install` writes
  `node "<pkg>/dist/cli/index.js" guard check`, but status, uninstall and the
  idempotency check matched the literal `nexus guard check`, so since 0.6.0
  `status` said "Installed: no", `uninstall` removed nothing and re-installing
  with `--tools` appended duplicates. Every command form any version wrote is
  now recognized; install replaces Nexus entries in place (one per event) and
  writes nothing when nothing changes; uninstall removes all of them and keeps
  the user's own hooks, even inside a shared matcher entry. Install refuses an
  empty `--tools` and a settings file whose hook lists are not arrays.
- `nexus guard status` is read-only and reports `yes (outdated)` with the
  reasons (millisecond timeout, stale or missing CLI path, duplicates, half an
  install, file tools not covered) and the exact install command that fixes
  it; it also surfaces an unreadable settings file and supports `--json`.
- **CLI switches swallowed arguments.** Any `--flag` took the next argument as
  its value, so `nexus secrets --json <dir>` and `--history <dir>` scanned the
  current directory and printed "No secrets detected" while `<dir>` held a
  token. Options are now declared: switches never consume an argument, value
  options take the next argument or `--opt=value` (a missing value is an
  error), `--` ends options, and unknown options are rejected with exit 1.
- `nexus secrets` exits 1 when it finds anything (0 when clean), so it can gate
  CI; `--max-commits` must be a positive whole number. With `--json`, stdout
  is pure JSON — progress and log lines go to stderr.
- The collector no longer wraps an already framed or quarantined excerpt in a
  second set of boundaries.

### Changed
- Public claims corrected to match the code and measurements:
  - Dependencies: `package.json` declares seven; Nexus imports two
    (`@modelcontextprotocol/sdk`, `zod`), the other five are security floors for
    the SDK's transitive packages, and a fresh install adds 96 packages (Nexus
    plus 95). The README badge and every "two direct dependencies" claim are
    fixed.
  - Memory is manual: nothing captures or recalls across sessions
    automatically (planned, not implemented); `nexus sync` exports to Obsidian
    and writes no memory. Tagline, website, CLI help and MCP descriptions
    updated; the README gains a *Memory* section.
  - promptguard is described by what produces findings (pattern and logic rules
    plus entropy/token signals); the keyword "semantic" stage fired on 0 of the
    908 cases in the adaptive, held-out, red-team and logic corpora. Memory search no longer claims trigram fuzzy
    matching, which `search()` never used.
  - The skill-extraction (51,353 observations → 67 skills) and memory-scale
    figures came from the maintainer's private corpus and are no longer listed
    as reproducible benchmarks.
  - Hook latency is stated as measured (~0.12 s per Bash check, ~0.35 s for a
    50 KB WebFetch result, ~0.75 s for 200 KB, p50) instead of "milliseconds".
  - README documents the hook's coverage, rewrite behavior, timeout, status
    output and known limitations; the library example no longer creates a
    literal `./~` directory.
  - MCP descriptions: `nexus_parse_session` defaults to `claude-code` (no
    auto-detection) and returns an overview, not messages; `nexus_scan` /
    `nexus_is_safe` run the scanner only, so they can disagree with
    `nexus_guard`.
- `npm run benchmark:guard` scores benign items with the same threshold as
  attacks and reports benign warnings and hard blocks separately (0/13 and
  0/13; attacks 30/30, 26 of them hard-blocked). The adaptive and round-2
  held-out benchmarks are labelled regression locks; the logic benchmark
  header states its 615 cases.
- CI runs weekly on `main` so new advisories surface before a release, cancels
  superseded pull-request runs, bounds every job with a timeout, and runs the
  examples on the full OS/Node matrix. Dependabot groups security updates,
  production minor/patch, development and GitHub Actions updates, and ignores
  semver-major bumps of the floor packages.
- Tests for output shapes, spotlight nonces, install round-trips, CLI
  arguments, performance budgets and benign false positives (318 tests).

## [0.7.4] — 2026-08-04

### Fixed
- Raise the MCP SDK floor to 1.30.0, whose declared
  `@hono/node-server` range accepts the 2.x security release line.
  This removes the invalid dependency edge exposed by a clean registry install
  of v0.7.3 without reverting to the vulnerable 1.x node adapter line.
- Replace the published shrinkwrap with a repository-only `package-lock.json`.
  The v0.7.3 registry install treated shrinkwrapped development entries as
  extraneous production packages; consumer-visible safe dependency floors now
  make the patched releases explicit install requirements without shipping the
  development tree.
- Make the packed-consumer smoke test reject any invalid, missing, or
  extraneous dependency in the complete installed tree, and explicitly verify
  the MCP SDK and Hono node adapter versions alongside the audited transitives.
- Run that clean consumer-install smoke test again in the release workflow
  immediately before OIDC publication.

### Changed
- Supersede v0.7.3 immediately after its successful npm publication; public
  APIs and product behavior are unchanged.

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
- The npm artifact was published successfully, then superseded by v0.7.4 after
  a clean consumer install exposed an incompatible shrinkwrapped dependency
  edge between MCP SDK 1.29.0 and `@hono/node-server` 2.0.12.

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
