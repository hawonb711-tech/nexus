# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [0.6.0] — unreleased

### Added
- **Agent firewall** (`src/guard/`, `nexus guard install`). A Claude Code
  PostToolUse hook that inspects untrusted tool output (WebFetch/WebSearch) and,
  when it carries a prompt injection, rewrites the result to a redacted,
  defanged version via the hook `updatedToolOutput` mechanism — so the model
  never reads the payload — while warning the user. Clean content passes through.
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
