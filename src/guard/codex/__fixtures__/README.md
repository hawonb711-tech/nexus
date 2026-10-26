# Codex CLI 0.164.0 fixtures

Test data for `src/guard/codex/` (the hook answering in Codex's dialect).

- `schemas/`: the JSON Schemas Codex generates for its command hooks' input and
  output (`codex-rs/hooks/schema/generated/*.json`). `output.test.ts` validates
  every Codex-dialect answer against the output schemas, which reject any
  field they do not list.
- `apply-patch-scenarios/`: Codex's portable apply_patch conformance cases
  (`codex-rs/apply-patch/tests/fixtures/scenarios`): `input/`, `patch.txt`,
  `expected/`. `patch.test.ts` runs the parser and the simulator over them.
  Their `.gitattributes` keeps the CRLF cases byte-exact.
- `payloads/`: hook payloads captured from a real `codex exec` 0.164.0 run
  (offline, against a scripted mock of the Responses API), trimmed to the
  payload. `{{CODEX_HOME}}` and `{{CWD}}` stand for the run's temporary
  `$CODEX_HOME` and workspace; the tests fill them in. `ephemeral.json` is
  from `codex exec --ephemeral`: a session with no rollout file, whose
  payloads carry `transcript_path: null`.

`schemas/` and `apply-patch-scenarios/` are copied unmodified from
https://github.com/openai/codex at tag `rust-v0.164.0` (commit 6aaac694),
Copyright 2025 OpenAI, under the Apache License 2.0 (`LICENSE-codex`).

`trust/` holds hook trust state Codex 0.164.0 accepted: each `*-hooks.json`
with the `[hooks.state."<key>"] trusted_hash` entries written for it (computed
from Codex's source, `codex-rs/hooks/src/engine/discovery.rs`), under which the
real `codex exec` ran the hooks without `--dangerously-bypass-hook-trust`.
`trust.test.ts` pins `trustHash` and `trustKey` to them.
- `run3-*`: the research run (a SessionStart matcher and statusMessage, a
  PreToolUse timeout, defaults, a Stop hook).
- `probe-*`: additionalContextLimit 4096 and 2500 (Codex's default, left out of
  the hash), timeout 0 (read as 1), a Stop matcher (ignored), a SessionEnd
  timeout of 10 (held to 3). Every hook but the `post_tool_use:0:0` one
  (apply_patch, which that run never called) ran.
- `install-*`: what `nexus guard install --codex --trust` wrote, in the
  end-to-end run whose s1/s2 sessions ran all four Nexus hooks.
