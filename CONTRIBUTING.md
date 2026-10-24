# Contributing to Nexus

Thanks for your interest. Nexus has two non-negotiable principles — please keep them in mind:

1. **Local-first, no model API.** Core analysis must run entirely on-device with no required cloud service. Nexus imports only two runtime dependencies, `@modelcontextprotocol/sdk` and `zod`. The other five entries in `dependencies` (`@hono/node-server`, `body-parser`, `fast-uri`, `hono`, `ip-address`) are security floors that force patched versions of the SDK's transitive packages — never import them. New heavy capabilities belong behind optional peers, lazy-imported, with a clean fallback. Features that intentionally fetch user-requested URLs must enforce the shared SSRF and untrusted-content boundaries before returning or persisting data.
2. **Honesty over hype.** A benchmark claim must ship with a **reproducible command**. A feature must show a **measured win** — and if it doesn't, we say so (see the "tried and rejected" section of the README). Negative results are welcome and valued.

## Getting started

```bash
git clone https://github.com/hawonb711-tech/nexus
cd nexus
npm install
npm run build      # tsc → dist/
npm test           # node --test across src/**/*.test.ts, with a temporary NEXUS_DATA
npm run lint       # tsc --noEmit
npm run audit:core # fail on high-severity core dependency advisories
```

`npm test` (`scripts/run-tests.mjs`) gives the run a temporary `NEXUS_DATA` unless you set one, and removes it afterwards, so tests never write into your real `~/.nexus`. A test that spawns Nexus (the CLI, the hook) or Claude Code should also give that process its own temporary `HOME`, `USERPROFILE`, `NEXUS_DATA` and `CLAUDE_CONFIG_DIR`, so it never reads or writes your real `~/.claude`, `~/.claude.json` or `~/.nexus`.

Node 20+ recommended (developed on Node 24). The project is ESM with `Node16` module resolution — **all relative imports need the `.js` extension** (e.g. `import { x } from "./y.js"`).

## Project layout

Each capability is a self-contained module under `src/<name>/` with `types.ts`, an `index.ts` barrel, and implementation files. Public API is re-exported from `src/index.ts`. MCP tools live in `src/mcp/server.ts`; CLI commands in `src/cli/index.ts`.

## Adding a feature

- Put new types in `src/<module>/types.ts`; barrel them in `index.ts`.
- Add a `*.test.ts` next to the code (Node's built-in test runner + `node:assert/strict`).
- If it's user-facing, wire a CLI command and/or an MCP tool, and document it in the README table.
- Run `npm run build && npm test` before opening a PR.

## Pull requests

- Keep PRs focused; one logical change per PR.
- Include tests for new behavior and a note on how you verified it.
- For anything touching detection (promptguard, guard, secrets) or ranking (memory, ml), include the before/after of the relevant `npm run benchmark:*` (all local ones: `npm run benchmark:local`) or `nexus eval-search` / `nexus dense-eval` numbers. Detection rules run on every fetched page and command, so also run `node --import tsx scripts/perf-audit.ts` when you add or change a regex. The audit exits non-zero only when an individual `rule:` or `integrity:` row is slow or super-linear; the whole-pipeline `scan()` / `inspect*()` rows legitimately take longer and are expected to be flagged for display — compare your branch against `main`. Instruction-file integrity code runs in the hook on instruction files, settings and commands, so a new regex or text scanner under `src/guard/integrity/` must pass the audit too: use bounded quantifiers (or the `lineSeq` / `oneOf` helpers in `src/guard/line-scan.ts`) and add the function to the audit's `INTEGRITY_TARGETS`.
- For changes to the hook's output, `npm run e2e:claude` checks that a real, locally installed Claude Code accepts the rewrite, and that the instruction-file integrity warning, write prompt and tripwire behave as documented (opt-in: it uses an isolated config, needs a logged-in Claude Code, and costs a few cents). If the fresh config is not authenticated (typical on Linux), set `NEXUS_E2E_CONFIG_SRC=~/.claude` (it is copied, never modified) or export `ANTHROPIC_API_KEY`.

Maintainer release steps are documented in [`docs/RELEASING.md`](docs/RELEASING.md).

## Reporting issues

Security-sensitive reports must use the private [GitHub Security Advisory form](https://github.com/hawonb711-tech/nexus/security/advisories/new), not a public issue. Never paste real credentials; use obvious fake placeholders. For everything else, a failing case + expected behavior is perfect.
