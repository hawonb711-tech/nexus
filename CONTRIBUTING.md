# Contributing to Nexus

Thanks for your interest. Nexus has two non-negotiable principles — please keep them in mind:

1. **Local-first, no model API.** Core analysis must run entirely on-device with no required cloud service. The declared direct dependencies are `@modelcontextprotocol/sdk` and `zod`; new heavy capabilities belong behind optional peers, lazy-imported, with a clean fallback. Features that intentionally fetch user-requested URLs must enforce the shared SSRF and untrusted-content boundaries before returning or persisting data.
2. **Honesty over hype.** A benchmark claim must ship with a **reproducible command**. A feature must show a **measured win** — and if it doesn't, we say so (see the "tried and rejected" section of the README). Negative results are welcome and valued.

## Getting started

```bash
git clone https://github.com/hawonb711-tech/nexus
cd nexus
npm install
npm run build      # tsc → dist/
npm test           # node --test across src/**/*.test.ts
npm run lint       # tsc --noEmit
npm run audit:core # fail on high-severity core dependency advisories
```

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
- For anything touching detection (promptguard, secrets) or ranking (memory, ml), include the before/after of the relevant `npx tsx scripts/*benchmark.ts` or `nexus eval-search` / `nexus dense-eval` numbers.

Maintainer release steps are documented in [`docs/RELEASING.md`](docs/RELEASING.md).

## Reporting issues

Security-sensitive reports must use the private [GitHub Security Advisory form](https://github.com/hawonb711-tech/nexus/security/advisories/new), not a public issue. Never paste real credentials; use obvious fake placeholders. For everything else, a failing case + expected behavior is perfect.
