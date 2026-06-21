# Contributing to Nexus

Thanks for your interest. Nexus has two non-negotiable principles — please keep them in mind:

1. **Local-first, zero-API.** Core code must run entirely on-device with no network calls and no required cloud service. The single core dependency is `@modelcontextprotocol/sdk`. New heavy dependencies belong in `optionalDependencies`, lazy-imported, with a clean fallback so the framework still works without them.
2. **Honesty over hype.** A benchmark claim must ship with a **reproducible command**. A feature must show a **measured win** — and if it doesn't, we say so (see the "tried and rejected" section of the README). Negative results are welcome and valued.

## Getting started

```bash
git clone https://github.com/hawonb711-tech/nexus
cd nexus
npm install
npm run build      # tsc → dist/
npm test           # node --test across src/**/*.test.ts
npm run lint       # tsc --noEmit
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

## Reporting issues

Security-sensitive reports: please open a minimal, redacted issue (never paste real credentials — `nexus secrets` exists precisely so you don't have to). For everything else, a failing case + expected behavior is perfect.
