# Examples

Short, runnable examples. From the repo root: `npm run build`, then
`node examples/<file>.mjs`. Each example is self-contained and makes **no
network calls**.

| File | Shows |
|------|-------|
| `prompt-injection.mjs` | Detect prompt injection in untrusted text |
| `secret-scan.mjs` | Scan a directory (and git history) for leaked credentials |
| `code-review.mjs` | Review a source string for bugs & security issues |
| `memory.mjs` | Ingest + cross-lingual semantic search over local memory |

These import from the built `dist/`. In your own project you'd instead
`import { scan } from "@hawon/nexus/promptguard"` after `npm install @hawon/nexus`.
