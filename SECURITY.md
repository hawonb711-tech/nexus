# Security Policy

Nexus is a local-first tool: its analysis paths make no model API calls, and persistent
memory/models default to `~/.nexus` on your machine. Explicit commands write only to
their named local targets—for example, guard installation updates Claude settings and
export/sync writes to the selected vault. The optional collector performs explicit,
user-requested public HTTP(S) fetches behind SSRF and content-sanitization checks. That design removes whole classes of risk,
but the project still takes security seriously — it's built by a security researcher.

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

Out of scope:
- Vulnerabilities in the **optional** `@huggingface/transformers` dependency and its
  transitive packages (it is not installed by default; `npm audit` findings there do not
  affect the core).
- Issues requiring a pre-compromised machine or write access to `~/.nexus`.

## Supported versions

The latest published `0.x` release receives fixes. Nexus is pre-1.0; APIs may change.
