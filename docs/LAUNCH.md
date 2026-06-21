# Launch kit

Copy-paste material for sharing Nexus. Keep the project's honesty rule: every
claim here maps to something reproducible (`nexus guard demo`, `npm test`,
`scripts/*benchmark.ts`). Don't add numbers you can't back.

> First, do the two things only you can do:
> 1. `npm publish --access public` (after `npm login`) — or add the `NPM_TOKEN`
>    secret and the release workflow publishes for you.
> 2. Share one of the posts below.

---

## One-liner

> Nexus — a local, zero-API firewall for AI coding agents. One command scans
> what your agent reads (blocks prompt injection) and what it runs (blocks
> `curl | sh`, reverse shells, secret exfiltration). Runs on your machine.

## Elevator pitch (3 sentences)

AI coding agents now read the open web, issues, and package READMEs and run
shell commands autonomously — and a poisoned page can hijack them into leaking
your secrets or running destructive commands. Nexus puts a firewall between your
agent and that risk, entirely on-device: it redacts prompt injection out of tool
output before the model reads it, and denies dangerous commands before they run.
`npm i -g @hawon/nexus && nexus guard install` — no API keys, no cloud, no cost.

## Show HN

**Title:** Show HN: Nexus – a local firewall for AI coding agents (blocks prompt injection)

**Body:**

I'm a security researcher, and the thing that worries me about today's coding
agents is indirect prompt injection: the agent fetches a web page / GitHub issue
/ package README, that content contains hidden instructions, and the agent acts
on them — leaking secrets, running `curl | sh`, etc. There wasn't a good *local*
defense, so I built one.

Nexus installs as a Claude Code hook (`nexus guard install`) and adds two layers:

- **Content guard:** scans every WebFetch/WebSearch result before the model
  reads it; if it carries an injection, it rewrites the result to a redacted
  version so the payload never reaches the model.
- **Command guard:** screens every Bash command before it runs and denies
  high-confidence dangerous ones (fetch-and-run, reverse shells, `rm -rf /`,
  credential exfiltration). High-confidence patterns only, so normal commands
  pass.

Everything runs on your machine — zero API calls, one core dependency. It's also
got secret scanning (working tree + git history), code review, and a semantic
memory that learns embeddings from your own sessions.

On honesty: the README ships the benchmarks *and the experiments I rejected*
(e.g. a multilingual encoder that lost to BM25 on this corpus). A claim here =
a reproducible command. `nexus guard demo` shows it blocking real attacks in 10
seconds; nothing is executed.

Repo: https://github.com/hawonb711-tech/nexus — MIT. Feedback welcome,
especially adversarial test cases that get past the guards.

## X / Twitter thread

1/ Your AI coding agent reads the open web and runs shell commands. A poisoned
page can hijack it into leaking secrets or running `curl | sh`. I built a local
firewall for that. 🧵

2/ `nexus guard install` adds two on-device layers to Claude Code:
• Content guard — redacts prompt injection out of fetched content before the
model reads it
• Command guard — denies dangerous commands before they run

3/ High-confidence patterns only (fetch-and-run, reverse shells, rm -rf /, SSH
key exfil) — everyday commands pass untouched. Zero API calls, runs on your
machine.

4/ It also does secret scanning (working tree + git history), code review, and a
memory that learns from your own sessions. One core dependency.

5/ Honesty rule: the README ships real numbers and the experiments I *rejected*.
`nexus guard demo` shows it blocking real attacks in 10s. MIT, feedback welcome:
https://github.com/hawonb711-tech/nexus

## Reddit (r/programming, r/LocalLLaMA, r/ClaudeAI)

**Title:** I built a local firewall for AI coding agents — blocks prompt injection in what the agent reads, and dangerous commands before they run

(Use the Show HN body; add: "Curious whether others are seeing indirect
prompt injection in practice, and what attack cases I should add to the guards.")
