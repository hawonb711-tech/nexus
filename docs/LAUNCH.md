# Launch kit

Copy-paste posts for sharing Nexus. Honest by rule: every claim maps to a
reproducible command (`nexus guard demo`, `npx tsx scripts/guard-benchmark.ts`,
`npm test`). The package is live: `npm i -g @hawon/nexus`.

> Highest-impact single action: post the X tweet (below) with a `nexus guard demo`
> screenshot, then cross-post Show HN + the relevant subreddit. Reply to every
> comment in the first 24h.

---

## X — single tweet (global)

```
Your AI coding agent reads the open web and runs shell commands on its own.

A poisoned page can hijack it into leaking your secrets or running `curl | sh`.

I built a local firewall for that — zero API, on your machine:

  npm i -g @hawon/nexus
  nexus guard install

github.com/hawonb711-tech/nexus
```

## X — thread (attach a `nexus guard demo` screenshot to tweet 1)

```
1/ Your AI coding agent reads the open web, GitHub issues, package READMEs — and runs shell commands. Poisoned content can hijack it into leaking secrets or running curl|sh. I built a local firewall for that. 🧵

2/ `nexus guard install` adds two on-device layers to Claude Code:
• what it READS → redacts prompt injection out of fetched content before the model sees the payload
• what it RUNS → denies curl|sh, reverse shells, rm -rf /, SSH-key exfil before they execute

3/ It also masks secrets that surface in tool output, and blocks backdoor writes (~/.ssh/authorized_keys, CI workflows). High-confidence patterns only — your normal commands pass untouched.

4/ Zero API calls. One core dependency. Runs entirely on your machine. Works in ANY MCP agent (Cursor, Cline, Continue…) via the nexus_guard tool — not just Claude Code.

5/ Honesty rule: the README ships real benchmarks *and the experiments I rejected*. `nexus guard demo` blocks real attacks in 10s, nothing executed — 30/30 on the corpus, 0 false positives.

  npm i -g @hawon/nexus

github.com/hawonb711-tech/nexus · MIT · adversarial test cases welcome 🙏
```

## X / Korean dev communities (긱뉴스, OKKY, Discord)

```
AI 코딩 에이전트가 웹·이슈·README를 읽다 숨은 명령에 납치되면 — 시크릿 유출, curl|sh 실행. 아무도 로컬에서 안 막아줬다.

그래서 만들었습니다. API 호출 0, 전부 내 머신에서. 한 줄:

  npm i -g @hawon/nexus
  nexus guard install

막히는 거 직접 보기: nexus guard demo
github.com/hawonb711-tech/nexus
```

## Show HN

**Title:** Show HN: Nexus – a local firewall for AI coding agents (blocks prompt injection)

```
I'm a security researcher, and what worries me about today's coding agents is indirect prompt injection: the agent fetches a web page / GitHub issue / package README, that content hides instructions, and the agent acts on them — leaking secrets, running curl|sh. There wasn't a good *local* defense, so I built one.

`nexus guard install` adds two on-device layers to Claude Code:
- Content guard: scans every WebFetch/WebSearch result before the model reads it; injections are rewritten to a redacted version so the payload never reaches the model. It also masks secrets that surface in tool output.
- Command guard: screens every Bash command before it runs and denies high-confidence dangerous ones (curl|sh, reverse shells, rm -rf /, credential exfil, backdoor file writes). High-confidence patterns only, so normal commands pass.

Everything runs on your machine — zero API calls, one core dependency. Also exposed as the nexus_guard MCP tool, so it works in any MCP agent (Cursor, Cline…), not just Claude Code.

On honesty: the README ships the benchmarks AND the experiments I rejected (e.g. a multilingual encoder that lost to BM25 on this corpus). A claim = a reproducible command. `nexus guard demo` blocks real attacks in 10s; nothing is executed. 30/30 on the benchmark corpus, 0 false positives.

npm i -g @hawon/nexus
Repo: https://github.com/hawonb711-tech/nexus — MIT. Feedback welcome, especially attack cases that slip past the guards.
```

## Reddit (r/LocalLLaMA, r/ClaudeAI, r/programming)

**Title:** I built a local firewall for AI coding agents — blocks prompt injection in what the agent reads, and dangerous commands before they run

Body: use the Show HN text, then add: "Curious whether others are hitting indirect
prompt injection in practice, and what attack cases I should add. MIT — PRs/issues welcome."

## First-comment FAQ (paste as a reply to seed the discussion)

- **Isn't this just regex?** The command/injection patterns are high-confidence and
  normalized against shell obfuscation (`cur\l`, `c"u"rl`), but yes — it's a
  high-signal tripwire, not a sandbox. Pair it with least privilege. The README says so.
- **Does it slow the agent down?** It's local typed-array/regex work, milliseconds.
- **Other agents?** Claude Code via hooks today; any MCP agent via the `nexus_guard` tool.
- **Telemetry?** None. Zero network calls in the core. Data stays in `~/.nexus`.
