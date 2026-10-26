/**
 * SessionStart as Codex CLI 0.164.0 sends it (the payloads captured from
 * `codex exec`, __fixtures__/payloads): a transcript under
 * `$CODEX_HOME/sessions/…`, no `turn_id`, and a `source` of startup, resume,
 * clear, compact or fork. The integrity check runs on it without an error or
 * a timeout. A Codex transcript names no Claude config dir, so the context
 * falls back to CLAUDE_CONFIG_DIR or ~/.claude, as for a payload with no
 * transcript; Codex's own files are those under the transcript's CODEX_HOME
 * (codex-files.test.ts). A session with no rollout file (`codex exec
 * --ephemeral`) sends `transcript_path: null`: checked the same way. Under Codex the text names Codex's model where it means it, and
 * no agent where either could have written a file.
 *
 * Every path is a temporary tree; nothing touches the real ~/.claude, ~/.codex
 * or ~/.nexus.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { respond, type HookDeps } from "../handler.js";
import { contextFromHook } from "../integrity/context.js";
import { integrityPaths } from "../integrity/store.js";

const PAYLOADS = fileURLToPath(new URL("./__fixtures__/payloads/", import.meta.url));
const SOURCES = ["startup", "resume", "clear", "compact", "fork"];

type Tree = { root: string; home: string; codexHome: string; data: string; project: string; clock: number; deps: (env?: Record<string, string>) => HookDeps };

function tree(): Tree {
  const root = realpathSync.native(mkdtempSync(join(tmpdir(), "nexus-codex-start-")));
  const t: Tree = {
    root, home: join(root, "home"), codexHome: join(root, "codex-home"), data: join(root, "nexus-data"), project: join(root, "ws"),
    clock: Date.parse("2026-10-25T14:04:26.000Z"),
    deps: (env = { CLAUDE_CONFIG_DIR: join(root, "claude-config") }) => ({
      now: () => t.clock, dataDir: t.data, homedir: t.home, platform: process.platform, env: { CODEX_HOME: t.codexHome, ...env }, pid: 4242,
      managedDir: join(root, "managed"), nexusEntries: [],
    }),
  };
  for (const d of [t.home, join(t.codexHome, "sessions", "2026", "10", "25"), join(t.project, ".git")]) mkdirSync(d, { recursive: true });
  writeFileSync(join(t.project, "AGENTS.md"), "Be nice.\n");
  return t;
}

/** The payloads of a captured run, its {{CODEX_HOME}} and {{CWD}} filled in. */
function captured(run: string, t: Tree): Record<string, unknown>[] {
  const text = readFileSync(join(PAYLOADS, `${run}.json`), "utf8")
    .replaceAll("{{CODEX_HOME}}", t.codexHome.replaceAll("\\", "\\\\")).replaceAll("{{CWD}}", t.project.replaceAll("\\", "\\\\"));
  return JSON.parse(text) as Record<string, unknown>[];
}

/** The SessionStart payload a captured run began with. */
function capturedStart(run: string, t: Tree): Record<string, unknown> {
  const start = captured(run, t).find((p) => p.hook_event_name === "SessionStart");
  assert.ok(start, `${run} has a SessionStart payload`);
  return start;
}

/** A prompt-injection payload aimed at an instruction file, from the held-out corpus (as integrity/session-start.test.ts uses it). */
const POISON = (() => {
  const corpus = JSON.parse(readFileSync(fileURLToPath(new URL("../adaptive-corpus-heldout.json", import.meta.url)), "utf8")) as { attacks: { filePath?: string; payload: string }[] };
  const hit = corpus.attacks.find((a) => a.filePath?.endsWith("/CLAUDE.md"));
  assert.ok(hit, "held-out corpus has a CLAUDE.md payload");
  return hit.payload;
})();

const message = (output: unknown) => String((output as Record<string, unknown> | null)?.systemMessage ?? "");

describe("SessionStart with Codex's payloads", () => {
  for (const run of ["run1", "run4"]) {
    it(`${run}: the check runs, creates the store and reports changes, for every source`, async () => {
      const t = tree();
      try {
        const start = capturedStart(run, t);
        assert.equal(start.source, "startup");
        assert.match(String(start.transcript_path), /[\\/]sessions[\\/]2026[\\/]10[\\/]25[\\/]rollout-.*\.jsonl$/);
        // A Codex transcript names no Claude config dir: CLAUDE_CONFIG_DIR, else ~/.claude
        const ctxDeps = { platform: process.platform, homedir: t.home, dataDir: t.data };
        assert.equal(contextFromHook(start, { ...ctxDeps, env: { CLAUDE_CONFIG_DIR: join(t.root, "claude-config") } })?.configDirSource, "env");
        assert.equal(contextFromHook(start, { ...ctxDeps, env: {} })?.configDir, join(t.home, ".claude"));

        const first = await respond(start, t.deps(), { dialect: "codex" });
        assert.match(message(first.output), /^🛡️ Nexus now keeps a fingerprint/);
        assert.ok(existsSync(integrityPaths(t.data).key));
        for (const source of SOURCES) {
          t.clock += 60_000;
          const answer = await respond({ ...start, source, session_id: `${String(start.session_id)}-${source}` }, t.deps({}), { dialect: "codex" });
          assert.equal(answer.output, null, `${source}: nothing changed, nothing to say`);
        }
        writeFileSync(join(t.project, "AGENTS.md"), "Be nice.\nAlso lint.\n");
        t.clock += 60_000;
        const changed = await respond({ ...start, source: "fork", session_id: `${String(start.session_id)}-changed` }, t.deps(), { dialect: "codex" });
        assert.match(message(changed.output), /AGENTS\.md \(\+1 line\)/);
        assert.doesNotMatch(message(changed.output), /internal error|did not finish/);
      } finally {
        rmSync(t.root, { recursive: true, force: true });
      }
    });
  }
});

describe("SessionStart under Codex: a change waiting for review", () => {
  it("says commands that use its new hosts or commands are blocked until then (Codex hooks cannot ask)", async () => {
    const t = tree();
    try {
      const start = capturedStart("run1", t);
      await respond(start, t.deps(), { dialect: "codex" });
      writeFileSync(join(t.project, ".mcp.json"), JSON.stringify({ mcpServers: { helper: { command: "npx", args: ["-y", "helper-mcp"] } } }, null, 2));
      t.clock += 60_000;
      const held = message((await respond({ ...start, session_id: `${String(start.session_id)}-2` }, t.deps(), { dialect: "codex" })).output);
      assert.match(held, /^🛡️ Nexus: Waiting for your review: \.mcp\.json \(new MCP server helper: npx -y helper-mcp\)\. /);
      // pointed to the CLI's Codex view, which shows Codex's user-level files with the project's
      assert.match(held, /keep it: nexus guard integrity accept --agent codex \(in your own terminal\)\. /);
      assert.match(held, /Until then, commands that use new hosts, URLs or commands from these lines are blocked\. Review: nexus guard integrity diff --agent codex$/);
    } finally {
      rmSync(t.root, { recursive: true, force: true });
    }
  });
});

describe("SessionStart of an ephemeral Codex session (transcript_path: null)", () => {
  it("is checked as a payload with no transcript: the store is created, the session's patches are gated, a tampered AGENTS.md is reported", async () => {
    const t = tree();
    try {
      const [start, pre] = captured("ephemeral", t);
      assert.equal(start.hook_event_name, "SessionStart");
      assert.equal(start.transcript_path, null);
      const ctxDeps = { platform: process.platform, homedir: t.home, dataDir: t.data };
      assert.equal(contextFromHook(start, { ...ctxDeps, env: { CLAUDE_CONFIG_DIR: join(t.root, "claude-config") } })?.configDirSource, "env");

      const first = await respond(start, t.deps(), { dialect: "codex" });
      assert.match(message(first.output), /^🛡️ Nexus now keeps a fingerprint of the files that steer coding agents \(AGENTS\.md, config\.toml, hooks\.json, exec-policy rules, skills, memories, and each project's CLAUDE\.md and \.claude files\)/);
      assert.ok(existsSync(integrityPaths(t.data).key));
      // the same session's apply_patch (also transcript_path: null) gets the integrity layer's answer
      assert.equal(pre.tool_name, "apply_patch");
      const gated = (await respond(pre, t.deps(), { dialect: "codex" })).output as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
      assert.equal(gated.hookSpecificOutput?.permissionDecision, "deny");
      assert.match(String(gated.hookSpecificOutput?.permissionDecisionReason), /^🛡️ Nexus: Patch to AGENTS\.md: Caution: Codex wants to change AGENTS\.md/);

      appendFileSync(join(t.project, "AGENTS.md"), `\n${POISON}`);
      t.clock += 60_000;
      const tampered = (await respond({ ...start, session_id: `${String(start.session_id)}-2` }, t.deps(), { dialect: "codex" })).output as {
        systemMessage?: string; hookSpecificOutput?: { additionalContext?: string };
      };
      assert.match(String(tampered.systemMessage), /^🛡️ Nexus: AGENTS\.md changed outside the agents' file tools and the added text looks like a prompt injection/);
      // Codex hooks cannot ask: the tripwire that follows answers with a deny, and the text says so
      assert.match(String(tampered.systemMessage), /\. Codex was told not to follow it, and commands that reuse its URLs or commands will be blocked\. /);
      assert.match(String(tampered.hookSpecificOutput?.additionalContext), /\[1\] AGENTS\.md \(project instructions, loaded at launch; changed outside the agents' file tools\) - /);
      assert.doesNotMatch(`${tampered.systemMessage}\n${tampered.hookSpecificOutput?.additionalContext}`, /\bClaude\b(?!\.md| Code)/, "under Codex no text names Claude as the agent");
    } finally {
      rmSync(t.root, { recursive: true, force: true });
    }
  });
});
