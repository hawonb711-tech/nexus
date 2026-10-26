/**
 * The one reading of `--codex` and `--agent` (dialect.ts): the agent a guard
 * command is for, with the errors every command shows, and the dialect a hook
 * answers in, which never fails: under flags that name neither agent, each
 * payload is answered in the dialect of the agent that sent it.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { agentFromFlags, dialectFor, dialectFromArgs, hookDialect } from "./dialect.js";

const PAYLOADS = fileURLToPath(new URL("./__fixtures__/payloads/", import.meta.url));

describe("agentFromFlags", () => {
  it("--codex or --agent codex is Codex, --agent claude or neither Claude Code", () => {
    assert.deepEqual(agentFromFlags(false, undefined), { agent: "claude" });
    assert.deepEqual(agentFromFlags(true, undefined), { agent: "codex" });
    assert.deepEqual(agentFromFlags(false, "codex"), { agent: "codex" });
    assert.deepEqual(agentFromFlags(false, "Codex"), { agent: "codex" });
    assert.deepEqual(agentFromFlags(true, "codex"), { agent: "codex" });
    assert.deepEqual(agentFromFlags(false, "CLAUDE"), { agent: "claude" });
  });

  it("a value that names neither agent, or --agent claude with --codex, is an error", () => {
    assert.deepEqual(agentFromFlags(false, "codx"), { error: '--agent must be claude or codex (got "codx")' });
    assert.deepEqual(agentFromFlags(true, "claude"), { error: "--codex and --agent claude contradict each other" });
    assert.deepEqual(agentFromFlags(false, ""), { error: '--agent must be claude or codex (got "")' });
    assert.deepEqual(agentFromFlags(false, `\x1b[31m${"x".repeat(80)}`), { error: `--agent must be claude or codex (got "?[31m${"x".repeat(35)}")` });
  });
});

describe("hookDialect and dialectFromArgs", () => {
  it("answer in Codex's dialect for Codex; flags that name neither agent leave it to the payload", () => {
    assert.equal(hookDialect(false, undefined), "claude");
    assert.equal(hookDialect(false, "claude"), "claude");
    assert.equal(hookDialect(true, undefined), "codex");
    assert.equal(hookDialect(false, "codx"), "unknown");
    assert.equal(hookDialect(false, "claud"), "unknown");
    assert.equal(hookDialect(true, "claude"), "unknown");
  });

  it("read a hook command's arguments the same way", () => {
    assert.equal(dialectFromArgs([]), "claude");
    assert.equal(dialectFromArgs(["--agent", "codex"]), "codex");
    assert.equal(dialectFromArgs(["--agent=CODEX"]), "codex");
    assert.equal(dialectFromArgs(["--codex"]), "codex");
    assert.equal(dialectFromArgs(["--agent", "claude"]), "claude");
    assert.equal(dialectFromArgs(["--agent", "codx"]), "unknown");
    assert.equal(dialectFromArgs(["--agent"]), "unknown", "a flag without its value");
    assert.equal(dialectFromArgs(["--codex", "--agent", "claude"]), "unknown");
  });
});

describe("dialectFor", () => {
  it("apply_patch is always answered in Codex's dialect", () => {
    assert.equal(dialectFor({ tool_name: "apply_patch" }, "claude"), "codex");
    assert.equal(dialectFor({ tool_name: "apply_patch" }, "unknown"), "codex");
    assert.equal(dialectFor({ tool_name: "Bash" }, "claude"), "claude");
    assert.equal(dialectFor({ tool_name: "Bash" }, "codex"), "codex");
  });

  it("under flags that name neither agent, every payload Codex 0.164.0 sent is answered in Codex's dialect", () => {
    const payloads = readdirSync(PAYLOADS).flatMap((f) => JSON.parse(readFileSync(join(PAYLOADS, f), "utf8")) as Record<string, unknown>[]);
    assert.ok(payloads.length > 20, "the captured runs");
    assert.ok(payloads.some((p) => p.hook_event_name === "SessionStart" && p.transcript_path === null), "an --ephemeral session's");
    for (const p of payloads) {
      const name = `${String(p.hook_event_name)} ${String(p.tool_name ?? "")}`;
      assert.equal(dialectFor(p, "unknown"), "codex", name);
      // without the flag only apply_patch is told apart: Claude Code's install keeps its answers
      assert.equal(dialectFor(p, "claude"), p.tool_name === "apply_patch" ? "codex" : "claude", name);
    }
    for (const transcript of ["C:\\Users\\me\\.codex\\sessions\\2026\\10\\25\\rollout-x.jsonl", "rollout-x.jsonl"]) {
      assert.equal(dialectFor({ hook_event_name: "SessionStart", transcript_path: transcript }, "unknown"), "codex", transcript);
    }
  });

  it("under flags that name neither agent, Claude Code's payloads are answered in Claude's dialect", () => {
    const transcript = "/home/me/.claude/projects/-home-me-app/5f8e2c1a-3b4d-4e6f-8a9b-0c1d2e3f4a5b.jsonl";
    const base = { session_id: "5f8e2c1a-3b4d-4e6f-8a9b-0c1d2e3f4a5b", transcript_path: transcript, cwd: "/home/me/app", permission_mode: "default" };
    for (const p of [
      { ...base, hook_event_name: "SessionStart", source: "startup", model: "claude-sonnet" },
      { ...base, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, tool_use_id: "toolu_1" },
      { ...base, hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: "https://x.test" }, tool_response: { result: "x" }, tool_use_id: "toolu_2" },
      { ...base, hook_event_name: "PostToolUse", tool_name: "mcp__docs__read", tool_input: {}, tool_response: [{ type: "text", text: "x" }], tool_use_id: "toolu_3" },
      { ...base, hook_event_name: "Stop", stop_hook_active: false },
      { hook_event_name: "PostToolUse", tool_name: "WebFetch" },
      "not an object",
      null,
    ]) {
      assert.equal(dialectFor(p, "unknown"), "claude", JSON.stringify(p));
    }
    // a rollout-named directory is not a rollout file
    assert.equal(dialectFor({ ...base, transcript_path: "/home/me/rollout-notes/s.jsonl" }, "unknown"), "claude");
  });
});
