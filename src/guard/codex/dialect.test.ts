/**
 * The one reading of `--codex` and `--agent` (dialect.ts): the agent a guard
 * command is for, with the errors every command shows, and the dialect a hook
 * answers in, which never fails: a flag that names neither agent answers in
 * Codex's dialect, valid for both.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { agentFromFlags, dialectFor, dialectFromArgs, hookDialect } from "./dialect.js";

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
  it("answer in Codex's dialect for Codex, and for a flag that names neither agent", () => {
    assert.equal(hookDialect(false, undefined), "claude");
    assert.equal(hookDialect(false, "claude"), "claude");
    assert.equal(hookDialect(true, undefined), "codex");
    assert.equal(hookDialect(false, "codx"), "codex");
    assert.equal(hookDialect(true, "claude"), "codex");
  });

  it("read a hook command's arguments the same way", () => {
    assert.equal(dialectFromArgs([]), "claude");
    assert.equal(dialectFromArgs(["--agent", "codex"]), "codex");
    assert.equal(dialectFromArgs(["--agent=CODEX"]), "codex");
    assert.equal(dialectFromArgs(["--codex"]), "codex");
    assert.equal(dialectFromArgs(["--agent", "claude"]), "claude");
    assert.equal(dialectFromArgs(["--agent", "codx"]), "codex");
    assert.equal(dialectFromArgs(["--agent"]), "codex", "a flag without its value");
    assert.equal(dialectFromArgs(["--codex", "--agent", "claude"]), "codex");
  });

  it("apply_patch is always answered in Codex's dialect", () => {
    assert.equal(dialectFor({ tool_name: "apply_patch" }, "claude"), "codex");
    assert.equal(dialectFor({ tool_name: "Bash" }, "claude"), "claude");
    assert.equal(dialectFor({ tool_name: "Bash" }, "codex"), "codex");
  });
});
