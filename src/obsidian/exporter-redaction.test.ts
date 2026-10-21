import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportSession } from "./exporter.js";
import type { ObsidianConfig } from "./types.js";
import type { ParsedSession } from "../parser/types.js";

const GHP = ["ghp_", "abcdefghijklmnopqrstuvwxyz1234567890"].join("");
const AKIA = "AKIA" + "7F3K9Q2M8R4V6X1Z";
const ANTHROPIC = "sk-ant-" + "api03-abcdefghijklmnopqrstuvwxyz0123";

function config(vaultPath: string): ObsidianConfig {
  return {
    vaultPath,
    folderStructure: "flat",
    includeToolCalls: true,
    includeTimestamps: false,
    createMOC: false,
    createDailyNotes: false,
    tagPrefix: "claude/",
  };
}

const session: ParsedSession = {
  sessionId: "sess-redact",
  projectPath: "/home/u/.claude/projects/-home-u-proj",
  cwd: "~/proj",
  gitBranch: "main",
  startedAt: "2026-06-21T10:00:00.000Z",
  endedAt: "2026-06-21T10:30:00.000Z",
  messages: [
    { role: "user", content: `Use token ${GHP} to push.`, timestamp: "2026-06-21T10:00:00.000Z" },
    {
      role: "assistant",
      content: "Setting up credentials now.",
      timestamp: "2026-06-21T10:01:00.000Z",
      toolCalls: [
        { name: "Bash", input: { command: `export AWS_KEY=${AKIA}` }, result: `configured ${AKIA}` },
        { name: "Write", input: { file_path: "cfg.env", content: `ANTHROPIC_API_KEY=${ANTHROPIC}` } },
        { name: "Edit", input: { file_path: "a.ts", old_string: "x", new_string: `const k = "${GHP}";` } },
      ],
    },
  ],
  toolsUsed: ["Bash", "Write", "Edit"],
  filesModified: ["cfg.env"],
  topics: ["deploy"],
  platform: "claude-code",
};

test("#5 obsidian export masks vendor tokens across every transcript surface", () => {
  const dir = mkdtempSync(join(tmpdir(), "nexus-vault-"));
  try {
    const result = exportSession(session, config(dir));
    const file = join(dir, result.filesCreated[0]);
    const vault = readFileSync(file, "utf-8");

    // No raw secret from any surface (message text, Bash cmd + result, Write
    // content, Edit diff, session title) survives into the vault.
    assert.ok(!vault.includes(GHP), "GitHub token leaked into vault");
    assert.ok(!vault.includes(AKIA), "AWS key leaked into vault");
    assert.ok(!vault.includes(ANTHROPIC), "Anthropic key leaked into vault");

    // The surrounding transcript structure is otherwise preserved.
    assert.ok(vault.includes("## Conversation"));
    assert.ok(vault.includes("#### Tool: Bash"));
    assert.ok(vault.includes("#### Tool: Write"));
    assert.ok(vault.includes("export AWS_KEY="));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("#5 export of a secret-free session is unchanged in substance", () => {
  const clean: ParsedSession = {
    ...session,
    messages: [
      { role: "user", content: "Fix the failing build please.", timestamp: "2026-06-21T10:00:00.000Z" },
      {
        role: "assistant",
        content: "Running the build.",
        timestamp: "2026-06-21T10:01:00.000Z",
        toolCalls: [{ name: "Bash", input: { command: "npm run build" }, result: "build ok" }],
      },
    ],
  };
  const dir = mkdtempSync(join(tmpdir(), "nexus-vault-"));
  try {
    const result = exportSession(clean, config(dir));
    const vault = readFileSync(join(dir, result.filesCreated[0]), "utf-8");
    assert.ok(vault.includes("npm run build"));
    assert.ok(vault.includes("build ok"));
    assert.ok(vault.includes("Running the build."));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
