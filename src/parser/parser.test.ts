import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, basename } from "node:path";

import { parseSession } from "./parse.js";
import { parseAnySession } from "./unified.js";
import type { ParsedSession } from "./types.js";

// Build a synthetic Claude-Code-style .jsonl session and write it to a temp file.
// Returns { dir, path } — caller is responsible for rmSync(dir).
function writeFixture(lines: unknown[]): { dir: string; path: string } {
  const dir = mkdtempSync(join(tmpdir(), "nexus-parser-"));
  const path = join(dir, "sess-abc123.jsonl");
  // The parser reads the file with readFileSync + splits on "\n", so each
  // entry is one JSON object per line (NDJSON / JSONL).
  writeFileSync(
    path,
    lines.map((l) => JSON.stringify(l)).join("\n") + "\n",
    "utf-8",
  );
  return { dir, path };
}

// A representative session: one user turn, one assistant turn that performs a
// tool_use (Write) plus a follow-up tool_result, and a metadata line that must
// be ignored. The user message text repeats "kubernetes" across >=3 messages so
// topic extraction (which requires a count >= 3) produces a deterministic topic.
function sampleLines() {
  return [
    {
      type: "file-history-snapshot", // METADATA_TYPE -> must be skipped entirely
      messageId: "snap-1",
      snapshot: {},
    },
    {
      type: "user",
      timestamp: "2026-06-21T10:00:00.000Z",
      sessionId: "real-session-id",
      cwd: "/home/hawon/proj",
      gitBranch: "main",
      message: { role: "user", content: "Help me debug the kubernetes deployment please" },
    },
    {
      type: "assistant",
      timestamp: "2026-06-21T10:00:05.000Z",
      message: {
        role: "assistant",
        content: [
          { type: "text", text: "Sure, writing a config file now." },
          {
            type: "tool_use",
            id: "toolu_01",
            name: "Write",
            input: { file_path: "/home/hawon/proj/deploy.yaml", content: "kind: Deployment" },
          },
        ],
      },
    },
    {
      type: "user",
      timestamp: "2026-06-21T10:00:06.000Z",
      message: {
        role: "user",
        content: [
          {
            type: "tool_result",
            tool_use_id: "toolu_01",
            content: "File written successfully",
          },
        ],
      },
    },
    {
      type: "user",
      timestamp: "2026-06-21T10:00:10.000Z",
      message: { role: "user", content: "Now scale the kubernetes pods to three replicas" },
    },
    {
      type: "assistant",
      timestamp: "2026-06-21T10:00:15.000Z",
      message: {
        role: "assistant",
        content: [
          {
            type: "tool_use",
            id: "toolu_02",
            name: "Bash",
            input: { command: "kubectl scale --replicas=3" },
          },
        ],
      },
    },
    {
      type: "user",
      timestamp: "2026-06-21T10:00:20.000Z",
      message: { role: "user", content: "Great, verify the kubernetes rollout finished" },
    },
  ];
}

test("parseSession returns a fully-shaped ParsedSession", () => {
  const { dir, path } = writeFixture(sampleLines());
  try {
    const parsed: ParsedSession = parseSession(path);

    // sessionId is taken from the entry's sessionId field, overriding filename.
    assert.equal(parsed.sessionId, "real-session-id");
    assert.equal(parsed.platform, "claude-code");
    assert.equal(parsed.projectPath, dirname(path));
    assert.equal(parsed.cwd, "/home/hawon/proj");
    assert.equal(parsed.gitBranch, "main");

    // first/last timestamps come from first/last non-metadata entries.
    assert.equal(parsed.startedAt, "2026-06-21T10:00:00.000Z");
    assert.equal(parsed.endedAt, "2026-06-21T10:00:20.000Z");

    // Array fields are always present.
    assert.ok(Array.isArray(parsed.messages));
    assert.ok(Array.isArray(parsed.toolsUsed));
    assert.ok(Array.isArray(parsed.filesModified));
    assert.ok(Array.isArray(parsed.topics));
    assert.equal(typeof parsed.summary, "string");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("messages capture user text, assistant text, and tool calls", () => {
  const { dir, path } = writeFixture(sampleLines());
  try {
    const parsed = parseSession(path);

    // The lone tool_result-only user entry has no extractable text, so it is
    // dropped. Remaining: 3 user text msgs + 2 assistant msgs = 5.
    assert.equal(parsed.messages.length, 5);

    const firstUser = parsed.messages[0];
    assert.equal(firstUser.role, "user");
    assert.equal(firstUser.content, "Help me debug the kubernetes deployment please");
    assert.equal(firstUser.timestamp, "2026-06-21T10:00:00.000Z");

    // The first assistant message carries text and a populated toolCalls array.
    const firstAssistant = parsed.messages.find((m) => m.role === "assistant");
    assert.ok(firstAssistant);
    assert.equal(firstAssistant.content, "Sure, writing a config file now.");
    assert.ok(Array.isArray(firstAssistant.toolCalls));
    assert.equal(firstAssistant.toolCalls?.[0].name, "Write");
    assert.deepEqual(firstAssistant.toolCalls?.[0].input, {
      file_path: "/home/hawon/proj/deploy.yaml",
      content: "kind: Deployment",
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tool_result is matched onto a tool_use that shares the same content array", () => {
  // extractToolCalls only correlates tool_use/tool_result within a single
  // entry's content array, so the fixture places both in one assistant entry.
  const { dir, path } = writeFixture([
    {
      type: "assistant",
      timestamp: "2026-06-21T10:00:00.000Z",
      message: {
        role: "assistant",
        content: [
          { type: "text", text: "running grep" },
          { type: "tool_use", id: "toolu_grep", name: "Grep", input: { pattern: "todo" } },
          {
            type: "tool_result",
            tool_use_id: "toolu_grep",
            content: "3 matches found",
          },
        ],
      },
    },
  ]);
  try {
    const parsed = parseSession(path);
    const grepCall = parsed.messages
      .flatMap((m) => m.toolCalls ?? [])
      .find((c) => c.name === "Grep");
    assert.ok(grepCall);
    assert.equal(grepCall.result, "3 matches found");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("toolsUsed is sorted+deduped and filesModified pulls file_path from modifying tools", () => {
  const { dir, path } = writeFixture(sampleLines());
  try {
    const parsed = parseSession(path);
    // Bash + Write, sorted alphabetically.
    assert.deepEqual(parsed.toolsUsed, ["Bash", "Write"]);
    // Only Write/Edit/NotebookEdit contribute files; Bash does not.
    assert.deepEqual(parsed.filesModified, ["/home/hawon/proj/deploy.yaml"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("topics surface words repeated across >=3 user messages; summary reflects first line + counts", () => {
  const { dir, path } = writeFixture(sampleLines());
  try {
    const parsed = parseSession(path);
    // "kubernetes" appears in 3 distinct user messages -> qualifies as a topic.
    assert.ok(parsed.topics.includes("kubernetes"));

    const summary = parsed.summary ?? "";
    assert.ok(summary.startsWith("Help me debug the kubernetes deployment please"));
    assert.ok(summary.includes("5 messages"));
    assert.ok(summary.includes("Tools: Bash, Write"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("malformed JSON lines are skipped and parsing still succeeds", () => {
  const dir = mkdtempSync(join(tmpdir(), "nexus-parser-"));
  const path = join(dir, "broken.jsonl");
  try {
    const good = JSON.stringify({
      type: "user",
      timestamp: "2026-06-21T11:00:00.000Z",
      message: { role: "user", content: "hello world" },
    });
    // A blank line and a non-JSON line must both be tolerated.
    writeFileSync(path, `${good}\nthis is not json\n\n`, "utf-8");

    const parsed = parseSession(path);
    assert.equal(parsed.messages.length, 1);
    assert.equal(parsed.messages[0].content, "hello world");
    // No sessionId in the entry -> falls back to filename without extension.
    assert.equal(parsed.sessionId, basename(path, ".jsonl"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("parseAnySession('claude-code') delegates to parseSession", () => {
  const { dir, path } = writeFixture(sampleLines());
  try {
    const viaUnified = parseAnySession(path, "claude-code");
    assert.equal(viaUnified.platform, "claude-code");
    assert.equal(viaUnified.sessionId, "real-session-id");
    assert.deepEqual(viaUnified.toolsUsed, ["Bash", "Write"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
