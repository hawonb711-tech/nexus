import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { sessionDomainFromPaths } from "./memory-skill-engine.js";

describe("sessionDomainFromPaths", () => {
  it("extracts the project name from Windows and POSIX paths", () => {
    assert.equal(sessionDomainFromPaths("C:\\Users\\alice\\code\\nexus"), "nexus");
    assert.equal(sessionDomainFromPaths("/home/alice/code/nexus"), "nexus");
  });

  it("falls back to projectPath and then unknown", () => {
    assert.equal(sessionDomainFromPaths(undefined, "D:\\work\\project"), "project");
    assert.equal(sessionDomainFromPaths(undefined, undefined), "unknown");
  });
});

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extractMemorySkills } from "./memory-skill-engine.js";
import { createNexusMemory } from "../memory-engine/nexus-memory.js";
import type { ParsedSession } from "../parser/types.js";

// compat-2 regression: observations extracted from a parsed agent session are
// attributed to `source: "session"` (origin = sessionId, trust = external),
// matching the web/feed/document wiring — not the default manual/trusted.
describe("reorganize ingest provenance", () => {
  it("tags session-derived observations with source=session/external", () => {
    const now = new Date().toISOString();
    const session: ParsedSession = {
      sessionId: "sess-compat2", projectPath: "/home/user/project", cwd: "/home/user/project",
      startedAt: now, endedAt: now, toolsUsed: ["Read", "Edit"], filesModified: ["src/auth.ts"],
      topics: ["auth"], platform: "claude-code",
      messages: [
        { role: "user", content: "How do I fix the failing authentication test in the JWT module?", timestamp: now },
        {
          role: "assistant",
          content: "I will inspect and fix the token expiry handling in the auth module.",
          timestamp: now,
          toolCalls: [
            { name: "Read", input: { file_path: "src/auth.ts" } },
            { name: "Edit", input: { file_path: "src/auth.ts", old_string: "a", new_string: "b" } },
          ],
        },
      ],
    };
    const dir = mkdtempSync(join(tmpdir(), "nexus-compat2-"));
    try {
      const res = extractMemorySkills([session], dir, 3);
      assert.ok(res.observationsIngested >= 1, "expected at least one observation ingested");
      const mem = createNexusMemory(dir);
      const stored = mem.scanIndex();
      assert.ok(stored.length >= 1);
      for (const obs of stored) {
        assert.equal(obs.provenance?.source, "session");
        assert.equal(obs.provenance?.trust, "external");
        assert.equal(obs.provenance?.origin, "sess-compat2");
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
