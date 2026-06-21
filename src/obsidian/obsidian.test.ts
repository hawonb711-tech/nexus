import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportSession } from "./exporter.js";
import { updateMOC } from "./moc.js";
import { appendToDailyNote } from "./daily-note.js";
import type { ObsidianConfig } from "./types.js";
import type { ParsedSession } from "../parser/types.js";

function makeSession(overrides: Partial<ParsedSession> = {}): ParsedSession {
  return {
    sessionId: "sess-123",
    projectPath: "/home/hawon/.claude/projects/-home-hawon-myproject",
    cwd: "~/myproject",
    gitBranch: "main",
    startedAt: "2026-06-21T10:00:00.000Z",
    endedAt: "2026-06-21T10:30:00.000Z",
    messages: [
      {
        role: "user",
        content: "Fix the failing build",
        timestamp: "2026-06-21T10:00:00.000Z",
      },
      {
        role: "assistant",
        content: "Sure, running the build now.",
        timestamp: "2026-06-21T10:01:00.000Z",
        toolCalls: [
          {
            name: "Bash",
            input: { command: "npm run build" },
            result: "build ok",
          },
        ],
      },
    ],
    toolsUsed: ["Bash"],
    filesModified: ["src/index.ts"],
    topics: ["build", "ci"],
    platform: "claude-code",
    ...overrides,
  };
}

function baseConfig(vaultPath: string, overrides: Partial<ObsidianConfig> = {}): ObsidianConfig {
  return {
    vaultPath,
    folderStructure: "flat",
    includeToolCalls: true,
    includeTimestamps: false,
    createMOC: false,
    createDailyNotes: false,
    tagPrefix: "claude/",
    ...overrides,
  };
}

test("exportSession returns an ExportResult with a created file and writes valid frontmatter + headers", () => {
  const vault = mkdtempSync(join(tmpdir(), "nexus-obsidian-"));
  try {
    const result = exportSession(makeSession(), baseConfig(vault));

    assert.equal(result.filesCreated.length, 1);
    assert.equal(result.filesUpdated.length, 0);
    assert.equal(result.mocUpdated, false);
    assert.equal(result.dailyNoteUpdated, false);

    const rel = result.filesCreated[0];
    // flat structure -> "Claude Sessions/<date> <title>.md"
    assert.match(rel, /^Claude Sessions[/\\]2026-06-21 Fix the failing build\.md$/);

    const md = readFileSync(join(vault, rel), "utf-8");
    // Frontmatter
    assert.ok(md.startsWith("---\n"), "starts with frontmatter fence");
    assert.match(md, /type: claude-session/);
    assert.match(md, /session_id: "sess-123"/);
    assert.match(md, /date: "2026-06-21"/);
    assert.match(md, /branch: "main"/);
    // Title header (from first user message)
    assert.match(md, /^# Fix the failing build$/m);
    // Sections + metadata block
    assert.match(md, /^## Conversation$/m);
    assert.match(md, /\*\*Duration\*\*: 30 min/);
    assert.match(md, /\*\*Messages\*\*: 2/);
  } finally {
    rmSync(vault, { recursive: true, force: true });
  }
});

test("tags are derived from tagPrefix and topics, and tool calls render when enabled", () => {
  const vault = mkdtempSync(join(tmpdir(), "nexus-obsidian-"));
  try {
    const result = exportSession(makeSession(), baseConfig(vault));
    const md = readFileSync(join(vault, result.filesCreated[0]), "utf-8");

    assert.match(md, /tags: \[claude\/session, claude\/build, claude\/ci\]/);
    assert.match(md, /topics: \["build", "ci"\]/);
    // Tool call block from the Bash tool
    assert.match(md, /#### Tool: Bash/);
    assert.match(md, /```bash\nnpm run build\n```/);
    assert.match(md, /<summary>Result<\/summary>/);
    assert.match(md, /build ok/);
  } finally {
    rmSync(vault, { recursive: true, force: true });
  }
});

test("includeToolCalls=false omits tool call rendering", () => {
  const vault = mkdtempSync(join(tmpdir(), "nexus-obsidian-"));
  try {
    const cfg = baseConfig(vault, { includeToolCalls: false });
    const result = exportSession(makeSession(), cfg);
    const md = readFileSync(join(vault, result.filesCreated[0]), "utf-8");

    assert.doesNotMatch(md, /#### Tool: Bash/);
    assert.doesNotMatch(md, /npm run build/);
  } finally {
    rmSync(vault, { recursive: true, force: true });
  }
});

test("re-exporting the same session marks the file as updated, not created", () => {
  const vault = mkdtempSync(join(tmpdir(), "nexus-obsidian-"));
  try {
    const session = makeSession();
    const cfg = baseConfig(vault);

    const first = exportSession(session, cfg);
    assert.equal(first.filesCreated.length, 1);

    const second = exportSession(session, cfg);
    assert.equal(second.filesCreated.length, 0);
    assert.equal(second.filesUpdated.length, 1);
    assert.equal(second.filesUpdated[0], first.filesCreated[0]);
  } finally {
    rmSync(vault, { recursive: true, force: true });
  }
});

test("by-project folder structure nests under the basename of projectPath", () => {
  const vault = mkdtempSync(join(tmpdir(), "nexus-obsidian-"));
  try {
    const result = exportSession(
      makeSession(),
      baseConfig(vault, { folderStructure: "by-project" }),
    );
    const rel = result.filesCreated[0];
    // basename("/home/hawon/.claude/projects/-home-hawon-myproject")
    assert.match(rel, /^Claude Sessions[/\\]-home-hawon-myproject[/\\]/);
  } finally {
    rmSync(vault, { recursive: true, force: true });
  }
});

test("updateMOC writes a MOC.md grouping sessions by date, project, and topic", () => {
  const vault = mkdtempSync(join(tmpdir(), "nexus-obsidian-"));
  try {
    updateMOC(vault, [makeSession()]);
    const mocPath = join(vault, "Claude Sessions", "MOC.md");
    assert.ok(existsSync(mocPath), "MOC.md created");

    const md = readFileSync(mocPath, "utf-8");
    assert.match(md, /^# Claude Sessions$/m);
    assert.match(md, /^## By Date$/m);
    assert.match(md, /^## By Project$/m);
    assert.match(md, /^## By Topic$/m);
    // Wikilink to the session note
    assert.match(md, /\[\[2026-06-21 Fix the failing build\]\]/);
    assert.match(md, /^### build$/m);
  } finally {
    rmSync(vault, { recursive: true, force: true });
  }
});

test("appendToDailyNote creates a dated note with a Claude Sessions section and message count", () => {
  const vault = mkdtempSync(join(tmpdir(), "nexus-obsidian-"));
  try {
    appendToDailyNote(vault, "2026-06-21", [makeSession()]);
    const notePath = join(vault, "Daily Notes", "2026-06-21.md");
    assert.ok(existsSync(notePath), "daily note created");

    const md = readFileSync(notePath, "utf-8");
    assert.match(md, /^## Claude Sessions$/m);
    assert.match(md, /\[\[2026-06-21 Fix the failing build\]\] - build, ci \(2 messages\)/);
  } finally {
    rmSync(vault, { recursive: true, force: true });
  }
});
