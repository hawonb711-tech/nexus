import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, basename, dirname } from "node:path";
import type { ParsedSession, ParsedMessage, ToolCall } from "../parser/types.js";
import type { ObsidianConfig, ExportResult } from "./types.js";
import { updateMOC } from "./moc.js";
import { appendToDailyNote } from "./daily-note.js";

export function exportSession(
  session: ParsedSession,
  config: ObsidianConfig,
): ExportResult {
  const result: ExportResult = {
    filesCreated: [],
    filesUpdated: [],
    mocUpdated: false,
    dailyNoteUpdated: false,
  };

  const title = buildSessionTitle(session);
  const date = session.startedAt.slice(0, 10);
  const relativePath = buildFilePath(session, config, title, date);
  const fullPath = join(config.vaultPath, relativePath);

  const markdown = renderSessionMarkdown(session, config, title, date);

  const dir = dirname(fullPath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  const alreadyExists = existsSync(fullPath);
  writeFileSync(fullPath, markdown, "utf-8");

  if (alreadyExists) {
    result.filesUpdated.push(relativePath);
  } else {
    result.filesCreated.push(relativePath);
  }

  if (config.createMOC) {
    updateMOC(config.vaultPath, [session]);
    result.mocUpdated = true;
  }

  if (config.createDailyNotes) {
    appendToDailyNote(config.vaultPath, date, [session]);
    result.dailyNoteUpdated = true;
  }

  return result;
}

function buildSessionTitle(session: ParsedSession): string {
  const firstUserMessage = session.messages.find((m) => m.role === "user");
  if (!firstUserMessage) {
    return "Untitled Session";
  }
  const raw = firstUserMessage.content
    .replace(/\n/g, " ")
    .replace(/[\\/:*?"<>|#^[\]]/g, "")
    .trim();
  if (raw.length <= 60) {
    return raw || "Untitled Session";
  }
  return raw.slice(0, 57) + "...";
}

function buildFilePath(
  session: ParsedSession,
  config: ObsidianConfig,
  title: string,
  date: string,
): string {
  const filename = `${date} ${title}.md`;
  const base = "Claude Sessions";

  switch (config.folderStructure) {
    case "by-date": {
      const [year, month] = date.split("-");
      return join(base, year, month, filename);
    }
    case "by-project": {
      const project = basename(session.projectPath) || "unknown";
      return join(base, project, filename);
    }
    case "flat":
      return join(base, filename);
  }
}

function renderSessionMarkdown(
  session: ParsedSession,
  config: ObsidianConfig,
  title: string,
  date: string,
): string {
  const lines: string[] = [];

  lines.push(renderFrontmatter(session, config, date));
  lines.push("");
  lines.push(`# ${title}`);
  lines.push("");
  lines.push(renderMetadataBlock(session));
  lines.push("");
  lines.push("## Conversation");
  lines.push("");

  for (const message of session.messages) {
    // Skip empty messages
    if (!message.content.trim() && (!message.toolCalls || message.toolCalls.length === 0)) continue;
    lines.push(renderMessage(message, config));
    lines.push("");
  }

  return lines.join("\n");
}

function renderFrontmatter(
  session: ParsedSession,
  config: ObsidianConfig,
  date: string,
): string {
  const projectDisplay = session.cwd ?? humanizeProjectPath(session.projectPath);
  // Limit topics to 10 and create clean tags
  const topTopics = session.topics.slice(0, 10);
  const tags = [
    `${config.tagPrefix}session`,
    ...topTopics.map((t) => `${config.tagPrefix}${sanitizeTag(t)}`),
  ];
  // Limit files_modified to 20 to keep frontmatter clean
  const topFiles = session.filesModified.slice(0, 20);

  const fm: string[] = ["---"];
  fm.push(`type: claude-session`);
  fm.push(`session_id: "${session.sessionId}"`);
  fm.push(`date: "${date}"`);
  fm.push(`project: "${projectDisplay}"`);
  if (session.gitBranch && session.gitBranch !== "HEAD") {
    fm.push(`branch: "${session.gitBranch}"`);
  }
  fm.push(`tools: [${session.toolsUsed.map((t) => `"${t}"`).join(", ")}]`);
  fm.push(`files_modified: ${topFiles.length}`);
  fm.push(`messages: ${session.messages.length}`);
  fm.push(`topics: [${topTopics.map((t) => `"${t}"`).join(", ")}]`);
  fm.push(`tags: [${tags.join(", ")}]`);
  fm.push("---");

  return fm.join("\n");
}

function sanitizeTag(tag: string): string {
  return tag.replace(/[^a-zA-Z0-9가-힣_-]/g, "-").replace(/-+/g, "-");
}

function humanizeProjectPath(raw: string): string {
  // Convert Claude internal project path to human-readable
  // e.g., "/home/hawon/.claude/projects/-home-hawon" → "~/"
  // e.g., "/home/hawon/.claude/projects/-home-hawon-myproject" → "~/myproject"
  const base = basename(raw);
  // Strip leading dash and replace dashes with /
  const cleaned = base.replace(/^-/, "").replace(/-/g, "/");
  // Find the home directory prefix and replace with ~/
  const homeMatch = cleaned.match(/^home\/([^/]+)\/?(.*)$/);
  if (homeMatch) {
    return homeMatch[2] ? `~/${homeMatch[2]}` : "~/";
  }
  return cleaned || raw;
}

function renderMetadataBlock(session: ParsedSession): string {
  const duration = computeDurationMinutes(session.startedAt, session.endedAt);
  const messageCount = session.messages.length;
  const toolCount = session.messages.reduce(
    (acc, m) => acc + (m.toolCalls?.length ?? 0),
    0,
  );
  const projectDisplay = session.cwd ?? humanizeProjectPath(session.projectPath);

  const lines: string[] = [];
  lines.push(`> **Project**: \`${projectDisplay}\``);
  if (session.gitBranch && session.gitBranch !== "HEAD") {
    lines.push(`> **Branch**: \`${session.gitBranch}\``);
  }
  lines.push(
    `> **Duration**: ${duration} min | **Messages**: ${messageCount} | **Tools**: ${toolCount}`,
  );

  return lines.join("\n");
}

function computeDurationMinutes(startedAt: string, endedAt: string): number {
  const start = new Date(startedAt).getTime();
  const end = new Date(endedAt).getTime();
  if (Number.isNaN(start) || Number.isNaN(end)) {
    return 0;
  }
  return Math.round((end - start) / 60000);
}

function renderMessage(message: ParsedMessage, config: ObsidianConfig): string {
  const lines: string[] = [];
  const roleLabel = message.role === "user" ? "User" : "Claude";

  if (config.includeTimestamps && message.timestamp) {
    lines.push(`### ${roleLabel} <small>${message.timestamp}</small>`);
  } else {
    lines.push(`### ${roleLabel}`);
  }

  lines.push("");
  lines.push(message.content);

  if (config.includeToolCalls && message.toolCalls) {
    for (const tool of message.toolCalls) {
      lines.push("");
      lines.push(renderToolCall(tool));
    }
  }

  return lines.join("\n");
}

function renderToolCall(tool: ToolCall): string {
  const lines: string[] = [];

  const fileArg = extractFileArg(tool);
  const header = fileArg
    ? `#### Tool: ${tool.name} \`${fileArg}\``
    : `#### Tool: ${tool.name}`;
  lines.push(header);
  lines.push("");

  const inputStr = formatToolInput(tool);
  if (inputStr) {
    const lang = guessLang(tool);
    lines.push(`\`\`\`${lang}`);
    lines.push(inputStr);
    lines.push("```");
  }

  if (tool.result) {
    lines.push("");
    lines.push("<details>");
    lines.push("<summary>Result</summary>");
    lines.push("");
    lines.push("```");
    lines.push(tool.result);
    lines.push("```");
    lines.push("");
    lines.push("</details>");
  }

  return lines.join("\n");
}

function extractFileArg(tool: ToolCall): string | undefined {
  const input = tool.input;
  if (typeof input.file_path === "string") return input.file_path;
  if (typeof input.path === "string") return input.path;
  return undefined;
}

function formatToolInput(tool: ToolCall): string {
  const input = tool.input;

  if (tool.name === "Edit" && typeof input.old_string === "string") {
    const lines: string[] = [];
    if (input.old_string) {
      for (const line of String(input.old_string).split("\n")) {
        lines.push(`- ${line}`);
      }
    }
    if (typeof input.new_string === "string") {
      for (const line of String(input.new_string).split("\n")) {
        lines.push(`+ ${line}`);
      }
    }
    return lines.join("\n");
  }

  if (tool.name === "Bash" && typeof input.command === "string") {
    return input.command;
  }

  if (tool.name === "Write" && typeof input.content === "string") {
    return input.content;
  }

  const keys = Object.keys(input);
  if (keys.length === 0) return "";
  return JSON.stringify(input, null, 2);
}

function guessLang(tool: ToolCall): string {
  if (tool.name === "Edit") return "diff";
  if (tool.name === "Bash") return "bash";
  if (tool.name === "Write") {
    const path = tool.input.file_path;
    if (typeof path === "string") {
      if (path.endsWith(".ts") || path.endsWith(".tsx")) return "typescript";
      if (path.endsWith(".js") || path.endsWith(".jsx")) return "javascript";
      if (path.endsWith(".py")) return "python";
      if (path.endsWith(".rs")) return "rust";
      if (path.endsWith(".go")) return "go";
      if (path.endsWith(".json")) return "json";
      if (path.endsWith(".yaml") || path.endsWith(".yml")) return "yaml";
    }
  }
  return "";
}
