import { readFileSync } from "node:fs";
import { basename, dirname } from "node:path";
import type { ParsedMessage, ParsedSession, ToolCall } from "./types.js";

const STOP_WORDS = new Set([
  "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
  "have", "has", "had", "do", "does", "did", "will", "would", "could",
  "should", "may", "might", "shall", "can", "need", "must", "ought",
  "i", "me", "my", "we", "our", "you", "your", "he", "she", "it",
  "they", "them", "his", "her", "its", "this", "that", "these", "those",
  "what", "which", "who", "whom", "how", "when", "where", "why",
  "and", "but", "or", "nor", "not", "no", "so", "if", "then", "else",
  "for", "of", "to", "in", "on", "at", "by", "with", "from", "as",
  "into", "about", "up", "out", "off", "over", "under", "again",
  "there", "here", "all", "each", "every", "both", "few", "more",
  "most", "some", "any", "other", "just", "also", "than", "too",
  "very", "only", "even", "still", "already", "now", "well",
  "get", "got", "make", "made", "go", "going", "come", "take",
  "use", "used", "using", "like", "want", "know", "see", "look",
  "think", "said", "say", "tell", "let", "put", "set", "try",
  "please", "thanks", "thank", "yes", "no", "ok", "okay", "sure",
  "dont", "don", "doesn", "didn", "won", "wouldn", "couldn", "shouldn",
  "im", "ive", "ill", "its", "thats", "theres", "heres",
]);

const METADATA_TYPES = new Set([
  "permission-mode",
  "attachment",
  "file-history-snapshot",
]);

const FILE_MODIFYING_TOOLS = new Set(["Edit", "Write", "NotebookEdit"]);

interface RawEntry {
  type?: string;
  timestamp?: string;
  sessionId?: string;
  cwd?: string;
  gitBranch?: string;
  message?: {
    content?: string | ContentBlock[];
    role?: string;
  };
}

interface ContentBlock {
  type: string;
  text?: string;
  name?: string;
  id?: string;
  tool_use_id?: string;
  input?: Record<string, unknown>;
  content?: string | ContentBlock[];
}

function extractTextFromContent(
  content: string | ContentBlock[] | undefined,
): string {
  if (content === undefined) return "";
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";

  const parts: string[] = [];
  for (const block of content) {
    if (block.type === "text" && typeof block.text === "string") {
      parts.push(block.text);
    }
  }
  return parts.join("\n");
}

function extractToolCalls(content: ContentBlock[] | undefined): ToolCall[] {
  if (!Array.isArray(content)) return [];

  const toolUseMap = new Map<string, ToolCall>();
  const calls: ToolCall[] = [];

  for (const block of content) {
    if (block.type === "tool_use" && block.name && block.id) {
      const call: ToolCall = {
        name: block.name,
        input: block.input ?? {},
      };
      toolUseMap.set(block.id, call);
      calls.push(call);
    }
    if (block.type === "tool_result" && block.tool_use_id) {
      const call = toolUseMap.get(block.tool_use_id);
      if (call) {
        call.result = typeof block.content === "string"
          ? block.content
          : extractTextFromContent(block.content as ContentBlock[]);
      }
    }
  }

  return calls;
}

function extractFilesFromToolCalls(toolCalls: ToolCall[]): string[] {
  const files: string[] = [];
  for (const call of toolCalls) {
    if (FILE_MODIFYING_TOOLS.has(call.name)) {
      const filePath = call.input["file_path"] ?? call.input["path"];
      if (typeof filePath === "string") {
        files.push(filePath);
      }
    }
  }
  return files;
}

// System/internal noise words from Claude Code JSONL metadata
const SYSTEM_NOISE = new Set([
  "task-notification", "task-id", "tool-use-id", "toolu", "output-file",
  "tmp", "claude-1000", "system-reminder", "task-tools", "taskupdate",
  "taskcreate", "tasklist", "taskget", "taskstop", "taskoutput",
  "completed", "in_progress", "stale", "relevant", "reminder",
  "applicable", "mention", "agent", "agentid", "internal",
]);

// Words that are common in code/technical contexts but not useful as topics
const CODE_NOISE = new Set([
  "const", "let", "var", "function", "return", "import", "export", "from",
  "type", "interface", "class", "new", "async", "await", "true", "false",
  "null", "undefined", "string", "number", "boolean", "void", "any",
  "src", "dist", "node", "npm", "git", "file", "files", "code", "run",
  "error", "errors", "test", "tests", "https", "http", "www", "com",
  "json", "yaml", "yml", "tsx", "jsx", "css", "html", "env",
  "log", "console", "process", "path", "index", "config",
  "result", "results", "output", "input", "data", "value", "values",
  "name", "names", "key", "keys", "map", "set", "list", "array",
  "line", "lines", "total", "count", "check", "find", "add", "update",
  "create", "delete", "remove", "read", "write", "open", "close",
  "start", "stop", "end", "done", "status", "version", "build",
]);

function extractTopics(userMessages: string[]): string[] {
  const wordCounts = new Map<string, number>();

  for (const msg of userMessages) {
    const words = msg
      .toLowerCase()
      .replace(/[^a-z가-힣0-9\s-]/g, " ")
      .split(/\s+/)
      .filter((w) => w.length > 2 && !STOP_WORDS.has(w) && !CODE_NOISE.has(w) && !SYSTEM_NOISE.has(w))
      // Filter out hex strings, UUIDs, hashes
      .filter((w) => !/^[0-9a-f]{6,}$/.test(w))
      // Filter out pure numbers
      .filter((w) => !/^\d+$/.test(w))
      // Filter out path-like tokens
      .filter((w) => !w.startsWith("-home-") && !w.startsWith("/home/"))
      // Filter out tokens with dashes that look like IDs
      .filter((w) => !(w.includes("-") && /[0-9a-f]{4,}/.test(w)));

    const unique = new Set(words);
    for (const word of unique) {
      wordCounts.set(word, (wordCounts.get(word) ?? 0) + 1);
    }
  }

  return Array.from(wordCounts.entries())
    .filter(([, count]) => count >= 3)
    .sort((a, b) => b[1] - a[1])
    .map(([word]) => word)
    .slice(0, 10); // Cap at 10 topics
}

function generateSummary(
  messages: ParsedMessage[],
  toolsUsed: string[],
): string {
  const firstUser = messages.find((m) => m.role === "user");
  const firstLine = firstUser
    ? firstUser.content.split("\n")[0].slice(0, 120)
    : "Empty session";

  const msgCount = messages.length;
  const toolStr =
    toolsUsed.length > 0 ? ` | Tools: ${toolsUsed.join(", ")}` : "";

  return `${firstLine} [${msgCount} messages${toolStr}]`;
}

export function parseSession(jsonlPath: string): ParsedSession {
  const raw = readFileSync(jsonlPath, "utf-8");
  const lines = raw.split("\n").filter((line) => line.trim().length > 0);

  const messages: ParsedMessage[] = [];
  const allToolCalls: ToolCall[] = [];
  const filesModifiedSet = new Set<string>();
  const toolsUsedSet = new Set<string>();
  const userTexts: string[] = [];

  let sessionId = basename(jsonlPath, ".jsonl");
  let cwd: string | undefined;
  let gitBranch: string | undefined;
  let firstTimestamp: string | undefined;
  let lastTimestamp: string | undefined;

  for (const line of lines) {
    let entry: RawEntry;
    try {
      entry = JSON.parse(line) as RawEntry;
    } catch {
      continue;
    }

    if (!entry.type || METADATA_TYPES.has(entry.type)) continue;

    if (entry.timestamp) {
      if (!firstTimestamp) firstTimestamp = entry.timestamp;
      lastTimestamp = entry.timestamp;
    }

    if (entry.sessionId) sessionId = entry.sessionId;
    if (entry.cwd) cwd = entry.cwd;
    if (entry.gitBranch) gitBranch = entry.gitBranch;

    if (entry.type === "user" && entry.message) {
      const content = extractTextFromContent(entry.message.content);
      if (content) {
        messages.push({
          role: "user",
          content,
          timestamp: entry.timestamp ?? "",
        });
        userTexts.push(content);
      }
      continue;
    }

    if (entry.type === "assistant" && entry.message) {
      const content = extractTextFromContent(entry.message.content);
      const toolCalls = extractToolCalls(
        entry.message.content as ContentBlock[] | undefined,
      );

      // Skip empty assistant messages (thinking-only blocks with no visible output)
      if (!content.trim() && toolCalls.length === 0) continue;

      const msg: ParsedMessage = {
        role: "assistant",
        content,
        timestamp: entry.timestamp ?? "",
      };

      if (toolCalls.length > 0) {
        msg.toolCalls = toolCalls;
        for (const tc of toolCalls) {
          allToolCalls.push(tc);
          toolsUsedSet.add(tc.name);
          for (const f of extractFilesFromToolCalls([tc])) {
            filesModifiedSet.add(f);
          }
        }
      }

      messages.push(msg);
      continue;
    }
  }

  const toolsUsed = Array.from(toolsUsedSet).sort();
  const filesModified = Array.from(filesModifiedSet).sort();
  const topics = extractTopics(userTexts);
  const summary = generateSummary(messages, toolsUsed);

  return {
    sessionId,
    projectPath: dirname(jsonlPath),
    cwd,
    gitBranch,
    startedAt: firstTimestamp ?? "",
    endedAt: lastTimestamp ?? "",
    messages,
    toolsUsed,
    filesModified,
    summary,
    topics,
  };
}
