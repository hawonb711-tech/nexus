import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import type {
  ParsedMessage,
  ParsedSession,
  PlatformDiscovery,
  ToolCall,
} from "./types.js";

const FILE_MODIFYING_TOOLS = new Set(["Edit", "Write", "NotebookEdit"]);

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
]);

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

interface OpenClawToolCall {
  name: string;
  arguments: Record<string, unknown>;
  result?: string;
}

interface OpenClawLine {
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: string;
  tool_calls?: OpenClawToolCall[];
}

interface OpenClawSessionMeta {
  sessionId?: string;
  projectPath?: string;
  cwd?: string;
  gitBranch?: string;
  startedAt?: string;
  endedAt?: string;
  summary?: string;
}

function extractTopics(userMessages: string[]): string[] {
  const wordCounts = new Map<string, number>();

  for (const msg of userMessages) {
    const words = msg
      .toLowerCase()
      .replace(/[^a-z가-힣0-9\s-]/g, " ")
      .split(/\s+/)
      .filter((w) => w.length > 2 && !STOP_WORDS.has(w) && !CODE_NOISE.has(w))
      .filter((w) => !/^[0-9a-f]{6,}$/.test(w))
      .filter((w) => !/^\d+$/.test(w))
      .filter((w) => !w.startsWith("-home-") && !w.startsWith("/home/"))
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
    .slice(0, 10);
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

export function discoverOpenClawSessions(
  openclawDir?: string,
): PlatformDiscovery {
  const resolvedDir = openclawDir ?? join(homedir(), ".openclaw");
  const agentsDir = join(resolvedDir, "agents");

  const sessions: PlatformDiscovery["sessions"] = [];

  let agentEntries: string[];
  try {
    agentEntries = readdirSync(agentsDir);
  } catch {
    return { platform: "openclaw", sessions: [], totalSessions: 0 };
  }

  for (const agentId of agentEntries) {
    const sessionsDir = join(agentsDir, agentId, "sessions");

    try {
      if (!statSync(join(agentsDir, agentId)).isDirectory()) continue;
    } catch {
      continue;
    }

    let sessionEntries: string[];
    try {
      sessionEntries = readdirSync(sessionsDir);
    } catch {
      continue;
    }

    for (const entry of sessionEntries) {
      if (!entry.endsWith(".jsonl")) continue;
      const fullPath = join(sessionsDir, entry);
      try {
        if (statSync(fullPath).isFile()) {
          sessions.push({ path: fullPath, projectId: agentId });
        }
      } catch {
        continue;
      }
    }
  }

  return {
    platform: "openclaw",
    sessions,
    totalSessions: sessions.length,
  };
}

export function parseOpenClawSession(jsonlPath: string): ParsedSession {
  const raw = readFileSync(jsonlPath, "utf-8");
  const lines = raw.split("\n").filter((line) => line.trim().length > 0);

  const messages: ParsedMessage[] = [];
  const filesModifiedSet = new Set<string>();
  const toolsUsedSet = new Set<string>();
  const userTexts: string[] = [];

  let firstTimestamp: string | undefined;
  let lastTimestamp: string | undefined;

  for (const line of lines) {
    let entry: OpenClawLine;
    try {
      entry = JSON.parse(line) as OpenClawLine;
    } catch {
      continue;
    }

    if (entry.role === "system") continue;

    if (entry.timestamp) {
      if (!firstTimestamp) firstTimestamp = entry.timestamp;
      lastTimestamp = entry.timestamp;
    }

    const toolCalls: ToolCall[] = [];
    if (entry.tool_calls && Array.isArray(entry.tool_calls)) {
      for (const tc of entry.tool_calls) {
        const call: ToolCall = {
          name: tc.name,
          input: tc.arguments ?? {},
          result: tc.result,
        };
        toolCalls.push(call);
        toolsUsedSet.add(tc.name);
        for (const f of extractFilesFromToolCalls([call])) {
          filesModifiedSet.add(f);
        }
      }
    }

    const content = entry.content ?? "";
    if (!content.trim() && toolCalls.length === 0) continue;

    const role = entry.role === "user" ? "user" : "assistant";

    const msg: ParsedMessage = {
      role,
      content,
      timestamp: entry.timestamp ?? "",
    };

    if (toolCalls.length > 0) {
      msg.toolCalls = toolCalls;
    }

    messages.push(msg);

    if (role === "user" && content) {
      userTexts.push(content);
    }
  }

  // Try to read session.json metadata from the same directory
  let meta: OpenClawSessionMeta = {};
  const metaPath = join(dirname(jsonlPath), "session.json");
  if (existsSync(metaPath)) {
    try {
      meta = JSON.parse(readFileSync(metaPath, "utf-8")) as OpenClawSessionMeta;
    } catch {
      // Ignore malformed metadata
    }
  }

  const sessionId =
    meta.sessionId ?? basename(jsonlPath, ".jsonl");
  const toolsUsed = Array.from(toolsUsedSet).sort();
  const filesModified = Array.from(filesModifiedSet).sort();
  const topics = extractTopics(userTexts);
  const summary =
    meta.summary ?? generateSummary(messages, toolsUsed);

  return {
    sessionId,
    projectPath: meta.projectPath ?? dirname(jsonlPath),
    cwd: meta.cwd,
    gitBranch: meta.gitBranch,
    startedAt: meta.startedAt ?? firstTimestamp ?? "",
    endedAt: meta.endedAt ?? lastTimestamp ?? "",
    messages,
    toolsUsed,
    filesModified,
    summary,
    topics,
    platform: "openclaw",
  };
}
