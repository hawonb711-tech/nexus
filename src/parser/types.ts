export type ParsedMessage = {
  role: "user" | "assistant";
  content: string;
  timestamp: string;
  toolCalls?: ToolCall[];
};

export type ToolCall = {
  name: string;
  input: Record<string, unknown>;
  result?: string;
};

export type ParsedSession = {
  sessionId: string;
  projectPath: string;
  cwd?: string;
  gitBranch?: string;
  startedAt: string;
  endedAt: string;
  messages: ParsedMessage[];
  toolsUsed: string[];
  filesModified: string[];
  summary?: string;
  topics: string[];
};

export type SessionDiscovery = {
  claudeDir: string;
  projects: { projectId: string; sessions: string[] }[];
  totalSessions: number;
};
