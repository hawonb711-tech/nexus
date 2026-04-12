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
  /** Which platform this session came from. */
  platform: "claude-code" | "openclaw" | "unknown";
};

export type SessionDiscovery = {
  claudeDir: string;
  projects: { projectId: string; sessions: string[] }[];
  totalSessions: number;
};

export type PlatformDiscovery = {
  platform: "claude-code" | "openclaw";
  sessions: { path: string; projectId: string }[];
  totalSessions: number;
};

export type UnifiedDiscovery = {
  platforms: PlatformDiscovery[];
  totalSessions: number;
};
