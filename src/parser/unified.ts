import { homedir } from "node:os";
import { join } from "node:path";
import { discoverSessions } from "./discover.js";
import {
  discoverOpenClawSessions,
  parseOpenClawSession,
} from "./openclaw-parser.js";
import { parseSession } from "./parse.js";
import type {
  ParsedSession,
  PlatformDiscovery,
  UnifiedDiscovery,
} from "./types.js";

export function discoverAllSessions(opts?: {
  claudeDir?: string;
  openclawDir?: string;
}): UnifiedDiscovery {
  const claudeDir = opts?.claudeDir ?? join(homedir(), ".claude");
  const openclawDir = opts?.openclawDir ?? join(homedir(), ".openclaw");

  // Discover Claude Code sessions
  const claudeDiscovery = discoverSessions(claudeDir);
  const claudeSessions: PlatformDiscovery["sessions"] = [];
  for (const project of claudeDiscovery.projects) {
    for (const sessionPath of project.sessions) {
      claudeSessions.push({ path: sessionPath, projectId: project.projectId });
    }
  }

  const claudePlatform: PlatformDiscovery = {
    platform: "claude-code",
    sessions: claudeSessions,
    totalSessions: claudeSessions.length,
  };

  // Discover OpenClaw sessions
  const openclawPlatform = discoverOpenClawSessions(openclawDir);

  const platforms = [claudePlatform, openclawPlatform];
  const totalSessions = platforms.reduce(
    (sum, p) => sum + p.totalSessions,
    0,
  );

  return { platforms, totalSessions };
}

export function parseAnySession(
  path: string,
  platform: "claude-code" | "openclaw",
): ParsedSession {
  switch (platform) {
    case "claude-code":
      return parseSession(path);
    case "openclaw":
      return parseOpenClawSession(path);
    default:
      throw new Error(`Unknown platform: ${platform as string}`);
  }
}
