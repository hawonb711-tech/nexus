import { readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { SessionDiscovery } from "./types.js";

export function discoverSessions(claudeDir?: string): SessionDiscovery {
  const resolvedDir = claudeDir ?? join(homedir(), ".claude");
  const projectsDir = join(resolvedDir, "projects");

  const projects: SessionDiscovery["projects"] = [];
  let totalSessions = 0;

  let projectEntries: string[];
  try {
    projectEntries = readdirSync(projectsDir);
  } catch {
    return { claudeDir: resolvedDir, projects: [], totalSessions: 0 };
  }

  for (const projectId of projectEntries) {
    const projectPath = join(projectsDir, projectId);

    try {
      if (!statSync(projectPath).isDirectory()) continue;
    } catch {
      continue;
    }

    const sessions: string[] = [];
    let entries: string[];

    try {
      entries = readdirSync(projectPath);
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (!entry.endsWith(".jsonl")) continue;
      const fullPath = join(projectPath, entry);
      try {
        if (statSync(fullPath).isFile()) {
          sessions.push(fullPath);
        }
      } catch {
        continue;
      }
    }

    if (sessions.length > 0) {
      projects.push({ projectId, sessions });
      totalSessions += sessions.length;
    }
  }

  return { claudeDir: resolvedDir, projects, totalSessions };
}
