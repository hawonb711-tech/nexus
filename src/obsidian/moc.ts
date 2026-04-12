import { writeFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { join, basename } from "node:path";
import type { ParsedSession } from "../parser/types.js";

type MOCEntry = {
  date: string;
  title: string;
  link: string;
  project: string;
  topics: string[];
};

export function updateMOC(vaultPath: string, sessions: ParsedSession[]): void {
  const dir = join(vaultPath, "Claude Sessions");
  const mocPath = join(dir, "MOC.md");

  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  const existing = existsSync(mocPath)
    ? parseMOCEntries(readFileSync(mocPath, "utf-8"))
    : [];

  const newEntries = sessions.map(sessionToEntry);
  const merged = mergeEntries(existing, newEntries);

  const markdown = renderMOC(merged);
  writeFileSync(mocPath, markdown, "utf-8");
}

function sessionToEntry(session: ParsedSession): MOCEntry {
  const date = session.startedAt.slice(0, 10);
  const title = buildTitle(session);
  return {
    date,
    title,
    link: `${date} ${title}`,
    project: basename(session.projectPath) || "unknown",
    topics: session.topics,
  };
}

function buildTitle(session: ParsedSession): string {
  const first = session.messages.find((m) => m.role === "user");
  if (!first) return "Untitled Session";
  const raw = first.content
    .replace(/\n/g, " ")
    .replace(/[\\/:*?"<>|#^[\]]/g, "")
    .trim();
  if (raw.length <= 60) return raw || "Untitled Session";
  return raw.slice(0, 57) + "...";
}

function mergeEntries(existing: MOCEntry[], incoming: MOCEntry[]): MOCEntry[] {
  const byLink = new Map<string, MOCEntry>();
  for (const e of existing) byLink.set(e.link, e);
  for (const e of incoming) byLink.set(e.link, e);
  return Array.from(byLink.values()).sort((a, b) =>
    b.date.localeCompare(a.date),
  );
}

function parseMOCEntries(content: string): MOCEntry[] {
  const entries: MOCEntry[] = [];
  const linkRe = /\[\[(.+?)\]\]/g;
  let currentProject: string | undefined;
  let currentTopics: string | undefined;

  for (const line of content.split("\n")) {
    const projectMatch = line.match(/^### (.+)/);
    if (projectMatch) {
      const section = detectSection(content, line);
      if (section === "project") {
        currentProject = projectMatch[1].trim();
      } else if (section === "topic") {
        currentTopics = projectMatch[1].trim();
      }
    }

    let match: RegExpExecArray | null;
    while ((match = linkRe.exec(line)) !== null) {
      const link = match[1];
      const dateMatch = link.match(/^(\d{4}-\d{2}-\d{2})\s+(.+)$/);
      if (dateMatch) {
        const existing = entries.find((e) => e.link === link);
        if (!existing) {
          entries.push({
            date: dateMatch[1],
            title: dateMatch[2],
            link,
            project: currentProject ?? "unknown",
            topics: currentTopics ? [currentTopics] : [],
          });
        } else if (currentTopics && !existing.topics.includes(currentTopics)) {
          existing.topics.push(currentTopics);
        }
      }
    }
  }

  return entries;
}

function detectSection(content: string, currentLine: string): "project" | "topic" | "date" {
  const lines = content.split("\n");
  const idx = lines.indexOf(currentLine);
  for (let i = idx - 1; i >= 0; i--) {
    if (lines[i].startsWith("## By Project")) return "project";
    if (lines[i].startsWith("## By Topic")) return "topic";
    if (lines[i].startsWith("## By Date")) return "date";
    if (lines[i].startsWith("## ")) break;
  }
  return "date";
}

function renderMOC(entries: MOCEntry[]): string {
  const lines: string[] = [];

  lines.push("# Claude Sessions");
  lines.push("");

  // By Date
  lines.push("## By Date");
  for (const entry of entries) {
    lines.push(`- [[${entry.link}]]`);
  }
  lines.push("");

  // By Project
  lines.push("## By Project");
  const byProject = groupBy(entries, (e) => e.project);
  for (const [project, projectEntries] of byProject) {
    lines.push(`### ${project}`);
    for (const entry of projectEntries) {
      lines.push(`- [[${entry.link}]]`);
    }
  }
  lines.push("");

  // By Topic
  lines.push("## By Topic");
  const topicMap = new Map<string, MOCEntry[]>();
  for (const entry of entries) {
    for (const topic of entry.topics) {
      if (!topicMap.has(topic)) topicMap.set(topic, []);
      topicMap.get(topic)!.push(entry);
    }
  }
  for (const [topic, topicEntries] of topicMap) {
    lines.push(`### ${topic}`);
    for (const entry of topicEntries) {
      lines.push(`- [[${entry.link}]]`);
    }
  }
  lines.push("");

  return lines.join("\n");
}

function groupBy<T>(items: T[], keyFn: (item: T) => string): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const item of items) {
    const key = keyFn(item);
    if (!map.has(key)) map.set(key, []);
    map.get(key)!.push(item);
  }
  return map;
}
