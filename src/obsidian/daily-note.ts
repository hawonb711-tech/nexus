import { writeFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { ParsedSession } from "../parser/types.js";

export function appendToDailyNote(
  vaultPath: string,
  date: string,
  sessions: ParsedSession[],
): void {
  const dir = join(vaultPath, "Daily Notes");
  const notePath = join(dir, `${date}.md`);

  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  const existing = existsSync(notePath)
    ? readFileSync(notePath, "utf-8")
    : "";

  const sessionBlock = renderSessionBlock(sessions);

  const updated = injectSessionBlock(existing, sessionBlock);
  writeFileSync(notePath, updated, "utf-8");
}

function renderSessionBlock(sessions: ParsedSession[]): string {
  const lines: string[] = [];
  lines.push("## Claude Sessions");

  for (const session of sessions) {
    const date = session.startedAt.slice(0, 10);
    const title = buildTitle(session);
    const link = `${date} ${title}`;
    const topicsStr = session.topics.length > 0
      ? session.topics.join(", ")
      : "general";
    const msgCount = session.messages.length;

    lines.push(`- [[${link}]] - ${topicsStr} (${msgCount} messages)`);
  }

  return lines.join("\n");
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

function injectSessionBlock(existing: string, block: string): string {
  if (!existing.trim()) {
    return block + "\n";
  }

  const marker = "## Claude Sessions";
  const markerIdx = existing.indexOf(marker);

  if (markerIdx === -1) {
    // Append to end
    const separator = existing.endsWith("\n") ? "\n" : "\n\n";
    return existing + separator + block + "\n";
  }

  // Replace existing Claude Sessions section
  const before = existing.slice(0, markerIdx);
  const afterMarker = existing.slice(markerIdx);

  // Find the next ## heading after our section
  const nextHeadingMatch = afterMarker.match(/\n(## (?!Claude Sessions))/);
  if (nextHeadingMatch && nextHeadingMatch.index !== undefined) {
    const after = afterMarker.slice(nextHeadingMatch.index);
    return before + block + "\n" + after;
  }

  // No next heading, replace everything from marker to end
  return before + block + "\n";
}
