import { randomUUID } from "node:crypto";
import type { ParsedMessage, ParsedSession, ToolCall } from "../parser/types.js";
import type { ExtractedSkill } from "./types.js";

/**
 * A task-completion sequence: user request -> assistant actions -> completion.
 */
type TaskSequence = {
  userMessage: ParsedMessage;
  assistantMessages: ParsedMessage[];
  allToolCalls: ToolCall[];
  filesInvolved: string[];
};

const FILE_PATH_TOOLS = new Set(["Edit", "Write", "Read", "NotebookEdit", "Glob", "Grep"]);

function extractFilePaths(toolCalls: ToolCall[]): string[] {
  const files = new Set<string>();
  for (const tc of toolCalls) {
    if (FILE_PATH_TOOLS.has(tc.name)) {
      const filePath = tc.input["file_path"] ?? tc.input["path"];
      if (typeof filePath === "string") {
        files.add(filePath);
      }
    }
    // Bash commands that reference files
    if (tc.name === "Bash") {
      const cmd = tc.input["command"];
      if (typeof cmd === "string") {
        const fileRefs = cmd.match(/[\w./~-]+\.\w{1,10}/g);
        if (fileRefs) {
          for (const ref of fileRefs) {
            if (ref.includes("/") || ref.includes(".ts") || ref.includes(".js") || ref.includes(".py")) {
              files.add(ref);
            }
          }
        }
      }
    }
  }
  return Array.from(files);
}

function extractActionName(userContent: string): string {
  const firstLine = userContent.split("\n")[0].trim();
  // Truncate to something reasonable for a skill name
  const cleaned = firstLine
    .replace(/^(please|can you|could you|i want to|i need to|let's|lets)\s+/i, "")
    .replace(/[.!?]+$/, "")
    .trim();

  if (cleaned.length > 60) {
    return cleaned.slice(0, 60).replace(/\s+\S*$/, "").trim();
  }
  return cleaned || "unnamed task";
}

function describeToolCall(tc: ToolCall): string {
  switch (tc.name) {
    case "Bash": {
      const cmd = tc.input["command"];
      return typeof cmd === "string"
        ? `Run \`Bash\`: \`${cmd.length > 80 ? cmd.slice(0, 80) + "..." : cmd}\``
        : `Run \`Bash\``;
    }
    case "Edit": {
      const fp = tc.input["file_path"];
      return typeof fp === "string" ? `\`Edit\`: modify \`${fp}\`` : `\`Edit\`: modify file`;
    }
    case "Write": {
      const fp = tc.input["file_path"];
      return typeof fp === "string" ? `\`Write\`: create/overwrite \`${fp}\`` : `\`Write\`: create file`;
    }
    case "Read": {
      const fp = tc.input["file_path"];
      return typeof fp === "string" ? `\`Read\`: read \`${fp}\`` : `\`Read\`: read file`;
    }
    case "Grep": {
      const pat = tc.input["pattern"];
      return typeof pat === "string" ? `\`Grep\`: search for \`${pat}\`` : `\`Grep\`: search`;
    }
    case "Glob": {
      const pat = tc.input["pattern"];
      return typeof pat === "string" ? `\`Glob\`: find files matching \`${pat}\`` : `\`Glob\`: find files`;
    }
    default:
      return `\`${tc.name}\``;
  }
}

function generalizeTrigger(userContent: string): string {
  const firstLine = userContent.split("\n")[0].trim();
  // Strip specifics to make it more generic
  let trigger = firstLine
    .replace(/^(please|can you|could you|i want to|i need to)\s+/i, "When you need to ")
    .replace(/[.!?]+$/, "");

  if (!trigger.toLowerCase().startsWith("when")) {
    trigger = "When asked to " + trigger.charAt(0).toLowerCase() + trigger.slice(1);
  }
  return trigger;
}

function computeConfidence(seq: TaskSequence): number {
  const toolCount = seq.allToolCalls.length;
  if (toolCount === 0) return 0;

  // Base confidence from tool usage
  let confidence = Math.min(0.3 + toolCount * 0.1, 0.95);

  // Boost for variety of tools
  const uniqueTools = new Set(seq.allToolCalls.map((tc) => tc.name));
  if (uniqueTools.size >= 3) confidence = Math.min(confidence + 0.1, 0.95);

  // Boost for files involved
  if (seq.filesInvolved.length > 0) confidence = Math.min(confidence + 0.05, 0.95);

  return Math.round(confidence * 100) / 100;
}

function findTaskSequences(session: ParsedSession): TaskSequence[] {
  const sequences: TaskSequence[] = [];
  const messages = session.messages;

  let i = 0;
  while (i < messages.length) {
    const msg = messages[i];
    if (msg.role !== "user") {
      i++;
      continue;
    }

    // Collect subsequent assistant messages until next user message
    const assistantMessages: ParsedMessage[] = [];
    let j = i + 1;
    while (j < messages.length && messages[j].role === "assistant") {
      assistantMessages.push(messages[j]);
      j++;
    }

    // Only keep sequences where the assistant actually did something with tools
    const allToolCalls: ToolCall[] = [];
    for (const am of assistantMessages) {
      if (am.toolCalls) {
        allToolCalls.push(...am.toolCalls);
      }
    }

    if (allToolCalls.length > 0) {
      const filesInvolved = extractFilePaths(allToolCalls);
      sequences.push({
        userMessage: msg,
        assistantMessages,
        allToolCalls,
        filesInvolved,
      });
    }

    i = j;
  }

  return sequences;
}

export function extractSkills(session: ParsedSession): ExtractedSkill[] {
  const sequences = findTaskSequences(session);
  const skills: ExtractedSkill[] = [];

  for (const seq of sequences) {
    const name = extractActionName(seq.userMessage.content);
    const toolsUsed = Array.from(new Set(seq.allToolCalls.map((tc) => tc.name))).sort();
    const steps = seq.allToolCalls.map((tc) => describeToolCall(tc));
    const trigger = generalizeTrigger(seq.userMessage.content);
    const confidence = computeConfidence(seq);
    const description = `Extracted from session: ${name}. Uses ${toolsUsed.join(", ")}.`;

    // Generalize file paths to glob patterns
    const filesInvolved = generalizeFilePaths(seq.filesInvolved);

    skills.push({
      id: randomUUID(),
      name,
      description,
      trigger,
      steps,
      toolsUsed,
      filesInvolved,
      sourceSession: session.sessionId,
      extractedAt: new Date().toISOString(),
      confidence,
    });
  }

  return skills;
}

function generalizeFilePaths(paths: string[]): string[] {
  if (paths.length === 0) return [];

  // Group by directory, produce glob patterns where multiple files share a dir
  const dirMap = new Map<string, Set<string>>();
  for (const p of paths) {
    const lastSlash = p.lastIndexOf("/");
    const dir = lastSlash >= 0 ? p.slice(0, lastSlash) : ".";
    const ext = p.includes(".") ? p.slice(p.lastIndexOf(".")) : "";
    const key = `${dir}|${ext}`;
    if (!dirMap.has(key)) dirMap.set(key, new Set());
    dirMap.get(key)!.add(p);
  }

  const result: string[] = [];
  for (const [key, fileset] of dirMap) {
    if (fileset.size >= 3) {
      const [dir, ext] = key.split("|");
      result.push(`${dir}/**/*${ext}`);
    } else {
      for (const f of fileset) {
        result.push(f);
      }
    }
  }

  return result.sort();
}
