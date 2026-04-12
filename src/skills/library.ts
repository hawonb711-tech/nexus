import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ExtractedSkill, SkillLibrary } from "./types.js";

const LIBRARY_FILE = "skill-library.json";

export function loadSkillLibrary(dataDir: string): SkillLibrary {
  const filePath = join(dataDir, LIBRARY_FILE);

  if (!existsSync(filePath)) {
    return {
      skills: [],
      version: 1,
      updatedAt: new Date().toISOString(),
    };
  }

  try {
    const raw = readFileSync(filePath, "utf-8");
    const data = JSON.parse(raw) as SkillLibrary;
    return data;
  } catch {
    return {
      skills: [],
      version: 1,
      updatedAt: new Date().toISOString(),
    };
  }
}

export function saveSkillLibrary(library: SkillLibrary, dataDir: string): void {
  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true });
  }
  const filePath = join(dataDir, LIBRARY_FILE);
  library.updatedAt = new Date().toISOString();
  writeFileSync(filePath, JSON.stringify(library, null, 2), "utf-8");
}

/**
 * Add skills to the library, deduplicating by name similarity.
 * Returns the number of new skills actually added.
 */
export function addSkills(library: SkillLibrary, skills: ExtractedSkill[]): number {
  let added = 0;

  for (const skill of skills) {
    const isDuplicate = library.skills.some(
      (existing) => nameSimilarity(existing.name, skill.name) > 0.8,
    );

    if (!isDuplicate) {
      library.skills.push(skill);
      added++;
    } else {
      // Update existing skill if new one has higher confidence
      const existingIdx = library.skills.findIndex(
        (existing) => nameSimilarity(existing.name, skill.name) > 0.8,
      );
      if (existingIdx >= 0 && skill.confidence > library.skills[existingIdx].confidence) {
        library.skills[existingIdx] = skill;
      }
    }
  }

  if (added > 0) {
    library.version++;
  }

  return added;
}

/**
 * Simple keyword search across skill names, descriptions, triggers, and tools.
 */
export function searchSkills(library: SkillLibrary, query: string): ExtractedSkill[] {
  const terms = query.toLowerCase().split(/\s+/).filter((t) => t.length > 0);
  if (terms.length === 0) return [];

  const scored: { skill: ExtractedSkill; score: number }[] = [];

  for (const skill of library.skills) {
    const searchable = [
      skill.name,
      skill.description,
      skill.trigger,
      ...skill.toolsUsed,
      ...skill.filesInvolved,
      ...skill.steps,
    ]
      .join(" ")
      .toLowerCase();

    let score = 0;
    for (const term of terms) {
      if (searchable.includes(term)) {
        score++;
        // Boost for name match
        if (skill.name.toLowerCase().includes(term)) {
          score += 2;
        }
      }
    }

    if (score > 0) {
      scored.push({ skill, score: score * skill.confidence });
    }
  }

  return scored
    .sort((a, b) => b.score - a.score)
    .map((s) => s.skill);
}

/**
 * Export skills to Obsidian-compatible markdown files.
 * Returns array of created file paths.
 */
export function exportToObsidian(library: SkillLibrary, vaultPath: string): string[] {
  const skillsDir = join(vaultPath, "Skills");
  if (!existsSync(skillsDir)) {
    mkdirSync(skillsDir, { recursive: true });
  }

  const createdFiles: string[] = [];

  for (const skill of library.skills) {
    const safeName = skill.name
      .replace(/[<>:"/\\|?*]/g, "-")
      .replace(/\s+/g, "-")
      .slice(0, 80);

    const fileName = `${safeName}.md`;
    const filePath = join(skillsDir, fileName);

    const toolsList = skill.toolsUsed.map((t) => `- ${t}`).join("\n");
    const stepsList = skill.steps.map((s, i) => `${i + 1}. ${s}`).join("\n");
    const filesList = skill.filesInvolved.map((f) => `- ${f}`).join("\n");

    const content = `---
type: skill
name: "${skill.name.replace(/"/g, '\\"')}"
tools: [${skill.toolsUsed.map((t) => `"${t}"`).join(", ")}]
confidence: ${skill.confidence}
source_session: "${skill.sourceSession}"
tags: [claude/skill]
---

# Skill: ${skill.name}

## When to use
${skill.trigger}

## Steps
${stepsList}

## Tools Used
${toolsList}

## Files Typically Involved
${filesList || "- (none detected)"}
`;

    writeFileSync(filePath, content, "utf-8");
    createdFiles.push(filePath);
  }

  return createdFiles;
}

/**
 * Compute similarity between two skill names (0-1).
 * Uses normalized token overlap (Jaccard-like).
 */
function nameSimilarity(a: string, b: string): number {
  const tokensA = new Set(a.toLowerCase().split(/\s+/).filter((t) => t.length > 1));
  const tokensB = new Set(b.toLowerCase().split(/\s+/).filter((t) => t.length > 1));

  if (tokensA.size === 0 && tokensB.size === 0) return 1;
  if (tokensA.size === 0 || tokensB.size === 0) return 0;

  let intersection = 0;
  for (const t of tokensA) {
    if (tokensB.has(t)) intersection++;
  }

  const union = new Set([...tokensA, ...tokensB]).size;
  return intersection / union;
}
