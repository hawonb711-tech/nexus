import { readFile, writeFile, mkdir } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { randomUUID } from "node:crypto";
import type { Skill, EvolutionLog } from "./types.js";

const RETIRE_THRESHOLD = 0.3; // retire if success rate below 30%
const MIN_INTERACTIONS_FOR_RETIRE = 5;

export type SkillManager = {
  learn(interaction: { input: string; output: string; success: boolean }): Skill | null;
  match(input: string): Skill | null;
  evolve(): void;
  listSkills(): Skill[];
  getLog(): EvolutionLog;
};

type PersistedData = {
  skills: Skill[];
  totalInteractions: number;
  skillsCreated: number;
  skillsRetired: number;
  lastEvolvedAt: string;
};

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s_-]/g, " ")
    .split(/\s+/)
    .filter((t) => t.length > 2);
}

function extractActionPattern(input: string): { name: string; trigger: string; template: string } | null {
  const tokens = tokenize(input);
  if (tokens.length < 2) return null;

  // Find action verbs and their objects
  const actionVerbs = [
    "create", "build", "generate", "fix", "debug", "test", "deploy",
    "refactor", "review", "analyze", "convert", "migrate", "update",
    "add", "remove", "delete", "install", "configure", "setup",
    "optimize", "format", "lint", "validate", "check", "run",
    "explain", "document", "search", "find", "replace", "transform",
  ];

  let verb: string | null = null;
  let object: string | null = null;

  for (const token of tokens) {
    if (!verb && actionVerbs.includes(token)) {
      verb = token;
    } else if (verb && !object && token.length > 2) {
      object = token;
    }
  }

  if (!verb || !object) return null;

  // Build a trigger regex from the action pattern
  const triggerPattern = `\\b${verb}\\b.*\\b${object}\\b`;

  return {
    name: `${verb}-${object}`,
    trigger: triggerPattern,
    template: `Action: ${verb} ${object}\nSteps from learned interaction.`,
  };
}

function extractKeyPhrases(input: string): string[] {
  const phrases: string[] = [];
  // Extract quoted strings
  const quoted = input.matchAll(/["']([^"']+)["']/g);
  for (const m of quoted) phrases.push(m[1]);

  // Extract code-like identifiers
  const identifiers = input.matchAll(/`([^`]+)`/g);
  for (const m of identifiers) phrases.push(m[1]);

  return phrases;
}

async function loadData(filePath: string): Promise<PersistedData> {
  try {
    const raw = await readFile(filePath, "utf-8");
    return JSON.parse(raw) as PersistedData;
  } catch {
    return {
      skills: [],
      totalInteractions: 0,
      skillsCreated: 0,
      skillsRetired: 0,
      lastEvolvedAt: new Date().toISOString(),
    };
  }
}

async function saveData(filePath: string, data: PersistedData): Promise<void> {
  await mkdir(dirname(filePath), { recursive: true });
  await writeFile(filePath, JSON.stringify(data, null, 2), "utf-8");
}

export function createSkillManager(dataDir: string): SkillManager {
  const filePath = join(dataDir, "skills.json");

  let data: PersistedData = {
    skills: [],
    totalInteractions: 0,
    skillsCreated: 0,
    skillsRetired: 0,
    lastEvolvedAt: new Date().toISOString(),
  };

  let loaded = false;

  function ensureLoadedSync(): void {
    if (loaded) return;
    try {
      const raw = readFileSync(filePath, "utf-8");
      data = JSON.parse(raw) as PersistedData;
    } catch {
      // File doesn't exist yet — use defaults
    }
    loaded = true;
  }

  function persist(): void {
    saveData(filePath, data).catch((err) => {
      process.stderr.write(`superdev: skill persist failed: ${String(err)}\n`);
    });
  }

  return {
    learn(interaction: { input: string; output: string; success: boolean }): Skill | null {
      ensureLoadedSync();

      data.totalInteractions++;

      if (!interaction.success) {
        // Update failure count for matching skills
        const matchedSkill = this.match(interaction.input);
        if (matchedSkill) {
          const skill = data.skills.find((s) => s.id === matchedSkill.id);
          if (skill) {
            skill.failureCount++;
            skill.updatedAt = new Date().toISOString();
            persist();
          }
        }
        return null;
      }

      // Check if we already have a matching skill
      const existing = this.match(interaction.input);
      if (existing) {
        const skill = data.skills.find((s) => s.id === existing.id);
        if (skill) {
          skill.successCount++;
          skill.updatedAt = new Date().toISOString();
          persist();
        }
        return existing;
      }

      // Try to extract a new skill pattern
      const pattern = extractActionPattern(interaction.input);
      if (!pattern) return null;

      // Check for duplicate trigger patterns
      const isDuplicate = data.skills.some((s) => s.trigger === pattern.trigger);
      if (isDuplicate) return null;

      const keyPhrases = extractKeyPhrases(interaction.input);
      const description = keyPhrases.length > 0
        ? `Learned pattern for: ${pattern.name} (context: ${keyPhrases.join(", ")})`
        : `Learned pattern for: ${pattern.name}`;

      const now = new Date().toISOString();
      const newSkill: Skill = {
        id: randomUUID(),
        name: pattern.name,
        description,
        trigger: pattern.trigger,
        template: pattern.template,
        learnedFrom: interaction.input.slice(0, 200),
        successCount: 1,
        failureCount: 0,
        createdAt: now,
        updatedAt: now,
      };

      data.skills.push(newSkill);
      data.skillsCreated++;
      persist();

      return newSkill;
    },

    match(input: string): Skill | null {
      ensureLoadedSync();
      const lowerInput = input.toLowerCase();
      let bestMatch: Skill | null = null;
      let bestScore = 0;

      for (const skill of data.skills) {
        try {
          const regex = new RegExp(skill.trigger, "i");
          if (regex.test(lowerInput)) {
            // Score by success rate and specificity
            const total = skill.successCount + skill.failureCount;
            const successRate = total > 0 ? skill.successCount / total : 0.5;
            const specificity = skill.trigger.length;
            const score = successRate * specificity;

            if (score > bestScore) {
              bestScore = score;
              bestMatch = skill;
            }
          }
        } catch {
          // Invalid regex, skip
          continue;
        }
      }

      return bestMatch;
    },

    evolve(): void {
      ensureLoadedSync();
      const retired: string[] = [];

      data.skills = data.skills.filter((skill) => {
        const total = skill.successCount + skill.failureCount;
        if (total < MIN_INTERACTIONS_FOR_RETIRE) return true;

        const successRate = skill.successCount / total;
        if (successRate < RETIRE_THRESHOLD) {
          retired.push(skill.id);
          return false;
        }
        return true;
      });

      data.skillsRetired += retired.length;
      data.lastEvolvedAt = new Date().toISOString();
      persist();
    },

    listSkills(): Skill[] {
      ensureLoadedSync();
      return [...data.skills];
    },

    getLog(): EvolutionLog {
      ensureLoadedSync();
      return {
        skills: [...data.skills],
        totalInteractions: data.totalInteractions,
        skillsCreated: data.skillsCreated,
        skillsRetired: data.skillsRetired,
        lastEvolvedAt: data.lastEvolvedAt,
      };
    },
  };
}
