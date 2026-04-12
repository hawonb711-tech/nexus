/**
 * Renders EvolvedSkill objects into rich Obsidian markdown
 * with evolution timeline, drift analysis, and anti-patterns.
 */

import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { EvolvedSkill, EvolutionEntry, DriftAnalysis } from "./pattern-engine.js";

export function renderEvolvedSkillMarkdown(skill: EvolvedSkill): string {
  const lines: string[] = [];

  // Frontmatter
  lines.push("---");
  lines.push(`type: evolved-skill`);
  lines.push(`id: "${skill.id}"`);
  lines.push(`name: "${skill.name}"`);
  lines.push(`confidence: ${skill.confidence.toFixed(2)}`);
  lines.push(`occurrences: ${skill.occurrences}`);
  lines.push(`first_seen: "${skill.firstSeen.slice(0, 10)}"`);
  lines.push(`last_seen: "${skill.lastSeen.slice(0, 10)}"`);
  lines.push(`tools: [${skill.currentApproach.tools.map((t) => `"${t}"`).join(", ")}]`);
  lines.push(`tags: [claude/evolved-skill]`);
  lines.push("---");
  lines.push("");

  // Title
  lines.push(`# ${skill.name}`);
  lines.push("");
  lines.push(`> ${skill.description}`);
  lines.push(`>`);
  lines.push(`> **Confidence**: ${(skill.confidence * 100).toFixed(0)}% | **Seen**: ${skill.occurrences}x | **First**: ${skill.firstSeen.slice(0, 10)} | **Last**: ${skill.lastSeen.slice(0, 10)}`);
  lines.push("");

  // Current Best Approach
  lines.push("## Current Approach");
  lines.push("");
  if (skill.currentApproach.steps.length > 0) {
    for (let i = 0; i < skill.currentApproach.steps.length; i++) {
      lines.push(`${i + 1}. \`${skill.currentApproach.steps[i]}\``);
    }
  } else {
    lines.push("_No structured steps recorded._");
  }
  lines.push("");

  // Evolution Timeline
  if (skill.evolution.length > 1) {
    lines.push("## Evolution Timeline");
    lines.push("");
    lines.push("How this skill changed over time:");
    lines.push("");

    for (let i = 0; i < skill.evolution.length; i++) {
      const entry = skill.evolution[i];
      const outcomeEmoji = entry.outcome === "success" ? "✅"
        : entry.outcome === "failure" ? "❌"
        : entry.outcome === "partial" ? "⚠️" : "❓";

      lines.push(`### ${i + 1}. ${entry.timestamp.slice(0, 10)} ${outcomeEmoji}`);
      lines.push("");
      lines.push(`**Session**: \`${entry.sessionId.slice(0, 8)}...\``);
      lines.push(`**Context**: ${entry.contextSummary || "_no context_"}`);
      lines.push("");

      if (entry.approach.length > 0) {
        lines.push("**Steps:**");
        for (const step of entry.approach.slice(0, 10)) {
          lines.push(`- \`${step}\``);
        }
        lines.push("");
      }

      // Drift from previous
      if (entry.drift && entry.drift.changes.length > 0) {
        lines.push(renderDrift(entry.drift));
        lines.push("");
      }
    }
  }

  // Applicable Contexts
  if (skill.applicableContexts.length > 0) {
    lines.push("## When to Use");
    lines.push("");
    for (const ctx of skill.applicableContexts) {
      lines.push(`- ${ctx}`);
    }
    lines.push("");
  }

  // Anti-Patterns
  if (skill.antiPatterns.length > 0) {
    lines.push("## Anti-Patterns");
    lines.push("");
    lines.push("Approaches that didn't work:");
    lines.push("");
    for (const ap of skill.antiPatterns) {
      lines.push(`- ⚠️ ${ap}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

function renderDrift(drift: DriftAnalysis): string {
  const lines: string[] = [];

  const reasonLabel: Record<string, string> = {
    user_correction: "🔄 User corrected the approach",
    failure_recovery: "🔧 Previous approach failed, recovered",
    optimization: "⚡ Optimized method",
    scope_change: "📐 Scope changed",
    context_dependent: "🌍 Different context required different approach",
    unknown: "❔ Reason unclear",
  };

  lines.push(`> **Why it changed**: ${reasonLabel[drift.reason] ?? drift.reason} (confidence: ${(drift.confidence * 100).toFixed(0)}%)`);

  if (drift.changes.length > 0) {
    lines.push(">");
    for (const change of drift.changes) {
      lines.push(`> - **${change.aspect}**: ${change.description}`);
      lines.push(`>   - Before: \`${change.old.slice(0, 80)}\``);
      lines.push(`>   - After: \`${change.new.slice(0, 80)}\``);
    }
  }

  return lines.join("\n");
}

/**
 * Export evolved skills to Obsidian vault.
 */
export function exportEvolvedSkills(
  skills: EvolvedSkill[],
  vaultPath: string,
): string[] {
  const dir = join(vaultPath, "Evolved Skills");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  const files: string[] = [];

  for (const skill of skills) {
    const safeName = skill.name
      .replace(/[<>:"/\\|?*#^[\]]/g, "-")
      .replace(/-+/g, "-")
      .slice(0, 60);

    const filePath = join(dir, `${safeName}.md`);
    const markdown = renderEvolvedSkillMarkdown(skill);
    writeFileSync(filePath, markdown, "utf-8");
    files.push(filePath);
  }

  return files;
}
