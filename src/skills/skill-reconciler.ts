/**
 * Skill Reconciler — Evolving Knowledge Through Contradiction
 *
 * The smartest part of the system. When a new skill conflicts with
 * an existing one, it doesn't just overwrite — it asks:
 *
 * "왜 그때는 이랬는데 이번에는 이랬지?"
 *
 * Then it:
 * 1. Finds the DIFFERENCE in context that caused the change
 * 2. Creates CONDITIONAL branches: "When [X], use A; when [Y], use B"
 * 3. Keeps COMMON parts merged
 *
 * Three core mechanisms:
 *
 * A. STRICT QUALITY GATE
 *    - Won't create a skill if context is unclear
 *    - Requires minimum understanding confidence
 *    - Rejects noise, ambiguity, and too-specific patterns
 *
 * B. PREFERENCE LEARNING
 *    - "이 상황에서는 A보다 B가 효율적"
 *    - Tracks which approaches were chosen over alternatives
 *    - Builds preference rankings per situation type
 *
 * C. SKILL RECONCILIATION
 *    - Detects when new wisdom contradicts existing
 *    - Finds the contextual difference that explains the change
 *    - Splits into conditional branches or merges common ground
 */

import type { Wisdom, WisdomBody } from "./wisdom-extractor.js";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

/** A refined skill with conditional branches. */
export type RefinedSkill = {
  id: string;
  /** Core topic this skill covers. */
  topic: string;
  /** What all branches share in common. */
  commonGround: string;
  /** Conditional branches: different approaches for different contexts. */
  branches: SkillBranch[];
  /** Learned preferences: "A > B when [condition]". */
  preferences: Preference[];
  /** How many times this skill was validated. */
  validations: number;
  /** Overall confidence. */
  confidence: number;
  /** Domain tags. */
  domains: string[];
  /** Version: increments on each reconciliation. */
  version: number;
  createdAt: string;
  updatedAt: string;
};

export type SkillBranch = {
  /** When does this branch apply? */
  condition: string;
  /** What to do. */
  approach: string;
  /** Why this approach for this condition. */
  rationale: string;
  /** Source wisdom IDs that support this branch. */
  sources: string[];
  /** Success count for this branch. */
  successCount: number;
  /** Failure count. */
  failureCount: number;
};

export type Preference = {
  /** The situation. */
  situation: string;
  /** Preferred approach. */
  preferred: string;
  /** Less preferred approach. */
  overWhat: string;
  /** Why preferred. */
  reason: string;
  /** How many times this preference was confirmed. */
  confirmations: number;
};

export type ReconciliationResult = {
  /** New skills created. */
  created: RefinedSkill[];
  /** Existing skills updated (new branch added). */
  updated: RefinedSkill[];
  /** Wisdoms rejected by quality gate. */
  rejected: { wisdom: Wisdom; reason: string }[];
  /** Preferences learned. */
  preferencesLearned: Preference[];
};

export type SkillLibrary = {
  skills: RefinedSkill[];
  version: number;
  updatedAt: string;
};

// ═══════════════════════════════════════════════════════════════════
// STRICT QUALITY GATE
// ═══════════════════════════════════════════════════════════════════

type QualityCheck = { pass: boolean; reason: string };

function qualityGate(wisdom: Wisdom): QualityCheck {
  const { body } = wisdom;

  // 1. Situation must be meaningful (not "일반적인 상황")
  if (!body.situation || body.situation === "일반적인 상황" || body.situation.length < 5) {
    return { pass: false, reason: "situation too vague — can't determine when this applies" };
  }

  // 2. Approach must be substantive
  if (!body.approach || body.approach.length < 10) {
    return { pass: false, reason: "approach too short — not enough information to be useful" };
  }

  // 3. Reason must exist
  if (!body.reason || body.reason.length < 5) {
    return { pass: false, reason: "no clear reason — can't learn without understanding why" };
  }

  // 4. Must not be system noise
  const noisePatterns = [
    /task-notification/i, /system-reminder/i, /<[a-z]/i,
    /\[result-id/i, /tool loaded/i, /Using Node/i,
    /npm warn/i, /npm notice/i, /npm error/i,
  ];
  const allText = `${body.situation} ${body.approach} ${body.reason}`;
  if (noisePatterns.some((p) => p.test(allText))) {
    return { pass: false, reason: "contains system noise — not a real interaction" };
  }

  // 5. Confidence must be above threshold
  if (wisdom.confidence < 0.5) {
    return { pass: false, reason: `confidence too low (${(wisdom.confidence * 100).toFixed(0)}% < 50%)` };
  }

  // 6. Must have at least one domain
  if (wisdom.domains.length === 0) {
    return { pass: false, reason: "no domain identified — too generic to be useful" };
  }

  // 7. Situation and approach must be different (not circular)
  const situationWords = new Set(tokenize(body.situation));
  const approachWords = new Set(tokenize(body.approach));
  const overlap = [...situationWords].filter((w) => approachWords.has(w)).length;
  const overlapRatio = overlap / Math.max(situationWords.size, 1);
  if (overlapRatio > 0.8) {
    return { pass: false, reason: "situation and approach are too similar — circular wisdom" };
  }

  return { pass: true, reason: "passed all quality checks" };
}

// ═══════════════════════════════════════════════════════════════════
// SIMILARITY MATCHING
// ═══════════════════════════════════════════════════════════════════

function computeTopicSimilarity(a: string, b: string): number {
  const aTokens = new Set(tokenize(a));
  const bTokens = new Set(tokenize(b));
  if (aTokens.size === 0 || bTokens.size === 0) return 0;

  const intersection = [...aTokens].filter((t) => bTokens.has(t)).length;
  const union = new Set([...aTokens, ...bTokens]).size;
  return intersection / union; // Jaccard
}

function findSimilarSkill(
  wisdom: Wisdom,
  library: SkillLibrary,
  threshold = 0.25,
): RefinedSkill | null {
  let bestMatch: RefinedSkill | null = null;
  let bestSimilarity = 0;

  for (const skill of library.skills) {
    // Compare topic similarity
    const topicSim = computeTopicSimilarity(wisdom.body.situation, skill.topic);

    // Compare domain overlap
    const domainOverlap = wisdom.domains.filter((d) =>
      skill.domains.includes(d),
    ).length / Math.max(wisdom.domains.length, 1);

    // Combined score
    const similarity = topicSim * 0.6 + domainOverlap * 0.4;

    if (similarity > bestSimilarity && similarity >= threshold) {
      bestSimilarity = similarity;
      bestMatch = skill;
    }
  }

  return bestMatch;
}

// ═══════════════════════════════════════════════════════════════════
// DIFFERENCE ANALYSIS
// ═══════════════════════════════════════════════════════════════════

type DifferenceAnalysis = {
  /** What's different in the context. */
  contextDifference: string;
  /** What's different in the approach. */
  approachDifference: string;
  /** What's the same. */
  commonGround: string;
  /** Is this a genuine contradiction or just a different context? */
  type: "contradiction" | "context_dependent" | "evolution" | "complementary";
};

function analyzeDifference(
  existingSkill: RefinedSkill,
  newWisdom: Wisdom,
): DifferenceAnalysis {
  const existingApproaches = existingSkill.branches.map((b) => b.approach).join(" ");
  const newApproach = newWisdom.body.approach;

  // Find common words
  const existingWords = new Set(tokenize(existingApproaches));
  const newWords = new Set(tokenize(newApproach));
  const common = [...existingWords].filter((w) => newWords.has(w));
  const onlyExisting = [...existingWords].filter((w) => !newWords.has(w));
  const onlyNew = [...newWords].filter((w) => !existingWords.has(w));

  const commonGround = common.length > 0
    ? `공통: ${common.slice(0, 5).join(", ")}`
    : "공통점 없음";

  const approachDifference = onlyNew.length > 0
    ? `새로운 접근: ${onlyNew.slice(0, 5).join(", ")}`
    : "접근법 동일";

  // Determine the context difference
  const existingConditions = existingSkill.branches.map((b) => b.condition).join(" ");
  const newContext = newWisdom.body.situation;
  const contextWords = tokenize(newContext).filter(
    (w) => !new Set(tokenize(existingConditions)).has(w),
  );
  const contextDifference = contextWords.length > 0
    ? contextWords.slice(0, 5).join(", ")
    : "맥락 차이 불명확";

  // Classify the type of difference
  let type: DifferenceAnalysis["type"] = "context_dependent";

  // If approaches are very different but context is similar → contradiction
  const approachOverlap = common.length / Math.max(existingWords.size, newWords.size, 1);
  if (approachOverlap < 0.2) {
    const contextOverlap = computeTopicSimilarity(existingConditions, newContext);
    if (contextOverlap > 0.5) {
      type = "contradiction";
    } else {
      type = "context_dependent";
    }
  }

  // If new approach is a superset of existing → evolution
  if (onlyNew.length > 0 && onlyExisting.length === 0) {
    type = "evolution";
  }

  // If approaches are different but non-overlapping domains → complementary
  if (approachOverlap < 0.3) {
    const domainOverlap = newWisdom.domains.filter((d) =>
      existingSkill.domains.includes(d),
    ).length;
    if (domainOverlap === 0) type = "complementary";
  }

  return { contextDifference, approachDifference, commonGround, type };
}

// ═══════════════════════════════════════════════════════════════════
// RECONCILIATION
// ═══════════════════════════════════════════════════════════════════

function reconcileWithExisting(
  existingSkill: RefinedSkill,
  newWisdom: Wisdom,
): { skill: RefinedSkill; preference?: Preference } {
  const diff = analyzeDifference(existingSkill, newWisdom);
  const updated = { ...existingSkill };
  let preference: Preference | undefined;

  switch (diff.type) {
    case "context_dependent": {
      // Add a new conditional branch
      updated.branches.push({
        condition: newWisdom.body.situation,
        approach: newWisdom.body.approach,
        rationale: `${newWisdom.body.reason} (맥락 차이: ${diff.contextDifference})`,
        sources: [newWisdom.id],
        successCount: newWisdom.type === "principle" ? 1 : 0,
        failureCount: newWisdom.type === "warning" ? 1 : 0,
      });
      updated.commonGround = diff.commonGround;
      break;
    }

    case "contradiction": {
      // The new approach contradicts the old one for similar contexts
      // → Create a preference: new > old (because it's more recent = learned from mistake)
      const existingBranch = updated.branches[updated.branches.length - 1];
      preference = {
        situation: newWisdom.body.situation,
        preferred: newWisdom.body.approach,
        overWhat: existingBranch?.approach ?? "이전 접근법",
        reason: `더 최신 경험에서 학습: ${newWisdom.body.reason}`,
        confirmations: 1,
      };

      // Update existing branch or add new one
      if (existingBranch) {
        existingBranch.failureCount++;
      }
      updated.branches.push({
        condition: `${newWisdom.body.situation} (개선된 접근)`,
        approach: newWisdom.body.approach,
        rationale: `이전 접근법(${existingBranch?.approach.slice(0, 30) ?? "?"})이 비효율적이어서 변경: ${newWisdom.body.reason}`,
        sources: [newWisdom.id],
        successCount: 1,
        failureCount: 0,
      });
      updated.preferences.push(preference);
      break;
    }

    case "evolution": {
      // New approach is an improvement — update the latest branch
      const lastBranch = updated.branches[updated.branches.length - 1];
      if (lastBranch) {
        lastBranch.approach = `${lastBranch.approach}\n→ 개선: ${newWisdom.body.approach}`;
        lastBranch.rationale += ` → 진화: ${newWisdom.body.reason}`;
        lastBranch.sources.push(newWisdom.id);
        lastBranch.successCount++;
      }
      break;
    }

    case "complementary": {
      // Different domain, just add as a new branch
      updated.branches.push({
        condition: newWisdom.body.situation,
        approach: newWisdom.body.approach,
        rationale: newWisdom.body.reason,
        sources: [newWisdom.id],
        successCount: 1,
        failureCount: 0,
      });
      // Merge domains
      for (const d of newWisdom.domains) {
        if (!updated.domains.includes(d)) updated.domains.push(d);
      }
      break;
    }
  }

  updated.version++;
  updated.updatedAt = new Date().toISOString();
  updated.validations++;

  // Recalculate confidence
  const totalSuccess = updated.branches.reduce((s, b) => s + b.successCount, 0);
  const totalFailure = updated.branches.reduce((s, b) => s + b.failureCount, 0);
  const total = totalSuccess + totalFailure;
  updated.confidence = total > 0
    ? Math.min(0.95, 0.3 + (totalSuccess / total) * 0.5 + updated.validations * 0.05)
    : updated.confidence;

  return { skill: updated, preference };
}

function createNewSkill(wisdom: Wisdom): RefinedSkill {
  return {
    id: createHash("sha256").update(wisdom.id + wisdom.body.situation).digest("hex").slice(0, 12),
    topic: wisdom.body.situation,
    commonGround: wisdom.body.approach,
    branches: [{
      condition: wisdom.body.situation,
      approach: wisdom.body.approach,
      rationale: wisdom.body.reason,
      sources: [wisdom.id],
      successCount: wisdom.type === "principle" ? 1 : 0,
      failureCount: wisdom.type === "warning" ? 1 : 0,
    }],
    preferences: [],
    validations: 1,
    confidence: wisdom.confidence,
    domains: [...wisdom.domains],
    version: 1,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

// ═══════════════════════════════════════════════════════════════════
// MAIN PIPELINE
// ═══════════════════════════════════════════════════════════════════

export function reconcileWisdom(
  wisdoms: Wisdom[],
  library: SkillLibrary,
): ReconciliationResult {
  const result: ReconciliationResult = {
    created: [],
    updated: [],
    rejected: [],
    preferencesLearned: [],
  };

  for (const wisdom of wisdoms) {
    // Step 1: Quality gate
    const quality = qualityGate(wisdom);
    if (!quality.pass) {
      result.rejected.push({ wisdom, reason: quality.reason });
      continue;
    }

    // Step 2: Find similar existing skill
    const existing = findSimilarSkill(wisdom, library);

    if (existing) {
      // Step 3a: Reconcile with existing
      const { skill: updated, preference } = reconcileWithExisting(existing, wisdom);

      // Replace in library
      const idx = library.skills.indexOf(existing);
      if (idx >= 0) library.skills[idx] = updated;
      result.updated.push(updated);

      if (preference) {
        result.preferencesLearned.push(preference);
      }
    } else {
      // Step 3b: Create new skill
      const newSkill = createNewSkill(wisdom);
      library.skills.push(newSkill);
      result.created.push(newSkill);
    }
  }

  library.version++;
  library.updatedAt = new Date().toISOString();

  return result;
}

// ═══════════════════════════════════════════════════════════════════
// PERSISTENCE
// ═══════════════════════════════════════════════════════════════════

export function loadRefinedLibrary(dataDir: string): SkillLibrary {
  const filePath = join(dataDir, "refined-skills.json");
  if (existsSync(filePath)) {
    return JSON.parse(readFileSync(filePath, "utf-8")) as SkillLibrary;
  }
  return { skills: [], version: 1, updatedAt: new Date().toISOString() };
}

export function saveRefinedLibrary(library: SkillLibrary, dataDir: string): void {
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(
    join(dataDir, "refined-skills.json"),
    JSON.stringify(library, null, 2),
    "utf-8",
  );
}

// ═══════════════════════════════════════════════════════════════════
// OBSIDIAN RENDERER
// ═══════════════════════════════════════════════════════════════════

export function renderRefinedSkillMarkdown(skill: RefinedSkill): string {
  const lines: string[] = [];

  lines.push("---");
  lines.push(`type: refined-skill`);
  lines.push(`topic: "${skill.topic.slice(0, 60)}"`);
  lines.push(`confidence: ${skill.confidence.toFixed(2)}`);
  lines.push(`version: ${skill.version}`);
  lines.push(`branches: ${skill.branches.length}`);
  lines.push(`validations: ${skill.validations}`);
  lines.push(`domains: [${skill.domains.map((d) => `"${d}"`).join(", ")}]`);
  lines.push(`tags: [claude/refined-skill]`);
  lines.push("---");
  lines.push("");
  lines.push(`# ${skill.topic.slice(0, 60)}`);
  lines.push("");
  lines.push(`> 확신도: ${(skill.confidence * 100).toFixed(0)}% | 버전: ${skill.version} | 검증: ${skill.validations}회`);
  lines.push("");

  // Common ground
  if (skill.commonGround) {
    lines.push("## 공통 원칙");
    lines.push("");
    lines.push(skill.commonGround);
    lines.push("");
  }

  // Conditional branches
  if (skill.branches.length > 1) {
    lines.push("## 상황별 접근법");
    lines.push("");
    lines.push("같은 주제라도 상황에 따라 접근법이 다릅니다:");
    lines.push("");

    for (let i = 0; i < skill.branches.length; i++) {
      const branch = skill.branches[i];
      const successRate = branch.successCount + branch.failureCount > 0
        ? (branch.successCount / (branch.successCount + branch.failureCount) * 100).toFixed(0)
        : "N/A";

      lines.push(`### ${i + 1}. ${branch.condition.slice(0, 60)}`);
      lines.push("");
      lines.push(`**접근법**: ${branch.approach}`);
      lines.push("");
      lines.push(`**이유**: ${branch.rationale}`);
      lines.push("");
      lines.push(`> 성공률: ${successRate}%`);
      lines.push("");
    }
  } else if (skill.branches.length === 1) {
    const branch = skill.branches[0];
    lines.push("## 접근법");
    lines.push("");
    lines.push(branch.approach);
    lines.push("");
    lines.push("## 이유");
    lines.push("");
    lines.push(branch.rationale);
    lines.push("");
  }

  // Preferences
  if (skill.preferences.length > 0) {
    lines.push("## 학습된 선호도");
    lines.push("");
    for (const pref of skill.preferences) {
      lines.push(`- **${pref.situation.slice(0, 50)}**에서:`);
      lines.push(`  - ✅ **${pref.preferred.slice(0, 50)}** 선호`);
      lines.push(`  - ❌ ~~${pref.overWhat.slice(0, 50)}~~ 비선호`);
      lines.push(`  - 이유: ${pref.reason.slice(0, 80)}`);
      lines.push(`  - 확인: ${pref.confirmations}회`);
      lines.push("");
    }
  }

  return lines.join("\n");
}

export function exportRefinedSkills(library: SkillLibrary, vaultPath: string): string[] {
  const dir = join(vaultPath, "Refined Skills");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  const files: string[] = [];
  for (const skill of library.skills) {
    const safeName = skill.topic
      .replace(/[<>:"/\\|?*#^[\]]/g, "-")
      .replace(/-+/g, "-")
      .slice(0, 60);
    const filePath = join(dir, `${safeName}.md`);
    writeFileSync(filePath, renderRefinedSkillMarkdown(skill), "utf-8");
    files.push(filePath);
  }
  return files;
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z가-힣0-9\s]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 2);
}
