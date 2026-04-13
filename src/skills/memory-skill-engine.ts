/**
 * Memory-Based Skill Engine
 *
 * Instead of extracting skills from individual sessions (weak),
 * this engine discovers skills from ACCUMULATED MEMORY across all sessions.
 *
 * Key insight: A skill isn't what happened once — it's what happened
 * REPEATEDLY across different contexts. If the same approach appears
 * 3+ times in different sessions, it's a genuine reusable pattern.
 *
 * Process:
 * 1. INGEST — All sessions → atomic observations in nexus memory
 * 2. CLUSTER — Group similar observations using semantic similarity
 * 3. FREQUENCY — Patterns that appear 3+ times = skill candidates
 * 4. ABSTRACT — Extract the common principle from the cluster
 * 5. BRANCH — If same topic has different approaches, find the condition
 * 6. VALIDATE — Cross-check: does this skill hold across contexts?
 *
 * This leverages our BM25 + semantic + knowledge graph memory engine
 * to do what raw regex/keyword extraction can't.
 */

import type { ParsedSession, ParsedMessage } from "../parser/types.js";
import type { Observation, NexusMemory, KnowledgeNode } from "../memory-engine/nexus-memory.js";
import { createNexusMemory } from "../memory-engine/nexus-memory.js";
import { semanticSimilarity, getSynonyms } from "../memory-engine/semantic.js";
import { createHash } from "node:crypto";

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export type MemorySkill = {
  id: string;
  /** Clear, actionable name. */
  name: string;
  /** When to use this skill. */
  situation: string;
  /** The principle / approach. */
  principle: string;
  /** Why this works (derived from evidence). */
  reasoning: string;
  /** Conditions that change the approach. */
  conditions: SkillCondition[];
  /** What NOT to do (from contradicting observations). */
  antiPatterns: string[];
  /** How many observations support this. */
  evidenceCount: number;
  /** Source domains (projects/contexts). */
  domains: string[];
  /** Tools typically involved. */
  tools: string[];
  /** Confidence 0-1. */
  confidence: number;
  /** When first/last observed. */
  firstSeen: string;
  lastSeen: string;
};

export type SkillCondition = {
  /** When this condition is true... */
  when: string;
  /** ...use this approach instead. */
  approach: string;
  /** Evidence count for this branch. */
  evidence: number;
};

export type ObservationCluster = {
  /** Cluster centroid (representative observation). */
  centroid: Observation;
  /** All observations in this cluster. */
  members: Observation[];
  /** Common keywords across all members. */
  commonKeywords: string[];
  /** Common tools. */
  commonTools: string[];
  /** Unique domains represented. */
  domains: Set<string>;
  /** Average confidence. */
  avgConfidence: number;
};

export type SkillExtractionResult = {
  /** Skills discovered. */
  skills: MemorySkill[];
  /** Observations ingested. */
  observationsIngested: number;
  /** Clusters formed. */
  clustersFormed: number;
  /** Clusters that became skills. */
  clustersPromoted: number;
  /** Duration in ms. */
  durationMs: number;
};

// ═══════════════════════════════════════════════════════════════════
// STEP 1: INGEST — Sessions → Observations
// ═══════════════════════════════════════════════════════════════════

/**
 * Extract meaningful observations from a session.
 * Focuses on ACTIONS taken and OUTCOMES observed, not raw chat.
 */
function extractActionObservations(session: ParsedSession): {
  text: string;
  domain: string;
  tags: string[];
}[] {
  const observations: { text: string; domain: string; tags: string[] }[] = [];
  const domain = session.cwd?.split("/").pop() ?? session.projectPath.split("/").pop() ?? "unknown";
  const messages = session.messages;

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];

    // Skip noise
    if (msg.content.startsWith("<") || msg.content.startsWith("{")) continue;
    if (msg.content.length < 20) continue;

    // Pattern 1: User asked + Claude used tools → the approach is the observation
    if (msg.role === "assistant" && msg.toolCalls && msg.toolCalls.length >= 2) {
      const userRequest = findPreviousUserMessage(messages, i);
      if (!userRequest || userRequest.length < 10) continue;

      const tools = msg.toolCalls.map((tc) => tc.name);
      const uniqueTools = [...new Set(tools)];
      const approach = describeApproach(msg.toolCalls);

      if (approach.length > 20) {
        observations.push({
          text: `상황: ${userRequest.slice(0, 100)} → 접근: ${approach}`,
          domain,
          tags: [...uniqueTools.map((t) => t.toLowerCase()), ...extractTags(userRequest)],
        });
      }
    }

    // Pattern 2: User correction → the corrected approach is valuable
    if (msg.role === "user" && isCorrection(msg.content)) {
      const prevAssistant = findPreviousAssistantMessage(messages, i);
      const nextAssistant = findNextAssistantMessage(messages, i);

      if (prevAssistant && nextAssistant) {
        const wrongApproach = describeMessage(prevAssistant);
        const rightApproach = describeMessage(nextAssistant);

        if (wrongApproach.length > 10 && rightApproach.length > 10) {
          observations.push({
            text: `주의: "${wrongApproach.slice(0, 60)}" 대신 "${rightApproach.slice(0, 60)}"가 효과적. 유저 피드백: "${msg.content.slice(0, 50)}"`,
            domain,
            tags: ["correction", ...extractTags(msg.content)],
          });
        }
      }
    }

    // Pattern 3: Error → Recovery → the recovery method is the observation
    if (msg.role === "assistant" && msg.toolCalls) {
      const hasError = msg.toolCalls.some((tc) =>
        tc.result && /error|fail|denied|not found/i.test(tc.result),
      );

      if (hasError) {
        // Look for recovery
        for (let j = i + 1; j < Math.min(i + 4, messages.length); j++) {
          const candidate = messages[j];
          if (candidate.role === "assistant" && candidate.toolCalls?.length) {
            const success = candidate.toolCalls.every((tc) =>
              !tc.result || !/error|fail/i.test(tc.result),
            );
            if (success) {
              const errorTool = msg.toolCalls.find((tc) => tc.result && /error/i.test(tc.result));
              const recoveryApproach = describeApproach(candidate.toolCalls);
              observations.push({
                text: `에러 복구: ${errorTool?.name ?? "도구"} 실패 후 ${recoveryApproach}로 해결`,
                domain,
                tags: ["error-recovery", ...extractTags(recoveryApproach)],
              });
              break;
            }
          }
        }
      }
    }

    // Pattern 4: Successful multi-step task (positive feedback follows tools)
    if (msg.role === "user" && isPositiveFeedback(msg.content) && i > 0) {
      const prevAssistant = messages[i - 1];
      if (prevAssistant?.role === "assistant" && prevAssistant.toolCalls && prevAssistant.toolCalls.length >= 2) {
        const userRequest = findPreviousUserMessage(messages, i - 1);
        const approach = describeApproach(prevAssistant.toolCalls);

        if (userRequest && approach.length > 20) {
          observations.push({
            text: `검증됨: "${userRequest.slice(0, 60)}" 요청에 ${approach} 접근이 성공적`,
            domain,
            tags: ["validated", ...extractTags(approach)],
          });
        }
      }
    }
  }

  return observations;
}

// ═══════════════════════════════════════════════════════════════════
// STEP 2: CLUSTER — Group similar observations
// ═══════════════════════════════════════════════════════════════════

function clusterObservations(
  memory: NexusMemory,
  minClusterSize: number,
): ObservationCluster[] {
  const stats = memory.getStats();
  if (stats.validObservations < minClusterSize) return [];

  // Get all valid observations via L1 scan
  const allObs = memory.scanIndex();
  const clusters: ObservationCluster[] = [];
  const assigned = new Set<string>();

  // For each observation, find its semantic neighbors
  for (const obs of allObs) {
    if (assigned.has(obs.id)) continue;

    // Search for similar observations
    const results = memory.search(obs.content, 20);
    const neighbors = results
      .filter((r) => r.score > 0.3 && !assigned.has(r.observation.id))
      .map((r) => r.observation);

    if (neighbors.length < minClusterSize - 1) continue; // Not enough similar observations

    // Form cluster
    const members = [obs, ...neighbors];
    for (const m of members) assigned.add(m.id);

    // Find common keywords
    const keywordCounts = new Map<string, number>();
    for (const m of members) {
      const words = tokenize(m.content);
      const unique = new Set(words);
      for (const w of unique) {
        keywordCounts.set(w, (keywordCounts.get(w) ?? 0) + 1);
      }
    }
    const commonKeywords = [...keywordCounts.entries()]
      .filter(([, count]) => count >= Math.ceil(members.length * 0.5))
      .sort(([, a], [, b]) => b - a)
      .map(([word]) => word)
      .slice(0, 10);

    // Collect tools and domains
    const commonTools = [...new Set(members.flatMap((m) => m.tags.filter((t) =>
      ["bash", "edit", "read", "write", "grep", "agent", "websearch"].includes(t),
    )))];

    const domains = new Set(members.map((m) => m.domain));

    clusters.push({
      centroid: obs,
      members,
      commonKeywords,
      commonTools,
      domains,
      avgConfidence: members.reduce((s, m) => s + m.confidence, 0) / members.length,
    });
  }

  return clusters.sort((a, b) => b.members.length - a.members.length);
}

// ═══════════════════════════════════════════════════════════════════
// STEP 3-6: ABSTRACT, BRANCH, VALIDATE → Skill
// ═══════════════════════════════════════════════════════════════════

function clusterToSkill(cluster: ObservationCluster): MemorySkill | null {
  const { members, commonKeywords, commonTools, domains } = cluster;

  if (members.length < 2) return null;
  if (commonKeywords.length < 2) return null;

  // ABSTRACT: Build the skill name and principle from common patterns
  const name = buildSkillName(commonKeywords, commonTools);
  const situation = buildSituation(members);
  const principle = buildPrinciple(members);
  const reasoning = buildReasoning(members);

  if (!name || !principle || principle.length < 15) return null;

  // BRANCH: Find conditions where approach differs
  const conditions = findConditions(members);

  // VALIDATE: Anti-patterns from corrections/errors
  const antiPatterns = members
    .filter((m) => m.content.includes("주의:") || m.content.includes("대신"))
    .map((m) => {
      const match = m.content.match(/주의:\s*"([^"]+)"/);
      return match ? match[1] : m.content.slice(0, 60);
    })
    .slice(0, 3);

  const timestamps = members.map((m) => m.createdAt).sort();

  // Confidence: more members + more domains + validated = higher
  const validated = members.filter((m) => m.tags.includes("validated")).length;
  const confidence = Math.min(0.95,
    0.2 +
    members.length * 0.05 +
    domains.size * 0.1 +
    validated * 0.15 +
    (antiPatterns.length > 0 ? 0.1 : 0),
  );

  return {
    id: createHash("sha256").update(name + situation).digest("hex").slice(0, 12),
    name,
    situation,
    principle,
    reasoning,
    conditions,
    antiPatterns,
    evidenceCount: members.length,
    domains: [...domains],
    tools: commonTools,
    confidence,
    firstSeen: timestamps[0] ?? "",
    lastSeen: timestamps[timestamps.length - 1] ?? "",
  };
}

function buildSkillName(keywords: string[], tools: string[]): string {
  // Take top 2-3 meaningful keywords as the skill name
  const meaningful = keywords.filter((k) => k.length > 3).slice(0, 3);
  if (meaningful.length === 0) return "";

  const toolStr = tools.length > 0 ? ` (${tools.slice(0, 2).join(", ")})` : "";
  return `${meaningful.join(" + ")}${toolStr}`;
}

function buildSituation(members: Observation[]): string {
  // Extract "상황:" parts from observations
  const situations: string[] = [];
  for (const m of members) {
    const match = m.content.match(/상황:\s*(.{10,80}?)(?:\s*→|$)/);
    if (match) situations.push(match[1].trim());
  }

  if (situations.length > 0) {
    // Find common prefix/theme across situations
    return situations[0].slice(0, 80);
  }

  // Fallback: use common topic
  return members[0].topic ?? "일반적인 개발 상황";
}

function buildPrinciple(members: Observation[]): string {
  // Extract "접근:" parts, find the most common one
  const approaches = new Map<string, number>();
  for (const m of members) {
    const match = m.content.match(/접근:\s*(.{10,100})/);
    if (match) {
      const approach = match[1].trim();
      approaches.set(approach, (approaches.get(approach) ?? 0) + 1);
    }
  }

  if (approaches.size > 0) {
    // Return most frequent approach
    const sorted = [...approaches.entries()].sort(([, a], [, b]) => b - a);
    return sorted[0][0];
  }

  // Fallback: use the validated observation if any
  const validated = members.find((m) => m.tags.includes("validated"));
  if (validated) return validated.content.slice(0, 150);

  return members[0].content.slice(0, 150);
}

function buildReasoning(members: Observation[]): string {
  const reasons: string[] = [];

  // From error recoveries
  const recoveries = members.filter((m) => m.tags.includes("error-recovery"));
  if (recoveries.length > 0) {
    reasons.push(`${recoveries.length}회 에러 복구 경험에서 학습`);
  }

  // From validations
  const validations = members.filter((m) => m.tags.includes("validated"));
  if (validations.length > 0) {
    reasons.push(`${validations.length}회 성공 확인됨`);
  }

  // From corrections
  const corrections = members.filter((m) => m.tags.includes("correction"));
  if (corrections.length > 0) {
    reasons.push(`${corrections.length}회 유저 수정 피드백 반영`);
  }

  // Cross-domain
  const domains = new Set(members.map((m) => m.domain));
  if (domains.size > 1) {
    reasons.push(`${domains.size}개 프로젝트에서 반복 확인`);
  }

  return reasons.length > 0
    ? reasons.join(". ") + "."
    : `${members.length}개 관찰에서 공통 패턴 발견`;
}

function findConditions(members: Observation[]): SkillCondition[] {
  const conditions: SkillCondition[] = [];

  // Group by domain and check if approaches differ
  const byDomain = new Map<string, Observation[]>();
  for (const m of members) {
    if (!byDomain.has(m.domain)) byDomain.set(m.domain, []);
    byDomain.get(m.domain)!.push(m);
  }

  if (byDomain.size < 2) return conditions;

  // Check if different domains have different approaches
  const domainApproaches = new Map<string, string>();
  for (const [domain, obs] of byDomain) {
    const approach = obs[0].content.match(/접근:\s*(.{10,80})/)?.[1] ?? obs[0].content.slice(0, 60);
    domainApproaches.set(domain, approach);
  }

  // Find divergent approaches
  const approaches = [...domainApproaches.values()];
  const first = approaches[0];
  for (const [domain, approach] of domainApproaches) {
    if (semanticSimilarity(first, approach) < 0.3) {
      conditions.push({
        when: `${domain} 프로젝트 컨텍스트`,
        approach: approach.slice(0, 100),
        evidence: byDomain.get(domain)?.length ?? 0,
      });
    }
  }

  return conditions;
}

// ═══════════════════════════════════════════════════════════════════
// MAIN PIPELINE
// ═══════════════════════════════════════════════════════════════════

/**
 * Full memory-based skill extraction pipeline.
 *
 * 1. Ingest all sessions into nexus memory
 * 2. Cluster similar observations
 * 3. Promote clusters with 3+ members to skills
 */
export function extractMemorySkills(
  sessions: ParsedSession[],
  dataDir: string,
  minClusterSize = 3,
): SkillExtractionResult {
  const start = performance.now();
  const memory = createNexusMemory(dataDir);

  // Step 1: Ingest all sessions
  let totalIngested = 0;
  for (const session of sessions) {
    const observations = extractActionObservations(session);
    for (const obs of observations) {
      const count = memory.ingest(obs.text, obs.domain, session.sessionId);
      totalIngested += count;
    }
  }
  memory.save();

  // Step 2: Cluster
  const clusters = clusterObservations(memory, minClusterSize);

  // Step 3-6: Convert clusters to skills
  const skills: MemorySkill[] = [];
  for (const cluster of clusters) {
    const skill = clusterToSkill(cluster);
    if (skill) skills.push(skill);
  }

  const durationMs = Math.round(performance.now() - start);

  return {
    skills: skills.sort((a, b) => b.confidence - a.confidence),
    observationsIngested: totalIngested,
    clustersFormed: clusters.length,
    clustersPromoted: skills.length,
    durationMs,
  };
}

// ═══════════════════════════════════════════════════════════════════
// OBSIDIAN RENDERER
// ═══════════════════════════════════════════════════════════════════

export function renderMemorySkillMarkdown(skill: MemorySkill): string {
  const lines: string[] = [];

  lines.push("---");
  lines.push(`type: memory-skill`);
  lines.push(`name: "${skill.name.slice(0, 60)}"`);
  lines.push(`confidence: ${skill.confidence.toFixed(2)}`);
  lines.push(`evidence: ${skill.evidenceCount}`);
  lines.push(`domains: [${skill.domains.map((d) => `"${d}"`).join(", ")}]`);
  lines.push(`tools: [${skill.tools.map((t) => `"${t}"`).join(", ")}]`);
  lines.push(`tags: [nexus/skill]`);
  lines.push("---");
  lines.push("");
  lines.push(`# ${skill.name}`);
  lines.push("");
  lines.push(`> 확신도: ${(skill.confidence * 100).toFixed(0)}% | 증거: ${skill.evidenceCount}개 | 도메인: ${skill.domains.join(", ")}`);
  lines.push("");

  lines.push("## 상황");
  lines.push("");
  lines.push(skill.situation);
  lines.push("");

  lines.push("## 원칙");
  lines.push("");
  lines.push(skill.principle);
  lines.push("");

  lines.push("## 이유");
  lines.push("");
  lines.push(skill.reasoning);
  lines.push("");

  if (skill.conditions.length > 0) {
    lines.push("## 조건별 분기");
    lines.push("");
    for (const cond of skill.conditions) {
      lines.push(`- **${cond.when}**: ${cond.approach} (증거 ${cond.evidence}개)`);
    }
    lines.push("");
  }

  if (skill.antiPatterns.length > 0) {
    lines.push("## 하지 말 것");
    lines.push("");
    for (const ap of skill.antiPatterns) {
      lines.push(`- ~~${ap}~~`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

import { STOP_WORDS } from "../shared/stop-words.js";

function tokenize(text: string): string[] {
  return text.toLowerCase().replace(/[^a-z가-힣0-9\s]/g, " ").split(/\s+/)
    .filter((w) => w.length > 2 && !STOP_WORDS.has(w));
}

function findPreviousUserMessage(messages: ParsedMessage[], index: number): string | null {
  for (let i = index - 1; i >= Math.max(0, index - 4); i--) {
    if (messages[i].role === "user" && messages[i].content.length > 10) {
      if (messages[i].content.startsWith("<")) continue;
      return messages[i].content;
    }
  }
  return null;
}

function findPreviousAssistantMessage(messages: ParsedMessage[], index: number): ParsedMessage | null {
  for (let i = index - 1; i >= Math.max(0, index - 3); i--) {
    if (messages[i].role === "assistant" && messages[i].content.length > 10) return messages[i];
  }
  return null;
}

function findNextAssistantMessage(messages: ParsedMessage[], index: number): ParsedMessage | null {
  for (let i = index + 1; i < Math.min(index + 4, messages.length); i++) {
    if (messages[i].role === "assistant" && messages[i].content.length > 10) return messages[i];
  }
  return null;
}

function describeApproach(toolCalls: { name: string; input: Record<string, unknown> }[]): string {
  const steps: string[] = [];
  const seen = new Set<string>();

  for (const tc of toolCalls) {
    if (seen.has(tc.name)) continue;
    seen.add(tc.name);

    switch (tc.name) {
      case "Bash": steps.push("명령어로 상태 확인"); break;
      case "Read": steps.push("파일 구조 파악"); break;
      case "Grep": steps.push("패턴 검색"); break;
      case "Edit": steps.push("코드 수정"); break;
      case "Write": steps.push("새 파일 생성"); break;
      case "Agent": steps.push("에이전트 위임"); break;
      case "WebSearch": steps.push("웹 검색"); break;
      default: steps.push(`${tc.name} 사용`);
    }
  }

  return steps.join(" → ");
}

function describeMessage(msg: ParsedMessage): string {
  if (msg.toolCalls && msg.toolCalls.length > 0) {
    return describeApproach(msg.toolCalls);
  }
  return msg.content.slice(0, 80);
}

function isCorrection(text: string): boolean {
  return /아니|말고|대신|다시|바꿔|아닌데|그거\s*말고|no[,.]?\s*(not|don't|instead)|wait|actually|wrong|instead/i.test(text);
}

function isPositiveFeedback(text: string): boolean {
  return /좋아|완벽|됐어|됐다|고마워|감사|ㅇㅇ|ㄱㄱ|ㅇㅋ|good|perfect|great|thanks|nice|works|다음|이제|next/i.test(text);
}

function extractTags(text: string): string[] {
  const tags: string[] = [];
  const patterns: [string, RegExp][] = [
    ["security", /보안|security|취약|exploit|injection/i],
    ["testing", /테스트|test|coverage/i],
    ["devops", /deploy|배포|docker|npm/i],
    ["debug", /debug|에러|error|fix/i],
    ["refactor", /refactor|리팩토|정리|clean/i],
    ["git", /git|commit|push|pr/i],
  ];
  for (const [tag, pattern] of patterns) {
    if (pattern.test(text)) tags.push(tag);
  }
  return tags;
}
