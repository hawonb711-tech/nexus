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

/** Knowledge tier: skill (complex), tip (quick), fact (reference). */
export type KnowledgeTier = "skill" | "tip" | "fact";

export type LearnedKnowledge = {
  id: string;
  tier: KnowledgeTier;
  name: string;
  content: string;
  domains: string[];
  tags: string[];
  evidenceCount: number;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
};

export type Tip = LearnedKnowledge & {
  tier: "tip";
  /** Quick one-liner advice. */
  advice: string;
  /** When this applies. */
  trigger: string;
};

export type Fact = LearnedKnowledge & {
  tier: "fact";
  /** The fact itself. */
  statement: string;
  /** How often referenced. */
  referenceCount: number;
};

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
  /** Complex skills (cross-session, multi-step). */
  skills: MemorySkill[];
  /** Quick tips (short, actionable). */
  tips: Tip[];
  /** Reference facts (frequently recalled). */
  facts: Fact[];
  /** Observations ingested. */
  observationsIngested: number;
  /** Clusters formed. */
  clustersFormed: number;
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
      const intent = classifyUserIntent(userRequest);

      if (approach.length > 20 && intent) {
        observations.push({
          text: `[${intent}] ${approach}`,
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
            text: `[수정] ${wrongApproach.slice(0, 40)} 대신 ${rightApproach.slice(0, 40)}`,
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

  // QUALITY GATE: Reject clusters that are just noise
  const cleanKeywords = commonKeywords.filter((k) => !SKILL_NAME_NOISE.has(k) && k.length > 3);
  if (cleanKeywords.length < 1) return null;

  // Reject if all members are from the same 1-message context (not cross-session)
  const uniqueSessions = new Set(members.map((m) => m.sourceSessionId).filter(Boolean));
  // Allow single-session clusters only if they have 4+ members
  if (uniqueSessions.size < 2 && members.length < 4) return null;

  // ABSTRACT: Build the skill name and principle from common patterns
  const name = buildSkillName(cleanKeywords, commonTools, members);
  const situation = buildSituation(members);
  const principle = buildPrinciple(members);
  const reasoning = buildReasoning(members);

  if (!name || !principle || principle.length < 20) return null;

  // Reject principles that are just UI messages, not technical insights
  const meaninglessPatterns = [
    /^이\s*URL을/i, /^흠,?\s*몇/i, /^잠깐/i,
    /^`\S+`\s*이름이/i, // "promptguard 이름이 이미 있는"
    /^\|.*\|.*\|/,       // Markdown tables
    /^http/i,            // Raw URLs
    /^```/,              // Code fences
  ];
  if (meaninglessPatterns.some((p) => p.test(principle))) return null;

  // Must contain at least one actionable word
  const actionable = /해야|하면|사용|필요|방법|대신|instead|should|use|need|avoid|better|always|never|경우|때는|위해/i;
  if (!actionable.test(principle) && !actionable.test(name)) return null;

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

function buildSkillName(keywords: string[], tools: string[], members: Observation[]): string {
  // Filter out noise keywords
  const meaningful = keywords
    .filter((k) => k.length > 3 && !SKILL_NAME_NOISE.has(k))
    .slice(0, 3);

  if (meaningful.length === 0) return "";

  // Try to find intent from members
  const intents = members
    .map((m) => m.content.match(/^\[([^\]]+)\]/)?.[1])
    .filter(Boolean) as string[];

  const topIntent = mostFrequent(intents);
  const toolStr = tools.length > 0 ? ` (${tools.slice(0, 2).join(", ")})` : "";

  if (topIntent) {
    return `${topIntent}: ${meaningful.slice(0, 2).join(", ")}${toolStr}`;
  }

  return `${meaningful.join(", ")}${toolStr}`;
}

function mostFrequent(arr: string[]): string | null {
  if (arr.length === 0) return null;
  const counts = new Map<string, number>();
  for (const item of arr) counts.set(item, (counts.get(item) ?? 0) + 1);
  return [...counts.entries()].sort(([, a], [, b]) => b - a)[0][0];
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
  // Priority 1: Find intent-tagged observations with tool approach
  const intentTagged = members
    .filter((m) => m.content.startsWith("["))
    .map((m) => {
      const match = m.content.match(/^\[[^\]]+\]\s*(.+)/);
      return match ? match[1].trim() : null;
    })
    .filter(Boolean) as string[];

  if (intentTagged.length > 0) {
    // Find most common approach pattern
    const approaches = new Map<string, number>();
    for (const approach of intentTagged) {
      approaches.set(approach, (approaches.get(approach) ?? 0) + 1);
    }
    const sorted = [...approaches.entries()].sort(([, a], [, b]) => b - a);
    return sorted[0][0];
  }

  // Priority 2: Validated observations
  const validated = members.find((m) => m.tags.includes("validated"));
  if (validated) {
    const clean = validated.content.replace(/^\[[^\]]+\]\s*/, "");
    return clean.slice(0, 150);
  }

  // Priority 3: Error recovery observations
  const recovery = members.find((m) => m.tags.includes("error-recovery"));
  if (recovery) return recovery.content.slice(0, 150);

  // Fallback: first member, cleaned
  const clean = members[0].content.replace(/^\[[^\]]+\]\s*/, "");
  return clean.slice(0, 150);
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

  // Step 2: Cluster for skills (need 3+ similar observations)
  const clusters = clusterObservations(memory, minClusterSize);

  // Step 3: Convert clusters to skills (strict gate)
  const skills: MemorySkill[] = [];
  for (const cluster of clusters) {
    const skill = clusterToSkill(cluster);
    if (skill) skills.push(skill);
  }

  // Step 4: Extract tips — smaller clusters (2+) with actionable content
  const tips = extractTips(memory);

  // Step 5: Extract facts — frequently accessed observations
  const facts = extractFacts(memory);

  const durationMs = Math.round(performance.now() - start);

  return {
    skills: skills.sort((a, b) => b.confidence - a.confidence),
    tips: tips.sort((a, b) => b.confidence - a.confidence),
    facts: facts.sort((a, b) => b.referenceCount - a.referenceCount),
    observationsIngested: totalIngested,
    clustersFormed: clusters.length,
    durationMs,
  };
}

// ═══════════════════════════════════════════════════════════════════
// TIPS — Short, actionable advice from single observations
// ═══════════════════════════════════════════════════════════════════

/** Patterns that indicate a tip-worthy observation. */
const TIP_PATTERNS: [string, RegExp][] = [
  ["명령어", /에서는?\s+.{5,40}(?:해야|필요|써야|붙여야|사용해야)/i],
  ["command", /(?:use|need|must|should|always|never)\s+.{5,50}/i],
  ["경로", /경로는?\s+.{5,40}/i],
  ["해결", /(?:해결|fix|solved|resolved).{5,40}(?:으로|by|with|via)/i],
  ["설정", /(?:설정|config|set).{5,30}(?:해야|to|=)/i],
  ["주의", /(?:주의|caution|warning|avoid|don't).{5,40}/i],
  ["대신", /.{5,30}대신\s+.{5,30}/i],
  ["instead", /.{5,30}instead of\s+.{5,30}/i],
];

function extractTips(memory: NexusMemory): Tip[] {
  const tips: Tip[] = [];
  const allObs = memory.scanIndex();

  for (const obs of allObs) {
    if (!obs.valid) continue;
    const content = obs.content;

    // Must be short-ish (tip, not essay)
    if (content.length < 15 || content.length > 200) continue;

    // Skip noise
    if (content.startsWith("[수정]")) continue; // Corrections go to skills
    if (/^\[.*\]\s*(명령어|파일|패턴|코드|에이전트)/.test(content)) continue; // Tool approaches go to skills

    // Check if it matches tip patterns
    let tipTrigger = "";
    let matched = false;
    for (const [trigger, pattern] of TIP_PATTERNS) {
      if (pattern.test(content)) {
        tipTrigger = trigger;
        matched = true;
        break;
      }
    }

    if (!matched) continue;

    // Must not be pure noise
    if (SKILL_NAME_NOISE.has(content.split(/\s/)[0].toLowerCase())) continue;

    // Must not contain markdown tables, long dashes, or quote fragments
    if (/^\||\|---|대신\s+.{0,5}$|^\*\*|^>/.test(content)) continue;

    // Extract the advice
    const advice = content
      .replace(/^\[[^\]]+\]\s*/, "") // Remove intent tags
      .replace(/\s+/g, " ")
      .trim();

    if (advice.length < 15) continue;

    tips.push({
      id: obs.id,
      tier: "tip",
      name: `${tipTrigger}: ${advice.slice(0, 40)}`,
      content: advice,
      advice,
      trigger: tipTrigger,
      domains: [obs.domain],
      tags: obs.tags,
      evidenceCount: 1,
      confidence: Math.min(0.8, obs.confidence + 0.1),
      firstSeen: obs.createdAt,
      lastSeen: obs.accessedAt,
    });
  }

  // Deduplicate similar tips
  return deduplicateTips(tips).slice(0, 50);
}

function deduplicateTips(tips: Tip[]): Tip[] {
  const unique: Tip[] = [];

  for (const tip of tips) {
    // Check semantic similarity against all existing tips
    const isDuplicate = unique.some((existing) =>
      semanticSimilarity(existing.advice, tip.advice) > 0.4,
    );
    if (!isDuplicate) unique.push(tip);
  }

  return unique;
}

// ═══════════════════════════════════════════════════════════════════
// FACTS — Frequently referenced knowledge
// ═══════════════════════════════════════════════════════════════════

function extractFacts(memory: NexusMemory): Fact[] {
  const facts: Fact[] = [];
  const allObs = memory.scanIndex();

  for (const obs of allObs) {
    if (!obs.valid) continue;

    // Facts are short, declarative statements
    if (obs.content.length < 10 || obs.content.length > 150) continue;

    // Allow initial facts (accessCount 0) if content is clearly factual
    // Facts grow in confidence as they get accessed more

    // Must look like a fact (declarative, not procedural)
    const content = obs.content.replace(/^\[[^\]]+\]\s*/, "").trim();

    // Fact patterns: "X는 Y이다", "X uses Y", paths, versions, configs
    const factPatterns = [
      /^.{3,20}(?:는|은|이)\s+.{3,40}(?:이다|입니다|다|임)/i, // Korean declarative
      /경로|path|url|port|version|버전/i, // Reference info
      /기본값|default|기본\s*설정/i, // Defaults
      /호환|compatible|support|지원/i, // Compatibility
    ];

    const isFact = factPatterns.some((p) => p.test(content));
    if (!isFact) continue;

    // Must not be noise
    if (/^\||^```|^http|^#|^\*\*|^>|대신|하지만|근본적/.test(content)) continue;
    if (content.length < 15) continue;
    // Must not be a sentence fragment (ends with proper punctuation or is self-contained)
    if (/[:\-—]$/.test(content.trim())) continue;

    facts.push({
      id: obs.id,
      tier: "fact",
      name: content.slice(0, 40),
      content,
      statement: content,
      referenceCount: obs.accessCount + 1,
      domains: [obs.domain],
      tags: obs.tags,
      evidenceCount: 1,
      confidence: obs.confidence,
      firstSeen: obs.createdAt,
      lastSeen: obs.accessedAt,
    });
  }

  return facts.slice(0, 30);
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

/** Render all knowledge (skills + tips + facts) as a single Obsidian page. */
export function renderKnowledgeBase(result: SkillExtractionResult): string {
  const lines: string[] = [];

  lines.push("---");
  lines.push("type: knowledge-base");
  lines.push(`generated: "${new Date().toISOString()}"`);
  lines.push(`skills: ${result.skills.length}`);
  lines.push(`tips: ${result.tips.length}`);
  lines.push(`facts: ${result.facts.length}`);
  lines.push("tags: [nexus/knowledge]");
  lines.push("---");
  lines.push("");
  lines.push("# Nexus Knowledge Base");
  lines.push("");
  lines.push(`> ${result.skills.length} skills | ${result.tips.length} tips | ${result.facts.length} facts | ${result.observationsIngested} observations`);
  lines.push("");

  // Skills
  if (result.skills.length > 0) {
    lines.push("## Skills");
    lines.push("");
    for (const s of result.skills) {
      lines.push(`### ${s.name}`);
      lines.push(`> ${(s.confidence * 100).toFixed(0)}% confidence | ${s.evidenceCount} evidence | ${s.domains.join(", ")}`);
      lines.push("");
      lines.push(`**상황**: ${s.situation}`);
      lines.push("");
      lines.push(`**원칙**: ${s.principle}`);
      lines.push("");
      lines.push(`**이유**: ${s.reasoning}`);
      if (s.antiPatterns.length > 0) {
        lines.push("");
        lines.push("**하지 말 것:**");
        for (const ap of s.antiPatterns) lines.push(`- ~~${ap}~~`);
      }
      lines.push("");
    }
  }

  // Tips
  if (result.tips.length > 0) {
    lines.push("## Tips");
    lines.push("");
    for (const t of result.tips) {
      lines.push(`- 💡 **${t.trigger}**: ${t.advice}`);
    }
    lines.push("");
  }

  // Facts
  if (result.facts.length > 0) {
    lines.push("## Facts");
    lines.push("");
    for (const f of result.facts) {
      lines.push(`- 📌 ${f.statement}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

import { STOP_WORDS } from "../shared/stop-words.js";

/** Classify user intent into abstract category. */
function classifyUserIntent(text: string): string | null {
  const lower = text.toLowerCase();
  const patterns: [string, RegExp][] = [
    ["코드 리뷰", /리뷰|review|검토|봐봐|봐줘|체크/i],
    ["버그 수정", /fix|고치|수정|bug|에러|error|안돼|doesn.t work/i],
    ["기능 구현", /만들|create|build|add|추가|implement|구현/i],
    ["리팩토링", /refactor|리팩토|정리|clean|개선/i],
    ["보안 분석", /보안|security|취약|vulnerab|audit|감사|scan/i],
    ["배포", /deploy|배포|publish|push|release|npm/i],
    ["테스트", /test|테스트|검증|verify/i],
    ["디버깅", /debug|디버그|trace|로그|log/i],
    ["설정", /설정|setup|install|config|설치/i],
    ["분석", /분석|analyze|조사|찾아|search|scan/i],
    ["문서화", /문서|doc|readme|설명/i],
    ["최적화", /최적화|optimize|performance|성능|빠르/i],
    ["아키텍처 매핑", /map|매핑|구조|architecture|onboard/i],
  ];

  for (const [intent, pattern] of patterns) {
    if (pattern.test(lower)) return intent;
  }

  // Skip if no clear intent (avoids noise)
  return null;
}

/** Noise keywords that should never appear in skill names. */
const SKILL_NAME_NOISE = new Set([
  "users", "hawon", "home", "mnt", "tmp", "claude", "dist", "src",
  "node", "npm", "git", "http", "https", "com", "org", "json",
  "file", "path", "data", "test", "true", "false", "null",
  "있습니다", "합니다", "입니다", "습니다", "했습니다",
  "대신", "주의", "에러", "하지", "그리고",
]);

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
