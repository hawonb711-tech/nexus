/**
 * Smart Skill Extractor — Context-Aware Pattern Recognition
 *
 * Unlike the basic extractor that treats every tool-call sequence as a skill,
 * this engine understands conversation FLOW:
 *
 * 1. EPISODE SEGMENTATION
 *    - Breaks sessions into "task episodes" (one coherent unit of work)
 *    - Detects episode boundaries: topic change, time gap, transition markers
 *
 * 2. INTENT CLASSIFICATION
 *    - Classifies what the user actually wanted (not just what tools ran)
 *    - "fix X" vs "build X" vs "investigate X" vs "deploy X"
 *
 * 3. DECISION POINT DETECTION
 *    - Finds moments where the approach changed:
 *      - User redirected ("아니 그게 아니라", "no wait", "instead")
 *      - Claude failed and tried differently
 *      - User gave feedback that shaped the next steps
 *    - These decision points ARE the real skill — not the tool calls
 *
 * 4. FLOW NARRATIVE
 *    - Builds a narrative: motivation → attempt → feedback → adaptation → result
 *    - This narrative IS the skill context that makes it reusable
 *
 * 5. QUALITY GATE
 *    - Only promotes patterns that are genuinely reusable
 *    - Filters: enough complexity, clear outcome, reproducible steps
 */

import type { ParsedSession, ParsedMessage, ToolCall } from "../parser/types.js";
import { createHash } from "node:crypto";

// ─── Types ───────────────────────────────────────────────────────

export type Episode = {
  /** Unique ID. */
  id: string;
  /** What the user wanted to achieve. */
  intent: Intent;
  /** Messages in this episode. */
  messages: ParsedMessage[];
  /** Tool calls made. */
  toolCalls: ToolCall[];
  /** Files modified. */
  files: string[];
  /** Decision points (where approach changed). */
  decisionPoints: DecisionPoint[];
  /** Full narrative of what happened. */
  narrative: Narrative;
  /** Outcome of the episode. */
  outcome: EpisodeOutcome;
  /** Start/end timestamps. */
  startedAt: string;
  endedAt: string;
  /** Skill quality score 0-1. Higher = more worth extracting. */
  skillQuality: number;
};

export type Intent = {
  /** High-level category. */
  category: IntentCategory;
  /** Human-readable description. */
  description: string;
  /** Key entities (files, modules, concepts). */
  entities: string[];
  /** Original user request. */
  originalRequest: string;
};

export type IntentCategory =
  | "fix_bug"           // Fix an error, crash, or incorrect behavior
  | "build_feature"     // Create something new
  | "refactor"          // Restructure existing code
  | "investigate"       // Analyze, debug, understand
  | "configure"         // Setup, install, config
  | "deploy"            // Deploy, publish, release
  | "test"              // Write or fix tests
  | "security"          // Security audit, vulnerability fix
  | "review"            // Code review, PR review
  | "learn"             // User asking to understand something
  | "misc";             // Doesn't fit other categories

export type DecisionPoint = {
  /** Index in episode messages where the decision occurred. */
  messageIndex: number;
  /** What triggered the change. */
  trigger: DecisionTrigger;
  /** What was the approach before. */
  before: string;
  /** What was the approach after. */
  after: string;
  /** Why (inferred). */
  reason: string;
};

export type DecisionTrigger =
  | "user_redirect"      // User explicitly changed direction
  | "error_recovery"     // Tool/command failed, had to adapt
  | "user_feedback"      // User gave positive/negative feedback
  | "scope_expansion"    // "also do X" — task grew
  | "scope_reduction"    // "just do X" — task narrowed
  | "approach_pivot";    // Claude realized a different method was better

export type Narrative = {
  /** Why this task was started. */
  motivation: string;
  /** What was attempted first. */
  initialApproach: string;
  /** Key turns (max 5). */
  keyTurns: NarrativeTurn[];
  /** Final result. */
  resolution: string;
  /** Lessons learned (what worked, what didn't). */
  lessons: string[];
};

export type NarrativeTurn = {
  what: string;
  why: string;
  outcome: "success" | "failure" | "partial";
};

export type EpisodeOutcome = {
  status: "completed" | "failed" | "abandoned" | "ongoing";
  /** Confidence in this assessment. */
  confidence: number;
  /** User's final reaction if any. */
  finalReaction?: string;
};

export type SmartSkill = {
  id: string;
  /** Clear, actionable name (e.g., "Fix ESLint errors in TypeScript project"). */
  name: string;
  /** When to use this skill. */
  whenToUse: string;
  /** Step-by-step approach (the real value). */
  approach: SmartStep[];
  /** What to watch out for. */
  pitfalls: string[];
  /** Tools typically needed. */
  tools: string[];
  /** Files/patterns typically involved. */
  filePatterns: string[];
  /** How many times this pattern appeared. */
  frequency: number;
  /** Quality score. */
  quality: number;
  /** Source episodes. */
  sourceEpisodes: string[];
};

export type SmartStep = {
  order: number;
  action: string;
  tool?: string;
  /** Why this step matters. */
  rationale: string;
  /** Common mistakes at this step. */
  caution?: string;
};

// ─── Transition/Redirect Markers ─────────────────────────────────

const TRANSITION_MARKERS_KO = [
  "자", "이제", "다음", "그러면", "그럼", "좋아", "오케이", "ㅇㅋ",
  "됐고", "됐어", "됐다", "다른거", "다른 거", "그거 말고",
];

const TRANSITION_MARKERS_EN = [
  "now", "next", "okay", "alright", "moving on", "let's",
  "done with that", "forget that", "different",
];

const REDIRECT_MARKERS_KO = [
  "아니", "아닌데", "그게 아니라", "말고", "대신", "다시",
  "잠깐", "멈춰", "스톱", "그만", "아 맞다", "근데",
  "그거 말고", "다른 방식", "다르게", "바꿔",
];

const REDIRECT_MARKERS_EN = [
  "no", "wait", "stop", "actually", "instead", "not that",
  "wrong", "different", "change", "scratch that", "never mind",
  "hold on", "but", "hmm",
];

const POSITIVE_MARKERS = [
  "좋아", "완벽", "됐어", "됐다", "고마워", "감사", "잘됐",
  "ㅇㅇ", "ㄱㄱ", "오케이", "ㅇㅋ",
  "good", "perfect", "great", "thanks", "nice", "works", "awesome",
];

const NEGATIVE_MARKERS = [
  "안돼", "안 돼", "틀렸", "잘못", "에러", "버그",
  "wrong", "error", "fail", "broken", "doesn't work", "bug", "crash",
];

const ERROR_PATTERNS = [
  /error/i, /Error:/i, /failed/i, /FAIL/i, /exception/i,
  /command not found/i, /permission denied/i, /ENOENT/i,
  /Cannot find/i, /not found/i, /exit code [1-9]/i,
];

// ─── Noise Filters ───────────────────────────────────────────────

const NOISE_PREFIXES = [
  "<task-notification>",
  "<system-reminder>",
  "<local-command",
  "Tool loaded",
  "Using Node for alias",
];

function isNoiseMessage(msg: ParsedMessage): boolean {
  const text = msg.content.trim();
  if (text.length === 0) return true;
  if (NOISE_PREFIXES.some((p) => text.startsWith(p))) return true;
  // System-injected metadata
  if (text.startsWith("{") && text.includes('"type"')) return true;
  return false;
}

function isSubstantiveUserMessage(msg: ParsedMessage): boolean {
  if (msg.role !== "user") return false;
  if (isNoiseMessage(msg)) return false;
  // Very short messages that are just acknowledgments
  const text = msg.content.trim();
  if (text.length <= 3 && /^[ㅇㄱㅎㅋ]+$/.test(text)) return false;
  return true;
}

// ─── Episode Segmentation ────────────────────────────────────────

/**
 * Break a session into coherent task episodes.
 *
 * Episode boundaries are detected by:
 * 1. Time gap > 10 minutes between messages
 * 2. Transition markers ("이제", "다음", "now let's")
 * 3. Complete topic change (low keyword overlap)
 */
export function segmentEpisodes(session: ParsedSession): Episode[] {
  const messages = session.messages.filter((m) => !isNoiseMessage(m));
  if (messages.length === 0) return [];

  const episodes: Episode[] = [];
  let currentMessages: ParsedMessage[] = [];
  let episodeCount = 0;

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    const prev = i > 0 ? messages[i - 1] : null;

    // Check for episode boundary
    let isBoundary = false;

    if (currentMessages.length > 0 && msg.role === "user") {
      // Time gap > 10 minutes
      if (prev && msg.timestamp && prev.timestamp) {
        const gap = new Date(msg.timestamp).getTime() - new Date(prev.timestamp).getTime();
        if (gap > 10 * 60 * 1000) isBoundary = true;
      }

      // Transition marker
      const text = msg.content.toLowerCase().trim();
      const firstWords = text.split(/\s+/).slice(0, 3).join(" ");
      if (TRANSITION_MARKERS_KO.some((m) => firstWords.includes(m)) ||
          TRANSITION_MARKERS_EN.some((m) => firstWords.includes(m))) {
        // Only if there's enough content in current episode
        if (currentMessages.length >= 4) isBoundary = true;
      }

      // Topic change: low keyword overlap with recent messages
      if (currentMessages.length >= 6) {
        const recentKeywords = extractMessageKeywords(
          currentMessages.slice(-4).filter((m) => m.role === "user"),
        );
        const newKeywords = extractMessageKeywords([msg]);
        const overlap = keywordOverlap(recentKeywords, newKeywords);
        if (overlap < 0.1 && newKeywords.size > 2) isBoundary = true;
      }
    }

    if (isBoundary && currentMessages.length >= 2) {
      const episode = buildEpisode(currentMessages, session.sessionId, episodeCount++);
      if (episode) episodes.push(episode);
      currentMessages = [];
    }

    currentMessages.push(msg);
  }

  // Final episode
  if (currentMessages.length >= 2) {
    const episode = buildEpisode(currentMessages, session.sessionId, episodeCount);
    if (episode) episodes.push(episode);
  }

  return episodes;
}

// ─── Intent Classification ───────────────────────────────────────

function classifyIntent(messages: ParsedMessage[]): Intent {
  const userMessages = messages.filter((m) => m.role === "user" && isSubstantiveUserMessage(m));
  if (userMessages.length === 0) {
    return {
      category: "misc",
      description: "Unknown task",
      entities: [],
      originalRequest: "",
    };
  }

  const firstRequest = userMessages[0].content;
  const allUserText = userMessages.map((m) => m.content).join(" ").toLowerCase();

  // Category detection with weighted keyword matching
  const categoryScores: Record<IntentCategory, number> = {
    fix_bug: 0, build_feature: 0, refactor: 0, investigate: 0,
    configure: 0, deploy: 0, test: 0, security: 0, review: 0,
    learn: 0, misc: 0,
  };

  const patterns: [IntentCategory, RegExp, number][] = [
    // Fix
    ["fix_bug", /fix|고치|수정|bug|error|에러|버그|오류|crash|안[되돼]|doesn.t work|broken/i, 3],
    ["fix_bug", /해결|resolve|debug|디버그|왜.*안/i, 2],

    // Build
    ["build_feature", /만들|생성|create|build|add|추가|implement|구현|새로/i, 3],
    ["build_feature", /write|작성|개발|develop/i, 2],

    // Refactor
    ["refactor", /refactor|리팩토|정리|clean|개선|improve|optimize|최적화/i, 3],
    ["refactor", /restructure|reorganize|simplify/i, 2],

    // Investigate
    ["investigate", /분석|analyze|찾아|find|확인|check|search|조사|탐색|스캔/i, 3],
    ["investigate", /what.*is|어떻게.*되|뭐가|왜.*이런/i, 2],

    // Configure
    ["configure", /설정|setup|install|config|설치|configure|init|초기화/i, 3],
    ["configure", /환경|environment|연결|connect|세팅/i, 2],

    // Deploy
    ["deploy", /배포|deploy|publish|push|release|올려|npm publish/i, 3],
    ["deploy", /upload|ship|pr.*제출|pr.*생성/i, 2],

    // Test
    ["test", /테스트|test|검증|verify|validate|확인.*동작/i, 3],

    // Security
    ["security", /보안|security|취약점|vulnerability|exploit|해킹|audit|감사/i, 3],
    ["security", /injection|xss|csrf|ssrf|인젝션/i, 2],

    // Review
    ["review", /리뷰|review|검토|봐봐|확인.*해봐|체크/i, 3],

    // Learn
    ["learn", /알려줘|설명|explain|tell me|뭐야|what is|how does|어떻게/i, 2],
    ["learn", /이해|understand|가르쳐|teach/i, 2],
  ];

  for (const [cat, pattern, weight] of patterns) {
    if (pattern.test(allUserText)) {
      categoryScores[cat] += weight;
    }
  }

  // Find highest
  let bestCat: IntentCategory = "misc";
  let bestScore = 0;
  for (const [cat, score] of Object.entries(categoryScores)) {
    if (score > bestScore) {
      bestScore = score;
      bestCat = cat as IntentCategory;
    }
  }

  // Extract entities (file names, module names, technical terms)
  const entities = extractEntities(allUserText);

  // Build description
  const categoryLabels: Record<IntentCategory, string> = {
    fix_bug: "Fix", build_feature: "Build", refactor: "Refactor",
    investigate: "Investigate", configure: "Configure", deploy: "Deploy",
    test: "Test", security: "Security audit", review: "Review",
    learn: "Learn about", misc: "Task",
  };

  const entityStr = entities.slice(0, 3).join(", ");
  const description = entityStr
    ? `${categoryLabels[bestCat]}: ${entityStr}`
    : `${categoryLabels[bestCat]}: ${firstRequest.slice(0, 60)}`;

  return {
    category: bestCat,
    description,
    entities,
    originalRequest: firstRequest,
  };
}

function extractEntities(text: string): string[] {
  const entities: string[] = [];

  // File paths
  const filePaths = text.match(/[\w./\\-]+\.\w{1,5}/g);
  if (filePaths) entities.push(...filePaths.slice(0, 3));

  // Backtick-quoted identifiers
  const backticks = text.match(/`([^`]+)`/g);
  if (backticks) entities.push(...backticks.map((b) => b.replace(/`/g, "")).slice(0, 3));

  // Technical terms (CamelCase, kebab-case)
  const techTerms = text.match(/[A-Z][a-z]+[A-Z]\w+|[a-z]+-[a-z]+-[a-z]+/g);
  if (techTerms) entities.push(...techTerms.slice(0, 3));

  return [...new Set(entities)].slice(0, 5);
}

// ─── Decision Point Detection ────────────────────────────────────

function detectDecisionPoints(messages: ParsedMessage[]): DecisionPoint[] {
  const points: DecisionPoint[] = [];

  for (let i = 1; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role !== "user") continue;

    const text = msg.content.toLowerCase();
    const prev = messages[i - 1];

    // User redirect
    if (REDIRECT_MARKERS_KO.some((m) => text.includes(m)) ||
        REDIRECT_MARKERS_EN.some((m) => text.includes(m))) {
      const prevAction = prev?.toolCalls?.[0]?.name ?? prev?.content.slice(0, 50) ?? "previous approach";
      points.push({
        messageIndex: i,
        trigger: "user_redirect",
        before: prevAction,
        after: msg.content.slice(0, 80),
        reason: `User changed direction: "${msg.content.slice(0, 60)}"`,
      });
      continue;
    }

    // Error recovery: check if previous assistant had errors in tool results
    if (prev?.role === "assistant" && prev.toolCalls) {
      const hasError = prev.toolCalls.some((tc) =>
        tc.result && ERROR_PATTERNS.some((p) => p.test(tc.result ?? "")),
      );
      if (hasError) {
        points.push({
          messageIndex: i,
          trigger: "error_recovery",
          before: prev.toolCalls.map((tc) => tc.name).join("→"),
          after: msg.content.slice(0, 80),
          reason: "Previous tool call failed, adapting approach",
        });
        continue;
      }
    }

    // Scope expansion: "그리고", "also", "추가로"
    const expansionMarkers = ["그리고", "추가로", "또", "also", "and also", "additionally"];
    if (expansionMarkers.some((m) => text.startsWith(m) || text.includes(` ${m} `))) {
      points.push({
        messageIndex: i,
        trigger: "scope_expansion",
        before: "original scope",
        after: msg.content.slice(0, 80),
        reason: `Scope expanded: "${msg.content.slice(0, 60)}"`,
      });
    }

    // User feedback (positive or negative)
    if (POSITIVE_MARKERS.some((m) => text.includes(m))) {
      points.push({
        messageIndex: i,
        trigger: "user_feedback",
        before: "awaiting feedback",
        after: "confirmed",
        reason: "User confirmed approach works",
      });
    } else if (NEGATIVE_MARKERS.some((m) => text.includes(m))) {
      points.push({
        messageIndex: i,
        trigger: "user_feedback",
        before: "attempted approach",
        after: msg.content.slice(0, 80),
        reason: `Negative feedback: "${msg.content.slice(0, 60)}"`,
      });
    }
  }

  return points;
}

// ─── Narrative Builder ───────────────────────────────────────────

function buildNarrative(messages: ParsedMessage[], decisionPoints: DecisionPoint[]): Narrative {
  const userMessages = messages.filter((m) => isSubstantiveUserMessage(m));
  const assistantMessages = messages.filter((m) => m.role === "assistant" && m.content.trim());

  // Motivation: what came before the first real request
  const motivation = userMessages.length > 0
    ? userMessages[0].content.slice(0, 150)
    : "Unknown";

  // Initial approach: first assistant response with tools
  const firstToolResponse = assistantMessages.find((m) => m.toolCalls && m.toolCalls.length > 0);
  const initialApproach = firstToolResponse
    ? `Used ${firstToolResponse.toolCalls?.map((tc) => tc.name).join(", ")} — ${firstToolResponse.content.slice(0, 100)}`
    : assistantMessages[0]?.content.slice(0, 100) ?? "No approach recorded";

  // Key turns from decision points
  const keyTurns: NarrativeTurn[] = decisionPoints.slice(0, 5).map((dp) => ({
    what: dp.after.slice(0, 100),
    why: dp.reason,
    outcome: dp.trigger === "user_feedback" && dp.after === "confirmed" ? "success" as const
      : dp.trigger === "error_recovery" ? "failure" as const
      : "partial" as const,
  }));

  // Resolution: last assistant message
  const lastAssistant = [...assistantMessages].reverse().find((m) => m.content.trim().length > 10);
  const resolution = lastAssistant?.content.slice(0, 150) ?? "No resolution recorded";

  // Lessons
  const lessons: string[] = [];
  for (const dp of decisionPoints) {
    if (dp.trigger === "error_recovery") {
      lessons.push(`Approach "${dp.before}" failed — switched to "${dp.after}"`);
    }
    if (dp.trigger === "user_redirect") {
      lessons.push(`User preferred different approach: ${dp.reason}`);
    }
  }

  return { motivation, initialApproach, keyTurns, resolution, lessons };
}

// ─── Episode Builder ─────────────────────────────────────────────

function buildEpisode(
  messages: ParsedMessage[],
  sessionId: string,
  index: number,
): Episode | null {
  // Must have at least one substantive user message and one assistant response
  const hasUser = messages.some((m) => isSubstantiveUserMessage(m));
  const hasAssistant = messages.some((m) => m.role === "assistant" && m.content.trim());
  if (!hasUser || !hasAssistant) return null;

  const intent = classifyIntent(messages);
  const decisionPoints = detectDecisionPoints(messages);

  // Collect tool calls and files
  const toolCalls: ToolCall[] = [];
  const files: string[] = [];
  for (const msg of messages) {
    if (msg.toolCalls) {
      for (const tc of msg.toolCalls) {
        toolCalls.push(tc);
        const fp = tc.input["file_path"] ?? tc.input["path"];
        if (typeof fp === "string") files.push(fp);
      }
    }
  }

  const narrative = buildNarrative(messages, decisionPoints);
  const outcome = inferEpisodeOutcome(messages);

  // Quality score
  const skillQuality = computeSkillQuality(
    messages, toolCalls, decisionPoints, outcome,
  );

  const timestamps = messages
    .map((m) => m.timestamp)
    .filter(Boolean)
    .sort();

  const id = createHash("sha256")
    .update(`${sessionId}:${index}:${intent.description}`)
    .digest("hex")
    .slice(0, 12);

  return {
    id,
    intent,
    messages,
    toolCalls,
    files: [...new Set(files)],
    decisionPoints,
    narrative,
    outcome,
    startedAt: timestamps[0] ?? "",
    endedAt: timestamps[timestamps.length - 1] ?? "",
    skillQuality,
  };
}

// ─── Outcome Inference ───────────────────────────────────────────

function inferEpisodeOutcome(messages: ParsedMessage[]): EpisodeOutcome {
  const userMessages = messages.filter((m) => isSubstantiveUserMessage(m));
  if (userMessages.length === 0) {
    return { status: "ongoing", confidence: 0.3 };
  }

  const lastUser = userMessages[userMessages.length - 1];
  const text = lastUser.content.toLowerCase();

  // Strong success
  if (POSITIVE_MARKERS.some((m) => text.includes(m))) {
    return { status: "completed", confidence: 0.9, finalReaction: lastUser.content.slice(0, 60) };
  }

  // Strong failure
  if (NEGATIVE_MARKERS.some((m) => text.includes(m))) {
    return { status: "failed", confidence: 0.8, finalReaction: lastUser.content.slice(0, 60) };
  }

  // If last message is a new task, previous was probably completed
  const lastIsNewTask = TRANSITION_MARKERS_KO.some((m) => text.includes(m)) ||
    TRANSITION_MARKERS_EN.some((m) => text.includes(m));
  if (lastIsNewTask) {
    return { status: "completed", confidence: 0.7 };
  }

  // Default: if there were tool calls and no complaints, probably completed
  const hasToolCalls = messages.some((m) => m.toolCalls && m.toolCalls.length > 0);
  if (hasToolCalls) {
    return { status: "completed", confidence: 0.5 };
  }

  return { status: "ongoing", confidence: 0.3 };
}

// ─── Quality Gate ────────────────────────────────────────────────

function computeSkillQuality(
  messages: ParsedMessage[],
  toolCalls: ToolCall[],
  decisionPoints: DecisionPoint[],
  outcome: EpisodeOutcome,
): number {
  let score = 0;

  // Has tool calls (indicates concrete work, not just chat)
  if (toolCalls.length >= 2) score += 0.2;
  if (toolCalls.length >= 5) score += 0.1;

  // Multiple tool types (more complex task)
  const uniqueTools = new Set(toolCalls.map((tc) => tc.name));
  if (uniqueTools.size >= 2) score += 0.15;
  if (uniqueTools.size >= 3) score += 0.1;

  // Has decision points (shows adaptation — valuable knowledge)
  if (decisionPoints.length >= 1) score += 0.15;
  if (decisionPoints.length >= 2) score += 0.1;

  // Successful outcome
  if (outcome.status === "completed") score += 0.15;
  if (outcome.confidence > 0.7) score += 0.05;

  // Not too short, not too long (sweet spot: 4-30 messages)
  const msgCount = messages.length;
  if (msgCount >= 4 && msgCount <= 30) score += 0.1;
  if (msgCount > 30) score -= 0.05; // Too long = probably multiple tasks

  // Has user feedback (validates the approach)
  const hasFeedback = decisionPoints.some((dp) => dp.trigger === "user_feedback");
  if (hasFeedback) score += 0.1;

  return Math.min(1, Math.max(0, score));
}

// ─── Smart Skill Generation ─────────────────────────────────────

/**
 * Convert high-quality episodes into actionable skills.
 */
export function generateSmartSkills(
  episodes: Episode[],
  minQuality = 0.3,
): SmartSkill[] {
  const qualified = episodes.filter((ep) => ep.skillQuality >= minQuality);
  const skills: SmartSkill[] = [];

  for (const episode of qualified) {
    const steps: SmartStep[] = [];
    let stepOrder = 1;

    // Build steps from tool calls + decision points
    const dpIndices = new Set(episode.decisionPoints.map((dp) => dp.messageIndex));

    for (const msg of episode.messages) {
      if (msg.role !== "assistant" || !msg.toolCalls) continue;

      for (const tc of msg.toolCalls) {
        const fileArg = tc.input["file_path"] ?? tc.input["path"] ?? tc.input["command"];
        const action = fileArg
          ? `${tc.name}: ${String(fileArg).slice(0, 80)}`
          : tc.name;

        const step: SmartStep = {
          order: stepOrder++,
          action,
          tool: tc.name,
          rationale: "", // Will be filled by context
        };

        steps.push(step);
      }
    }

    // Add rationale from decision points
    for (const dp of episode.decisionPoints) {
      if (dp.trigger === "error_recovery" && steps.length > 0) {
        const nearestStep = steps[Math.min(dp.messageIndex, steps.length - 1)];
        if (nearestStep) {
          nearestStep.caution = dp.reason;
        }
      }
    }

    // Add rationale from narrative
    if (steps.length > 0 && episode.narrative.initialApproach) {
      steps[0].rationale = `Start here: ${episode.narrative.initialApproach.slice(0, 80)}`;
    }

    // Build pitfalls from failed decision points
    const pitfalls = episode.decisionPoints
      .filter((dp) => dp.trigger === "error_recovery" || dp.trigger === "user_redirect")
      .map((dp) => dp.reason)
      .slice(0, 5);

    // File patterns
    const filePatterns = generalizeFilePaths(episode.files);

    const skill: SmartSkill = {
      id: episode.id,
      name: episode.intent.description,
      whenToUse: episode.narrative.motivation.slice(0, 200),
      approach: steps.slice(0, 15), // Cap at 15 steps
      pitfalls,
      tools: [...new Set(episode.toolCalls.map((tc) => tc.name))],
      filePatterns,
      frequency: 1,
      quality: episode.skillQuality,
      sourceEpisodes: [episode.id],
    };

    skills.push(skill);
  }

  return skills.sort((a, b) => b.quality - a.quality);
}

// ─── Full Pipeline ───────────────────────────────────────────────

/**
 * Run the full smart extraction pipeline on sessions.
 */
export function smartExtract(sessions: ParsedSession[]): {
  episodes: Episode[];
  skills: SmartSkill[];
} {
  const allEpisodes: Episode[] = [];

  for (const session of sessions) {
    const episodes = segmentEpisodes(session);
    allEpisodes.push(...episodes);
  }

  const skills = generateSmartSkills(allEpisodes);

  return { episodes: allEpisodes, skills };
}

// ─── Helpers ─────────────────────────────────────────────────────

function extractMessageKeywords(messages: ParsedMessage[]): Set<string> {
  const keywords = new Set<string>();
  const stopWords = new Set([
    "the", "a", "is", "are", "and", "or", "to", "in", "for", "of",
    "이", "그", "저", "을", "를", "에", "가", "는", "은", "의",
  ]);

  for (const msg of messages) {
    const words = msg.content.toLowerCase().split(/\s+/);
    for (const w of words) {
      if (w.length > 2 && !stopWords.has(w)) keywords.add(w);
    }
  }
  return keywords;
}

function keywordOverlap(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  const intersection = [...a].filter((w) => b.has(w)).length;
  const union = new Set([...a, ...b]).size;
  return intersection / union;
}

function generalizeFilePaths(files: string[]): string[] {
  if (files.length === 0) return [];

  // Group by directory
  const byDir = new Map<string, string[]>();
  for (const f of files) {
    const parts = f.split("/");
    const dir = parts.slice(0, -1).join("/") || ".";
    const ext = f.split(".").pop() ?? "";
    byDir.set(dir, [...(byDir.get(dir) ?? []), ext]);
  }

  // If 3+ files in same dir with same extension, generalize
  const patterns: string[] = [];
  for (const [dir, exts] of byDir) {
    const extCounts = new Map<string, number>();
    for (const ext of exts) {
      extCounts.set(ext, (extCounts.get(ext) ?? 0) + 1);
    }
    for (const [ext, count] of extCounts) {
      if (count >= 3) {
        patterns.push(`${dir}/**/*.${ext}`);
      }
    }
  }

  // If no patterns, return unique files (max 5)
  if (patterns.length === 0) {
    return [...new Set(files)].slice(0, 5);
  }

  return [...new Set(patterns)];
}
