/**
 * Global Context Model — Holistic Session Understanding
 *
 * Core insight: In a conversation with an AI assistant,
 * there are NO truly unrelated messages. Everything connects.
 *
 * This module adds three layers above the per-message context engine:
 *
 * 1. HIERARCHICAL GOAL TRACKING
 *    Session Goal → Episode Goals → Turn Intents
 *    "오픈소스 기여자 되기" → "OpenClaw 감사" → "취약점 분석"
 *
 * 2. THREAD WEAVING
 *    Every message belongs to one or more threads.
 *    Threads can pause, resume, merge, and fork.
 *    A "tangent" is just a thread pause, not a disconnection.
 *
 * 3. USER STATE MODEL
 *    Tracks the user's cognitive/emotional state:
 *    engagement, frustration, curiosity, momentum, fatigue
 *    This affects HOW skills should be extracted, not just WHAT.
 *
 * 4. IMPLICIT CONNECTION DETECTION
 *    When the user switches topics, WHY?
 *    - Inspiration: previous result sparked new idea
 *    - Dependency: need X before continuing Y
 *    - Fatigue: taking a break from hard task
 *    - Strategy: building toward a larger goal
 */

import type { ParsedMessage } from "../parser/types.js";
import { getSynonyms } from "../memory-engine/semantic.js";

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export type SessionGoal = {
  /** High-level goal inferred from the full session. */
  description: string;
  /** Confidence 0-1. */
  confidence: number;
  /** Evidence: which messages support this goal. */
  evidence: number[];  // message indices
  /** Sub-goals that serve this goal. */
  subGoals: EpisodeGoal[];
  /** Progress toward this goal. */
  progress: number;  // 0-1
};

export type EpisodeGoal = {
  description: string;
  /** Which session goal this serves. */
  parentGoalIndex: number;
  /** Message range. */
  startIndex: number;
  endIndex: number;
  /** Status. */
  status: "active" | "paused" | "completed" | "abandoned";
  /** How this connects to the parent goal. */
  connectionType: ConnectionType;
};

export type ConnectionType =
  | "direct"         // Directly serves the goal
  | "prerequisite"   // Need this before the goal
  | "inspiration"    // Result inspired this sub-goal
  | "validation"     // Checking if the goal is achieved
  | "strategic"      // Part of a larger strategy
  | "recovery"       // Fixing something that went wrong
  | "exploration";   // Exploring possibilities before committing

export type Thread = {
  id: string;
  /** What this thread is about. */
  topic: string;
  /** Keywords that identify this thread. */
  keywords: Set<string>;
  /** Message indices in this thread. */
  messageIndices: number[];
  /** Current state. */
  state: "active" | "paused" | "completed" | "merged";
  /** If paused, what paused it (thread ID of the interrupting thread). */
  pausedBy?: string;
  /** If merged, into which thread. */
  mergedInto?: string;
  /** Thread that this was forked from. */
  forkedFrom?: string;
  /** Start time. */
  startedAt: number;
  /** Last activity. */
  lastActiveAt: number;
};

export type UserState = {
  /** How engaged the user is (0=disengaged, 1=fully engaged). */
  engagement: number;
  /** Frustration level (0=calm, 1=very frustrated). */
  frustration: number;
  /** Curiosity (0=focused, 1=exploratory). */
  curiosity: number;
  /** Momentum (0=stuck, 1=fast progress). */
  momentum: number;
  /** Fatigue (0=fresh, 1=tired). */
  fatigue: number;
  /** Communication style: terse (ㅇㅇ, ㄱㄱ) vs verbose. */
  terseness: number;  // 0=verbose, 1=very terse
};

export type TopicSwitch = {
  fromThread: string;
  toThread: string;
  atMessageIndex: number;
  reason: SwitchReason;
  /** How the old topic connects to the new one. */
  implicitConnection: string;
};

export type SwitchReason =
  | "inspiration"     // "아 맞다" — just remembered/realized something
  | "dependency"      // Can't continue without doing something else first
  | "fatigue"         // Switching to easier task
  | "completion"      // Finished the previous, moving to next
  | "urgency"         // Something more important came up
  | "strategic"       // Building toward something bigger
  | "curiosity"       // Wanted to explore something
  | "frustration";    // Giving up or taking a break

export type GlobalContext = {
  /** Inferred session-level goals. */
  sessionGoals: SessionGoal[];
  /** All conversation threads. */
  threads: Map<string, Thread>;
  /** Active threads (can be multiple). */
  activeThreadIds: string[];
  /** Topic switches. */
  topicSwitches: TopicSwitch[];
  /** User state (updated every message). */
  userState: UserState;
  /** User state history. */
  userStateHistory: UserState[];
  /** Full narrative arc of the session. */
  narrativeArc: NarrativeArc;
};

export type NarrativeArc = {
  /** One-sentence summary of the entire session. */
  summary: string;
  /** Key milestones. */
  milestones: Milestone[];
  /** Overall trajectory. */
  trajectory: "building" | "exploring" | "fixing" | "learning" | "mixed";
};

export type Milestone = {
  messageIndex: number;
  description: string;
  significance: number;  // 0-1
};

// ═══════════════════════════════════════════════════════════════════
// THREAD WEAVING
// ═══════════════════════════════════════════════════════════════════

let threadCounter = 0;

function createThread(topic: string, keywords: string[], messageIndex: number): Thread {
  return {
    id: `thread-${++threadCounter}`,
    topic,
    keywords: new Set(keywords),
    messageIndices: [messageIndex],
    state: "active",
    startedAt: messageIndex,
    lastActiveAt: messageIndex,
  };
}

function findBestThread(
  threads: Map<string, Thread>,
  message: ParsedMessage,
  messageIndex: number,
): { thread: Thread; similarity: number } | null {
  const msgKeywords = extractTopicKeywords(message.content);
  if (msgKeywords.length === 0) return null;

  let bestThread: Thread | null = null;
  let bestSimilarity = 0;

  for (const thread of threads.values()) {
    if (thread.state === "merged") continue;

    // Keyword overlap WITH synonym expansion
    const expandedThreadKeywords = new Set(thread.keywords);
    for (const k of thread.keywords) for (const syn of getSynonyms(k)) expandedThreadKeywords.add(syn);
    const expandedMsgKeywords = new Set(msgKeywords);
    for (const k of msgKeywords) for (const syn of getSynonyms(k)) expandedMsgKeywords.add(syn);
    const overlap = [...expandedMsgKeywords].filter((k) => expandedThreadKeywords.has(k)).length;
    const similarity = overlap / Math.sqrt(msgKeywords.length * thread.keywords.size || 1);

    // Recency boost: more recent threads are more likely matches
    const recency = Math.exp(-(messageIndex - thread.lastActiveAt) * 0.05);
    const score = similarity * 0.7 + recency * 0.3;

    if (score > bestSimilarity && score > 0.15) {
      bestSimilarity = score;
      bestThread = thread;
    }
  }

  return bestThread ? { thread: bestThread, similarity: bestSimilarity } : null;
}

function detectTopicSwitch(
  activeThreadIds: string[],
  newThreadId: string,
  message: ParsedMessage,
  messageIndex: number,
  userState: UserState,
): TopicSwitch | null {
  if (activeThreadIds.length === 0) return null;
  const fromThread = activeThreadIds[activeThreadIds.length - 1];
  if (fromThread === newThreadId) return null;

  const text = message.content.toLowerCase();
  let reason: SwitchReason = "completion";
  let connection = "sequential progression";

  // Detect switch reason — prioritize language cues over state inference
  // Language cues are more reliable than inferred emotional state
  if (/아\s*맞다|oh\s*right|actually|참|근데\s*아까|그러고\s*보니/.test(text)) {
    reason = "inspiration";
    connection = "remembered something related from the previous work";
  } else if (/먼저|before|first|일단|우선/.test(text)) {
    reason = "dependency";
    connection = "need to do this before continuing the previous task";
  } else if (/그리고|also|추가로|and also|plus|이것도|이거도/.test(text)) {
    reason = "strategic";
    connection = "building on what was just accomplished";
  } else if (/궁금|wonder|curious|혹시|어때|어떨까/.test(text)) {
    reason = "curiosity";
    connection = "exploring a related idea";
  } else if (/급|urgent|빨리|지금 당장/.test(text)) {
    reason = "urgency";
    connection = "something more important needs attention";
  } else if (/이제|다음|자\s|next|now let|moving on|그럼 이제/.test(text)) {
    reason = "completion";
    connection = "finished the previous task, moving to next";
  } else if (/다른|different|다르게|다른거|other/.test(text)) {
    reason = "strategic";
    connection = "pivoting to a different approach or topic";
  } else if (userState.frustration > 0.7) {
    // Only use state inference as LAST resort, with high threshold
    reason = "frustration";
    connection = "previous task was difficult, switching to something else";
  } else {
    // Default: assume strategic progression, not frustration
    reason = "completion";
    connection = "natural progression in the workflow";
  }

  return {
    fromThread,
    toThread: newThreadId,
    atMessageIndex: messageIndex,
    reason,
    implicitConnection: connection,
  };
}

// ═══════════════════════════════════════════════════════════════════
// USER STATE MODEL
// ═══════════════════════════════════════════════════════════════════

function updateUserState(
  current: UserState,
  message: ParsedMessage,
  isToolSuccess: boolean,
): UserState {
  if (message.role !== "user") {
    // Assistant messages affect momentum
    const toolCount = message.toolCalls?.length ?? 0;
    return {
      ...current,
      momentum: clamp(current.momentum + (isToolSuccess ? 0.05 : -0.1) * (toolCount > 0 ? 1 : 0)),
    };
  }

  const text = message.content;
  const len = text.length;
  const lower = text.toLowerCase();

  // Terseness: short messages = terse
  const newTerseness = len < 10 ? 0.9 : len < 30 ? 0.6 : len < 100 ? 0.3 : 0.1;

  // Engagement: longer messages, questions, code = more engaged
  const hasQuestion = text.includes("?") || /뭐|어떻게|왜|how|what|why/.test(lower);
  const hasCode = /`[^`]+`/.test(text);
  const engagementDelta = (hasQuestion ? 0.1 : 0) + (hasCode ? 0.1 : 0) + (len > 50 ? 0.1 : -0.05);

  // Frustration: only explicit negative words, not ambiguous ones like "아" or "안"
  // "아" alone is too common (e.g., "아 맞다" = "oh right", not frustration)
  const strongFrustration = /에러|버그|error|bug|fail|crash|broken|damn|ugh|씨발|짜증|망했/.test(lower);
  const mildFrustration = /안돼|안 돼|doesn.t work|not working|왜.*안.*돼/.test(lower);
  const frustrationDelta = strongFrustration ? 0.15 : mildFrustration ? 0.08 : -0.08;

  // Curiosity: questions, "어때", "혹시", exploratory language
  const curiositySignals = /궁금|wonder|어때|혹시|what if|could we|한번|try/.test(lower);
  const curiosityDelta = curiositySignals ? 0.15 : -0.03;

  // Momentum: short confirmations after results = high momentum
  const momentumSignals = /ㅇㅇ|ㄱㄱ|ㅇㅋ|ok|go|계속|next|다음/.test(lower);
  const momentumDelta = momentumSignals ? 0.15 : -0.02;

  // Fatigue: increases slowly, but resets partially on high-engagement messages
  const isEnergized = /!|ㄱㄱ|ㅇㅋ|좋아|만들|하자|해보자|let's|build|create/.test(lower);
  const fatigueDelta = isEnergized ? -0.1 : 0.005;

  return {
    engagement: clamp(current.engagement + engagementDelta),
    frustration: clamp(current.frustration + frustrationDelta),
    curiosity: clamp(current.curiosity + curiosityDelta),
    momentum: clamp(current.momentum + momentumDelta),
    fatigue: clamp(current.fatigue + fatigueDelta),
    terseness: current.terseness * 0.7 + newTerseness * 0.3, // Smoothed
  };
}

function clamp(v: number): number {
  return Math.max(0, Math.min(1, v));
}

// ═══════════════════════════════════════════════════════════════════
// HIERARCHICAL GOAL INFERENCE
// ═══════════════════════════════════════════════════════════════════

function inferSessionGoals(
  threads: Map<string, Thread>,
  topicSwitches: TopicSwitch[],
): SessionGoal[] {
  // Cluster threads by semantic similarity
  const threadList = [...threads.values()].filter((t) => t.state !== "merged");
  if (threadList.length === 0) return [];

  // Find overarching themes
  const allKeywords = new Map<string, number>();
  for (const thread of threadList) {
    for (const kw of thread.keywords) {
      allKeywords.set(kw, (allKeywords.get(kw) ?? 0) + 1);
    }
  }

  // Keywords that appear across multiple threads = session-level concepts
  const sessionKeywords = [...allKeywords.entries()]
    .filter(([, count]) => count >= 2)
    .sort(([, a], [, b]) => b - a)
    .map(([kw]) => kw);

  // If threads are mostly connected by strategic/inspiration switches, it's one big goal
  const strategicSwitches = topicSwitches.filter(
    (s) => s.reason === "strategic" || s.reason === "inspiration" || s.reason === "completion",
  );
  const isOneGoal = strategicSwitches.length > topicSwitches.length * 0.5;

  if (isOneGoal && sessionKeywords.length > 0) {
    // Single session goal — pick the most meaningful keywords
    const meaningfulKeywords = sessionKeywords.filter(
      (kw) => kw.length > 3 && !/hawon|home|tmp|claude|task|tool/.test(kw),
    );
    const topKw = meaningfulKeywords.length > 0 ? meaningfulKeywords : sessionKeywords;
    const description = `${topKw.slice(0, 5).join(", ")} — 종합 작업`;
    const subGoals: EpisodeGoal[] = threadList.map((thread, i) => ({
      description: thread.topic,
      parentGoalIndex: 0,
      startIndex: thread.startedAt,
      endIndex: thread.lastActiveAt,
      status: thread.state === "completed" ? "completed" as const : "active" as const,
      connectionType: determineConnectionType(thread, topicSwitches),
    }));

    return [{
      description,
      confidence: Math.min(0.9, 0.3 + sessionKeywords.length * 0.1),
      evidence: threadList.flatMap((t) => t.messageIndices).slice(0, 20),
      subGoals,
      progress: subGoals.filter((g) => g.status === "completed").length / subGoals.length,
    }];
  }

  // Multiple goals: group threads by keyword clusters
  const goals: SessionGoal[] = [];
  const assigned = new Set<string>();

  for (const thread of threadList) {
    if (assigned.has(thread.id)) continue;

    // Find related threads
    const related = threadList.filter((t) => {
      if (t.id === thread.id || assigned.has(t.id)) return false;
      const overlap = [...thread.keywords].filter((k) => t.keywords.has(k)).length;
      return overlap >= 2;
    });

    const group = [thread, ...related];
    for (const t of group) assigned.add(t.id);

    const groupKeywords = new Set<string>();
    for (const t of group) {
      for (const kw of t.keywords) groupKeywords.add(kw);
    }

    goals.push({
      description: [...groupKeywords].slice(0, 5).join(", "),
      confidence: Math.min(0.8, 0.3 + group.length * 0.15),
      evidence: group.flatMap((t) => t.messageIndices).slice(0, 10),
      subGoals: group.map((t) => ({
        description: t.topic,
        parentGoalIndex: goals.length,
        startIndex: t.startedAt,
        endIndex: t.lastActiveAt,
        status: t.state === "completed" ? "completed" as const : "active" as const,
        connectionType: "direct" as const,
      })),
      progress: group.filter((t) => t.state === "completed").length / group.length,
    });
  }

  return goals;
}

function determineConnectionType(
  thread: Thread,
  switches: TopicSwitch[],
): ConnectionType {
  const switchToThis = switches.find((s) => s.toThread === thread.id);
  if (!switchToThis) return "direct";

  switch (switchToThis.reason) {
    case "inspiration": return "inspiration";
    case "dependency": return "prerequisite";
    case "strategic": return "strategic";
    case "completion": return "direct";
    case "frustration": return "recovery";
    case "curiosity": return "exploration";
    default: return "direct";
  }
}

// ═══════════════════════════════════════════════════════════════════
// NARRATIVE ARC
// ═══════════════════════════════════════════════════════════════════

function buildNarrativeArc(
  goals: SessionGoal[],
  threads: Map<string, Thread>,
  switches: TopicSwitch[],
  milestones: Milestone[],
): NarrativeArc {
  // Determine trajectory from thread behavior, not just keywords
  // Count switch reasons to understand the session's nature
  const switchReasonCounts: Record<string, number> = {};
  for (const s of switches) {
    switchReasonCounts[s.reason] = (switchReasonCounts[s.reason] ?? 0) + 1;
  }

  let trajectory: NarrativeArc["trajectory"] = "mixed";
  const totalSwitches = switches.length || 1;

  // If mostly completion/strategic → building (making things in sequence)
  const buildingRatio = ((switchReasonCounts["completion"] ?? 0) + (switchReasonCounts["strategic"] ?? 0)) / totalSwitches;
  // If mostly curiosity/inspiration → exploring
  const exploringRatio = ((switchReasonCounts["curiosity"] ?? 0) + (switchReasonCounts["inspiration"] ?? 0)) / totalSwitches;
  // If mostly frustration/dependency → fixing
  const fixingRatio = ((switchReasonCounts["frustration"] ?? 0) + (switchReasonCounts["dependency"] ?? 0)) / totalSwitches;

  if (buildingRatio > 0.4) trajectory = "building";
  else if (exploringRatio > 0.3) trajectory = "exploring";
  else if (fixingRatio > 0.4) trajectory = "fixing";
  // Also check goal descriptions as fallback
  else {
    const goalText = goals.map((g) => g.description.toLowerCase()).join(" ");
    if (/build|create|만들|구현|deploy|publish/.test(goalText)) trajectory = "building";
    else if (/learn|explain|이해|설명/.test(goalText)) trajectory = "learning";
  }

  // Build summary
  const goalDescs = goals.map((g) => g.description).slice(0, 3);
  const completedCount = goals.filter((g) => g.progress >= 0.8).length;
  const summary = goals.length > 0
    ? `Session covering ${goalDescs.join(", ")}. ${completedCount}/${goals.length} goals reached.`
    : "Session with no clear goal structure.";

  return { summary, milestones, trajectory };
}

// ═══════════════════════════════════════════════════════════════════
// MAIN: GLOBAL CONTEXT BUILDER
// ═══════════════════════════════════════════════════════════════════

export function createGlobalContext(): {
  /** Process a message and update global understanding. */
  process: (message: ParsedMessage, messageIndex: number) => void;
  /** Get current global context. */
  getContext: () => GlobalContext;
  /** Get a human-readable summary of the session so far. */
  getSummary: () => string;
  /** Finalize: compute session goals and narrative arc. */
  finalize: () => GlobalContext;
} {
  const context: GlobalContext = {
    sessionGoals: [],
    threads: new Map(),
    activeThreadIds: [],
    topicSwitches: [],
    userState: {
      engagement: 0.5,
      frustration: 0,
      curiosity: 0.3,
      momentum: 0.5,
      fatigue: 0,
      terseness: 0.5,
    },
    userStateHistory: [],
    narrativeArc: {
      summary: "",
      milestones: [],
      trajectory: "mixed",
    },
  };

  const milestones: Milestone[] = [];

  return {
    process(message: ParsedMessage, messageIndex: number): void {
      // 1. Update user state
      const isToolSuccess = message.role === "assistant" &&
        (message.toolCalls ?? []).every((tc) => !tc.result || !/error|fail/i.test(tc.result));
      context.userState = updateUserState(context.userState, message, isToolSuccess);
      context.userStateHistory.push({ ...context.userState });

      // Only process user messages for thread/goal tracking
      if (message.role !== "user") return;
      if (message.content.trim().length === 0) return;

      // 2. Thread weaving
      const bestMatch = findBestThread(context.threads, message, messageIndex);

      if (bestMatch && bestMatch.similarity > 0.2) {
        // Continue existing thread
        const thread = bestMatch.thread;
        if (thread.state === "paused") thread.state = "active";
        thread.messageIndices.push(messageIndex);
        thread.lastActiveAt = messageIndex;

        // Add new keywords
        for (const kw of extractTopicKeywords(message.content)) {
          thread.keywords.add(kw);
        }

        // Detect topic switch if this thread was not the active one
        const switchEvent = detectTopicSwitch(
          context.activeThreadIds, thread.id, message, messageIndex, context.userState,
        );
        if (switchEvent) {
          context.topicSwitches.push(switchEvent);

          // Pause the old active thread
          const oldThread = context.threads.get(switchEvent.fromThread);
          if (oldThread && oldThread.state === "active") {
            oldThread.state = "paused";
            oldThread.pausedBy = thread.id;
          }
        }

        // Update active threads
        context.activeThreadIds = context.activeThreadIds.filter((id) => id !== thread.id);
        context.activeThreadIds.push(thread.id);
      } else {
        // New thread
        const keywords = extractTopicKeywords(message.content);
        if (keywords.length > 0) {
          const topic = keywords.slice(0, 3).join(" ");
          const thread = createThread(topic, keywords, messageIndex);
          context.threads.set(thread.id, thread);

          const switchEvent = detectTopicSwitch(
            context.activeThreadIds, thread.id, message, messageIndex, context.userState,
          );
          if (switchEvent) {
            context.topicSwitches.push(switchEvent);

            const oldThread = context.threads.get(switchEvent.fromThread);
            if (oldThread && oldThread.state === "active") {
              oldThread.state = "paused";
            }
          }

          context.activeThreadIds.push(thread.id);
        }
      }

      // 3. Milestone detection
      const isMilestone = detectMilestone(message, context);
      if (isMilestone) {
        milestones.push(isMilestone);
      }

      // Trim active threads (max 3)
      if (context.activeThreadIds.length > 3) {
        context.activeThreadIds = context.activeThreadIds.slice(-3);
      }
    },

    getContext(): GlobalContext {
      return context;
    },

    getSummary(): string {
      const threads = [...context.threads.values()];
      const active = threads.filter((t) => t.state === "active");
      const paused = threads.filter((t) => t.state === "paused");

      const us = context.userState;
      const stateEmoji =
        us.frustration > 0.5 ? "😤" :
        us.momentum > 0.7 ? "🚀" :
        us.curiosity > 0.6 ? "🤔" :
        us.fatigue > 0.6 ? "😴" :
        us.engagement > 0.7 ? "🔥" : "💭";

      const lines = [
        `${stateEmoji} User State: engagement=${us.engagement.toFixed(1)} frustration=${us.frustration.toFixed(1)} momentum=${us.momentum.toFixed(1)} fatigue=${us.fatigue.toFixed(1)}`,
        `Threads: ${active.length} active, ${paused.length} paused, ${threads.length} total`,
        `Active: ${active.map((t) => t.topic).join(" | ")}`,
        `Switches: ${context.topicSwitches.length} (${context.topicSwitches.map((s) => s.reason).join(", ")})`,
        `Goals: ${context.sessionGoals.length}`,
      ];

      return lines.join("\n");
    },

    finalize(): GlobalContext {
      // Compute session goals
      context.sessionGoals = inferSessionGoals(context.threads, context.topicSwitches);
      context.narrativeArc = buildNarrativeArc(
        context.sessionGoals, context.threads, context.topicSwitches, milestones,
      );
      return context;
    },
  };
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

const NOISE_WORDS = new Set([
  "the", "a", "an", "is", "are", "was", "to", "in", "on", "for", "of",
  "and", "or", "but", "not", "이", "그", "저", "을", "를", "에", "가",
  "는", "은", "의", "로", "으로", "에서", "까지", "부터",
  "task-notification", "task-id", "tool-use-id", "system-reminder",
]);

function extractTopicKeywords(text: string): string[] {
  // Skip system/noise messages
  if (text.startsWith("<") || text.startsWith("{")) return [];

  const words = text
    .toLowerCase()
    .replace(/[^a-z가-힣0-9\s-]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 2 && !NOISE_WORDS.has(w))
    .filter((w) => !/^[0-9a-f]{6,}$/.test(w))
    .filter((w) => !/^\d+$/.test(w));

  // Also extract backtick entities
  const backticks = text.match(/`([^`]+)`/g);
  if (backticks) {
    for (const bt of backticks) {
      const label = bt.replace(/`/g, "").toLowerCase();
      if (label.length > 1 && label.length < 40) words.push(label);
    }
  }

  return [...new Set(words)];
}

function detectMilestone(
  message: ParsedMessage,
  context: GlobalContext,
): Milestone | null {
  const text = message.content.toLowerCase();

  // Skip system/noise messages
  if (message.content.startsWith("<") || message.content.startsWith("{") ||
      message.content.startsWith("┌──") || /task-notification|system-reminder/.test(text)) {
    return null;
  }

  // Significant events
  if (/완료|완성|성공|done|success|deployed|published|merged|push.*완/.test(text)) {
    return {
      messageIndex: context.userStateHistory.length,
      description: message.content.slice(0, 80),
      significance: 0.8,
    };
  }

  // Major decision
  if (/결정|decided|let's go|확정|ㄱㄱ.*만들/.test(text)) {
    return {
      messageIndex: context.userStateHistory.length,
      description: message.content.slice(0, 80),
      significance: 0.6,
    };
  }

  // Momentum shift
  if (context.userState.momentum > 0.8 && context.userStateHistory.length > 2) {
    const prev = context.userStateHistory[context.userStateHistory.length - 2];
    if (prev && prev.momentum < 0.5) {
      return {
        messageIndex: context.userStateHistory.length,
        description: "Momentum spike — breakthrough moment",
        significance: 0.7,
      };
    }
  }

  return null;
}
