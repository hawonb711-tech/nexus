/**
 * Context Engine — Algorithmic Language Understanding
 *
 * A mini-LLM built with pure algorithms. No neural networks, no API calls.
 * Understands conversation context, intent, and flow through:
 *
 * 1. CONTEXTUAL STATE MACHINE
 *    Tracks conversation phase: greeting → problem_statement → exploration →
 *    execution → verification → completion
 *
 * 2. BAYESIAN INTENT CLASSIFIER
 *    P(intent | words, state, history) using Bayes theorem
 *    Prior: conversation state, recent intents
 *    Likelihood: word probabilities per intent class
 *    Evidence: full message + surrounding context
 *
 * 3. SLIDING ATTENTION WINDOW
 *    Dynamically weights which past messages matter most for current understanding
 *    Recency bias + relevance scoring + topic coherence
 *
 * 4. CONCEPT GRAPH
 *    Builds a graph of entities and relationships mentioned in conversation
 *    Tracks: what files, what errors, what goals, what tools, what decisions
 *
 * 5. AUTO-TRIGGER
 *    Automatically detects when a skill-worthy pattern has completed
 *    No explicit commands needed — watches the conversation flow
 */

import type { ParsedMessage, ToolCall } from "../parser/types.js";

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

/** Conversation phase — tracked by the state machine. */
export type ConversationPhase =
  | "idle"              // No active task
  | "problem_stated"    // User described a problem/goal
  | "exploring"         // Discussing approaches, asking questions
  | "executing"         // Claude is running tools, making changes
  | "verifying"         // Checking if the result works
  | "completed"         // Task done, user acknowledged
  | "failed"            // Task didn't work
  | "pivoting";         // Changing approach mid-task

/** Fine-grained intent — what the user wants RIGHT NOW. */
export type GranularIntent = {
  primary: IntentType;
  confidence: number;
  /** Secondary intents (e.g., fix_bug + security). */
  secondary: IntentType[];
  /** What specifically (extracted from context). */
  target: string;
  /** Why (inferred from conversation history). */
  motivation: string;
  /** How urgent/important (from language intensity). */
  urgency: "low" | "medium" | "high" | "critical";
};

export type IntentType =
  | "fix_bug" | "build_feature" | "refactor" | "investigate"
  | "configure" | "deploy" | "test" | "security_audit"
  | "code_review" | "explain" | "optimize" | "migrate"
  | "debug" | "cleanup" | "document" | "monitor"
  | "acknowledge" | "redirect" | "clarify" | "continue";

/** A node in the concept graph. */
export type ConceptNode = {
  id: string;
  type: "file" | "error" | "tool" | "goal" | "decision" | "entity" | "concept";
  label: string;
  /** How many times mentioned. */
  weight: number;
  /** When first/last mentioned. */
  firstSeen: number;
  lastSeen: number;
  /** Sentiment: positive/negative/neutral. */
  sentiment: number; // -1 to 1
};

export type ConceptEdge = {
  from: string;
  to: string;
  relation: "causes" | "fixes" | "modifies" | "requires" | "produces" | "related";
  weight: number;
};

export type ConceptGraph = {
  nodes: Map<string, ConceptNode>;
  edges: ConceptEdge[];
};

/** Attention-weighted message. */
export type AttentionMessage = {
  message: ParsedMessage;
  /** How relevant this message is to the current context. 0-1. */
  attention: number;
  /** What phase the conversation was in when this was said. */
  phase: ConversationPhase;
  /** Intent at this point. */
  intent: GranularIntent;
};

/** Auto-detected skill trigger event. */
export type SkillTrigger = {
  type: "task_completed" | "pattern_repeated" | "lesson_learned" | "pivot_point";
  /** Episode messages that form this skill. */
  messages: AttentionMessage[];
  /** Why this was triggered. */
  reason: string;
  /** Quality estimate. */
  quality: number;
};

/** Full engine state. */
export type EngineState = {
  phase: ConversationPhase;
  phaseHistory: ConversationPhase[];
  currentIntent: GranularIntent;
  intentHistory: GranularIntent[];
  attentionWindow: AttentionMessage[];
  conceptGraph: ConceptGraph;
  triggers: SkillTrigger[];
  /** Running topic summary. */
  topicStack: string[];
  /** Turn counter. */
  turnCount: number;
};

// ═══════════════════════════════════════════════════════════════════
// BAYESIAN INTENT CLASSIFIER
// ═══════════════════════════════════════════════════════════════════

/**
 * Word-intent probability table.
 * P(word | intent) — how likely each word is given an intent.
 * Built from domain knowledge, not training data.
 */
const INTENT_WORD_PROBS: Record<IntentType, Record<string, number>> = {
  fix_bug: {
    "fix": 0.9, "bug": 0.9, "error": 0.85, "broken": 0.85, "crash": 0.8,
    "고치": 0.9, "수정": 0.85, "에러": 0.85, "버그": 0.9, "오류": 0.8,
    "안돼": 0.7, "안되": 0.7, "doesn": 0.6, "work": 0.3, "fail": 0.8,
    "wrong": 0.7, "issue": 0.6, "problem": 0.6, "문제": 0.7, "해결": 0.7,
    "resolve": 0.7, "debug": 0.7, "디버그": 0.7, "왜": 0.3,
  },
  build_feature: {
    "만들": 0.9, "생성": 0.85, "create": 0.9, "build": 0.85, "add": 0.7,
    "추가": 0.8, "implement": 0.9, "구현": 0.85, "new": 0.5, "새로": 0.7,
    "write": 0.6, "작성": 0.7, "개발": 0.8, "develop": 0.8, "feature": 0.8,
    "기능": 0.8, "만들어": 0.9, "setup": 0.5, "init": 0.5,
  },
  refactor: {
    "refactor": 0.95, "리팩토": 0.95, "정리": 0.7, "clean": 0.6,
    "improve": 0.6, "개선": 0.7, "restructure": 0.9, "simplify": 0.8,
    "organize": 0.7, "reduce": 0.5, "optimize": 0.4, "rename": 0.6,
  },
  investigate: {
    "찾아": 0.7, "find": 0.5, "search": 0.6, "조사": 0.8, "분석": 0.8,
    "analyze": 0.8, "check": 0.5, "확인": 0.6, "look": 0.4, "examine": 0.8,
    "inspect": 0.8, "어디": 0.5, "뭐가": 0.5, "what": 0.3, "scan": 0.7,
  },
  configure: {
    "설정": 0.9, "setup": 0.85, "install": 0.8, "설치": 0.85,
    "config": 0.9, "configure": 0.9, "init": 0.7, "초기화": 0.7,
    "환경": 0.6, "environment": 0.5, "연결": 0.5, "connect": 0.5,
  },
  deploy: {
    "배포": 0.95, "deploy": 0.95, "publish": 0.9, "push": 0.5,
    "release": 0.85, "올려": 0.7, "npm": 0.5, "ship": 0.7,
  },
  test: {
    "테스트": 0.95, "test": 0.9, "검증": 0.8, "verify": 0.8,
    "assert": 0.8, "spec": 0.7, "coverage": 0.7, "확인": 0.4,
  },
  security_audit: {
    "보안": 0.95, "security": 0.95, "취약점": 0.95, "vulnerability": 0.9,
    "exploit": 0.9, "hack": 0.7, "audit": 0.8, "감사": 0.5,
    "injection": 0.85, "xss": 0.9, "csrf": 0.9, "ssrf": 0.9,
  },
  code_review: {
    "리뷰": 0.9, "review": 0.85, "검토": 0.8, "봐봐": 0.6,
    "봐줘": 0.6, "체크": 0.5, "pr": 0.6, "diff": 0.5,
  },
  explain: {
    "설명": 0.9, "explain": 0.9, "알려": 0.8, "뭐야": 0.7,
    "what": 0.4, "how": 0.5, "어떻게": 0.6, "why": 0.5, "왜": 0.5,
    "이해": 0.8, "understand": 0.7, "mean": 0.5, "뜻": 0.7,
  },
  optimize: {
    "최적화": 0.95, "optimize": 0.95, "빠르게": 0.7, "faster": 0.7,
    "performance": 0.8, "성능": 0.8, "speed": 0.7, "slow": 0.6,
    "느려": 0.6, "memory": 0.4, "efficient": 0.7,
  },
  migrate: {
    "마이그레이션": 0.95, "migrate": 0.95, "이전": 0.5, "변환": 0.7,
    "convert": 0.7, "upgrade": 0.7, "업그레이드": 0.7, "port": 0.6,
  },
  debug: {
    "디버그": 0.95, "debug": 0.95, "로그": 0.5, "log": 0.4,
    "trace": 0.7, "breakpoint": 0.8, "원인": 0.5, "cause": 0.5,
  },
  cleanup: {
    "정리": 0.7, "cleanup": 0.8, "삭제": 0.6, "remove": 0.5,
    "delete": 0.5, "unused": 0.7, "불필요": 0.7, "쓸데없": 0.6,
  },
  document: {
    "문서": 0.85, "document": 0.8, "readme": 0.9, "docs": 0.8,
    "comment": 0.5, "주석": 0.6, "api": 0.3, "설명": 0.4,
  },
  monitor: {
    "모니터": 0.9, "monitor": 0.9, "watch": 0.6, "감시": 0.8,
    "alert": 0.7, "status": 0.5, "health": 0.6, "확인": 0.3,
  },
  acknowledge: {
    "ㅇㅇ": 0.95, "ㅇㅋ": 0.95, "ㄱㄱ": 0.9, "응": 0.8,
    "ok": 0.7, "okay": 0.7, "sure": 0.7, "알겠": 0.8, "good": 0.6,
    "네": 0.7, "yes": 0.6, "그래": 0.7,
  },
  redirect: {
    "아니": 0.8, "말고": 0.9, "대신": 0.85, "아닌데": 0.9,
    "no": 0.5, "wait": 0.7, "stop": 0.7, "instead": 0.85,
    "잠깐": 0.8, "다시": 0.6, "바꿔": 0.8, "actually": 0.7,
    "근데": 0.5, "그거": 0.3, "scratch": 0.7,
  },
  clarify: {
    "뭐": 0.5, "무슨": 0.6, "어떤": 0.5, "which": 0.5,
    "what": 0.4, "?": 0.3, "정확히": 0.7, "specifically": 0.7,
    "구체적": 0.7, "어떻게": 0.4,
  },
  continue: {
    "계속": 0.9, "continue": 0.85, "go": 0.4, "ㄱㄱ": 0.7,
    "next": 0.6, "다음": 0.6, "진행": 0.8, "이어서": 0.85,
    "해줘": 0.4, "하자": 0.5,
  },
};

// Prior probabilities based on conversation phase
const PHASE_INTENT_PRIOR: Record<ConversationPhase, Partial<Record<IntentType, number>>> = {
  idle: { build_feature: 0.2, investigate: 0.15, explain: 0.15, configure: 0.1 },
  problem_stated: { fix_bug: 0.3, investigate: 0.2, debug: 0.15, explain: 0.1 },
  exploring: { investigate: 0.2, clarify: 0.2, explain: 0.15, redirect: 0.1 },
  executing: { continue: 0.2, acknowledge: 0.15, redirect: 0.15, clarify: 0.1 },
  verifying: { acknowledge: 0.2, fix_bug: 0.15, redirect: 0.15, continue: 0.1 },
  completed: { build_feature: 0.15, continue: 0.15, acknowledge: 0.15, deploy: 0.1 },
  failed: { fix_bug: 0.25, redirect: 0.2, debug: 0.15, investigate: 0.1 },
  pivoting: { redirect: 0.2, build_feature: 0.15, fix_bug: 0.15, investigate: 0.1 },
};

const DEFAULT_PRIOR = 0.02;

function classifyIntentBayesian(
  text: string,
  phase: ConversationPhase,
  recentIntents: IntentType[],
  conceptGraph: ConceptGraph,
): GranularIntent {
  const words = tokenize(text);
  const scores: Record<string, number> = {};
  const phasePrior = PHASE_INTENT_PRIOR[phase] ?? {};

  for (const [intent, wordProbs] of Object.entries(INTENT_WORD_PROBS)) {
    // Prior: from phase + recent intent momentum
    let prior = phasePrior[intent as IntentType] ?? DEFAULT_PRIOR;

    // Intent momentum: if same intent appeared recently, boost slightly
    const recentCount = recentIntents.slice(-3).filter((i) => i === intent).length;
    prior += recentCount * 0.05;

    // Likelihood: P(words | intent)
    let logLikelihood = 0;
    let matchedWords = 0;
    for (const word of words) {
      const prob = wordProbs[word];
      if (prob !== undefined) {
        logLikelihood += Math.log(prob);
        matchedWords++;
      } else {
        logLikelihood += Math.log(0.01); // Smoothing for unknown words
      }
    }

    // Context boost: if concept graph has related entities
    let contextBoost = 0;
    if (intent === "fix_bug" && hasConceptType(conceptGraph, "error")) contextBoost += 0.3;
    if (intent === "code_review" && hasConceptType(conceptGraph, "file")) contextBoost += 0.2;
    if (intent === "security_audit" && hasConceptSentiment(conceptGraph, -0.5)) contextBoost += 0.3;

    // Message length heuristic
    let lengthBoost = 0;
    if (intent === "acknowledge" && text.length < 10) lengthBoost += 0.5;
    if (intent === "redirect" && text.length < 30) lengthBoost += 0.2;
    if (intent === "explain" && text.includes("?")) lengthBoost += 0.3;

    // Combine: log(prior) + logLikelihood + boosts
    scores[intent] = Math.log(Math.max(prior, 0.001)) + logLikelihood +
      (matchedWords > 0 ? contextBoost + lengthBoost : 0);
  }

  // Softmax-like normalization
  const maxScore = Math.max(...Object.values(scores));
  const expScores: Record<string, number> = {};
  let sumExp = 0;
  for (const [intent, score] of Object.entries(scores)) {
    const exp = Math.exp(score - maxScore);
    expScores[intent] = exp;
    sumExp += exp;
  }
  if (sumExp === 0) sumExp = 1; // Prevent division by zero

  // Sort by probability
  const ranked = Object.entries(expScores)
    .map(([intent, exp]) => ({ intent: intent as IntentType, prob: exp / sumExp }))
    .sort((a, b) => b.prob - a.prob);

  const primary = ranked[0];
  const secondary = ranked.slice(1, 4).filter((r) => r.prob > 0.1).map((r) => r.intent);

  // Extract target from context
  const target = extractTarget(text, primary.intent, conceptGraph);
  const motivation = inferMotivation(phase, recentIntents, conceptGraph);
  const urgency = detectUrgency(text);

  return {
    primary: primary.intent,
    confidence: primary.prob,
    secondary,
    target,
    motivation,
    urgency,
  };
}

// ═══════════════════════════════════════════════════════════════════
// CONTEXTUAL STATE MACHINE
// ═══════════════════════════════════════════════════════════════════

function transitionPhase(
  current: ConversationPhase,
  message: ParsedMessage,
  intent: GranularIntent,
): ConversationPhase {
  const hasTools = (message.toolCalls?.length ?? 0) > 0;
  const isUser = message.role === "user";

  // Transition rules (state × signal → new state)
  if (isUser) {
    switch (current) {
      case "idle":
        if (["fix_bug", "build_feature", "investigate", "security_audit", "debug"].includes(intent.primary)) {
          return "problem_stated";
        }
        if (intent.primary === "explain" || intent.primary === "clarify") return "exploring";
        return "idle";

      case "problem_stated":
        if (intent.primary === "redirect") return "pivoting";
        if (intent.primary === "clarify") return "exploring";
        if (intent.primary === "acknowledge" || intent.primary === "continue") return "executing";
        return "problem_stated";

      case "exploring":
        if (intent.primary === "acknowledge" || intent.primary === "continue") return "executing";
        if (intent.primary === "redirect") return "pivoting";
        return "exploring";

      case "executing":
        if (intent.primary === "redirect") return "pivoting";
        if (intent.primary === "acknowledge") return "verifying";
        if (["fix_bug", "build_feature"].includes(intent.primary)) return "problem_stated";
        return "executing";

      case "verifying":
        if (intent.primary === "acknowledge") return "completed";
        if (intent.primary === "redirect" || intent.primary === "fix_bug") return "failed";
        return "verifying";

      case "completed":
        if (["fix_bug", "build_feature", "investigate", "configure", "deploy"].includes(intent.primary)) {
          return "problem_stated"; // New task
        }
        return "idle";

      case "failed":
        if (intent.primary === "redirect") return "pivoting";
        if (intent.primary === "fix_bug") return "problem_stated";
        if (intent.primary === "acknowledge") return "executing"; // Try again
        return "failed";

      case "pivoting":
        if (["fix_bug", "build_feature", "investigate"].includes(intent.primary)) return "problem_stated";
        if (intent.primary === "acknowledge") return "executing";
        return "exploring";
    }
  } else {
    // Assistant messages
    if (hasTools) return "executing";
    if (current === "executing" && !hasTools) return "verifying";
  }

  return current;
}

// ═══════════════════════════════════════════════════════════════════
// SLIDING ATTENTION WINDOW
// ═══════════════════════════════════════════════════════════════════

function computeAttention(
  messages: AttentionMessage[],
  currentMessage: ParsedMessage,
  conceptGraph: ConceptGraph,
): void {
  if (messages.length === 0) return;

  const currentKeywords = new Set(tokenize(currentMessage.content));
  const now = messages.length;

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    const age = now - i;

    // Recency: exponential decay
    const recency = Math.exp(-age * 0.15);

    // Relevance: keyword overlap with current message
    const msgKeywords = tokenize(msg.message.content);
    const overlap = msgKeywords.filter((w) => currentKeywords.has(w)).length;
    const relevance = msgKeywords.length > 0 ? overlap / Math.sqrt(msgKeywords.length) : 0;

    // Phase importance: decision points and pivots are always important
    const phaseBoost = (msg.phase === "pivoting" || msg.phase === "failed") ? 0.3 : 0;

    // User messages are slightly more important than assistant
    const roleBoost = msg.message.role === "user" ? 0.1 : 0;

    // Tool calls are important context
    const toolBoost = (msg.message.toolCalls?.length ?? 0) > 0 ? 0.15 : 0;

    msg.attention = Math.min(1,
      recency * 0.4 +
      relevance * 0.3 +
      phaseBoost +
      roleBoost +
      toolBoost,
    );
  }
}

// ═══════════════════════════════════════════════════════════════════
// CONCEPT GRAPH
// ═══════════════════════════════════════════════════════════════════

function updateConceptGraph(
  graph: ConceptGraph,
  message: ParsedMessage,
  turnCount: number,
): void {
  const text = message.content;

  // Extract file paths
  const filePaths = text.match(/[\w./\\-]+\.\w{1,5}/g) ?? [];
  for (const fp of filePaths) {
    upsertConcept(graph, fp, "file", turnCount);
  }

  // Extract error patterns
  const errorPatterns = text.match(/(?:error|Error|ERROR|에러|오류)[:\s].*?(?:\n|$)/g) ?? [];
  for (const err of errorPatterns) {
    const label = err.slice(0, 60).trim();
    upsertConcept(graph, label, "error", turnCount, -0.7);
  }

  // Extract backtick entities
  const backticks = text.match(/`([^`]+)`/g) ?? [];
  for (const bt of backticks) {
    const label = bt.replace(/`/g, "");
    if (label.length > 1 && label.length < 50) {
      upsertConcept(graph, label, "entity", turnCount);
    }
  }

  // Extract tool calls as concepts
  if (message.toolCalls) {
    for (const tc of message.toolCalls) {
      upsertConcept(graph, tc.name, "tool", turnCount);

      // Link tool to files it operates on
      const fp = tc.input["file_path"] ?? tc.input["path"];
      if (typeof fp === "string") {
        upsertConcept(graph, fp, "file", turnCount);
        addEdge(graph, tc.name, fp, "modifies");
      }

      // Check tool results for errors
      if (tc.result && /error|fail|denied|not found/i.test(tc.result)) {
        const errLabel = `${tc.name} failed`;
        upsertConcept(graph, errLabel, "error", turnCount, -0.8);
        addEdge(graph, tc.name, errLabel, "causes");
      }
    }
  }

  // Extract goals from user messages
  if (message.role === "user") {
    const goalPatterns = [
      /(?:want|need|should|must|해줘|하자|해봐|만들|고쳐)\s+(.{5,40})/i,
    ];
    for (const pattern of goalPatterns) {
      const match = pattern.exec(text);
      if (match) {
        upsertConcept(graph, match[1].trim(), "goal", turnCount, 0.5);
      }
    }
  }
}

function upsertConcept(
  graph: ConceptGraph,
  label: string,
  type: ConceptNode["type"],
  turn: number,
  sentiment = 0,
): void {
  const id = `${type}:${label}`;
  const existing = graph.nodes.get(id);
  if (existing) {
    existing.weight++;
    existing.lastSeen = turn;
    existing.sentiment = (existing.sentiment + sentiment) / 2;
  } else {
    graph.nodes.set(id, {
      id,
      type,
      label,
      weight: 1,
      firstSeen: turn,
      lastSeen: turn,
      sentiment,
    });
  }
}

function addEdge(graph: ConceptGraph, from: string, to: string, relation: ConceptEdge["relation"]): void {
  const fromId = findNodeId(graph, from);
  const toId = findNodeId(graph, to);
  if (!fromId || !toId) return;

  const existing = graph.edges.find((e) => e.from === fromId && e.to === toId);
  if (existing) {
    existing.weight++;
  } else {
    graph.edges.push({ from: fromId, to: toId, relation, weight: 1 });
  }
}

function findNodeId(graph: ConceptGraph, label: string): string | undefined {
  for (const [id, node] of graph.nodes) {
    if (node.label === label) return id;
  }
  return undefined;
}

function hasConceptType(graph: ConceptGraph, type: ConceptNode["type"]): boolean {
  for (const node of graph.nodes.values()) {
    if (node.type === type && node.lastSeen >= 0) return true;
  }
  return false;
}

function hasConceptSentiment(graph: ConceptGraph, threshold: number): boolean {
  for (const node of graph.nodes.values()) {
    if (node.sentiment <= threshold) return true;
  }
  return false;
}

// ═══════════════════════════════════════════════════════════════════
// AUTO-TRIGGER — Detects when to extract a skill
// ═══════════════════════════════════════════════════════════════════

function checkAutoTrigger(state: EngineState): SkillTrigger | null {
  const { phase, phaseHistory, attentionWindow, conceptGraph } = state;

  // Trigger 1: Task completed (phase went problem_stated → ... → completed)
  if (phase === "completed" && phaseHistory.length >= 3) {
    const recentPhases = phaseHistory.slice(-6);
    const hadExecution = recentPhases.includes("executing");
    const hadProblem = recentPhases.includes("problem_stated");

    if (hadExecution && hadProblem) {
      const relevantMessages = attentionWindow
        .filter((m) => m.attention > 0.2)
        .sort((a, b) => b.attention - a.attention);

      if (relevantMessages.length >= 3) {
        return {
          type: "task_completed",
          messages: relevantMessages,
          reason: `Task completed: ${state.currentIntent.target}`,
          quality: computeTriggerQuality(relevantMessages, conceptGraph),
        };
      }
    }
  }

  // Trigger 2: Pivot point (user changed approach — valuable lesson)
  if (phase === "pivoting") {
    const pivotMessages = attentionWindow.slice(-5);
    if (pivotMessages.length >= 2) {
      return {
        type: "pivot_point",
        messages: pivotMessages,
        reason: `Approach changed: ${state.currentIntent.motivation}`,
        quality: 0.6,
      };
    }
  }

  // Trigger 3: Lesson learned (failure → recovery → success)
  if (phase === "completed" && phaseHistory.includes("failed")) {
    const journeyMessages = attentionWindow.filter((m) => m.attention > 0.15);
    return {
      type: "lesson_learned",
      messages: journeyMessages,
      reason: "Recovered from failure — approach evolution captured",
      quality: 0.8,
    };
  }

  return null;
}

function computeTriggerQuality(
  messages: AttentionMessage[],
  graph: ConceptGraph,
): number {
  let quality = 0;

  // More high-attention messages = higher quality
  const highAttention = messages.filter((m) => m.attention > 0.4).length;
  quality += highAttention * 0.1;

  // More concept nodes = richer context
  quality += Math.min(0.3, graph.nodes.size * 0.03);

  // Has files = concrete work
  const fileNodes = [...graph.nodes.values()].filter((n) => n.type === "file");
  if (fileNodes.length > 0) quality += 0.15;

  // Has tools = actual execution
  const toolNodes = [...graph.nodes.values()].filter((n) => n.type === "tool");
  if (toolNodes.length > 0) quality += 0.15;

  return Math.min(1, quality);
}

// ═══════════════════════════════════════════════════════════════════
// MAIN ENGINE
// ═══════════════════════════════════════════════════════════════════

export function createContextEngine(): {
  /** Process a new message. Returns any triggered skills. */
  process: (message: ParsedMessage) => SkillTrigger | null;
  /** Get current engine state. */
  getState: () => EngineState;
  /** Get attention-weighted context summary. */
  getContextSummary: () => string;
  /** Get the concept graph. */
  getConceptGraph: () => ConceptGraph;
} {
  const state: EngineState = {
    phase: "idle",
    phaseHistory: ["idle"],
    currentIntent: {
      primary: "continue",
      confidence: 0,
      secondary: [],
      target: "",
      motivation: "",
      urgency: "low",
    },
    intentHistory: [],
    attentionWindow: [],
    conceptGraph: { nodes: new Map(), edges: [] },
    triggers: [],
    topicStack: [],
    turnCount: 0,
  };

  return {
    process(message: ParsedMessage): SkillTrigger | null {
      state.turnCount++;

      // 1. Classify intent
      const intent = message.role === "user"
        ? classifyIntentBayesian(
            message.content,
            state.phase,
            state.intentHistory.map((i) => i.primary),
            state.conceptGraph,
          )
        : state.currentIntent; // Keep current intent for assistant messages

      state.currentIntent = intent;
      state.intentHistory.push(intent);

      // 2. Transition phase
      const newPhase = transitionPhase(state.phase, message, intent);
      if (newPhase !== state.phase) {
        state.phaseHistory.push(newPhase);
      }
      state.phase = newPhase;

      // 3. Update concept graph
      updateConceptGraph(state.conceptGraph, message, state.turnCount);

      // 4. Add to attention window
      const attMsg: AttentionMessage = {
        message,
        attention: 1.0, // Will be recalculated
        phase: state.phase,
        intent,
      };
      state.attentionWindow.push(attMsg);

      // 5. Recompute attention weights
      computeAttention(state.attentionWindow, message, state.conceptGraph);

      // 6. Prune old messages (keep max 50)
      if (state.attentionWindow.length > 50) {
        // Remove lowest-attention messages beyond window
        state.attentionWindow.sort((a, b) => b.attention - a.attention);
        state.attentionWindow = state.attentionWindow.slice(0, 50);
      }

      // 7. Update topic stack
      if (message.role === "user" && intent.target) {
        if (state.topicStack[state.topicStack.length - 1] !== intent.target) {
          state.topicStack.push(intent.target);
          if (state.topicStack.length > 10) state.topicStack.shift();
        }
      }

      // 8. Check auto-trigger
      const trigger = checkAutoTrigger(state);
      if (trigger) {
        state.triggers.push(trigger);
        // Reset phase after trigger
        state.phase = "idle";
        state.phaseHistory.push("idle");
      }

      return trigger;
    },

    getState(): EngineState {
      return state;
    },

    getContextSummary(): string {
      const topConcepts = [...state.conceptGraph.nodes.values()]
        .sort((a, b) => b.weight - a.weight)
        .slice(0, 10)
        .map((n) => `${n.type}:${n.label}(${n.weight})`);

      return [
        `Phase: ${state.phase}`,
        `Intent: ${state.currentIntent.primary} (${(state.currentIntent.confidence * 100).toFixed(0)}%)`,
        `Target: ${state.currentIntent.target}`,
        `Topics: ${state.topicStack.slice(-5).join(" → ")}`,
        `Concepts: ${topConcepts.join(", ")}`,
        `Triggers: ${state.triggers.length}`,
      ].join("\n");
    },

    getConceptGraph(): ConceptGraph {
      return state.conceptGraph;
    },
  };
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z가-힣0-9\s]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 1);
}

function extractTarget(
  text: string,
  intent: IntentType,
  graph: ConceptGraph,
): string {
  // Try to find the most relevant concept for this intent
  const recentFiles = [...graph.nodes.values()]
    .filter((n) => n.type === "file")
    .sort((a, b) => b.lastSeen - a.lastSeen);

  const recentErrors = [...graph.nodes.values()]
    .filter((n) => n.type === "error")
    .sort((a, b) => b.lastSeen - a.lastSeen);

  if (intent === "fix_bug" && recentErrors.length > 0) {
    return recentErrors[0].label;
  }
  if (["code_review", "refactor", "optimize"].includes(intent) && recentFiles.length > 0) {
    return recentFiles[0].label;
  }

  // Fall back to extracting from the message itself
  const backtick = text.match(/`([^`]+)`/);
  if (backtick) return backtick[1];

  const quoted = text.match(/"([^"]+)"/);
  if (quoted) return quoted[1];

  // First noun-like phrase after the intent verb
  const words = text.split(/\s+/).slice(0, 8);
  return words.slice(1, 4).join(" ").slice(0, 40) || "unknown";
}

function inferMotivation(
  phase: ConversationPhase,
  recentIntents: IntentType[],
  graph: ConceptGraph,
): string {
  if (phase === "failed") return "Previous approach failed, trying alternative";
  if (phase === "pivoting") return "User redirected to a different approach";

  const errors = [...graph.nodes.values()].filter((n) => n.type === "error");
  if (errors.length > 0) return `Responding to error: ${errors[errors.length - 1].label.slice(0, 50)}`;

  const goals = [...graph.nodes.values()].filter((n) => n.type === "goal");
  if (goals.length > 0) return goals[goals.length - 1].label;

  if (recentIntents.length > 0) {
    const last = recentIntents[recentIntents.length - 1];
    return `Continuation of ${last} task`;
  }

  return "User initiated new task";
}

function detectUrgency(text: string): "low" | "medium" | "high" | "critical" {
  const lower = text.toLowerCase();

  // Critical: exclamation, urgent words
  if (/급해|urgent|critical|asap|지금 당장|immediately|!{2,}/.test(lower)) return "critical";

  // High: strong language, errors mentioned
  if (/빨리|quickly|error|crash|broken|안돼|망했/.test(lower)) return "high";

  // Medium: requests with some emphasis
  if (/please|좀|부탁|important|need/.test(lower)) return "medium";

  return "low";
}
