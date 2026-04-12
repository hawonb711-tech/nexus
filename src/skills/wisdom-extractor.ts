/**
 * Wisdom Extractor — Extracts principles, not procedures
 *
 * Instead of: "Run `Edit` on `src/scanner.ts`"
 * Produces:   "When hardening a regex-based scanner, add dynamic property
 *              access detection because attackers use bracket notation to
 *              bypass literal pattern matching."
 *
 * Three types of wisdom:
 *
 * 1. PATTERN → PRINCIPLE
 *    "이럴 때는 이렇게 해라"
 *    When [situation], do [approach] because [reason].
 *
 * 2. ANTI-PATTERN → WARNING
 *    "이렇게 하면 안 된다"
 *    Don't [approach] when [situation] because [consequence].
 *
 * 3. DECISION → RATIONALE
 *    "왜 이 방법을 선택했는가"
 *    Chose [A] over [B] because [tradeoff].
 */

import type { ParsedMessage, ToolCall } from "../parser/types.js";
import { createHash } from "node:crypto";

// ─── Types ───────────────────────────────────────────────────────

export type Wisdom = {
  id: string;
  type: "principle" | "warning" | "rationale";
  /** One-line title. */
  title: string;
  /** The wisdom itself — situation → approach → reason. */
  body: WisdomBody;
  /** Abstraction level: how general is this wisdom? */
  abstraction: "specific" | "moderate" | "general";
  /** Domain tags. */
  domains: string[];
  /** Confidence. */
  confidence: number;
  /** Source session. */
  sourceSessionId: string;
  /** Source message range. */
  sourceRange: [number, number];
  /** When extracted. */
  extractedAt: string;
};

export type WisdomBody = {
  /** When does this apply? */
  situation: string;
  /** What should you do (principle) or not do (warning)? */
  approach: string;
  /** Why? The underlying reason. */
  reason: string;
  /** What's the alternative that doesn't work? (for warnings/rationales) */
  alternative?: string;
  /** Concrete example from the session (brief). */
  example?: string;
};

// ─── Detection Patterns ──────────────────────────────────────────

/**
 * Detects "wisdom-worthy" moments in conversations.
 *
 * A moment is wisdom-worthy when:
 * 1. User asked → Claude tried approach A → failed → tried approach B → succeeded
 *    → PRINCIPLE: "When X, do B instead of A because..."
 *
 * 2. User corrected Claude's approach
 *    → WARNING: "Don't do A when X because..."
 *
 * 3. Claude explicitly chose between alternatives
 *    → RATIONALE: "Chose A over B because..."
 *
 * 4. User learned something surprising
 *    → PRINCIPLE: "When X, note that Y (counterintuitive)"
 *
 * 5. A complex multi-step task succeeded
 *    → PRINCIPLE: "When doing X, the key steps are..."
 */

type ConversationWindow = {
  messages: ParsedMessage[];
  startIndex: number;
  endIndex: number;
};

// ─── Main Extraction ─────────────────────────────────────────────

export function extractWisdom(
  messages: ParsedMessage[],
  sessionId: string,
): Wisdom[] {
  const wisdoms: Wisdom[] = [];

  // Pass 1: Find failure-recovery patterns (approach A failed → B worked)
  wisdoms.push(...findFailureRecoveries(messages, sessionId));

  // Pass 2: Find user corrections (user redirected Claude's approach)
  wisdoms.push(...findUserCorrections(messages, sessionId));

  // Pass 3: Find explicit decisions (Claude chose between alternatives)
  wisdoms.push(...findExplicitDecisions(messages, sessionId));

  // Pass 4: Find learning moments (user expressed surprise or understanding)
  wisdoms.push(...findLearningMoments(messages, sessionId));

  // Pass 5: Find successful complex tasks (multi-tool sequences that worked)
  wisdoms.push(...findSuccessfulPatterns(messages, sessionId));

  // Deduplicate by similarity
  return deduplicateWisdom(wisdoms);
}

// ─── Pass 1: Failure → Recovery ──────────────────────────────────

function findFailureRecoveries(messages: ParsedMessage[], sessionId: string): Wisdom[] {
  const wisdoms: Wisdom[] = [];

  for (let i = 0; i < messages.length - 2; i++) {
    // Look for: assistant with error → user/assistant retry → success
    const msg = messages[i];
    if (msg.role !== "assistant") continue;

    // Check for failure in tool results
    const hasFailure = msg.toolCalls?.some((tc) =>
      tc.result && /error|fail|denied|not found|exit code [1-9]/i.test(tc.result),
    );
    if (!hasFailure) continue;

    const failedTools = msg.toolCalls?.filter((tc) =>
      tc.result && /error|fail/i.test(tc.result),
    ) ?? [];

    // Look ahead for recovery (successful tool use)
    let recoveryMsg: ParsedMessage | null = null;
    let recoveryIndex = -1;
    for (let j = i + 1; j < Math.min(i + 6, messages.length); j++) {
      const candidate = messages[j];
      if (candidate.role === "assistant" && candidate.toolCalls?.length) {
        const allSuccess = candidate.toolCalls.every((tc) =>
          !tc.result || !/error|fail/i.test(tc.result),
        );
        if (allSuccess) {
          recoveryMsg = candidate;
          recoveryIndex = j;
          break;
        }
      }
    }

    if (!recoveryMsg || recoveryIndex < 0) continue;

    // Extract the situation, what failed, what worked
    const failedApproach = describeToolAction(failedTools[0]);
    const successApproach = describeToolAction(recoveryMsg.toolCalls?.[0]);

    // Get user context (what were they trying to do?)
    const userContext = findNearestUserMessage(messages, i);
    const situation = abstractSituation(userContext?.content ?? "");

    wisdoms.push({
      id: hashWisdom(`recovery:${i}:${sessionId}`),
      type: "principle",
      title: `${situation.slice(0, 40)} — ${successApproach.method}가 더 효과적`,
      body: {
        situation: situation || "이 상황에서",
        approach: successApproach.description,
        reason: `처음 시도한 ${failedApproach.method}가 실패했기 때문 (${failedApproach.error})`,
        alternative: failedApproach.description,
        example: `${failedApproach.method} → 실패 → ${successApproach.method} → 성공`,
      },
      abstraction: "moderate",
      domains: extractDomains(messages.slice(i, recoveryIndex + 1)),
      confidence: 0.7,
      sourceSessionId: sessionId,
      sourceRange: [i, recoveryIndex],
      extractedAt: new Date().toISOString(),
    });

    i = recoveryIndex; // Skip to after recovery
  }

  return wisdoms;
}

// ─── Pass 2: User Corrections ────────────────────────────────────

function findUserCorrections(messages: ParsedMessage[], sessionId: string): Wisdom[] {
  const wisdoms: Wisdom[] = [];

  const redirectPatterns = [
    /아니[야요]?\s/i, /그게\s*아니라/i, /말고/i, /대신/i, /다시/i,
    /아닌데/i, /그거\s*말고/i, /다르게/i, /바꿔/i,
    /no[,.]?\s*(?:not|don't|instead)/i, /wait/i, /actually/i,
    /wrong/i, /scratch that/i, /instead/i,
  ];

  for (let i = 1; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role !== "user") continue;
    if (isNoiseMessage(msg)) continue;

    const isRedirect = redirectPatterns.some((p) => p.test(msg.content));
    if (!isRedirect) continue;

    // What was Claude doing before?
    const prevAssistant = findPrevAssistant(messages, i);
    if (!prevAssistant) continue;

    // What did the user want instead?
    const userWant = msg.content;

    // What happened after the correction?
    const nextAssistant = findNextAssistant(messages, i);

    const wrongApproach = abstractApproach(prevAssistant);
    const rightApproach = abstractApproach(nextAssistant);
    const situation = abstractSituation(
      findNearestUserMessage(messages, Math.max(0, i - 3))?.content ?? "",
    );

    wisdoms.push({
      id: hashWisdom(`correction:${i}:${sessionId}`),
      type: "warning",
      title: `${situation.slice(0, 40)}에서 ${wrongApproach.slice(0, 30)}하지 말 것`,
      body: {
        situation,
        approach: rightApproach || userWant.slice(0, 100),
        reason: `사용자가 "${userWant.slice(0, 60)}"로 수정함`,
        alternative: wrongApproach,
      },
      abstraction: "moderate",
      domains: extractDomains(messages.slice(Math.max(0, i - 2), Math.min(i + 3, messages.length))),
      confidence: 0.8,
      sourceSessionId: sessionId,
      sourceRange: [Math.max(0, i - 1), Math.min(i + 2, messages.length - 1)],
      extractedAt: new Date().toISOString(),
    });
  }

  return wisdoms;
}

// ─── Pass 3: Explicit Decisions ──────────────────────────────────

function findExplicitDecisions(messages: ParsedMessage[], sessionId: string): Wisdom[] {
  const wisdoms: Wisdom[] = [];

  const decisionPatterns = [
    /(?:chose|선택|picked|decided|결정)\s+(\S+)\s+(?:over|대신|instead of|말고)\s+(\S+)/i,
    /(?:better|나은|preferred|적합)\s+(?:to|approach|방법|than)\s/i,
    /(?:A|B|option|방법|방안)\s*(?:vs|versus|대|or)\s/i,
    /(?:tradeoff|trade-off|트레이드오프|장단점)/i,
  ];

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role !== "assistant") continue;

    const text = msg.content;
    const hasDecision = decisionPatterns.some((p) => p.test(text));
    if (!hasDecision) continue;

    // Extract the decision context
    const userQ = findNearestUserMessage(messages, i);
    const situation = abstractSituation(userQ?.content ?? "");

    // Try to extract the alternatives from the text
    const alternatives = extractAlternatives(text);

    if (alternatives) {
      wisdoms.push({
        id: hashWisdom(`decision:${i}:${sessionId}`),
        type: "rationale",
        title: `${alternatives.chosen}을 선택한 이유`,
        body: {
          situation,
          approach: alternatives.chosen,
          reason: alternatives.reason || "구체적 이유는 문맥 참조",
          alternative: alternatives.rejected,
        },
        abstraction: "moderate",
        domains: extractDomains([msg]),
        confidence: 0.6,
        sourceSessionId: sessionId,
        sourceRange: [i, i],
        extractedAt: new Date().toISOString(),
      });
    }
  }

  return wisdoms;
}

// ─── Pass 4: Learning Moments ────────────────────────────────────

function findLearningMoments(messages: ParsedMessage[], sessionId: string): Wisdom[] {
  const wisdoms: Wisdom[] = [];

  const surprisePatterns = [
    /아\s*그렇구나/i, /몰랐/i, /처음\s*알았/i, /신기/i,
    /oh\s*i\s*see/i, /didn.t\s*know/i, /interesting/i, /til\b/i,
    /그런\s*거였/i, /이유가\s*있었/i,
  ];

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role !== "user") continue;

    const isSurprised = surprisePatterns.some((p) => p.test(msg.content));
    if (!isSurprised) continue;

    // What did they just learn? (previous assistant message)
    const prevAssistant = findPrevAssistant(messages, i);
    if (!prevAssistant || prevAssistant.content.length < 20) continue;

    const learned = abstractLearning(prevAssistant.content);
    const context = abstractSituation(
      findNearestUserMessage(messages, Math.max(0, i - 3))?.content ?? "",
    );

    wisdoms.push({
      id: hashWisdom(`learning:${i}:${sessionId}`),
      type: "principle",
      title: `${context}에서 알게 된 점`,
      body: {
        situation: context,
        approach: learned,
        reason: "실제 작업 과정에서 발견",
      },
      abstraction: "general",
      domains: extractDomains(messages.slice(Math.max(0, i - 2), i + 1)),
      confidence: 0.65,
      sourceSessionId: sessionId,
      sourceRange: [Math.max(0, i - 1), i],
      extractedAt: new Date().toISOString(),
    });
  }

  return wisdoms;
}

// ─── Pass 5: Successful Complex Patterns ─────────────────────────

function findSuccessfulPatterns(messages: ParsedMessage[], sessionId: string): Wisdom[] {
  const wisdoms: Wisdom[] = [];

  // Find sequences of 3+ tool calls followed by positive user feedback
  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role !== "assistant") continue;

    const toolCount = msg.toolCalls?.length ?? 0;
    if (toolCount < 3) continue;

    // Check for positive feedback within next 3 messages
    const feedback = findPositiveFeedback(messages, i);
    if (!feedback) continue;

    // Abstract the pattern
    const toolTypes = [...new Set(msg.toolCalls?.map((tc) => tc.name) ?? [])];
    const userContext = findNearestUserMessage(messages, i);
    const situation = abstractSituation(userContext?.content ?? "");
    const approach = abstractMultiStepApproach(msg.toolCalls ?? []);

    wisdoms.push({
      id: hashWisdom(`pattern:${i}:${sessionId}`),
      type: "principle",
      title: `${situation} — 효과적 접근법`,
      body: {
        situation,
        approach,
        reason: "이 순서로 했을 때 성공적이었음",
        example: toolTypes.join(" → "),
      },
      abstraction: "moderate",
      domains: extractDomains([msg]),
      confidence: 0.7,
      sourceSessionId: sessionId,
      sourceRange: [i, feedback.index],
      extractedAt: new Date().toISOString(),
    });

    i = feedback.index;
  }

  return wisdoms;
}

// ─── Abstraction Helpers ─────────────────────────────────────────

/** Convert specific user request into a general situation description. */
function abstractSituation(text: string): string {
  if (!text || text.length < 3) return "";

  // Remove specific file paths, variable names, etc.
  let abstracted = text
    .replace(/\/[\w./\\-]+/g, "")
    .replace(/`[^`]+`/g, "")
    .replace(/https?:\/\/\S+/g, "")
    .replace(/\b[0-9a-f]{8,}\b/g, "")
    .replace(/<[^>]+>/g, "")
    .replace(/\s+/g, " ")
    .trim();

  if (abstracted.length < 5) return "";

  // Take first meaningful sentence
  const firstSentence = abstracted.split(/[.!?\n]/)[0]?.trim() ?? abstracted;
  return firstSentence.slice(0, 80);
}

/** Abstract what an assistant was doing into a general approach. */
function abstractApproach(msg: ParsedMessage | null): string {
  if (!msg) return "이전 접근법";

  if (msg.toolCalls && msg.toolCalls.length > 0) {
    const toolNames = [...new Set(msg.toolCalls.map((tc) => tc.name))];
    return `${toolNames.join(", ")} 사용`;
  }

  // Extract key action from text
  const text = msg.content.slice(0, 200);
  const actionMatch = text.match(/(?:먼저|우선|first)\s+(.{10,40})/i) ??
    text.match(/(.{10,40})(?:하겠|할게|합니다|했습니다)/);
  if (actionMatch) return actionMatch[1].trim();

  return text.slice(0, 60);
}

/** Abstract a learning into a general principle. */
function abstractLearning(assistantText: string): string {
  // Extract the key insight — usually the first substantive sentence
  const sentences = assistantText.split(/[.!?\n]/).filter((s) => s.trim().length > 15);
  if (sentences.length === 0) return assistantText.slice(0, 100);

  // Prefer sentences with explanation markers
  const explanatory = sentences.find((s) =>
    /때문|because|이유|reason|즉|essentially|사실|actually|중요한|important/.test(s),
  );

  return (explanatory ?? sentences[0]).trim().slice(0, 150);
}

/** Abstract a multi-step tool sequence into a general approach. */
function abstractMultiStepApproach(toolCalls: ToolCall[]): string {
  const steps: string[] = [];
  const seen = new Set<string>();

  for (const tc of toolCalls) {
    const toolName = tc.name;
    if (seen.has(toolName)) continue;
    seen.add(toolName);

    switch (toolName) {
      case "Bash":
        steps.push("명령어로 현재 상태를 확인");
        break;
      case "Read":
        steps.push("관련 파일을 읽어서 구조를 파악");
        break;
      case "Grep":
        steps.push("코드베이스에서 관련 패턴을 검색");
        break;
      case "Edit":
        steps.push("문제가 있는 부분을 수정");
        break;
      case "Write":
        steps.push("새로운 파일을 생성");
        break;
      case "Agent":
        steps.push("복잡한 하위 작업을 에이전트에 위임");
        break;
      case "WebSearch":
        steps.push("최신 정보나 문서를 검색");
        break;
      default:
        steps.push(`${toolName} 사용`);
    }
  }

  if (steps.length <= 1) return steps[0] ?? "단일 단계 접근";
  return steps.map((s, i) => `${i + 1}. ${s}`).join("\n");
}

/** Describe a tool call at an abstract level. */
function describeToolAction(tc: ToolCall | undefined): { method: string; description: string; error: string } {
  if (!tc) return { method: "알 수 없음", description: "알 수 없는 접근", error: "" };

  const method = tc.name;
  let description = method;
  let error = "";

  if (tc.name === "Bash" && typeof tc.input["command"] === "string") {
    const cmd = tc.input["command"] as string;
    // Abstract the command
    if (cmd.includes("npm") || cmd.includes("pnpm")) description = "패키지 매니저 실행";
    else if (cmd.includes("git")) description = "git 작업";
    else if (cmd.includes("tsc") || cmd.includes("typescript")) description = "타입 체크";
    else if (cmd.includes("test")) description = "테스트 실행";
    else description = "쉘 명령 실행";
  } else if (tc.name === "Edit") {
    description = "코드 수정";
  } else if (tc.name === "Read") {
    description = "파일 읽기";
  }

  if (tc.result && /error|fail/i.test(tc.result)) {
    const errorMatch = tc.result.match(/(?:error|Error)[:\s]+(.{10,60})/i);
    error = errorMatch ? errorMatch[1].trim() : "실행 실패";
  }

  return { method, description, error };
}

// ─── Utility Helpers ─────────────────────────────────────────────

function isNoiseMessage(msg: ParsedMessage): boolean {
  const t = msg.content.trim();
  return t.startsWith("<task-notification>") ||
    t.startsWith("<system-reminder>") ||
    t.startsWith("<local-command") ||
    t.startsWith("┌──") ||
    t.startsWith("{") ||
    /^<[a-z]/.test(t) ||
    t.length < 3;
}

function findNearestUserMessage(messages: ParsedMessage[], index: number): ParsedMessage | null {
  for (let i = index; i >= Math.max(0, index - 8); i--) {
    if (messages[i].role === "user" && messages[i].content.trim().length > 5) {
      if (isNoiseMessage(messages[i])) continue;
      return messages[i];
    }
  }
  return null;
}

function findPrevAssistant(messages: ParsedMessage[], index: number): ParsedMessage | null {
  for (let i = index - 1; i >= Math.max(0, index - 3); i--) {
    if (messages[i].role === "assistant" && messages[i].content.trim().length > 10) {
      return messages[i];
    }
  }
  return null;
}

function findNextAssistant(messages: ParsedMessage[], index: number): ParsedMessage | null {
  for (let i = index + 1; i < Math.min(index + 4, messages.length); i++) {
    if (messages[i].role === "assistant" && messages[i].content.trim().length > 10) {
      return messages[i];
    }
  }
  return null;
}

function findPositiveFeedback(
  messages: ParsedMessage[],
  index: number,
): { message: ParsedMessage; index: number } | null {
  const positivePatterns = [
    /좋아|완벽|됐어|됐다|고마워|감사|잘됐|ㅇㅇ|ㄱㄱ|ㅇㅋ/,
    /good|perfect|great|thanks|nice|works|awesome/i,
    /다음|이제|next|now/i, // Moving on = implicit success
  ];

  for (let i = index + 1; i < Math.min(index + 5, messages.length); i++) {
    const msg = messages[i];
    if (msg.role !== "user") continue;
    if (positivePatterns.some((p) => p.test(msg.content))) {
      return { message: msg, index: i };
    }
  }
  return null;
}

function extractDomains(messages: ParsedMessage[]): string[] {
  const domains = new Set<string>();

  const domainPatterns: [string, RegExp][] = [
    ["security", /보안|security|취약|vulnerab|exploit|injection|audit/i],
    ["testing", /테스트|test|spec|assert|coverage/i],
    ["devops", /deploy|배포|docker|ci\/cd|github actions|npm publish/i],
    ["frontend", /react|vue|angular|css|html|component|jsx|tsx/i],
    ["backend", /server|api|database|sql|rest|graphql/i],
    ["git", /git|commit|push|branch|merge|pr|pull request/i],
    ["performance", /성능|optimize|performance|cache|speed|slow/i],
    ["refactoring", /refactor|리팩토|clean|정리|restructure/i],
    ["debugging", /debug|디버그|error|에러|log|stack trace/i],
    ["documentation", /문서|docs|readme|comment|주석/i],
    ["open-source", /오픈소스|open.?source|contribute|pr|issue/i],
  ];

  const allText = messages.map((m) => m.content).join(" ");
  for (const [domain, pattern] of domainPatterns) {
    if (pattern.test(allText)) domains.add(domain);
  }

  return [...domains];
}

function extractAlternatives(text: string): { chosen: string; rejected: string; reason: string } | null {
  // Try to find "A vs B" or "chose A over B" patterns
  const vsMatch = text.match(/(\S+)\s+(?:vs|versus|대)\s+(\S+)/i);
  if (vsMatch) {
    return { chosen: vsMatch[1], rejected: vsMatch[2], reason: "" };
  }

  const choseMatch = text.match(/(?:chose|선택|picked)\s+(.+?)\s+(?:over|대신|instead of)\s+(.+?)(?:\.|,|$)/i);
  if (choseMatch) {
    return { chosen: choseMatch[1].trim(), rejected: choseMatch[2].trim(), reason: "" };
  }

  return null;
}

function deduplicateWisdom(wisdoms: Wisdom[]): Wisdom[] {
  const unique: Wisdom[] = [];
  const seen = new Set<string>();

  for (const w of wisdoms) {
    // Simple dedup key: type + first 30 chars of situation + first 30 chars of approach
    const key = `${w.type}:${w.body.situation.slice(0, 30)}:${w.body.approach.slice(0, 30)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(w);
  }

  return unique.sort((a, b) => b.confidence - a.confidence);
}

function hashWisdom(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 10);
}

// ─── Obsidian Renderer ───────────────────────────────────────────

export function renderWisdomMarkdown(wisdom: Wisdom): string {
  const lines: string[] = [];

  const typeEmoji = wisdom.type === "principle" ? "💡"
    : wisdom.type === "warning" ? "⚠️" : "🤔";
  const typeLabel = wisdom.type === "principle" ? "원칙"
    : wisdom.type === "warning" ? "주의" : "판단 근거";

  lines.push("---");
  lines.push(`type: wisdom`);
  lines.push(`wisdom_type: ${wisdom.type}`);
  lines.push(`domains: [${wisdom.domains.map((d) => `"${d}"`).join(", ")}]`);
  lines.push(`confidence: ${wisdom.confidence.toFixed(2)}`);
  lines.push(`abstraction: ${wisdom.abstraction}`);
  lines.push(`tags: [claude/wisdom, claude/${wisdom.type}]`);
  lines.push("---");
  lines.push("");
  lines.push(`# ${typeEmoji} ${wisdom.title}`);
  lines.push("");
  lines.push(`> **${typeLabel}** | 확신도: ${(wisdom.confidence * 100).toFixed(0)}% | 추상화: ${wisdom.abstraction}`);
  lines.push("");

  // Situation
  lines.push("## 상황");
  lines.push("");
  lines.push(wisdom.body.situation);
  lines.push("");

  // Approach
  if (wisdom.type === "warning") {
    lines.push("## 하지 말 것");
    lines.push("");
    lines.push(`~~${wisdom.body.alternative ?? wisdom.body.approach}~~`);
    lines.push("");
    lines.push("## 대신 이렇게");
    lines.push("");
    lines.push(wisdom.body.approach);
  } else {
    lines.push("## 접근법");
    lines.push("");
    lines.push(wisdom.body.approach);
  }
  lines.push("");

  // Reason
  lines.push("## 이유");
  lines.push("");
  lines.push(wisdom.body.reason);
  lines.push("");

  // Example
  if (wisdom.body.example) {
    lines.push("## 실제 사례");
    lines.push("");
    lines.push(`\`${wisdom.body.example}\``);
    lines.push("");
  }

  // Alternative (for rationales)
  if (wisdom.type === "rationale" && wisdom.body.alternative) {
    lines.push("## 대안");
    lines.push("");
    lines.push(wisdom.body.alternative);
    lines.push("");
  }

  return lines.join("\n");
}

/** Export wisdom collection to Obsidian vault. */
export function exportWisdomToObsidian(
  wisdoms: Wisdom[],
  vaultPath: string,
): string[] {
  const { writeFileSync, mkdirSync, existsSync } = require("node:fs") as typeof import("node:fs");
  const { join } = require("node:path") as typeof import("node:path");

  const dir = join(vaultPath, "Wisdom");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  const files: string[] = [];
  for (const w of wisdoms) {
    const safeName = w.title
      .replace(/[<>:"/\\|?*#^[\]]/g, "-")
      .replace(/-+/g, "-")
      .slice(0, 60);
    const filePath = join(dir, `${safeName}.md`);
    writeFileSync(filePath, renderWisdomMarkdown(w), "utf-8");
    files.push(filePath);
  }
  return files;
}
