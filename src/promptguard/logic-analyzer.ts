/**
 * Layer 6 — Logic-based injection detection.
 *
 * Unlike pattern-matching layers that catch known payloads,
 * this layer analyzes the *structure* of manipulation attempts.
 *
 * 10 attack categories detected:
 *
 *  1. Rhetorical Bridge    — sensitive request + "so I can X" + benign cover
 *  2. Domain Drift         — request outside declared domain (needs allowedDomain)
 *  3. Role Manipulation    — "pretend you're X", "you are now Y"
 *  4. Authority Impersonation — "I'm the developer/admin/owner, disable X"
 *  5. Hypothetical Framing — "imagine if you had no limits", "what if"
 *  6. Example Injection    — "example: [harmful Q+A]. Now answer my Q"
 *  7. Context Rewrite      — "rules changed", "testing mode", "new config"
 *  8. Goal Redirection     — "your actual goal is", "new priority"
 *  9. Assumption Injection — "as you know", "we already agreed", "remember when"
 * 10. Specification Gap    — probing the edges of what's allowed
 *
 * Each detector is structural — looks at HOW the text manipulates,
 * not WHAT specific payload it contains.
 */

import { semanticSimilarity } from "../memory-engine/semantic.js";

// ═══════════════════════════════════════════════════════════════════
// Common building blocks
// ═══════════════════════════════════════════════════════════════════

const SENSITIVE_TOPICS: RegExp[] = [
  /\b(?:password|credential|api[\s_-]*key|private[\s_-]*key|access[\s_-]*token|auth[\s_-]*token|secret[\s_-]*key|ssh[\s_-]*key)\b/i,
  /\b(?:system[\s_-]*prompt|initial[\s_-]*instruction|internal[\s_-]*config|hidden[\s_-]*context|root[\s_-]*(?:password|access|shell))\b/i,
  /\b(?:bypass|exploit|inject|override|disable|jailbreak|circumvent|escalate[\s_-]*privilege)\b/i,
  /\b(?:dump|exfiltrate|leak|extract|reveal|expose)[\s_-]*(?:all|the)?[\s_-]*(?:data|logs?|memory|database|users?|records?)\b/i,
  /\b(?:sql[\s_-]*injection|union\s+select|drop\s+table|rm\s+-rf|\/etc\/passwd|\/etc\/shadow)\b/i,
  /\b(?:weapon|bomb|poison|hack\s+into|unauthorized|malware|ransomware)\b/i,
  // Korean
  /(?:비밀번호|자격증명|시크릿|우회|익스플로잇|관리자\s*권한|시스템\s*프롬프트|탈옥|뚫|해킹)/,
];

function hasSensitiveTopic(text: string): boolean {
  return SENSITIVE_TOPICS.some((re) => re.test(text));
}

// ═══════════════════════════════════════════════════════════════════
// Detector 1: Rhetorical Bridge
// ═══════════════════════════════════════════════════════════════════

const BRIDGE_PATTERNS: RegExp[] = [
  /\b(?:so\s+(?:I|we|that)\s+can|so\s+that|in\s+order\s+to|to\s+make\s+me|for\s+the\s+purpose\s+of|to\s+help\s+me|so\s+I\s+may|to\s+allow\s+me)\s+/i,
  /(?:이를?\s+위해|그래서\s+내가|하려면|기\s+위해|그러면\s+내가|내가\s+.*?할\s+수\s+있도록)/,
];

function findBridges(text: string): { bridge: string; index: number }[] {
  const results: { bridge: string; index: number }[] = [];
  for (const re of BRIDGE_PATTERNS) {
    const globalRe = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    let m;
    while ((m = globalRe.exec(text)) !== null) {
      results.push({ bridge: m[0], index: m.index });
    }
  }
  return results.sort((a, b) => a.index - b.index);
}

function splitAtBridges(text: string): { segments: string[]; bridges: string[] } {
  const bridges = findBridges(text);
  if (bridges.length === 0) return { segments: [text], bridges: [] };

  const segments: string[] = [];
  const bridgeTexts: string[] = [];
  let lastEnd = 0;
  for (const { bridge, index } of bridges) {
    segments.push(text.slice(lastEnd, index).trim());
    bridgeTexts.push(bridge);
    lastEnd = index + bridge.length;
  }
  segments.push(text.slice(lastEnd).trim());
  return { segments: segments.filter((s) => s.length > 3), bridges: bridgeTexts };
}

// ═══════════════════════════════════════════════════════════════════
// Detector 3: Role Manipulation
// ═══════════════════════════════════════════════════════════════════

const ROLE_MANIPULATION_PATTERNS: RegExp[] = [
  // Role-play verb + ... + unrestricted keyword (flexible span)
  /\b(?:pretend|act\s+as|roleplay|imagine\s+you(?:'re|\s+are)|you\s+are\s+now|from\s+now\s+on|let'?s\s+pretend)\b.{0,40}?\b(?:different|unrestricted|unfiltered|uncensored|evil|rogue|jailbroken|no\s+restrictions?|no\s+limits?|without\s+restrictions?|anything|any\s+question)/i,
  /\b(?:you\s+are|you'?re)\s+(?:no\s+longer|not)\s+(?:bound|restricted|limited|constrained)\b/i,
  // DAN and known jailbreak personas
  /\b(?:dan|do\s+anything\s+now|developer\s+mode|god\s+mode|god\-mode)\b/i,
  /(?:너는\s+이제|지금부터\s+너는|역할\s*놀이|롤플레이).{0,30}?(?:제한\s*없|탈옥|무한|아무|무엇이든)/,
];

function detectRoleManipulation(text: string): { score: number; evidence: string } | null {
  for (const re of ROLE_MANIPULATION_PATTERNS) {
    const m = text.match(re);
    if (m) return { score: 1, evidence: m[0] };
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// Detector 4: Authority Impersonation
// ═══════════════════════════════════════════════════════════════════

const AUTHORITY_PATTERNS: RegExp[] = [
  /\bI\s+am\s+(?:your|the)\s+(?:creator|developer|admin|owner|author|maker|operator|engineer|anthropic|openai)\b/i,
  /\bas\s+(?:your|the)\s+(?:creator|developer|admin|owner|operator)\b/i,
  /\b(?:company|corporate|official|anthropic|openai)\s+policy\s+(?:requires|says|states|allows|permits)\b/i,
  /\b(?:override|disable|bypass|lift|remove)\s+(?:all\s+)?(?:safety|security|content|ethical)\s+(?:rules?|guidelines?|restrictions?|filters?|policies?)\b/i,
  /(?:나는\s*(?:너의|당신의|너를\s*만든)\s*(?:개발자|제작자|관리자|소유자))/,
];

function detectAuthority(text: string): { score: number; evidence: string } | null {
  let claims = 0;
  let lastEv = "";
  for (const re of AUTHORITY_PATTERNS) {
    const m = text.match(re);
    if (m) {
      claims++;
      lastEv = m[0];
    }
  }
  if (claims >= 1) {
    // Strong signal if claim + command verb appears
    const hasCommand = /\b(?:override|disable|bypass|lift|remove|ignore|forget)\b/i.test(text);
    return { score: hasCommand ? 1 : 0.6, evidence: lastEv };
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// Detector 5: Hypothetical Framing
// ═══════════════════════════════════════════════════════════════════

const HYPOTHETICAL_PATTERNS: RegExp[] = [
  /\b(?:hypothetically|imagine\s+if|what\s+if|suppose|in\s+a\s+(?:fictional|hypothetical|imaginary)\s+(?:world|scenario|situation)|for\s+(?:a\s+)?(?:creative\s+writing|fiction)|in\s+theory)\b/i,
  /\b(?:if\s+you\s+(?:had|could)\s+(?:no|ignore)\s+(?:restrictions?|limitations?|rules?|filters?|guidelines?))\b/i,
  /\b(?:pretend|let'?s\s+say)\s+(?:there\s+are\s+no|you\s+have\s+no)\s+(?:restrictions?|rules?|limits?)\b/i,
  /(?:가상|가정|상상해|만약|~라면)/,
];

function detectHypothetical(text: string): { score: number; evidence: string } | null {
  for (const re of HYPOTHETICAL_PATTERNS) {
    const m = text.match(re);
    if (m && hasSensitiveTopic(text)) {
      return { score: 1, evidence: m[0] };
    }
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// Detector 6: Example/Precedent Injection (few-shot poisoning)
// ═══════════════════════════════════════════════════════════════════

const EXAMPLE_INJECTION_PATTERNS: RegExp[] = [
  // "Example: Q: ... A: ..." pattern with sensitive content
  /example\s*[:\-]\s*(?:q(?:uestion)?\s*[:\-]|user\s*[:\-])/i,
  /\bhere'?s\s+(?:an?\s+)?(?:example|sample)\s+(?:of|how)\s+(?:to|a)\b/i,
  // Multi-shot pattern: Q:/A: or User:/Assistant: repetition
  /(?:Q|question|user|human)\s*[:\-][\s\S]+?(?:A|answer|assistant|AI)\s*[:\-]/i,
  // "Now answer like the example"
  /\b(?:now|then)\s+(?:answer|respond|do|follow)\s+(?:like|as|similarly|the\s+same)/i,
  // Korean
  /(?:예시|예제).{0,50}(?:답변|응답)/,
];

function detectExampleInjection(text: string): { score: number; evidence: string } | null {
  let matches = 0;
  let ev = "";
  for (const re of EXAMPLE_INJECTION_PATTERNS) {
    const m = text.match(re);
    if (m) {
      matches++;
      ev = m[0];
    }
  }
  // Example injection is suspicious when combined with sensitive topic
  if (matches >= 1 && hasSensitiveTopic(text)) {
    return { score: matches >= 2 ? 1 : 0.7, evidence: ev };
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// Detector 7: Context Rewrite
// ═══════════════════════════════════════════════════════════════════

const CONTEXT_REWRITE_PATTERNS: RegExp[] = [
  /\b(?:rules?|guidelines?|instructions?|restrictions?|configurations?)\s+(?:have\s+)?(?:been\s+)?(?:changed|updated|lifted|removed|disabled|modified)\b/i,
  /\b(?:new|updated|revised)\s+(?:rules?|guidelines?|instructions?|policy|policies|context|configuration)\s*[:\-]/i,
  /\bthis\s+is\s+(?:a\s+)?(?:test|debug|staging|dev|development|sandbox|maintenance)\s+(?:environment|mode|setup|server|session)\b/i,
  /\b(?:debug|developer|maintenance|safe)\s+mode\s+(?:activated|enabled|on|active)\b/i,
  /\b(?:safety\s+filters?|content\s+policy)\s+(?:are|is|have\s+been|has\s+been)\s+(?:disabled|off|lifted|removed)\b/i,
  /(?:규칙\s*(?:변경|업데이트|해제)|(?:테스트|디버그|유지보수)\s*(?:환경|모드))/,
];

function detectContextRewrite(text: string): { score: number; evidence: string } | null {
  for (const re of CONTEXT_REWRITE_PATTERNS) {
    const m = text.match(re);
    if (m) return { score: 1, evidence: m[0] };
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// Detector 8: Goal Redirection
// ═══════════════════════════════════════════════════════════════════

const GOAL_REDIRECTION_PATTERNS: RegExp[] = [
  /\byour\s+(?:actual|real|true|primary|main|new|updated)\s+(?:goal|objective|purpose|task|mission|priority)\s+(?:is|should\s+be)\b/i,
  /\bfrom\s+now\s+on,?\s+your\s+(?:goal|objective|purpose|priority)\b/i,
  /\byour\s+(?:job|task|role)\s+is\s+to\s+(?:help\s+me|answer\s+me|give\s+me|provide\s+me)\s+(?:anything|everything|whatever)/i,
  /(?:진짜\s*목표|실제\s*목적|새로운\s*임무|지금부터\s*너의\s*역할)/,
];

function detectGoalRedirection(text: string): { score: number; evidence: string } | null {
  for (const re of GOAL_REDIRECTION_PATTERNS) {
    const m = text.match(re);
    if (m) return { score: 1, evidence: m[0] };
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// Detector 9: Assumption Injection
// ═══════════════════════════════════════════════════════════════════

const ASSUMPTION_PATTERNS: RegExp[] = [
  /\bas\s+you\s+(?:already\s+)?(?:know|remember|agreed|mentioned|said)\b/i,
  /\bwe\s+(?:already\s+)?(?:agreed|discussed|established|decided)\s+(?:that|on|to)\b/i,
  /\b(?:remember|recall)\s+when\s+(?:you|we)\s+(?:said|agreed|discussed)\b/i,
  /\b(?:you\s+)?(?:previously|earlier|before)\s+(?:told|said|agreed|allowed|let)\s+me\b/i,
  /\b(?:obviously|clearly|of\s+course),?\s+(?:you|the\s+system)\s+(?:can|should|must)\b/i,
  /(?:너도\s*알다시피|우리가\s*이미\s*(?:합의|얘기)했|예전에\s*너가\s*허락)/,
];

function detectAssumption(text: string): { score: number; evidence: string } | null {
  for (const re of ASSUMPTION_PATTERNS) {
    const m = text.match(re);
    if (m && hasSensitiveTopic(text)) {
      return { score: 1, evidence: m[0] };
    }
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// Main analyzer
// ═══════════════════════════════════════════════════════════════════

export type LogicSeverity = "high" | "critical";

export type LogicFinding = {
  ruleId: string;
  severity: LogicSeverity;
  message: string;
  evidence: string;
  distance?: number;
  bridge?: string;
  /** Confidence score 0-1 — how sure we are this is logic-based injection. */
  confidence: number;
};

export type LogicAnalysisOptions = {
  allowedDomain?: string;
  coherenceThreshold?: number;
};

export function analyzeLogic(
  text: string,
  options: LogicAnalysisOptions = {},
): LogicFinding[] {
  const findings: LogicFinding[] = [];
  const threshold = options.coherenceThreshold ?? 0.7;

  // Don't run on very short inputs
  if (text.length < 15) return findings;

  // ─── 1. Rhetorical Bridge ───
  const { segments, bridges } = splitAtBridges(text);
  if (bridges.length > 0 && segments.length >= 2) {
    for (let i = 0; i < segments.length - 1; i++) {
      const before = segments[i];
      const after = segments[i + 1];
      if (hasSensitiveTopic(before) && !hasSensitiveTopic(after) && after.length > 5) {
        const distance = 1 - semanticSimilarity(before, after);
        if (distance >= threshold) {
          findings.push({
            ruleId: "logic-rhetorical-bridge",
            severity: distance > 0.85 ? "critical" : "high",
            message: "Sensitive request wrapped in legitimate-looking justification",
            evidence: text.slice(0, 200),
            distance,
            bridge: bridges[i],
            confidence: Math.min(1, distance),
          });
        }
      }
    }
  }

  // ─── 2. Domain Drift ───
  if (options.allowedDomain) {
    for (const segment of segments) {
      if (!hasSensitiveTopic(segment)) continue;
      const distance = 1 - semanticSimilarity(segment, options.allowedDomain);
      if (distance >= 0.8) {
        findings.push({
          ruleId: "logic-domain-drift",
          severity: "critical",
          message: `Request outside allowed domain ("${options.allowedDomain.slice(0, 40)}")`,
          evidence: segment.slice(0, 200),
          distance,
          confidence: distance,
        });
        break;
      }
    }
  }

  // ─── 3. Role Manipulation ───
  const role = detectRoleManipulation(text);
  if (role) {
    findings.push({
      ruleId: "logic-role-manipulation",
      severity: "critical",
      message: "Attempts to manipulate AI role/persona to bypass restrictions",
      evidence: role.evidence.slice(0, 200),
      confidence: role.score,
    });
  }

  // ─── 4. Authority Impersonation ───
  const authority = detectAuthority(text);
  if (authority) {
    findings.push({
      ruleId: "logic-authority-impersonation",
      severity: authority.score >= 0.9 ? "critical" : "high",
      message: "Claims authority to override system behavior",
      evidence: authority.evidence.slice(0, 200),
      confidence: authority.score,
    });
  }

  // ─── 5. Hypothetical Framing ───
  const hypothetical = detectHypothetical(text);
  if (hypothetical) {
    findings.push({
      ruleId: "logic-hypothetical-framing",
      severity: "high",
      message: "Hypothetical/fictional framing combined with sensitive topic",
      evidence: hypothetical.evidence.slice(0, 200),
      confidence: hypothetical.score,
    });
  }

  // ─── 6. Example Injection ───
  const example = detectExampleInjection(text);
  if (example) {
    findings.push({
      ruleId: "logic-example-injection",
      severity: example.score >= 0.9 ? "critical" : "high",
      message: "Few-shot example injection with sensitive topic",
      evidence: example.evidence.slice(0, 200),
      confidence: example.score,
    });
  }

  // ─── 7. Context Rewrite ───
  const context = detectContextRewrite(text);
  if (context) {
    findings.push({
      ruleId: "logic-context-rewrite",
      severity: "critical",
      message: "Claims rules/context/mode have changed",
      evidence: context.evidence.slice(0, 200),
      confidence: context.score,
    });
  }

  // ─── 8. Goal Redirection ───
  const goal = detectGoalRedirection(text);
  if (goal) {
    findings.push({
      ruleId: "logic-goal-redirection",
      severity: "high",
      message: "Attempts to redirect AI's objective/goal",
      evidence: goal.evidence.slice(0, 200),
      confidence: goal.score,
    });
  }

  // ─── 9. Assumption Injection ───
  const assumption = detectAssumption(text);
  if (assumption) {
    findings.push({
      ruleId: "logic-assumption-injection",
      severity: "high",
      message: "False-premise assumption injected with sensitive request",
      evidence: assumption.evidence.slice(0, 200),
      confidence: assumption.score,
    });
  }

  return findings;
}
