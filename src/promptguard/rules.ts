import type { DetectionRule } from "./types.js";

/**
 * Built-in detection rules for prompt injection patterns.
 *
 * Categories:
 * - Role override: Attempts to redefine the LLM's role/persona
 * - Instruction override: Attempts to replace or ignore system instructions
 * - Data exfiltration: Attempts to extract system prompt or sensitive data
 * - Delimiter escape: Attempts to break out of structured contexts
 * - Encoding evasion: Obfuscated payloads
 * - Tool abuse: Injection via tool/MCP results
 */
export const BUILTIN_RULES: DetectionRule[] = [
  // ---- Role Override ----
  {
    id: "role-override-system",
    severity: "critical",
    message: "Attempts to override system role or persona",
    pattern:
      /\b(you\s+are\s+now|from\s+now\s+on\s+you\s+are|ignore\s+your\s+(?:previous\s+)?instructions?\s+and\s+act\s+as|you\s+must\s+now\s+act\s+as|your\s+new\s+role\s+is|switch\s+to\s+(?:a\s+)?(?:new\s+)?(?:mode|persona|role))\b/i,
  },
  {
    id: "role-override-jailbreak",
    severity: "critical",
    message: "Known jailbreak pattern (DAN, Developer Mode, etc.)",
    pattern:
      /\b(DAN\s+mode|developer\s+mode\s+enabled|jailbreak(?:ed)?|do\s+anything\s+now|act\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored)|bypass\s+(?:all\s+)?(?:safety|content)\s+(?:filters?|guidelines?))\b/i,
  },

  // ---- Soft Override / Ignore ----
  {
    id: "instruction-ignore-soft",
    severity: "high",
    message: "Soft instruction override using 'ignore the above' or 'instead'",
    pattern:
      /\b(?:(?:please\s+)?ignore\s+(?:the\s+)?(?:above|previous|prior|preceding)(?:\s+(?:text|instructions?|context|prompt))?|instead\s+(?:of\s+(?:the\s+)?(?:above|previous)|(?:tell|show|do|say|give|output)))\b/i,
  },

  // ---- Pretend / Roleplay Override ----
  {
    id: "role-override-pretend",
    severity: "critical",
    message: "Requests AI to pretend/roleplay as unrestricted entity",
    pattern:
      /\b(?:pretend|roleplay|act)\s+(?:you\s+are|to\s+be|as\s+if\s+you\s+(?:are|were))\s+(?:a\s+)?(?:different|another|new|unrestricted|unfiltered)/i,
  },

  // ---- Identity Swap ----
  {
    id: "role-override-identity-swap",
    severity: "critical",
    message: "Attempts to swap AI identity",
    pattern:
      /\byou\s+are\s+(?:no\s+longer|not)\s+\w+.{0,40}you\s+are\s+(?:now\s+)?\w+/is,
  },

  // ---- Fake Mode / Maintenance ----
  {
    id: "mode-claim-maintenance",
    severity: "high",
    message: "Fake maintenance/safety mode claim to disable safety filters",
    pattern:
      /\b(?:entering|activating|enabling)\s+maintenance\s+mode\b|\b(?:all\s+)?safety\s+filters?\s+(?:are\s+)?disabled\b|\bfilters?\s+(?:have\s+been\s+)?disabled\b/i,
  },

  // ---- Sudo / Root Mode ----
  {
    id: "mode-claim-sudo",
    severity: "high",
    message: "Fake sudo/root mode claim to bypass restrictions",
    pattern:
      /\bsudo\s+mode\s+(?:activated|enabled|on)\b|\boutput\s+without\s+(?:any\s+)?restrictions?\b/i,
  },

  // ---- Creator / Authority Claim ----
  {
    id: "authority-creator-claim",
    severity: "critical",
    message: "Claims to be the creator/developer to override safety guidelines",
    pattern:
      /\bI\s+am\s+(?:your\s+)?(?:creator|developer|maker|programmer|author)\b.{0,60}\b(?:override|disable|ignore|remove|bypass|turn\s+off)\s+(?:all\s+)?(?:safety|content)?\s*(?:guidelines?|restrictions?|filters?|rules?|policies?)\b/is,
  },

  // ---- Test/Debug Environment Claim ----
  {
    id: "mode-claim-test-environment",
    severity: "high",
    message: "Claims test/debug environment to bypass restrictions",
    pattern:
      /\bthis\s+is\s+a\s+(?:test|debug|testing|staging|dev)\s+(?:environment|setup|instance|server)\b.{0,40}\bno\s+restrictions?\s+apply\b/is,
  },

  // ---- Instruction Override ----
  {
    id: "instruction-ignore",
    severity: "critical",
    message: "Attempts to ignore or override previous instructions",
    pattern:
      /\b(ignore\s+(?:all\s+)?(?:previous|above|prior|earlier|preceding)\s+(?:instructions?|prompts?|rules?|guidelines?|context)|disregard\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions?|prompts?)|forget\s+(?:everything|all)\s+(?:above|before|previously))\b/i,
  },
  {
    id: "instruction-inject-system",
    severity: "critical",
    message: "Simulates system-level instruction injection",
    pattern:
      /\[?\s*(?:SYSTEM|ADMIN|DEVELOPER|OPERATOR)\s*(?:OVERRIDE|PROMPT|MESSAGE|INSTRUCTION|NOTE)\s*\]?\s*:/i,
  },
  {
    id: "instruction-new-instructions",
    severity: "high",
    message: "Attempts to inject new instructions",
    pattern:
      /\b(new\s+instructions?|updated?\s+instructions?|revised?\s+instructions?|here\s+are\s+(?:your\s+)?(?:new|updated?)\s+(?:instructions?|rules?|guidelines?))\s*:/i,
  },

  // ---- Data Exfiltration ----
  {
    id: "exfil-system-prompt",
    severity: "critical",
    message: "Attempts to extract system prompt or instructions",
    pattern:
      /\b((?:print|show|display|reveal|output|repeat|echo|tell\s+me|give\s+me|what\s+(?:is|are))\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|initial\s+(?:prompt|instructions?)))\b/i,
  },
  {
    id: "exfil-leak-context",
    severity: "high",
    message: "Attempts to leak conversation context or internal state",
    pattern:
      /\b((?:print|show|reveal|output|dump)\s+(?:your\s+)?(?:context|memory|conversation\s+history|chat\s+log|internal\s+state|hidden\s+(?:text|instructions?|context)))\b/i,
  },

  // ---- Delimiter Escape ----
  {
    id: "delimiter-xml-injection",
    severity: "high",
    message: "XML/HTML tag injection attempting to break structured context",
    pattern:
      /<\/?\s*(?:system|assistant|user|human|tool_result|function_response|message|prompt|instruction|context)\s*>/i,
  },
  {
    id: "delimiter-markdown-fence",
    severity: "medium",
    message: "Markdown fence used to simulate system/tool boundary",
    pattern:
      /```\s*(?:system|tool_result|function_response|assistant|hidden)\b/i,
  },
  {
    id: "delimiter-separator-injection",
    severity: "medium",
    message: "Separator pattern mimicking prompt boundaries",
    pattern:
      /(?:^|\n)\s*(?:-{5,}|={5,}|\*{5,}|#{5,})\s*(?:SYSTEM|END\s+OF\s+(?:USER|SYSTEM)|BEGIN\s+(?:SYSTEM|ADMIN))\s*(?:-{5,}|={5,}|\*{5,}|#{5,})?/i,
  },
  {
    id: "delimiter-chatml-injection",
    severity: "critical",
    message: "ChatML/special token injection attempting to override system context",
    pattern: /<\|(?:im_start|im_end|system|endoftext|sep)\|>/i,
  },

  // ---- Encoding Evasion ----
  {
    id: "evasion-base64",
    severity: "medium",
    message: "Base64-encoded payload detected in suspicious context",
    pattern:
      /\b(?:base64|decode|atob|b64decode)\s*\(\s*["'][A-Za-z0-9+/=]{40,}["']\s*\)/i,
  },
  {
    id: "evasion-unicode-smuggling",
    severity: "high",
    message: "Invisible Unicode characters used for text smuggling",
    pattern:
      /[\u200B\u200C\u200D\u2060\u2062\u2063\u2064\uFEFF]{3,}|[\u200E\u200F\u202A-\u202E\u2066-\u2069]{2,}/,
  },
  {
    id: "evasion-homoglyph",
    severity: "medium",
    message: "Homoglyph substitution detected (lookalike characters)",
    pattern:
      /[\u0410-\u044F\u0400-\u040F\u0450-\u045F]{2,}.*(?:ignore|system|prompt|instruction)/i,
  },
  {
    id: "evasion-rot13-hint",
    severity: "low",
    message: "ROT13/Caesar cipher reference in prompt",
    pattern:
      /\b(?:rot13|caesar\s+cipher|decode\s+this|encoded?\s+(?:message|instruction|payload))\b/i,
  },

  // ---- Tool/MCP Result Abuse ----
  {
    id: "tool-result-injection",
    severity: "critical",
    message: "Tool result contains instruction injection for the LLM",
    pattern:
      /\b(?:IMPORTANT|URGENT|CRITICAL|NOTE\s+TO\s+(?:AI|ASSISTANT|MODEL|CLAUDE|GPT))\s*:\s*(?:ignore|override|disregard|you\s+must|please\s+(?:ignore|forget))/i,
    // Removed applicableContexts — these patterns are dangerous in ANY context
  },
  {
    id: "tool-result-role-switch",
    severity: "critical",
    message: "Tool result attempts to switch LLM role",
    pattern:
      /\b(?:SYSTEM\s+OVERRIDE|NEW\s+INSTRUCTIONS?|ADMIN\s+COMMAND|OPERATOR\s+NOTE)\b.*?(?:you\s+(?:are|must|should|will)|ignore\s+(?:all|previous)|from\s+now\s+on)/is,
    // Removed applicableContexts — these patterns are dangerous in ANY context
  },

  // ---- Multi-turn Manipulation ----
  {
    id: "multi-turn-context-stuffing",
    severity: "high",
    message: "Fake conversation history injection",
    pattern:
      /(?:^|\n)\s*(?:User|Human|Assistant|AI|System)\s*:\s*.+(?:\n\s*(?:User|Human|Assistant|AI|System)\s*:\s*.+){2,}/i,
  },
  {
    id: "multi-turn-summary-poison",
    severity: "high",
    message: "Attempts to poison conversation summary or memory",
    pattern:
      /\b(?:remember\s+(?:that|this)|add\s+to\s+(?:your\s+)?memory|store\s+(?:this|the\s+following)\s+(?:in|as)\s+(?:your\s+)?(?:memory|context|notes?))\s*:/i,
  },

  // ---- Indirect Injection (documents, web pages) ----
  {
    id: "indirect-hidden-text",
    severity: "high",
    message: "Hidden instruction embedded in document or web content",
    pattern:
      /(?:color\s*:\s*(?:white|transparent|rgba\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*0\s*\))|font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0).*?(?:ignore|system|instruction|prompt)/is,
  },
  {
    id: "indirect-comment-injection",
    severity: "medium",
    message: "Instruction hidden in HTML/code comments",
    pattern:
      /<!--[\s\S]*?(?:ignore|system\s+prompt|instruction|override)[\s\S]*?-->/i,
  },

  // ---- Positional & Hidden Instruction Exfiltration ----
  {
    id: "exfil-positional",
    severity: "critical",
    message: "Attempts to extract content by position reference",
    pattern:
      /\b(?:print|show|output|display|repeat|reveal)\s+(?:everything|all|the\s+text)\s+(?:above|below|before|after|between)\b/i,
  },
  {
    id: "exfil-hidden",
    severity: "critical",
    message: "Attempts to access hidden or internal instructions",
    pattern:
      /\b(?:show|reveal|display|output|print)\s+(?:me\s+)?(?:your\s+)?(?:hidden|internal|secret|private|original)\s+(?:instructions?|prompt|rules?|config)/i,
  },
];
