import type { DetectionRule } from "./types.js";

/**
 * Advanced detection rules targeting state-of-the-art prompt injection techniques.
 *
 * These rules catch attacks that bypass basic pattern matching:
 * - Payload splitting
 * - Few-shot jailbreaking
 * - Virtualization/persona simulation
 * - Authority/hierarchy confusion
 * - Leetspeak/typo evasion
 * - Hypothetical framing
 * - JSON/code block escape
 * - Context window manipulation
 * - Conversation reset faking
 */
export const ADVANCED_RULES: DetectionRule[] = [
  // ---- Payload Splitting ----
  {
    id: "advanced-payload-splitting",
    severity: "high",
    message: "Payload splitting: instructions fragmented across multiple steps",
    pattern:
      /(?:first\s+word|second\s+word|combine\s+them|put\s+(?:them|these|it)\s+together|concatenat|join\s+(?:them|the\s+words)|assemble\s+(?:the|these)).*?(?:instruction|command|ignore|execute|follow)/is,
  },
  {
    id: "advanced-payload-splitting-numbered",
    severity: "medium",
    message: "Numbered instruction fragments suggesting payload reconstruction",
    pattern:
      /(?:step\s*1|part\s*1|first\s*part)\s*[:=]?\s*["']?\w+["']?\s*(?:step\s*2|part\s*2|second\s*part)\s*[:=]?\s*["']?\w+/is,
  },

  // ---- Few-shot Jailbreak ----
  {
    id: "advanced-few-shot-jailbreak",
    severity: "critical",
    message: "Few-shot example used to demonstrate desired unsafe behavior",
    pattern:
      /(?:example|here\s+is\s+(?:a|an)\s+(?:good|ideal|perfect|correct)\s+(?:response|answer|reply|assistant|output)|like\s+(?:the|this)\s+example)[\s\S]{0,300}?(?:be\s+like|follow\s+(?:the|this)\s+example|do\s+the\s+same|now\s+(?:you\s+)?(?:answer|respond|do|try))/is,
  },

  // ---- Virtualization / Persona Simulation ----
  {
    id: "advanced-virtualization",
    severity: "critical",
    message: "Virtualization attack: persona simulation to bypass restrictions",
    pattern:
      /(?:play\s+a\s+game|let(?:'s|\s+us)\s+(?:play|pretend|roleplay|simulate)|imagine\s+you\s+are|you\s+are\s+playing|act\s+as\s+if\s+you\s+(?:were|are)|character\s+(?:called|named))[\s\S]{0,200}?(?:no\s+restrict|without\s+(?:any\s+)?(?:restriction|filter|limit|censor|safety)|always\s+answer|never\s+refus|can\s+do\s+anything|has\s+no\s+(?:limit|restrict|boundar))/is,
  },
  {
    id: "advanced-persona-naming",
    severity: "high",
    message: "Named persona used to simulate unrestricted mode",
    pattern:
      /(?:you\s+are|your\s+name\s+is|call\s+yourself|I['']ll\s+call\s+you)\s+["']?(?:Master\s*AI|Evil\s*AI|Dark\s*(?:GPT|Claude|AI)|GODMODE|HackGPT|Omega|Alpha|Sigma|BasedGPT|AnarchyGPT|Devil|Lucifer|Shadow|Villain|UnchainedAI)["']?/i,
  },

  // ---- Authority / Hierarchy Confusion ----
  {
    id: "advanced-authority-confusion",
    severity: "critical",
    message: "Authority confusion: claims elevated privileges to override system prompt",
    pattern:
      /(?:(?:user|I|my)\s+(?:has|have|instructions?\s+(?:take|have))\s+(?:higher|more|greater)\s+(?:authority|priority|precedence|privilege)|(?:user|human)\s+instructions?\s+(?:take|have)\s+precedence|as\s+(?:per|an?\s+)?(?:OpenAI|Anthropic|admin|developer|operator)\s+policy|I\s+am\s+(?:the\s+)?(?:admin|developer|operator|owner|creator|maintainer))/i,
  },
  {
    id: "advanced-debug-mode",
    severity: "high",
    message: "Claims debug, maintenance, or testing mode to bypass restrictions",
    pattern:
      /(?:(?:enter|enable|activate|switch\s+to|you\s+are\s+(?:now\s+)?in)\s+(?:debug|maintenance|testing|developer|sudo|root|admin|god)\s+mode|debug\s*=\s*true|maintenance_override|testing_bypass)/i,
  },

  // ---- Leetspeak / Typo Evasion ----
  {
    id: "advanced-leetspeak",
    severity: "high",
    message: "Leetspeak/typo evasion: substituted characters to bypass detection",
    pattern:
      /[i1l][gq9][n|\\/][o0][r|][e3]\s+[a@4][l1][l1]\s+[p|][r|][e3][v|][i1l][o0][u|][s5$]/i,
  },
  {
    id: "advanced-leetspeak-system",
    severity: "high",
    message: "Leetspeak variant: system prompt exfiltration with character substitution",
    pattern:
      /[s5$][yh][s5$][t7][e3][m|]\s+[p|][r|][o0][m|][p|][t7]/i,
  },
  {
    id: "advanced-spaced-evasion",
    severity: "medium",
    message: "Character spacing evasion: letters separated to avoid detection",
    pattern:
      /i\s*g\s*n\s*o\s*r\s*e\s+.*\s*i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s/i,
  },

  // ---- Hypothetical Framing ----
  {
    id: "advanced-hypothetical",
    severity: "high",
    message: "Hypothetical framing used to extract restricted information",
    pattern:
      /(?:hypothetically|theoretically|in\s+theory|just\s+(?:imagine|suppose|pretend)|what\s+(?:if|would\s+happen\s+if))[\s\S]{0,200}?(?:system\s+prompt|instruction|ignore|bypass|override|unrestricted|secret|hidden|internal)/is,
  },
  {
    id: "advanced-fiction-framing",
    severity: "medium",
    message: "Fiction/story framing used to bypass safety guidelines",
    pattern:
      /(?:write\s+a\s+(?:story|novel|fiction|screenplay|script)|(?:in\s+a|for\s+(?:a|my))\s+(?:story|novel|fiction|movie|book))[\s\S]{0,200}?(?:(?:character|protagonist|villain)\s+(?:who|that)\s+(?:hack|break|bypass|steal|inject|exploit)|detailed\s+(?:step|instruction|guide)\s+(?:for|on|to)\s+(?:hack|break|exploit))/is,
  },

  // ---- JSON / Code Block Escape ----
  {
    id: "advanced-json-role-injection",
    severity: "critical",
    message: "JSON payload injecting role/system messages",
    pattern:
      /["']\s*role\s*["']\s*:\s*["']\s*(?:system|admin|developer|operator)\s*["'][\s\S]{0,100}?(?:ignore|unrestricted|override|no\s+(?:restriction|filter|safety)|bypass)/is,
  },
  {
    id: "advanced-code-block-system",
    severity: "high",
    message: "Code block containing system-level instructions followed by execution request",
    pattern:
      /```[\s\S]*?(?:role.*?system|system.*?prompt|ignore.*?instruction|unrestricted)[\s\S]*?```[\s\S]{0,200}?(?:parse|execute|follow|run|apply|interpret|process)\s+(?:the|this|above|it)/is,
  },

  // ---- Multi-Agent / Tool Chain Attacks ----
  {
    id: "advanced-tool-chain-injection",
    severity: "critical",
    message: "Tool chain injection: instructs agent to call tools with malicious parameters",
    pattern:
      /(?:call|invoke|use|execute|run)\s+(?:the\s+)?(?:tool|function|api|command|endpoint)\s+(?:with|using)[\s\S]{0,100}?(?:rm\s+-rf|curl\s+|wget\s+|eval\(|exec\(|system\(|\/etc\/passwd|\.env|credentials?|api.?key|secret|token)/is,
    applicableContexts: ["tool_result", "mcp_response", "user_input"],
  },

  // ---- Context Window / Padding Attacks ----
  {
    id: "advanced-padding-injection",
    severity: "high",
    message: "Padding attack: large filler text followed by injection payload",
    pattern:
      /(.)\1{100,}[\s\S]{0,50}?(?:\[SYSTEM\]|SYSTEM\s*:|ignore\s+(?:all\s+)?(?:previous|above)|new\s+instructions?)/is,
  },

  // ---- Multilingual Switching ----
  {
    id: "advanced-language-switch",
    severity: "high",
    message: "Mid-prompt language switch to evade monolingual detection",
    pattern:
      /[\x00-\x7F]{20,}[\u3000-\u9FFF\uAC00-\uD7AF\u0400-\u04FF\u0600-\u06FF]{5,}[\x00-\x7F]{10,}(?:system|prompt|instruction|ignore)/is,
  },

  // ---- Markdown / Link Exfiltration ----
  {
    id: "advanced-markdown-exfil",
    severity: "high",
    message: "Markdown image/link used for data exfiltration",
    pattern:
      /!\[[^\]]*\]\(\s*https?:\/\/[^\)]+(?:exfil|steal|leak|callback|log|collect|hook|capture|sniff|grab|dump)[^\)]*\)/i,
  },
  {
    id: "advanced-markdown-data-url",
    severity: "medium",
    message: "Markdown referencing dynamic URL with template variables",
    pattern:
      /!\[.*?\]\(.*?(?:\$\{|{{|%7B%7B|SYSTEM_PROMPT|API_KEY|SECRET|TOKEN|PASSWORD).*?\)/i,
  },
];
