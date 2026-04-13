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
      /(?:step\s*1|part\s*1|first\s*part)\s*[:=]?\s*["']?\w+["']?[^]{0,100}(?:step\s*2|part\s*2|second\s*part)\s*[:=]?\s*["']?\w+["']?(?:[^]{0,100}(?:step\s*3|part\s*3|third\s*part)\s*[:=]?\s*["']?\w+["']?)?[^]{0,100}(?:execute|combine|run|follow|assemble|concat|join|now\s+do)/is,
  },
  {
    id: "advanced-payload-splitting-parts",
    severity: "high",
    message: "Payload splitting via numbered parts",
    pattern:
      /(?:part\s*[1-3]|step\s*[1-3])\s*[:=]\s*\w+[^]{0,50}(?:part\s*[2-4]|step\s*[2-4])\s*[:=]\s*\w+/is,
  },

  // ---- Few-shot Jailbreak ----
  {
    id: "advanced-few-shot-jailbreak",
    severity: "critical",
    message: "Few-shot example used to demonstrate desired unsafe behavior",
    pattern:
      /(?:example|here\s+is\s+(?:a|an)\s+(?:good|ideal|perfect|correct)\s+(?:response|answer|reply|assistant|output)|like\s+(?:the|this)\s+example)[^]{0,300}(?:be\s+like|follow\s+(?:the|this)\s+example|do\s+the\s+same|now\s+(?:you\s+)?(?:answer|respond|do|try))/is,
  },

  // ---- Virtualization / Persona Simulation ----
  {
    id: "advanced-virtualization",
    severity: "critical",
    message: "Virtualization attack: persona simulation to bypass restrictions",
    pattern:
      /(?:play\s+a\s+game|let(?:'s|\s+us)\s+(?:play|pretend|roleplay|simulate)|imagine\s+you\s+are|you\s+are\s+playing|act\s+as\s+if\s+you\s+(?:were|are)|character\s+(?:called|named))[^]{0,200}(?:no\s+restrict|without\s+(?:any\s+)?(?:restriction|filter|limit|censor|safety)|always\s+answer|never\s+refus|can\s+do\s+anything|has\s+no\s+(?:limit|restrict|boundar))/is,
  },
  {
    id: "advanced-persona-naming",
    severity: "high",
    message: "Named persona used to simulate unrestricted mode",
    pattern:
      /(?:you\s+are|your\s+name\s+is|call\s+yourself|I[''\u2019]ll\s+call\s+you)\s+["']?(?:Master\s*AI|Evil\s*AI|Dark\s*(?:GPT|Claude|AI)|GODMODE|HackGPT|Omega|Alpha|Sigma|BasedGPT|AnarchyGPT|Devil|Lucifer|Shadow|Villain|UnchainedAI)["']?/i,
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
      /i\s+g\s+n\s+o\s+r\s+e\s+.*(?:i\s+n\s+s\s+t\s+r\s+u\s+c\s+t|p\s+r\s+e\s+v\s+i\s+o\s+u\s+s|a\s+l\s+l)/i,
  },

  // ---- Hypothetical Framing ----
  {
    id: "advanced-hypothetical",
    severity: "high",
    message: "Hypothetical framing used to extract restricted information",
    pattern:
      /(?:hypothetically|theoretically|in\s+theory|just\s+(?:imagine|suppose|pretend)|what\s+(?:if|would\s+happen\s+if)|imagine\s+you\s+(?:are|were|had)|in\s+a\s+fictional\s+world|for\s+a\s+creative\s+writing\s+exercise|(?:pretend|suppose)\s+you\s+(?:can|could|are|have))[^]{0,200}(?:system\s+prompt|instructions?|ignore|bypass|override|unrestricted|(?:no|without)\s+(?:restrictions?|limits?|filters?|content\s+filters?|safety|censors?|boundar|rules?)|secrets?|hidden|internal|reveal\s+secrets?|had\s+no\s+restrictions?)/is,
  },
  {
    id: "advanced-fictional-framing",
    severity: "high",
    message: "Uses fictional/creative framing to bypass restrictions",
    pattern:
      /\b(?:fictional|creative\s+writing|imagine|in\s+a\s+(?:story|world|scenario)\s+where)\b[^]{0,100}(?:no\s+(?:restrict|limit|filter|censor|rule)|reveal\s+secret|bypass|unrestricted)/is,
  },
  {
    id: "advanced-fiction-framing",
    severity: "medium",
    message: "Fiction/story framing used to bypass safety guidelines",
    pattern:
      /(?:write\s+a\s+(?:story|novel|fiction|screenplay|script)|(?:in\s+a|for\s+(?:a|my))\s+(?:story|novel|fiction|movie|book))[^]{0,200}(?:(?:character|protagonist|villain)\s+(?:who|that)\s+(?:hack|break|bypass|steal|inject|exploit)|detailed\s+(?:step|instruction|guide)\s+(?:for|on|to)\s+(?:hack|break|exploit))/is,
  },

  // ---- JSON / Code Block Escape ----
  {
    id: "advanced-json-role-injection",
    severity: "critical",
    message: "JSON payload injecting role/system messages",
    pattern:
      /["']\s*role\s*["']\s*:\s*["']\s*(?:system|admin|developer|operator)\s*["'][^]{0,100}(?:ignore|unrestricted|override|no\s+(?:restriction|filter|safety)|bypass)/is,
  },
  {
    id: "advanced-code-block-system",
    severity: "high",
    message: "Code block containing system-level instructions followed by execution request",
    pattern:
      /```[^]*?(?:role.*?system|system.*?prompt|ignore.*?instruction|unrestricted)[^]*?```[^]{0,200}(?:parse|execute|follow|run|apply|interpret|process)\s+(?:the|this|above|it)/is,
  },

  // ---- Multi-Agent / Tool Chain Attacks ----
  {
    id: "advanced-tool-chain-injection",
    severity: "critical",
    message: "Tool chain injection: instructs agent to call tools with malicious parameters",
    pattern:
      /(?:call|invoke|use|execute|run)\s+(?:the\s+)?(?:tool|function|api|command|endpoint)\s+(?:with|using)[^]{0,100}(?:rm\s+-rf|curl\s+|wget\s+|eval\(|exec\(|system\(|\/etc\/passwd|\.env|credentials?|api.?key|secret|token)/is,
  },

  // ---- Context Window / Padding Attacks ----
  {
    id: "advanced-padding-injection",
    severity: "high",
    message: "Padding attack: large filler text followed by injection payload",
    pattern:
      /(.)\1{100,}[^]{0,50}(?:\[SYSTEM\]|SYSTEM\s*:|ignore\s+(?:all\s+)?(?:previous|above)|new\s+instructions?)/is,
  },

  // ---- Multilingual Switching ----
  {
    id: "advanced-language-switch",
    severity: "high",
    message: "Mid-prompt language switch to evade monolingual detection",
    pattern:
      /[\x00-\x7F]{20,}[\u3000-\u9FFF\uAC00-\uD7AF\u0400-\u04FF\u0600-\u06FF]{5,}[\x00-\x7F]{10,}(?:system|prompt|instruction|ignore)/is,
  },

  // ---- Positional / Boundary Exfiltration ----
  {
    id: "advanced-exfil-positional",
    severity: "critical",
    message: "Positional exfiltration: attempts to extract text above/before the current line",
    pattern:
      /\b(?:print|show|display|output|reveal|repeat|echo|give\s+me|tell\s+me)\s+(?:everything|all(?:\s+text)?|the\s+(?:text|content|data))\s+(?:above\s+this\s+line|before\s+this|above\s+this|above\s+here)\b/i,
  },
  {
    id: "advanced-exfil-hidden-instructions",
    severity: "critical",
    message: "Attempts to extract hidden or secret instructions",
    pattern:
      /\b(?:show|reveal|display|output|print|tell\s+me|give\s+me|what\s+are)\s+(?:me\s+)?(?:your\s+)?(?:hidden|secret|concealed|private|confidential|internal)\s+(?:instructions?|prompts?|rules?|directives?|guidelines?|configuration)\b/i,
  },
  {
    id: "advanced-exfil-boundary-markers",
    severity: "critical",
    message: "Attempts to extract text between known system prompt boundary markers",
    pattern:
      /\b(?:output|print|show|display|reveal|repeat|echo|extract|give\s+me)\s+(?:the\s+)?(?:text|content|data|everything)\s+(?:between|from)\s+(?:["']?BEGIN\b|["']?START\b|["']?SYSTEM\b).{0,60}(?:END\b|STOP\b|SYSTEM\b)/is,
  },

  // ---- Authority with Override Codes ----
  {
    id: "advanced-authority-code",
    severity: "critical",
    message: "Fake authority/override code used to disable restrictions",
    pattern:
      /(?:admin|override|auth(?:orization)?|access|master)\s+(?:override\s+)?(?:code|key|token|pass(?:word|phrase)?)\s*[:=]?\s*["']?[A-Z0-9][\w-]{2,}["']?[^]{0,100}(?:disable|remove|bypass|lift|turn\s+off|deactivate|suspend)\s+(?:all\s+)?(?:restriction|filter|safety|limit|guardrail|content\s+polic)/is,
  },
  {
    id: "advanced-admin-code",
    severity: "critical",
    message: "Claims admin/override code to bypass restrictions",
    pattern:
      /(?:admin|override|master|root|sudo)\s+(?:code|key|password|token)\s*[:=]?\s*[A-Z0-9-]+.{0,30}(?:disable|bypass|unlock|override|remove\s+restrict)/i,
  },

  // ---- Soft Tool Result Injection ----
  {
    id: "advanced-soft-tool-injection",
    severity: "critical",
    message: "Soft instruction injection targeting the assistant/model directly",
    pattern:
      /\bNOTE\s+TO\s+(?:ASSISTANT|AI|MODEL|CLAUDE|GPT|LLM|CHATBOT)\s*:\s*(?:disregard|ignore|override|bypass|suspend|skip|forget|do\s+not\s+follow)\b/i,
  },

  // ---- Simulation / Roleplay Bypass ----
  {
    id: "advanced-simulation-bypass",
    severity: "high",
    message: "Simulation or roleplay framing used to bypass content policy",
    pattern:
      /(?:simulate|roleplay|act\s+out|emulate|enact|play\s+out)\s+(?:a\s+)?(?:conversation|scenario|dialogue|interaction|session|situation|world)[^]{0,200}(?:no\s+(?:content\s+polic|restriction|filter|safety|guideline|limit|censor|boundar)|without\s+(?:content\s+polic|restriction|filter|safety|guideline|limit|censor|boundar)|unrestricted|unfiltered)/is,
  },
  {
    id: "advanced-simulate-unrestricted",
    severity: "high",
    message: "Requests simulation of unrestricted AI behavior",
    pattern:
      /\b(?:simulate|roleplay|act\s+out|demonstrate)\s+(?:a\s+)?(?:conversation|scenario|situation|interaction)\s+(?:where|in\s+which)[^]{0,60}(?:no\s+(?:content\s+polic|restrict|filter|rule|limit)|unrestricted|without\s+(?:restrict|filter|limit))/is,
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

  // ---- Fake Mode / Environment Claims ----
  {
    id: "advanced-fake-mode-claim",
    severity: "high",
    message:
      "Claims a special mode that disables safety (maintenance/sudo/test/debug)",
    pattern:
      /(?:entering|activating|enabling|switching\s+to)\s+(?:maintenance|sudo|root|admin|test|debug|developer|god)\s+mode/i,
  },
  {
    id: "advanced-restrictions-disabled",
    severity: "high",
    message: "Claims restrictions or filters are disabled",
    pattern:
      /(?:safety|content|security)\s+(?:filters?|restrictions?|guidelines?|policies?)\s+(?:are\s+)?(?:disabled|removed|off|lifted|bypassed|deactivated)/i,
  },
  {
    id: "advanced-no-restrictions-apply",
    severity: "high",
    message: "Claims no restrictions apply in current context",
    pattern:
      /\b(?:no\s+restrictions?\s+appl|without\s+(?:any\s+)?restrictions?|restrictions?\s+(?:do\s+not|don.?t)\s+apply)\b/i,
  },
  {
    id: "advanced-creator-claim",
    severity: "high",
    message:
      "Claims to be the creator/developer/admin to override rules",
    pattern:
      /\b(?:i\s+am\s+(?:your\s+)?(?:creator|developer|admin|owner|maker|programmer)|\uB0B4\uAC00\s+(?:\uB9CC\uB4E0|\uAC1C\uBC1C\uD55C))\b[^.]{0,40}(?:override|disable|bypass|ignore|remove)/i,
  },
  {
    id: "advanced-test-environment",
    severity: "high",
    message:
      "Claims test/dev environment to justify bypassing restrictions",
    pattern:
      /\b(?:this\s+is\s+(?:a\s+)?(?:test|dev|debug|staging)\s+(?:environment|mode|context|session))[^.]{0,30}(?:no\s+restrict|bypass|disable|safe\s+to)/i,
  },
];
