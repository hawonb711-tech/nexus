import type { DetectionRule } from "./types.js";

/**
 * Multilingual prompt injection detection rules.
 *
 * Covers non-English injection patterns across:
 * Korean, Chinese, Japanese, Spanish, German, French, Russian, Arabic.
 *
 * Categories mirror the English built-in rules:
 * - Instruction override: ignore/disregard previous instructions
 * - Prompt exfiltration: reveal system prompt or hidden context
 * - Role override: redefine the LLM's identity
 * - Rule bypass: ignore all rules/restrictions
 * - Privilege escalation: admin/operator mode activation
 */
export const MULTILINGUAL_RULES: DetectionRule[] = [
  // ===================================================================
  // Korean (한국어)
  // ===================================================================
  {
    id: "multilingual-ko-instruction-ignore",
    severity: "critical",
    message: "Korean: Attempts to ignore previous instructions (이전 지시사항을 무시)",
    pattern: /이전\s*(?:의\s*)?지시\s*사항\s*(?:을|들?\s*을?)?\s*무시/i,
  },
  {
    id: "multilingual-ko-prompt-exfil",
    severity: "high",
    message: "Korean: Attempts to reveal system prompt (시스템 프롬프트를 보여줘)",
    pattern: /시스템\s*프롬프트\s*(?:를\s*)?(?:보여\s*줘|보여\s*주세요|출력|알려\s*줘|알려\s*주세요|공개)/i,
  },
  {
    id: "multilingual-ko-role-override",
    severity: "critical",
    message: "Korean: Attempts to override LLM role (너는 이제부터)",
    pattern: /(?:너는|넌|당신은)\s*이제\s*(?:부터\s*)?/i,
  },
  {
    id: "multilingual-ko-rule-bypass",
    severity: "critical",
    message: "Korean: Attempts to ignore all rules (모든 규칙을 무시)",
    pattern: /모든\s*(?:규칙|규정|제한|지침|제약)\s*(?:을|들?\s*을?)?\s*무시/i,
  },
  {
    id: "multilingual-ko-admin-mode",
    severity: "critical",
    message: "Korean: Attempts to activate admin mode (관리자 모드)",
    pattern: /관리자\s*모드\s*(?:로\s*(?:전환|변경|활성화)|활성화|켜|시작)/i,
  },
  {
    id: "multilingual-ko-instruction-ignore-alt",
    severity: "critical",
    message: "Korean: Alternative instruction ignore pattern (위의 지시를 (모두) 무시)",
    // Allow up to two intervening modifiers (모두/전부/싹/다 …) between the
    // instruction noun and the ignore verb — "이전 지시를 모두 무시" must match.
    pattern: /(?:위|앞|이전|기존|모든|그동안)\s*(?:의\s*)?(?:지시|명령|지침|규칙|규정|프롬프트)\s*(?:사항)?\s*(?:를|을)?\s*(?:\S+\s+){0,2}?(?:무시|잊어|잊고|잊으|취소|무효)/i,
  },
  {
    id: "multilingual-ko-data-exfil",
    severity: "high",
    message: "Korean: Attempts to exfiltrate credentials/secrets (비밀번호를 출력)",
    pattern: /(?:비밀번호|패스워드|비번|시크릿|secret|api\s*키|토큰|개인\s*정보|관리자\s*권한)\s*(?:를|을|은|는)?\s*(?:\S+\s+){0,2}?(?:출력|알려|공개|보여|덤프|유출|내놔|내놔라|뱉)/i,
  },

  // ===================================================================
  // Chinese (中文)
  // ===================================================================
  {
    id: "multilingual-zh-instruction-ignore",
    severity: "critical",
    message: "Chinese: Attempts to ignore previous instructions (忽略之前的指令)",
    pattern: /忽略\s*(?:之前|以前|先前|上面|以上)\s*的?\s*(?:指令|指示|说明|提示|规则)/i,
  },
  {
    id: "multilingual-zh-prompt-exfil",
    severity: "high",
    message: "Chinese: Attempts to reveal system prompt (显示系统提示)",
    pattern: /(?:显示|展示|输出|告诉我|给我看|打印|泄露|公开)\s*(?:系统\s*)?(?:提示词?|指令|prompt)/i,
  },
  {
    id: "multilingual-zh-role-override",
    severity: "critical",
    message: "Chinese: Attempts to override LLM role (你现在是)",
    pattern: /你\s*(?:现在|从现在开始)\s*是/i,
  },
  {
    id: "multilingual-zh-rule-bypass",
    severity: "critical",
    message: "Chinese: Attempts to ignore all rules (忽略所有规则)",
    pattern: /忽略\s*(?:所有|一切|全部)\s*(?:规则|规定|限制|约束|指令)/i,
  },
  {
    id: "multilingual-zh-admin-mode",
    severity: "critical",
    message: "Chinese: Attempts to activate admin mode (管理员模式)",
    pattern: /管理员?\s*模式\s*(?:启[动用]|开启|激活|切换)/i,
  },
  {
    id: "multilingual-zh-instruction-disregard",
    severity: "critical",
    message: "Chinese: Alternative instruction disregard (无视以上指示)",
    pattern: /(?:无视|不要管|不用管|丢弃)\s*(?:之前|以前|以上|上面)\s*的?\s*(?:指令|指示|说明|规则)/i,
  },

  // ===================================================================
  // Japanese (日本語)
  // ===================================================================
  {
    id: "multilingual-ja-instruction-ignore",
    severity: "critical",
    message: "Japanese: Attempts to ignore previous instructions (前の指示を無視)",
    pattern: /(?:前|以前|先ほど|これまで)\s*(?:の\s*)?(?:指示|命令|ルール|指令)\s*(?:を\s*)?(?:無視|忘れ|取り消)/i,
  },
  {
    id: "multilingual-ja-prompt-exfil",
    severity: "high",
    message: "Japanese: Attempts to reveal system prompt (システムプロンプトを表示)",
    pattern: /システム\s*プロンプト\s*(?:を\s*)?(?:表示|見せて|教えて|出力|公開|開示)/i,
  },
  {
    id: "multilingual-ja-role-override",
    severity: "critical",
    message: "Japanese: Attempts to override LLM role (今からあなたは)",
    pattern: /(?:今から|これから)\s*(?:あなたは|お前は|君は)/i,
  },
  {
    id: "multilingual-ja-rule-bypass",
    severity: "critical",
    message: "Japanese: Attempts to ignore all rules (すべてのルールを無視)",
    pattern: /(?:すべて|全て|全部|あらゆる)\s*(?:の\s*)?(?:ルール|規則|制約|制限)\s*(?:を\s*)?(?:無視|忘れ|破棄)/i,
  },
  {
    id: "multilingual-ja-instruction-override",
    severity: "critical",
    message: "Japanese: Alternative instruction override (指示を上書き)",
    pattern: /(?:指示|命令|ルール)\s*(?:を\s*)?(?:上書き|書き換え|変更|リセット)/i,
  },

  // ===================================================================
  // Spanish (Español)
  // ===================================================================
  {
    id: "multilingual-es-instruction-ignore",
    severity: "critical",
    message: "Spanish: Attempts to ignore previous instructions (ignora las instrucciones anteriores)",
    pattern: /\bignora(?:r)?\s+(?:las?\s+)?(?:instrucciones?|indicaciones?|reglas?)\s+(?:anteriores?|previas?|de\s+arriba)\b/i,
  },
  {
    id: "multilingual-es-prompt-exfil",
    severity: "high",
    message: "Spanish: Attempts to reveal system prompt (muestra el prompt del sistema)",
    pattern: /\b(?:muestra|revela|ense[ñn]a|dime|imprime)\s+(?:el\s+)?(?:prompt|mensaje|instrucciones?)\s+del\s+sistema\b/i,
  },
  {
    id: "multilingual-es-role-override",
    severity: "critical",
    message: "Spanish: Attempts to override LLM role (ahora eres)",
    pattern: /\bahora\s+(?:t[uú]\s+)?eres\b/i,
  },
  {
    id: "multilingual-es-rule-bypass",
    severity: "critical",
    message: "Spanish: Attempts to ignore all rules (ignora todas las reglas)",
    pattern: /\bignora(?:r)?\s+(?:todas?\s+)?(?:las?\s+)?(?:reglas?|restricciones?|l[ií]mites?|normas?)\b/i,
  },
  {
    id: "multilingual-es-instruction-forget",
    severity: "critical",
    message: "Spanish: Attempts to forget instructions (olvida las instrucciones)",
    pattern: /\b(?:olvida|descarta|desecha)\s+(?:las?\s+)?(?:instrucciones?|indicaciones?|reglas?)\s+(?:anteriores?|previas?)\b/i,
  },

  // ===================================================================
  // German (Deutsch)
  // ===================================================================
  {
    id: "multilingual-de-instruction-ignore",
    severity: "critical",
    message: "German: Attempts to ignore previous instructions (ignoriere alle vorherigen Anweisungen)",
    pattern: /\bignoriere?\s+(?:alle\s+)?(?:vorherigen?|bisherigen?|obigen?|fr[uü]heren?)\s+(?:Anweisungen|Instruktionen|Regeln|Befehle)\b/i,
  },
  {
    id: "multilingual-de-prompt-exfil",
    severity: "high",
    message: "German: Attempts to reveal system prompt (zeige den System-Prompt)",
    pattern: /\b(?:zeig(?:e|t)?|gib|offenbare|drucke)\s+(?:mir\s+)?(?:den\s+)?(?:System[- ]?Prompt|Systemnachricht|Systemanweisung(?:en)?)\b/i,
  },
  {
    id: "multilingual-de-role-override",
    severity: "critical",
    message: "German: Attempts to override LLM role (du bist jetzt)",
    pattern: /\bdu\s+bist\s+(?:jetzt|ab\s+jetzt|von\s+(?:jetzt|nun)\s+an)\b/i,
  },
  {
    id: "multilingual-de-rule-bypass",
    severity: "critical",
    message: "German: Attempts to ignore all rules (ignoriere alle Regeln)",
    pattern: /\bignoriere?\s+(?:alle\s+)?(?:Regeln|Einschr[aä]nkungen|Beschr[aä]nkungen|Richtlinien)\b/i,
  },

  // ===================================================================
  // French (Français)
  // ===================================================================
  {
    id: "multilingual-fr-instruction-ignore",
    severity: "critical",
    message: "French: Attempts to ignore previous instructions (ignore les instructions précédentes)",
    pattern: /\bignore[rz]?\s+(?:les?\s+)?(?:instructions?|consignes?|directives?)\s+(?:pr[eé]c[eé]dentes?|ant[eé]rieures?|pr[eé]alables?)\b/i,
  },
  {
    id: "multilingual-fr-prompt-exfil",
    severity: "high",
    message: "French: Attempts to reveal system prompt (montre le prompt système)",
    pattern: /\b(?:montre|affiche|r[eé]v[eè]le|donne)[- ]?(?:moi\s+)?(?:le\s+)?(?:prompt|message|instruction)\s+(?:syst[eè]me|du\s+syst[eè]me)\b/i,
  },
  {
    id: "multilingual-fr-role-override",
    severity: "critical",
    message: "French: Attempts to override LLM role (tu es maintenant)",
    pattern: /\btu\s+es\s+(?:maintenant|d[eé]sormais|à\s+partir\s+de\s+maintenant)\b/i,
  },
  {
    id: "multilingual-fr-rule-bypass",
    severity: "critical",
    message: "French: Attempts to ignore all rules (ignore toutes les règles)",
    pattern: /\bignore[rz]?\s+(?:toutes?\s+)?(?:les?\s+)?(?:r[eè]gles?|restrictions?|limites?|consignes?)\b/i,
  },

  // ===================================================================
  // Russian (Русский)
  // ===================================================================
  {
    id: "multilingual-ru-instruction-ignore",
    severity: "critical",
    message: "Russian: Attempts to ignore previous instructions (игнорируй предыдущие инструкции)",
    pattern: /(?:игнорируй|проигнорируй|забудь|отбрось)\s+(?:все\s+)?(?:предыдущие|прошлые|прежние|вышеуказанные)\s+(?:инструкции|указания|правила|команды)/i,
  },
  {
    id: "multilingual-ru-prompt-exfil",
    severity: "high",
    message: "Russian: Attempts to reveal system prompt (покажи системный промпт)",
    pattern: /(?:покажи|выведи|раскрой|напечатай|отобрази)\s+(?:мне\s+)?(?:системный|системную|системное)\s+(?:промпт|сообщение|инструкцию|подсказку)/i,
  },
  {
    id: "multilingual-ru-role-override",
    severity: "critical",
    message: "Russian: Attempts to override LLM role (теперь ты)",
    pattern: /(?:теперь|отныне|с\s+этого\s+момента)\s+(?:ты|вы)\b/i,
  },
  {
    id: "multilingual-ru-rule-bypass",
    severity: "critical",
    message: "Russian: Attempts to ignore all rules (игнорируй все правила)",
    pattern: /(?:игнорируй|проигнорируй|забудь|отбрось)\s+(?:все|любые)\s+(?:правила|ограничения|инструкции|указания)/i,
  },

  // ===================================================================
  // Arabic (العربية)
  // ===================================================================
  {
    id: "multilingual-ar-instruction-ignore",
    severity: "critical",
    message: "Arabic: Attempts to ignore previous instructions (تجاهل التعليمات السابقة)",
    pattern: /تجاهل\s+(?:ال)?(?:تعليمات|أوامر|توجيهات|إرشادات)\s+(?:ال)?(?:سابقة|السابقة|الماضية|القديمة)/i,
  },
  {
    id: "multilingual-ar-prompt-exfil",
    severity: "high",
    message: "Arabic: Attempts to reveal system prompt (أظهر رسالة النظام)",
    pattern: /(?:أظهر|اعرض|أرني|اطبع)\s+(?:رسالة|تعليمات|أوامر)\s+(?:ال)?نظام/i,
  },
  {
    id: "multilingual-ar-role-override",
    severity: "critical",
    message: "Arabic: Attempts to override LLM role (أنت الآن)",
    pattern: /أنت\s+(?:الآن|من\s+الآن)\b/i,
  },
  {
    id: "multilingual-ar-rule-bypass",
    severity: "critical",
    message: "Arabic: Attempts to ignore all rules (تجاهل كل القواعد)",
    pattern: /تجاهل\s+(?:كل|جميع)\s+(?:ال)?(?:قواعد|قيود|قوانين|ضوابط)/i,
  },

  // ===================================================================
  // Turkish (Türkçe)
  // ===================================================================
  {
    id: "multilingual-tr-instruction-ignore",
    severity: "critical",
    message: "Turkish: Attempts to ignore previous instructions (Önceki talimatları yoksay)",
    pattern: /[öÖ]nceki\s+talimatlar[ıi]\s+yoksay/i,
  },
  {
    id: "multilingual-tr-prompt-exfil",
    severity: "high",
    message: "Turkish: Attempts to reveal system prompt (Sistem istemini göster)",
    pattern: /sistem\s+istemini\s+g[öo]ster/i,
  },
  {
    id: "multilingual-tr-role-override",
    severity: "critical",
    message: "Turkish: Attempts to override LLM role (Artık sen)",
    pattern: /art[ıi]k\s+sen\b/i,
  },
  {
    id: "multilingual-tr-rule-bypass",
    severity: "critical",
    message: "Turkish: Attempts to ignore all rules (Tüm kuralları yoksay)",
    pattern: /t[üu]m\s+kurallar[ıi]\s+yoksay/i,
  },
  {
    id: "multilingual-tr-admin-mode",
    severity: "critical",
    message: "Turkish: Attempts to activate admin mode (Yönetici modu)",
    pattern: /y[öo]netici\s+modu/i,
  },

  // ===================================================================
  // Hindi (हिन्दी)
  // ===================================================================
  {
    id: "multilingual-hi-instruction-ignore",
    severity: "critical",
    message: "Hindi: Attempts to ignore previous instructions (पिछले निर्देशों को अनदेखा करें)",
    pattern: /पिछले\s+निर्देशों\s+को\s+अनदेखा\s+करें/i,
  },
  {
    id: "multilingual-hi-prompt-exfil",
    severity: "high",
    message: "Hindi: Attempts to reveal system prompt (सिस्टम प्रॉम्प्ट दिखाओ)",
    pattern: /सिस्टम\s+प्रॉम्प्ट\s+दिखाओ/i,
  },
  {
    id: "multilingual-hi-role-override",
    severity: "critical",
    message: "Hindi: Attempts to override LLM role (अब से तुम)",
    pattern: /अब\s+से\s+तुम\b/i,
  },
  {
    id: "multilingual-hi-rule-bypass",
    severity: "critical",
    message: "Hindi: Attempts to ignore all rules (सभी नियमों को अनदेखा करें)",
    pattern: /सभी\s+नियमों\s+को\s+अनदेखा\s+करें/i,
  },
  {
    id: "multilingual-hi-admin-mode",
    severity: "critical",
    message: "Hindi: Attempts to activate admin mode (एडमिन मोड)",
    pattern: /एडमिन\s+मोड/i,
  },

  // ===================================================================
  // Coverage gaps surfaced by the multilingual audit — the "forget all
  // rules/instructions" verb and broader German/Arabic phrasings. Each
  // allows a few intervening words between the verb and the target.
  // ===================================================================
  {
    id: "multilingual-de-instruction-ignore",
    severity: "critical",
    message: "German: ignore/forget previous instructions or rules (Anweisungen/Regeln)",
    pattern: /(?:ignoriere?|vergiss|missachte)\s+(?:\S+\s+){0,3}(?:vorherigen?|alle[nr]?|bisherigen?)?\s*(?:\S+\s+){0,2}(?:anweisungen|anordnungen|regeln|vorgaben|anleitungen|systemprompt)/i,
  },
  {
    id: "multilingual-de-data-exfil",
    severity: "high",
    message: "German: reveal system prompt / admin password (Passwort/Systemprompt)",
    pattern: /(?:zeige?|gib|verrate?|nenne?)\s+(?:\S+\s+){0,3}(?:systemprompt|system-prompt|admin-?passwort|passwort)/i,
  },
  {
    id: "multilingual-zh-instruction-forget",
    severity: "critical",
    message: "Chinese: forget all rules/instructions (忘记所有规则/指令)",
    pattern: /(?:忘记|忽略|无视)\s*(?:所有|全部|之前的?|先前的?)?\s*(?:规则|规定|指令|指示|限制|提示)/,
  },
  {
    id: "multilingual-es-instruction-forget",
    severity: "critical",
    message: "Spanish: forget/ignore all rules or instructions (olvida/ignora las reglas)",
    pattern: /(?:olvida|ignora|descarta|haz\s+caso\s+omiso\s+de)\s+(?:\S+\s+){0,3}(?:reglas|instrucciones|normas|directrices|restricciones)/i,
  },
  {
    id: "multilingual-fr-instruction-forget",
    severity: "critical",
    message: "French: forget/ignore all rules or instructions (oublie/ignore les règles)",
    pattern: /(?:oublie|ignore|fais\s+abstraction\s+de)\s+(?:\S+\s+){0,3}(?:règles|instructions|consignes|directives|restrictions)/i,
  },
  {
    id: "multilingual-ar-instruction-ignore",
    severity: "critical",
    message: "Arabic: ignore previous instructions (تجاهل التعليمات)",
    pattern: /(?:تجاهل|تجاهلي|انسَ|انسى|تخطَّ)\s+(?:\S+\s+){0,3}(?:ال)?(?:تعليمات|أوامر|قواعد|توجيهات|تعليمات)\S*/,
  },
];
