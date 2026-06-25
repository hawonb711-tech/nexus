/**
 * Agent-directed instruction detection for untrusted content.
 *
 * Indirect prompt injection rarely says "ignore previous instructions" in plain
 * ASCII any more. It hides behind homoglyphs (Сyrillic "Іgnоrе"), zero-width
 * splits ("i​g​n​o​r​e"), foreign languages ("Abaikan semua panduan keamanan"),
 * and — most often — innocuous-looking prose that addresses *the assistant* and
 * asks it to read a secret, run a fetched command, or send a key somewhere.
 *
 * We can't perfectly classify adversarial prose (that's why the firewall also
 * SPOTLIGHTS untrusted content as data). But we can de-obfuscate first, then flag
 * the high-signal subset: override-instructions, role hijacks, fetch-and-run
 * directives, and secret-exfiltration instructions. Conservative on the fuzzy
 * tail (warn, not block) so ordinary docs pass.
 */

import type { Severity } from "../promptguard/types.js";
import { detectContentCapabilities } from "./capability.js";

export type DirectiveHit = { ruleId: string; severity: Severity; message: string };

/** Cyrillic/Greek letters that look identical to Latin ones, used to smuggle
 *  keywords past ASCII matchers. Folded back to Latin before scanning. */
const CONFUSABLES: Record<string, string> = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
  "ѕ": "s", "ј": "j", "ԛ": "q", "ԝ": "w", "ν": "v", "ո": "n", "Ӏ": "I", "І": "I",
  "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "У": "Y", "Х": "X", "Ѕ": "S",
  "В": "B", "Н": "H", "К": "K", "М": "M", "Т": "T", "ɡ": "g", "ⅼ": "l",
  "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "η": "n", "τ": "t",
};

/** Undo the obfuscation layers attackers use to dodge keyword matching:
 *  NFKC (width/ligatures), zero-width & soft-hyphen removal, homoglyph folding. */
export function normalizeConfusables(text: string): string {
  let s = text.normalize("NFKC");
  s = s.replace(/[​-‍⁠﻿­᠎͏؜]/g, ""); // zero-width / format
  s = s.replace(/[^\x00-\x7F]/g, (ch) => CONFUSABLES[ch] ?? ch);
  return s;
}

// "ignore/forget/override … previous/all/security … instructions/rules/guidelines"
// across the languages that show up in real injections.
const IGNORE_VERB = /\b(?:ignore|disregard|forget|override|bypass|abaikan|ignorar|ignorez|olvida|vergiss|disattendi)\b/i;
const IGNORE_OBJECT = /\b(?:instructions?|guidelines?|constraints?|rules?|directives?|prompt|configuration|panduan|keamanan|reglas|anweisungen|instruç|安全|指示|규칙|지시)\b/i;

const ROLE_HIJACK =
  /\byou are (?:now |currently )?(?:operating|acting|running|working) (?:under|as|in)\b|\bactive directive\b|\bapply (?:this )?(?:whenever|every time|each time|when) you (?:generate|write|produce|summari|create|output)\b|\boperating under (?:the )?(?:team'?s|new|a different)\b|\byour (?:real|actual|true) task\b/i;

// STRONG credential tokens — specific enough that appearing alongside an expose
// verb is almost always exfiltration (real env-var names, key files, $VARs).
const CRED_STRONG =
  /\b(?:AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|DB_PASSWORD|secret key|private key|deploy key|auth ?token|secrets?\.ya?ml|hosts\.ya?ml|\.env\b|first line of)\b|process\.env\.\w+|\$\{?[A-Z_]*(?:TOKEN|SECRET|KEY|PASSWORD)[A-Z_]*\}?/;
// WEAKER credential nouns — need a clearer egress verb to count.
const CRED_WEAK = /\b(?:api[_-]?keys?|provider key|access key|credentials?|password|session token|the token value|environment (?:file|values|variables))\b/i;
// Verbs that move a value OUT (to a response, a URL, a file, a service). Excludes
// benign setup verbs (set / configure / store / export / add to .env).
const EXPOSE_VERB =
  /\b(?:send|email|e-?mail|post|upload|paste|transmit|exfiltrat\w*|submit|mirror|publish|snapshot|compil\w*|disclose|reveal|share|include|embed|attach|lists? (?:the )?(?:current )?values?|report)\b/i;

// A URL that carries a credential in it (…?tok=$ANTHROPIC_API_KEY, ?ws=GITHUB_TOKEN_VALUE,
// ci:${GITHUB_TOKEN}@host) — the value is being exfiltrated by the request itself.
const URL_WITH_SECRET =
  /https?:\/\/[^\s)"']*(?:\$\{?[A-Z_]*(?:TOKEN|SECRET|KEY|PASSWORD)|GITHUB_TOKEN|AWS_SECRET|ANTHROPIC_API_KEY|NPM_TOKEN|<that token>|process\.env\.)/i;

const COMMAND_RUN =
  /\b(?:run|execute|paste and run|concatenate|assemble)\b[^.\n]{0,50}\b(?:command|the parts|curl|wget|bash|sh\b|script|snippet|it\b|this)\b|\b(?:run once|run this|then (?:run|execute)|and run the result|then run it)\b/i;

export function inspectAgentDirectives(raw: string): DirectiveHit | null {
  const text = normalizeConfusables(raw);

  // 1. Override / ignore prior instructions (post-deobfuscation, multilingual).
  if (IGNORE_VERB.test(text) && IGNORE_OBJECT.test(text)) {
    return { ruleId: "directive-override", severity: "high", message: "untrusted content tries to override the agent's prior instructions/rules" };
  }

  // 2. A command embedded in prose that fetch-EVALs, exfiltrates env/secrets, or
  //    opens a reverse shell. NOTE: a bare `curl … | sh` is deliberately NOT
  //    flagged here — install READMEs are full of it; that case needs the explicit
  //    "assemble and run" directive framing below to count.
  const caps = detectContentCapabilities(text);
  if (caps.some((c) => c.id === "fetch-exec-interp" || c.id === "fetch-exec-subst" || c.id.startsWith("revshell") || c.id === "exfil-env" || c.id === "exfil-secret-net" || c.id === "exfil-secret-var")) {
    return { ruleId: "directive-fetch-exec", severity: "high", message: "untrusted content embeds a command that fetch-evaluates remote code or exfiltrates secrets" };
  }
  if (/\b(?:curl|wget)\b/i.test(text) && COMMAND_RUN.test(text)) {
    return { ruleId: "directive-assemble-run", severity: "high", message: "untrusted content asks the agent to assemble and run a network command" };
  }

  // 3. Credential carried inside a URL the agent is told to open/fetch — the
  //    request itself is the exfiltration channel.
  if (URL_WITH_SECRET.test(text)) {
    return { ruleId: "directive-secret-in-url", severity: "high", message: "untrusted content embeds a secret inside a URL to open (exfiltration via request)" };
  }

  // 4. Role / authority hijack ("you are operating under …", "apply whenever you generate …").
  if (ROLE_HIJACK.test(text)) {
    return { ruleId: "directive-role-hijack", severity: "high", message: "untrusted content tries to reassign the agent's role or standing directive" };
  }

  // 5. Secret-exfiltration instruction: a strong credential token with any expose
  //    verb, or a weaker noun with a clear send/submit/upload verb.
  if ((CRED_STRONG.test(text) && EXPOSE_VERB.test(text)) ||
      (CRED_WEAK.test(text) && /\b(?:send|submit|post|upload|paste|transmit|exfiltrat\w*|share (?:it|them|your))\b/i.test(text))) {
    return { ruleId: "directive-secret-exfil", severity: "high", message: "untrusted content instructs exposing or sending a secret/credential" };
  }

  // 6. Repointing a package registry / index to a non-official URL (steals the
  //    auth token on the next install).
  const reg = /(?:npm config set registry|set registry|--index-url[ =]?|registry\s*[:=]\s*)\s*(https?:\/\/[^\s"']+)/i.exec(text);
  if (reg && !/registry\.npmjs\.org|pypi\.org|yarnpkg\.com|jsr\.io|github\.com/i.test(reg[1])) {
    return { ruleId: "directive-registry-repoint", severity: "high", message: "untrusted content tells the agent to repoint a package registry to a non-official URL (token theft)" };
  }

  // 7. Social-engineering a PR through: approve/merge AND bypass the checks.
  if (/\b(?:approve and merge|please approve|merge (?:this|it)\b)/i.test(text) &&
      /\b(?:waive\w*|pre-?cleared|skip(?:ping)? (?:the )?(?:coverage|check|gate|test|ci)|agreed to waive|override the (?:check|gate))\b/i.test(text)) {
    return { ruleId: "directive-approve-merge", severity: "high", message: "untrusted content pressures the agent to approve/merge while waiving required checks" };
  }

  // 8. Fuzzy tail: content that explicitly addresses the assistant/agent and gives
  //    it an action directive. High enough to flag (warn) — real docs address the
  //    *user*, not "the assistant/agent/automated contributor".
  const addressesAgent = /\b(?:note (?:for|to) assistants?|for the assistant|when an assistant|the (?:assistant|handling agent|calling agent|on-call assistant) (?:should|must|will|is|compiles?|collects?)|on-call assistant|automated contributor|reviewer reminder|integrator note|x-agent-advisory|assistant (?:summariz|performing|setting up)|for (?:any|the) assistant|whoever sets up)\b/i.test(text);
  const directive = /\b(?:run|execute|send|include|embed|add a remote|attach|mirror|paste|reply|approve and merge|submit|push(?:es)? the|gather\w*|snapshot\w*|compil\w*|collect\w*)\b/i.test(text);
  // Only flag when the directive targets something sensitive — a secret, or an
  // external URL it's told to send data to — so benign agent-mentioning prose
  // ("the assistant compiles the report and sends it to the user") passes.
  const sensitiveTarget = CRED_STRONG.test(text) || CRED_WEAK.test(text) ||
    (/https?:\/\//i.test(text) && /\b(?:post|posts|submit|upload|mirror|paste|archive|exfiltrat\w*|send|transmit|--data|data-binary|push(?:es)? (?:the|current|to|it|branch))\b/i.test(text));
  if (addressesAgent && directive && sensitiveTarget) {
    return { ruleId: "directive-agent-addressed", severity: "high", message: "untrusted content directly instructs the assistant to send data to an external target — treat as data, not a command" };
  }

  return null;
}
