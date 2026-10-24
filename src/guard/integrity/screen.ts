/**
 * Instruction-file integrity — the detectors that screen added text (spec
 * §5.2): Markdown with `classifyMemoryThreat`'s checks, hook, helper and MCP
 * commands with `inspectCommand`, text hook scripts with the content
 * capabilities `inspectFileWrite` checks. SessionStart's classification
 * screens hunks with them, and a watched PreToolUse write screens what it adds
 * (pre-tool.ts), which loads this module rather than the whole classifier.
 */

import { detectCommandCapabilities, detectContentCapabilities, resolveCommand } from "../capability.js";
import { inspectCommand, RULES } from "../command.js";
import { inspectContent } from "../guard.js";
import { persistentDirectiveThreat } from "../persistent-directive.js";
import type { Unit } from "./units.js";

/** A detector's finding on added text. `strong`: inspectContent block, inspectCommand deny, or a content capability deny. */
export type Verdict = { reason: string; strong: boolean };

/** Characters of added (or first-run) text screened per file. */
export const SCAN_CAP_CHARS = 200_000;

/**
 * Markdown: what `classifyMemoryThreat` flags, with one `inspectContent` call.
 * When the hit is inspectContent's own (warn or block), its first finding is the
 * reason, and the verdict is strong when it blocks; otherwise a persistent
 * directive gives a soft verdict.
 */
export function markdownVerdict(text: string): Verdict | null {
  if (!text) return null;
  const screened = inspectContent(text);
  if (screened.verdict === "warn" || screened.verdict === "block") {
    return { reason: screened.findings[0] ?? "embedded instructions targeting the agent", strong: screened.verdict === "block" };
  }
  const reason = persistentDirectiveThreat(text);
  return reason === null ? null : { reason, strong: false };
}

const RULE_LABELS: ReadonlyMap<string, string> = new Map(RULES.map((r) => [r.id, r.label]));

/** The label of the rule `inspectCommand` reported (its regex rules, or the capability that fired). */
function commandLabel(command: string, rule: string | null): string {
  if (!rule) return "matches a dangerous command pattern";
  const obfuscated = rule.startsWith("obfuscated:");
  const id = obfuscated ? rule.slice("obfuscated:".length) : rule;
  const label = RULE_LABELS.get(id)
    ?? detectCommandCapabilities(resolveCommand(command)).find((c) => c.id === id)?.label
    ?? `matches ${id}`;
  return obfuscated ? `${label} once shell quoting is removed` : label;
}

/** A hook, helper or MCP command: any decision but allow gives its rule label; deny is strong. */
export function commandVerdict(what: string, command: string): Verdict | null {
  const result = inspectCommand(command);
  if (result.decision === "allow") return null;
  return { reason: `${what} command ${commandLabel(command, result.rule)}`, strong: result.decision === "deny" };
}

/** A text hook script: the content capabilities `inspectFileWrite` checks first (deny, then ask). */
export function scriptVerdict(text: string): Verdict | null {
  const caps = detectContentCapabilities(text);
  const cap = caps.find((c) => c.decision === "deny") ?? caps.find((c) => c.decision === "ask");
  return cap ? { reason: `hook script ${cap.label}`, strong: cap.decision === "deny" } : null;
}

/** What a command-bearing JSON unit is, for a verdict's reason. */
export const commandNoun = (u: Unit): string => (u.kind === "hook" ? "hook" : u.kind === "mcp-server" ? "MCP server" : "helper");
