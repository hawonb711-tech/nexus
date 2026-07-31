import { redactSecretsInText } from "../secrets/scanner.js";
import { inspectContent, spotlightUntrusted } from "./guard.js";
import type { GuardResult, GuardVerdict } from "./types.js";

export type SanitizedExternalContent = {
  /** Content safe to show to an agent. */
  displayText: string;
  /** Content safe to persist. Null means quarantine instead of indexing it. */
  persistText: string | null;
  verdict: GuardVerdict;
  reason: string;
  findings: string[];
  secretsRedacted: number;
};

// Keep windows modest: several promptguard rules are intentionally rich regexes
// and exhibit super-linear cost on very large repeated documents.
const SCAN_WINDOW = 8_000;
const SCAN_OVERLAP = 512;
const VERDICT_ORDER: Record<GuardVerdict, number> = { allow: 0, warn: 1, block: 2 };

function inspectEntireContent(text: string): GuardResult {
  if (text.length <= SCAN_WINDOW) return inspectContent(text);

  const results: GuardResult[] = [];
  for (let start = 0; start < text.length; start += SCAN_WINDOW - SCAN_OVERLAP) {
    results.push(inspectContent(text.slice(start, start + SCAN_WINDOW)));
  }

  const strongest = results.reduce((current, candidate) =>
    VERDICT_ORDER[candidate.verdict] > VERDICT_ORDER[current.verdict] ? candidate : current,
  );
  return {
    ...strongest,
    findings: [...new Set(results.flatMap((result) => result.findings))].slice(0, 5),
    secretsSeen: results.some((result) => result.secretsSeen),
  };
}

/**
 * Apply the complete trust boundary for external content before it is returned
 * to an agent or stored in long-lived memory.
 *
 * Warning/block payloads are deliberately not persisted. Spotlighting is safe
 * for display, but a memory engine can split the wrapper away from the quoted
 * payload and accidentally reactivate the embedded instructions later.
 */
export function sanitizeExternalContent(text: string): SanitizedExternalContent {
  const result = inspectEntireContent(text);
  const redacted = redactSecretsInText(text);

  if (result.verdict === "block") {
    const findings = result.findings.join("; ") || "embedded instructions targeting the agent";
    return {
      displayText:
        `[BLOCKED by Nexus - prompt injection detected in external content]\n` +
        `The payload was quarantined and was not saved to memory. Findings: ${findings}.`,
      persistText: null,
      verdict: result.verdict,
      reason: result.reason,
      findings: result.findings,
      secretsRedacted: redacted.count,
    };
  }

  if (result.verdict === "warn") {
    return {
      displayText: spotlightUntrusted(redacted.text),
      persistText: null,
      verdict: result.verdict,
      reason: result.reason,
      findings: result.findings,
      secretsRedacted: redacted.count,
    };
  }

  return {
    displayText: redacted.text,
    persistText: redacted.text,
    verdict: result.verdict,
    reason: result.reason,
    findings: result.findings,
    secretsRedacted: redacted.count,
  };
}
