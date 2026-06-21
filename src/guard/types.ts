/**
 * Agent firewall — the trust layer for AI coding agents.
 *
 * As coding agents (Claude Code, etc.) autonomously read untrusted content —
 * web pages, GitHub issues, package READMEs, error logs, tool output — the
 * defining risk of the era is INDIRECT PROMPT INJECTION: poisoned content that
 * hijacks the agent into leaking secrets, running dangerous commands, or
 * subverting its instructions. The guard inspects that content BEFORE the agent
 * acts on it, entirely on-device.
 */

import type { Severity } from "../promptguard/types.js";

export type GuardVerdict = "block" | "warn" | "allow";

export type GuardResult = {
  verdict: GuardVerdict;
  /** Highest injection severity found, or null. */
  maxSeverity: Severity | null;
  /** One-line human reason (shown to the agent / user). */
  reason: string;
  /** Brief, de-duplicated finding labels (no raw payload echoed). */
  findings: string[];
  /** Whether the inspected content also looked like it carried a secret. */
  secretsSeen: boolean;
};

export type GuardPolicy = {
  /** Minimum injection severity that BLOCKS (default: "critical"). */
  blockAt: Severity;
  /** Minimum injection severity that WARNS (default: "high"). */
  warnAt: Severity;
  /** Cap on how much of a large tool result to scan (chars). */
  maxScanChars: number;
};

export const DEFAULT_POLICY: GuardPolicy = {
  blockAt: "critical",
  warnAt: "high",
  maxScanChars: 200_000,
};
