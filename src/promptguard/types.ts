/** Severity levels for detected threats. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Where the injection was found. */
export type InjectionContext =
  | "user_input"
  | "tool_result"
  | "mcp_response"
  | "system_prompt"
  | "document"
  | "unknown";

/** A single detection finding. */
export type Finding = {
  /** Rule that triggered. */
  ruleId: string;
  /** Human-readable description. */
  message: string;
  /** Severity of the finding. */
  severity: Severity;
  /** Matched evidence (truncated). */
  evidence: string;
  /** Byte offset of the match start. */
  offset: number;
  /** Where the input came from. */
  context: InjectionContext;
};

/** Result of scanning a single input. */
export type ScanResult = {
  /** Whether any injection was detected. */
  injected: boolean;
  /** Highest severity found, or null if clean. */
  maxSeverity: Severity | null;
  /** All findings. */
  findings: Finding[];
  /** Time taken in milliseconds. */
  durationMs: number;
  /** Deep analysis layers (only present when enableDeepScan is true). */
  analysis?: DeepAnalysis;
};

/** Deep analysis results from advanced detection layers. */
export type DeepAnalysis = {
  /** Text normalization transforms applied. */
  normalization?: { transforms: string[] };
  /** Shannon entropy and statistical anomalies. */
  entropy?: { shannonEntropy: number; findings: Finding[] };
  /** Semantic intent classification. */
  semantic?: { score: number; category: string; confidence: number };
  /** Token-level statistical analysis. */
  tokens?: { totalTokens: number; specialCharRatio: number; uppercaseRatio: number; findings: Finding[] };
};

/** Options for the scanner. */
export type ScanOptions = {
  /** Context of the input being scanned. */
  context?: InjectionContext;
  /** Minimum severity to report. */
  minSeverity?: Severity;
  /** Maximum findings before stopping. */
  maxFindings?: number;
  /** Custom rules to add. */
  customRules?: DetectionRule[];
  /** Rule IDs to disable. */
  disabledRules?: string[];
  /** Enable deep analysis (normalization, entropy, semantic, token). Default: true. */
  enableDeepScan?: boolean;
  /** Include multilingual rules. Default: true. */
  enableMultilingual?: boolean;
  /** The allowed domain for the AI agent. Enables domain-drift detection. */
  allowedDomain?: string;
  /** Enable logic-based detection (rhetorical bridge, domain drift, coherence gap). Default: true. */
  enableLogicAnalysis?: boolean;
  /**
   * The input is an agent instruction file (CLAUDE.md, AGENTS.md, …) or a few
   * paragraphs of one, as the instruction-file integrity screen hands it over.
   * Such a file states rules and names settings that read as attacks in a
   * message, so a few rules tuned for messages give way to their
   * instruction-file forms (`DetectionRule.instructionFile`) and the logic
   * detectors keep their signals closer together
   * (`LogicAnalysisOptions.instructionFile`). Independent of `context`.
   */
  instructionFile?: boolean;
};

/** A detection rule definition. */
export type DetectionRule = {
  id: string;
  severity: Severity;
  message: string;
  pattern: RegExp;
  /** Only fire if this secondary pattern also matches. */
  requiresContext?: RegExp;
  /** Contexts where this rule applies. */
  applicableContexts?: InjectionContext[];
  /**
   * Whether the rule screens instruction files (`ScanOptions.instructionFile`):
   * false for a rule tuned for messages that instruction files trip on, true for
   * its form for them. Unset, it screens both.
   */
  instructionFile?: boolean;
};
