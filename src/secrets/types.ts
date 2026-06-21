/**
 * Types for the secret scanner — finds committed credentials in the working
 * tree and across git history (including secrets introduced then later removed,
 * which the working tree no longer shows but which remain exposed in history).
 */

export type SecretSeverity = "critical" | "high" | "medium" | "low";

/** Where a finding came from. */
export type SecretSource = "working-tree" | "git-history";

/** How the secret was detected. */
export type SecretDetector = "pattern" | "entropy";

export type SecretFinding = {
  id: string;
  /** Human label, e.g. "AWS access key", "GitHub PAT", "high-entropy string". */
  rule: string;
  detector: SecretDetector;
  severity: SecretSeverity;
  source: SecretSource;
  /** Repo-relative path. */
  file: string;
  /** 1-based line number; 0 when unknown. */
  line: number;
  /** The secret, masked — never the raw value. */
  redacted: string;
  /** Redacted surrounding context (<= 160 chars). */
  evidence: string;
  /** Short commit hash (git-history findings only). */
  commit?: string;
  commitDate?: string;
  author?: string;
  /** For git-history findings: does the same secret still exist in the working tree? */
  stillPresent?: boolean;
  /** Truncated SHA-256 of the raw secret — lets the same secret be matched across
   *  surfaces without collisions, without ever storing the raw value. */
  fingerprint: string;
  suggestion: string;
};

export type SecretScanResult = {
  findings: SecretFinding[];
  filesScanned: number;
  commitsScanned: number;
  durationMs: number;
  /** Non-zero fields mean coverage was bounded — never silently truncated. */
  truncated: {
    /** Files skipped because they were too large or binary. */
    files?: number;
    /** Files that existed but could not be read (e.g. permission denied). */
    unreadable?: number;
    /** Set when the hard file-count cap was hit and some files were never walked. */
    filesCapped?: number;
    commits?: number;
    findings?: number;
    historyUnavailable?: string;
  };
  summary: string;
};

export type SecretScanOptions = {
  /** Also scan git history (git log -p). Off by default. */
  includeHistory?: boolean;
  /** Enable entropy-based detection of unrecognized high-randomness strings. Off by default (higher false-positive rate). */
  entropy?: boolean;
  /** Cap on commits scanned in history mode (default 1000). */
  maxCommits?: number;
  /** Skip files larger than this many bytes (default 1 MiB). */
  maxFileSize?: number;
  /** Cap on total findings returned (default 1000). */
  maxFindings?: number;
  /** Directory names to skip, in addition to the defaults. */
  ignore?: string[];
};
