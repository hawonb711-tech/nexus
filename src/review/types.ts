export type ReviewSeverity = "critical" | "warning" | "suggestion" | "info";

export type ReviewCategory =
  | "bug"
  | "security"
  | "performance"
  | "style"
  | "complexity"
  | "duplication"
  | "dead_code"
  | "ai_slop"
  | "missing_test"
  | "error_handling";

export type ReviewFinding = {
  id: string;
  file: string;
  line: number;
  endLine?: number;
  severity: ReviewSeverity;
  category: ReviewCategory;
  message: string;
  evidence: string;
  suggestion?: string;
};

export type ReviewResult = {
  findings: ReviewFinding[];
  score: number; // 0-100, overall quality score
  summary: string;
  durationMs: number;
};

export type ReviewOptions = {
  minSeverity?: ReviewSeverity;
  categories?: ReviewCategory[];
  maxFindings?: number;
};
