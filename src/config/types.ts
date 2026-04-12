export type ConfigIssue = {
  file: string;
  key: string;
  issue: "missing" | "mismatch" | "deprecated" | "insecure" | "duplicate";
  message: string;
  severity: "critical" | "warning" | "info";
  suggestion?: string;
};

export type ConfigReport = {
  files: string[];
  issues: ConfigIssue[];
  envVarCount: number;
};
