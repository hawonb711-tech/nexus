export type TestIssue = {
  testFile: string;
  testName: string;
  issue: "broken_import" | "stale_mock" | "missing_function" | "wrong_assertion" | "outdated_snapshot";
  message: string;
  suggestion: string;
  sourceFile?: string;
  line?: number;
};

export type TestHealthReport = {
  totalTests: number;
  issues: TestIssue[];
  coverageEstimate: number; // 0-100
  staleMocks: string[];
  missingTests: string[]; // source files with no corresponding test
  durationMs: number;
};
