import type { TestIssue } from "./types.js";

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0) as number[]);

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function findClosestMatch(target: string, candidates: string[]): string | null {
  if (candidates.length === 0) return null;

  let best = candidates[0];
  let bestDist = levenshtein(target.toLowerCase(), best.toLowerCase());

  for (let i = 1; i < candidates.length; i++) {
    const dist = levenshtein(target.toLowerCase(), candidates[i].toLowerCase());
    if (dist < bestDist) {
      bestDist = dist;
      best = candidates[i];
    }
  }

  // Only suggest if reasonably close (within 50% of target length)
  const threshold = Math.ceil(target.length * 0.5);
  return bestDist <= threshold ? best : null;
}

function extractFunctionCandidates(suggestion: string): string[] {
  const match = suggestion.match(/Current functions: (.+)$/);
  if (!match) return [];
  return match[1].split(", ").map((s) => s.trim()).filter(Boolean);
}

export function suggestFixes(issues: TestIssue[]): string[] {
  const suggestions: string[] = [];

  for (const issue of issues) {
    switch (issue.issue) {
      case "broken_import": {
        const importPath = issue.sourceFile ?? "";
        // Suggest looking for files with similar names
        const fileName = importPath.split("/").pop() ?? importPath;
        suggestions.push(
          `[${issue.testFile}] Broken import "${importPath}": ` +
          `Search for files matching "*${fileName}*" in the project. ` +
          `The file may have been moved or renamed. ` +
          `Update the import path in the test file.`
        );
        break;
      }

      case "stale_mock": {
        suggestions.push(
          `[${issue.testFile}] Stale mock detected: ${issue.message}. ` +
          `Options: (1) Remove the mock if the function was deleted, ` +
          `(2) Update the mock target to the renamed function, ` +
          `(3) Check if the mock is still needed after refactoring.`
        );
        break;
      }

      case "missing_function": {
        // Try to extract function candidates from the suggestion
        const candidates = extractFunctionCandidates(issue.suggestion);
        const testName = issue.testName;

        // Extract the referenced function name from the message
        const fnMatch = issue.message.match(/reference function "(\w+)"/);
        const referencedFn = fnMatch?.[1] ?? "";

        if (referencedFn && candidates.length > 0) {
          const closest = findClosestMatch(referencedFn, candidates);
          if (closest) {
            suggestions.push(
              `[${issue.testFile}] Test "${testName}" references "${referencedFn}" ` +
              `which no longer exists. Closest match: "${closest}". ` +
              `Update the test to use the new function name.`
            );
          } else {
            suggestions.push(
              `[${issue.testFile}] Test "${testName}" references "${referencedFn}" ` +
              `which no longer exists. No close match found. ` +
              `Available functions: ${candidates.join(", ")}. ` +
              `Consider removing or rewriting this test.`
            );
          }
        } else {
          suggestions.push(
            `[${issue.testFile}] ${issue.message}. ${issue.suggestion}`
          );
        }
        break;
      }

      case "wrong_assertion": {
        suggestions.push(
          `[${issue.testFile}] ${issue.message}. ` +
          `Review the test assertions against current function behavior. ` +
          `${issue.suggestion}`
        );
        break;
      }

      case "outdated_snapshot": {
        suggestions.push(
          `[${issue.testFile}] Test file is outdated: ${issue.message}. ` +
          `The corresponding source file${issue.sourceFile ? ` (${issue.sourceFile})` : ""} ` +
          `has been modified more recently. Review tests for correctness ` +
          `and update snapshots if applicable.`
        );
        break;
      }
    }
  }

  return suggestions;
}
