import type { ReviewOptions, ReviewResult, ReviewFinding } from "./types.js";
import { reviewCode } from "./analyzer.js";

interface DiffHunk {
  file: string;
  addedLines: Map<number, string>; // line number -> content
}

function parseDiff(diff: string): DiffHunk[] {
  const hunks: DiffHunk[] = [];
  const lines = diff.split("\n");

  let currentFile = "";
  let currentHunk: DiffHunk | null = null;
  let newLineNum = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Detect file header: +++ b/path/to/file
    if (line.startsWith("+++ ")) {
      const filePath = line.slice(4).replace(/^b\//, "");
      currentFile = filePath;
      currentHunk = { file: currentFile, addedLines: new Map() };
      hunks.push(currentHunk);
      continue;
    }

    // Detect --- line (skip)
    if (line.startsWith("--- ")) {
      continue;
    }

    // Detect hunk header: @@ -oldStart,oldCount +newStart,newCount @@
    const hunkHeader = line.match(/^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/);
    if (hunkHeader) {
      newLineNum = parseInt(hunkHeader[1], 10);
      continue;
    }

    // Skip diff metadata lines
    if (
      line.startsWith("diff ") ||
      line.startsWith("index ") ||
      line.startsWith("new file") ||
      line.startsWith("deleted file") ||
      line.startsWith("similarity") ||
      line.startsWith("rename") ||
      line.startsWith("Binary")
    ) {
      continue;
    }

    if (!currentHunk) continue;

    if (line.startsWith("+")) {
      // Added line — strip the leading "+"
      currentHunk.addedLines.set(newLineNum, line.slice(1));
      newLineNum++;
    } else if (line.startsWith("-")) {
      // Removed line — does not advance new line counter
      continue;
    } else {
      // Context line (space prefix or empty)
      newLineNum++;
    }
  }

  return hunks;
}

function reconstructAddedCode(hunk: DiffHunk): string {
  if (hunk.addedLines.size === 0) return "";

  const sortedLines = [...hunk.addedLines.entries()].sort(
    (a, b) => a[0] - b[0],
  );

  // Build a sparse source with placeholders so line numbers align
  const maxLine = sortedLines[sortedLines.length - 1][0];
  const minLine = sortedLines[0][0];
  const codeLines: string[] = [];

  // We only need the added lines; pad to keep line numbers consistent
  for (let n = minLine; n <= maxLine; n++) {
    const content = hunk.addedLines.get(n);
    codeLines.push(content ?? "");
  }

  return codeLines.join("\n");
}

function remapFindings(
  findings: ReviewFinding[],
  hunk: DiffHunk,
  minLine: number,
): ReviewFinding[] {
  const addedLineNums = new Set(hunk.addedLines.keys());
  return findings
    .map((f) => {
      // reviewCode produces 1-based line numbers within the reconstructed code.
      // minLine is the starting line number in the actual file.
      // So actual = minLine + (f.line - 1) = minLine + f.line - 1
      const actualLine = minLine + f.line - 1;
      return { ...f, file: hunk.file, line: actualLine };
    })
    .filter((f) => addedLineNums.has(f.line));
}

export function reviewDiff(
  diff: string,
  options: ReviewOptions = {},
): ReviewResult {
  const start = performance.now();
  const hunks = parseDiff(diff);
  const allFindings: ReviewFinding[] = [];

  for (const hunk of hunks) {
    if (hunk.addedLines.size === 0) continue;

    const sortedEntries = [...hunk.addedLines.entries()].sort(
      (a, b) => a[0] - b[0],
    );
    const minLine = sortedEntries[0][0];
    const code = reconstructAddedCode(hunk);

    const result = reviewCode(code, hunk.file, options);
    const remapped = remapFindings(result.findings, hunk, minLine);
    allFindings.push(...remapped);
  }

  // De-duplicate by line+message
  const seen = new Set<string>();
  const deduped: ReviewFinding[] = [];
  for (const f of allFindings) {
    const key = `${f.file}:${f.line}:${f.message}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(f);
    }
  }

  // Re-assign sequential IDs
  const findings = deduped.map((f, i) => ({
    ...f,
    id: `D${String(i + 1).padStart(4, "0")}`,
  }));

  // Apply maxFindings
  const limited =
    options.maxFindings && options.maxFindings > 0
      ? findings.slice(0, options.maxFindings)
      : findings;

  const score = computeDiffScore(limited);
  const summary = buildDiffSummary(limited, hunks.length, score);
  const durationMs = Math.round(performance.now() - start);

  return { findings: limited, score, summary, durationMs };
}

function computeDiffScore(findings: ReviewFinding[]): number {
  const penaltyMap: Record<string, number> = {
    critical: 15,
    warning: 8,
    suggestion: 3,
    info: 1,
  };
  let penalty = 0;
  for (const f of findings) {
    penalty += penaltyMap[f.severity] ?? 0;
  }
  return Math.max(0, Math.min(100, 100 - penalty));
}

function buildDiffSummary(
  findings: ReviewFinding[],
  fileCount: number,
  score: number,
): string {
  if (findings.length === 0) {
    return `Reviewed changes across ${fileCount} file${fileCount === 1 ? "" : "s"}. No issues found in added lines.`;
  }

  const files = new Set(findings.map((f) => f.file));
  return (
    `Reviewed ${fileCount} file${fileCount === 1 ? "" : "s"}, ` +
    `found ${findings.length} issue${findings.length === 1 ? "" : "s"} ` +
    `in ${files.size} file${files.size === 1 ? "" : "s"}. Score: ${score}/100.`
  );
}
