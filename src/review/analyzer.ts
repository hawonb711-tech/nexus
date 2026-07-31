import type {
  ReviewCategory,
  ReviewFinding,
  ReviewOptions,
  ReviewResult,
  ReviewSeverity,
} from "./types.js";

const SEVERITY_ORDER: Record<ReviewSeverity, number> = {
  critical: 0,
  warning: 1,
  suggestion: 2,
  info: 3,
};

const SEVERITY_PENALTY: Record<ReviewSeverity, number> = {
  critical: 15,
  warning: 8,
  suggestion: 3,
  info: 1,
};

function createIdGenerator(): () => string {
  let counter = 0;
  return () => `R${String(++counter).padStart(4, "0")}`;
}

let nextId = createIdGenerator();

function finding(
  file: string,
  line: number,
  severity: ReviewSeverity,
  category: ReviewCategory,
  message: string,
  evidence: string,
  suggestion?: string,
  endLine?: number,
): ReviewFinding {
  return {
    id: nextId(),
    file,
    line,
    ...(endLine !== undefined ? { endLine } : {}),
    severity,
    category,
    message,
    evidence,
    ...(suggestion !== undefined ? { suggestion } : {}),
  };
}

// ---------------------------------------------------------------------------
// Bug detectors
// ---------------------------------------------------------------------------

function detectConsoleStatements(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const re = /\bconsole\.(log|error|warn|debug|info|trace)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const match = line.match(re);
    if (match && !line.trimStart().startsWith("//")) {
      const method = match[1];
      results.push(
        finding(
          file,
          i + 1,
          "warning",
          "bug",
          `console.${method} statement left in code`,
          line.trim(),
          "Remove or replace with a proper logger",
        ),
      );
    }
  }
}

function detectTodoComments(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const re = /\/\/\s*(TODO|FIXME|HACK|XXX)\b/i;
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(re);
    if (match) {
      results.push(
        finding(
          file,
          i + 1,
          "info",
          "bug",
          `Unfinished work marker: ${match[1].toUpperCase()}`,
          lines[i].trim(),
          "Resolve or track in an issue before merging",
        ),
      );
    }
  }
}

function detectEmptyCatch(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const re = /catch\s*\([^)]*\)\s*\{\s*\}/;
  const joined = lines.join("\n");
  let offset = 0;
  let match: RegExpExecArray | null;
  const global = new RegExp(re.source, "g");
  while ((match = global.exec(joined)) !== null) {
    const lineNum = joined.substring(0, match.index).split("\n").length;
    results.push(
      finding(
        file,
        lineNum,
        "warning",
        "error_handling",
        "Empty catch block swallows errors silently",
        match[0].trim(),
        "Log the error or handle it explicitly",
      ),
    );
    offset = match.index + match[0].length;
  }
}

function detectLooseNullCheck(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const re = /[^!=]==[^=]\s*(null|undefined)\b/;
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i]) && !lines[i].trimStart().startsWith("//")) {
      results.push(
        finding(
          file,
          i + 1,
          "suggestion",
          "bug",
          "Loose equality with null/undefined",
          lines[i].trim(),
          "Use === for strict equality or explicit nullish checks",
        ),
      );
    }
  }
}

function detectUnreachableCode(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  // Only flag unreachable code when return/throw is at the same or lower indent
  // level as the next non-trivial line AND not inside a nested block.
  const terminatorRe = /^(\s*)(return|throw)\b[^]*?;?\s*$/;
  for (let i = 0; i < lines.length - 1; i++) {
    const match = terminatorRe.exec(lines[i]);
    if (!match) continue;
    if (/[\[{(]\s*$/.test(lines[i].trimEnd())) continue;

    const terminatorIndent = match[1].length;
    const next = lines[i + 1];
    const nextTrimmed = next?.trim();

    // Skip if next line is closing brace, blank, comment, case/default, else, catch, finally
    if (
      !nextTrimmed ||
      nextTrimmed === "}" ||
      nextTrimmed === "})" ||
      nextTrimmed === "});" ||
      nextTrimmed === "}," ||
      nextTrimmed.startsWith("//") ||
      nextTrimmed.startsWith("/*") ||
      nextTrimmed.startsWith("*") ||
      nextTrimmed.startsWith("case ") ||
      nextTrimmed.startsWith("default:") ||
      nextTrimmed.startsWith("else") ||
      nextTrimmed.startsWith("catch") ||
      nextTrimmed.startsWith("finally") ||
      nextTrimmed.startsWith("export") ||
      nextTrimmed.startsWith("function") ||
      nextTrimmed.startsWith("const ") ||
      nextTrimmed.startsWith("class ")
    ) {
      continue;
    }

    // Only flag if next line has same or greater indentation (same scope)
    const nextIndent = next ? next.length - next.trimStart().length : 0;
    if (nextIndent <= terminatorIndent) continue;

    results.push(
      finding(
        file,
        i + 2,
        "warning",
        "bug",
        "Potentially unreachable code after return/throw",
        nextTrimmed,
        "Remove dead code or restructure control flow",
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// AI slop detectors
// ---------------------------------------------------------------------------

function detectObviousComments(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const patterns = [
    /\/\/\s*increment\s+\w+\s+by\s+\d+/i,
    /\/\/\s*set\s+\w+\s+to\s+/i,
    /\/\/\s*declare\s+(a\s+)?(new\s+)?variable/i,
    /\/\/\s*import\s+\w+/i,
    /\/\/\s*define\s+(a\s+)?(the\s+)?function/i,
    /\/\/\s*return\s+the\s+(result|value|output)/i,
    /\/\/\s*initialize\s+(the\s+)?\w+\s+(variable|array|object)/i,
    /\/\/\s*loop\s+(through|over)\s+(the\s+)?(array|list|items|elements)/i,
    /\/\/\s*check\s+if\s+\w+\s+is\s+(null|undefined|true|false|empty)/i,
    /\/\/\s*create\s+(a\s+)?(new\s+)?(instance|object)\s+of/i,
    /\/\/\s*call\s+(the\s+)?\w+\s+(function|method)/i,
    /\/\/\s*add\s+\w+\s+to\s+(the\s+)?(array|list|map|set|object)/i,
    /\/\/\s*export\s+(the\s+)?(function|class|interface|type|const)/i,
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pat of patterns) {
      if (pat.test(line)) {
        results.push(
          finding(
            file,
            i + 1,
            "warning",
            "ai_slop",
            "Comment states the obvious — likely AI-generated boilerplate",
            line.trim(),
            "Remove trivial comments; prefer self-documenting code",
          ),
        );
        break;
      }
    }
  }
}

function detectRepeatedBoilerplate(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  // Normalize lines for structural comparison: strip whitespace and identifiers
  const normalized: string[] = lines.map((l) =>
    l
      .trim()
      .replace(/["'`].*?["'`]/g, '""')
      .replace(/\b[a-zA-Z_]\w*\b/g, "_ID_")
      .replace(/\d+/g, "0"),
  );

  // Check for repeated 5-line blocks (raised from 3 to reduce false positives)
  const blockSize = 5;
  const seen = new Map<string, number[]>();

  for (let i = 0; i <= normalized.length - blockSize; i++) {
    const block = normalized.slice(i, i + blockSize).join("\n");
    // Skip trivial blocks and blocks that are mostly structural (braces, imports)
    const content = block.replace(/\s/g, "");
    if (content.length < 30) continue;
    // Skip if the block is just identifiers and structure (too normalized)
    if (content.replace(/_ID_/g, "").replace(/[{}();,=\n]/g, "").length < 10) continue;

    const existing = seen.get(block);
    if (existing) {
      existing.push(i + 1);
    } else {
      seen.set(block, [i + 1]);
    }
  }

  let boilerplateCount = 0;
  for (const [_block, locations] of seen) {
    if (locations.length >= 4 && boilerplateCount < 3) {
      boilerplateCount++;
      results.push(
        finding(
          file,
          locations[0],
          "suggestion",
          "ai_slop",
          `Repeated boilerplate pattern found ${locations.length} times`,
          `Lines: ${locations.slice(0, 5).join(", ")}`,
          "Extract into a shared helper or use a loop/map",
        ),
      );
    }
  }
}

function detectUnnecessaryTypeAssertions(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const re = /\bas\s+(any|unknown)\b/;
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i]) && !lines[i].trimStart().startsWith("//")) {
      results.push(
        finding(
          file,
          i + 1,
          "warning",
          "ai_slop",
          "Unnecessary type assertion (as any / as unknown)",
          lines[i].trim(),
          "Fix the underlying type issue instead of casting",
        ),
      );
    }
  }
}

function detectLongFunctions(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const funcStartRe =
    /^(\s*)(export\s+)?(async\s+)?function\s+\w+|^(\s*)(export\s+)?(const|let|var)\s+\w+\s*=\s*(async\s+)?\(|^(\s*)(public|private|protected|static|\s)*(async\s+)?\w+\s*\([^)]*\)\s*[:{]/;
  const maxLines = 80;

  for (let i = 0; i < lines.length; i++) {
    if (!funcStartRe.test(lines[i])) continue;

    // Find matching brace depth
    let depth = 0;
    let started = false;
    let end = i;

    for (let j = i; j < lines.length; j++) {
      for (const ch of lines[j]) {
        if (ch === "{") {
          depth++;
          started = true;
        } else if (ch === "}") {
          depth--;
        }
      }
      if (started && depth <= 0) {
        end = j;
        break;
      }
    }

    const length = end - i + 1;
    if (length > maxLines) {
      results.push(
        finding(
          file,
          i + 1,
          "warning",
          "ai_slop",
          `Function is ${length} lines long (max recommended: ${maxLines})`,
          lines[i].trim(),
          "Break into smaller, focused functions",
          end + 1,
        ),
      );
    }
  }
}

function detectDeepNesting(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const maxDepth = 6;
  let inTemplateLiteral = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let unescapedBackticks = 0;
    for (let j = 0; j < line.length; j++) {
      if (line[j] !== "`") continue;

      let precedingBackslashes = 0;
      for (let k = j - 1; k >= 0 && line[k] === "\\"; k--) {
        precedingBackslashes++;
      }
      if (precedingBackslashes % 2 === 0) unescapedBackticks++;
    }

    const touchesTemplateLiteral =
      inTemplateLiteral || unescapedBackticks > 0;
    if (unescapedBackticks % 2 === 1) {
      inTemplateLiteral = !inTemplateLiteral;
    }
    if (touchesTemplateLiteral) continue;

    // Count leading indentation in spaces (normalize tabs to 2 spaces)
    const stripped = line.replace(/\t/g, "  ");
    const indent = stripped.length - stripped.trimStart().length;
    const content = stripped.trim();

    // Only flag actual code lines (not braces-only or blanks)
    if (content.length < 3 || content === "{" || content === "}") continue;

    // Estimate nesting: assume 2-space indent
    const indentUnit = 2;
    const depth = Math.floor(indent / indentUnit);

    if (depth >= maxDepth) {
      results.push(
        finding(
          file,
          i + 1,
          "suggestion",
          "ai_slop",
          `Code is nested ${depth} levels deep`,
          content.substring(0, 80),
          "Extract nested logic into separate functions or use early returns",
        ),
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Security detectors
// ---------------------------------------------------------------------------

function detectHardcodedSecrets(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const patterns = [
    { re: /(?:api[_-]?key|apikey)\s*[:=]\s*["'`][A-Za-z0-9_\-]{16,}["'`]/i, label: "API key" },
    { re: /(?:password|passwd|pwd)\s*[:=]\s*["'`][^"'`]{4,}["'`]/i, label: "password" },
    { re: /(?:secret|token)\s*[:=]\s*["'`][A-Za-z0-9_\-]{16,}["'`]/i, label: "secret/token" },
    { re: /(?:AKIA|ASIA)[A-Z0-9]{16}/, label: "AWS access key" },
    { re: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/, label: "private key" },
    { re: /ghp_[A-Za-z0-9_]{36}/, label: "GitHub PAT" },
    { re: /sk-[A-Za-z0-9]{32,}/, label: "OpenAI/Stripe secret key" },
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trimStart().startsWith("//") || line.trimStart().startsWith("*")) continue;
    for (const { re, label } of patterns) {
      if (re.test(line)) {
        results.push(
          finding(
            file,
            i + 1,
            "critical",
            "security",
            `Potential hardcoded ${label}`,
            line.trim().substring(0, 120),
            "Use environment variables or a secrets manager",
          ),
        );
        break;
      }
    }
  }
}

function detectSqlInjection(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const sqlKeyword = /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP)\b/i;

  // String concatenation: line has a string literal + variable (handles mixed quotes)
  const stringConcat = /["'`]\s*\+|\+\s*["'`]/;

  // Template literal interpolation with SQL keyword
  const templateRe =
    /`[^`]*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP)\b[^`]*\$\{/i;

  // Parameterized query (safe — do not flag)
  const parameterized = /\?\s*[,)\]]|\$\d+/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trimStart().startsWith("//")) continue;

    const hasSqlKeyword = sqlKeyword.test(line);
    const hasConcatenation = stringConcat.test(line);
    const hasTemplateInterp = templateRe.test(line);
    const isSafe = parameterized.test(line);

    if (
      !isSafe &&
      (hasTemplateInterp || (hasSqlKeyword && hasConcatenation))
    ) {
      results.push(
        finding(
          file,
          i + 1,
          "critical",
          "security",
          "SQL string concatenation / template literal — potential SQL injection",
          line.trim().substring(0, 120),
          "Use parameterized queries or prepared statements",
        ),
      );
    }
  }
}

function detectEvalUsage(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const re = /\b(eval|Function)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i]) && !lines[i].trimStart().startsWith("//")) {
      results.push(
        finding(
          file,
          i + 1,
          "critical",
          "security",
          "eval() or Function() constructor — potential code injection",
          lines[i].trim(),
          "Avoid eval; use safer alternatives like JSON.parse or a sandboxed interpreter",
        ),
      );
    }
  }
}

function detectInnerHtml(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const re = /\.innerHTML\s*=/;
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) {
      results.push(
        finding(
          file,
          i + 1,
          "critical",
          "security",
          "Direct innerHTML assignment — potential XSS",
          lines[i].trim(),
          "Use textContent, or sanitize input with a trusted library",
        ),
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Performance detectors
// ---------------------------------------------------------------------------

function detectNestedLoops(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const loopRe = /\b(for|while)\s*\(/;
  const arrayOpRe = /\.(find|filter|some|every|includes|indexOf|map|forEach|reduce)\s*\(/;
  const reportedLines = new Set<number>();
  const maxFindings = 5;

  for (let i = 0; i < lines.length; i++) {
    if (reportedLines.size >= maxFindings) break;
    if (!loopRe.test(stripQuotedText(lines[i]))) continue;
    // Scan inner body (next ~30 lines within braces)
    let depth = 0;
    for (let j = i; j < Math.min(lines.length, i + 40); j++) {
      for (const ch of lines[j]) {
        if (ch === "{") depth++;
        if (ch === "}") depth--;
      }
      const codeLine = stripQuotedText(lines[j]);
      if (
        j > i &&
        !reportedLines.has(j) &&
        (loopRe.test(codeLine) || arrayOpRe.test(codeLine))
      ) {
        reportedLines.add(j);
        results.push(
          finding(
            file,
            j + 1,
            "warning",
            "performance",
            "Nested loop or array operation inside loop — O(n^2) potential",
            lines[j].trim(),
            "Consider using a Map/Set for lookups or restructure the algorithm",
          ),
        );
        break;
      }
      if (depth <= 0 && j > i) break;
    }
  }
}

function detectSyncFileOps(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  // Only flag sync file ops if the file has async functions (indicates async context)
  const hasAsync = lines.some((l) => /\basync\b/.test(l));
  if (!hasAsync) return; // File uses sync deliberately

  const re = /\b(readFileSync|writeFileSync|mkdirSync|readdirSync|statSync|unlinkSync|renameSync|copyFileSync)\b/;
  // Don't flag existsSync — commonly used in sync guards
  let flagCount = 0;
  for (let i = 0; i < lines.length; i++) {
    if (flagCount >= 3) break; // Cap at 3 to avoid noise
    if (re.test(lines[i]) && !lines[i].trimStart().startsWith("//")) {
      flagCount++;
      results.push(
        finding(
          file,
          i + 1,
          "suggestion",
          "performance",
          "Synchronous file operation may block the event loop",
          lines[i].trim(),
          "Use the async fs/promises API instead",
        ),
      );
    }
  }
}

function detectMissingAwait(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  // Heuristic: calling an async-named function without await, or .then(), or assigning to promise
  const asyncCallRe =
    /(?<!\bawait\s)(?<!\breturn\s)(?<!\bnew\s)\b(fetch|readFile|writeFile|mkdir|readdir)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trimStart().startsWith("//")) continue;
    const codeLine = stripQuotedText(line);
    if (asyncCallRe.test(codeLine) && !codeLine.includes(".then(") && !codeLine.includes("await")) {
      results.push(
        finding(
          file,
          i + 1,
          "warning",
          "performance",
          "Possibly missing await on async call",
          line.trim(),
          "Add await or handle the returned Promise",
        ),
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Dead code detectors
// ---------------------------------------------------------------------------

function detectUnusedImports(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  // Collect all import statements, handling multi-line imports.
  const imports: {
    startLine: number;
    endLine: number;
    names: string[];
  }[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Check if this line starts an import statement
    if (!/^\s*import\s+/.test(line)) continue;

    // Accumulate the full import statement (may span multiple lines)
    let fullStatement = line;
    let endLine = i;
    while (
      endLine < lines.length - 1 &&
      !/\bfrom\s+["'`]/.test(fullStatement)
    ) {
      endLine++;
      fullStatement += "\n" + lines[endLine];
    }

    // Skip `import type { ... } from` and `import type X from` (compile-time only)
    if (/^\s*import\s+type\s+[\w{]/.test(fullStatement)) {
      i = endLine;
      continue;
    }
    // Skip bare side-effect imports: `import "module"`
    if (/^\s*import\s+["'`]/.test(fullStatement)) {
      i = endLine;
      continue;
    }

    const names: string[] = [];

    // Extract default import: `import foo from` or `import foo, { ... } from`
    const defaultMatch = fullStatement.match(
      /import\s+(\w+)\s*(?:,|\s+from\b)/,
    );
    if (defaultMatch && defaultMatch[1] !== "type") {
      names.push(defaultMatch[1]);
    }

    // Extract named imports: `{ a, b as c, d }`
    const namedMatch = fullStatement.match(/\{([^}]+)\}/);
    if (namedMatch) {
      for (const part of namedMatch[1].split(",")) {
        const trimmed = part.trim();
        if (!trimmed) continue;
        // Skip inline `type Foo` inside `import { type Foo, bar } from "..."`
        if (/^type\s+/.test(trimmed)) continue;
        const token = trimmed.split(/\s+as\s+/);
        const local = (token[1] ?? token[0]).trim();
        if (local) names.push(local);
      }
    }

    // Extract namespace import: `import * as ns from "..."`
    const nsMatch = fullStatement.match(/import\s+\*\s+as\s+(\w+)/);
    if (nsMatch) {
      names.push(nsMatch[1]);
    }

    if (names.length > 0) {
      imports.push({ startLine: i, endLine, names });
    }

    // Advance past multi-line import
    i = endLine;
  }

  // Check each imported name for usage in the rest of the file
  for (const imp of imports) {
    const importLineSet = new Set<number>();
    for (let l = imp.startLine; l <= imp.endLine; l++) {
      importLineSet.add(l);
    }
    const rest = lines.filter((_, idx) => !importLineSet.has(idx)).join("\n");

    for (const name of imp.names) {
      if (!name) continue;
      const usage = new RegExp(`\\b${escapeRegex(name)}\\b`);
      if (!usage.test(rest)) {
        results.push(
          finding(
            file,
            imp.startLine + 1,
            "info",
            "dead_code",
            `Unused import '${name}'`,
            lines[imp.startLine].trim(),
            "Remove the unused import",
          ),
        );
      }
    }
  }
}

function detectCommentedOutCode(
  lines: string[],
  file: string,
  results: ReviewFinding[],
): void {
  const codeIndicators =
    /^\s*\/\/\s*(const|let|var|function|class|if|for|while|return|import|export|try|switch|await|async|\w+\s*\(|\w+\s*=\s*[^=])/;

  let streak = 0;
  let streakStart = 0;

  for (let i = 0; i < lines.length; i++) {
    if (codeIndicators.test(lines[i])) {
      if (streak === 0) streakStart = i;
      streak++;
    } else {
      if (streak >= 3) {
        results.push(
          finding(
            file,
            streakStart + 1,
            "info",
            "dead_code",
            `${streak} consecutive lines of commented-out code`,
            lines[streakStart].trim(),
            "Remove dead code; rely on version control for history",
            streakStart + streak,
          ),
        );
      }
      streak = 0;
    }
  }
  // Handle trailing streak
  if (streak >= 3) {
    results.push(
      finding(
        file,
        streakStart + 1,
        "info",
        "dead_code",
        `${streak} consecutive lines of commented-out code`,
        lines[streakStart].trim(),
        "Remove dead code; rely on version control for history",
        streakStart + streak,
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function stripQuotedText(line: string): string {
  let result = "";
  let quote: '"' | "'" | "`" | null = null;
  let escaped = false;

  for (const char of line) {
    if (quote !== null) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = null;
      }
      continue;
    }

    if (char === '"' || char === "'" || char === "`") {
      quote = char;
      result += '""';
    } else {
      result += char;
    }
  }

  return result;
}

function filterFindings(
  findings: ReviewFinding[],
  options: ReviewOptions,
): ReviewFinding[] {
  let filtered = findings;

  if (options.minSeverity) {
    const minLevel = SEVERITY_ORDER[options.minSeverity];
    filtered = filtered.filter((f) => SEVERITY_ORDER[f.severity] <= minLevel);
  }

  if (options.categories && options.categories.length > 0) {
    const allowed = new Set(options.categories);
    filtered = filtered.filter((f) => allowed.has(f.category));
  }

  if (options.maxFindings && options.maxFindings > 0) {
    // Keep highest severity first
    filtered.sort(
      (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
    );
    filtered = filtered.slice(0, options.maxFindings);
  }

  return filtered;
}

function computeScore(findings: ReviewFinding[]): number {
  // Diminishing penalty: each additional finding of the same severity contributes less
  const counts: Record<string, number> = {};
  let penalty = 0;
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    const n = counts[f.severity];
    // First occurrence: full penalty; subsequent: diminishing (1/sqrt(n))
    penalty += SEVERITY_PENALTY[f.severity] / Math.sqrt(n);
  }
  return Math.max(0, Math.min(100, Math.round(100 - penalty)));
}

function buildSummary(findings: ReviewFinding[], score: number): string {
  if (findings.length === 0) {
    return "No issues found. Code looks clean.";
  }

  const bySeverity: Record<string, number> = {};
  const byCategory: Record<string, number> = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
  }

  const parts: string[] = [];
  parts.push(`Found ${findings.length} issue${findings.length === 1 ? "" : "s"}`);
  parts.push(`Score: ${score}/100`);

  const severityParts: string[] = [];
  for (const sev of ["critical", "warning", "suggestion", "info"] as const) {
    if (bySeverity[sev]) {
      severityParts.push(`${bySeverity[sev]} ${sev}`);
    }
  }
  parts.push(`Breakdown: ${severityParts.join(", ")}`);

  const topCategories = Object.entries(byCategory)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([cat, n]) => `${cat}(${n})`)
    .join(", ");
  parts.push(`Top categories: ${topCategories}`);

  return parts.join(". ") + ".";
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export function reviewCode(
  code: string,
  filePath: string,
  options: ReviewOptions = {},
): ReviewResult {
  const start = performance.now();
  nextId = createIdGenerator();

  const lines = code.split("\n");
  const findings: ReviewFinding[] = [];

  // Bug patterns
  detectConsoleStatements(lines, filePath, findings);
  detectTodoComments(lines, filePath, findings);
  detectEmptyCatch(lines, filePath, findings);
  detectLooseNullCheck(lines, filePath, findings);
  detectUnreachableCode(lines, filePath, findings);

  // AI slop patterns
  detectObviousComments(lines, filePath, findings);
  detectRepeatedBoilerplate(lines, filePath, findings);
  detectUnnecessaryTypeAssertions(lines, filePath, findings);
  detectLongFunctions(lines, filePath, findings);
  detectDeepNesting(lines, filePath, findings);

  // Security patterns
  detectHardcodedSecrets(lines, filePath, findings);
  detectSqlInjection(lines, filePath, findings);
  detectEvalUsage(lines, filePath, findings);
  detectInnerHtml(lines, filePath, findings);

  // Performance patterns
  detectNestedLoops(lines, filePath, findings);
  detectSyncFileOps(lines, filePath, findings);
  detectMissingAwait(lines, filePath, findings);

  // Dead code patterns
  detectUnusedImports(lines, filePath, findings);
  detectCommentedOutCode(lines, filePath, findings);

  const filtered = filterFindings(findings, options);
  const score = computeScore(filtered);
  const summary = buildSummary(filtered, score);
  const durationMs = Math.round(performance.now() - start);

  return { findings: filtered, score, summary, durationMs };
}
