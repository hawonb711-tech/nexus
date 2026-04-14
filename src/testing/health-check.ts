import { readdir, stat, readFile } from "node:fs/promises";
import { join, relative, basename, dirname, extname } from "node:path";
import type { TestHealthReport, TestIssue } from "./types.js";

const TEST_PATTERNS = [
  /\.test\.[tj]s$/,
  /\.spec\.[tj]s$/,
  /^test_.*\.py$/,
  /.*_test\.go$/,
];

const SOURCE_EXTENSIONS = new Set([".ts", ".js", ".py", ".go", ".tsx", ".jsx"]);

const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

function isTestFile(filename: string): boolean {
  return TEST_PATTERNS.some((p) => p.test(filename));
}

function isSourceFile(filename: string): boolean {
  const ext = extname(filename);
  return SOURCE_EXTENSIONS.has(ext) && !isTestFile(filename);
}

async function walkDir(dir: string, ignore: Set<string> = new Set(["node_modules", ".git", "dist", "build", "__pycache__", ".venv"])): Promise<string[]> {
  const results: string[] = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    if (ignore.has(entry.name)) continue;
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      const sub = await walkDir(fullPath, ignore);
      results.push(...sub);
    } else if (entry.isFile()) {
      results.push(fullPath);
    }
  }
  return results;
}

function extractImports(content: string, ext: string): string[] {
  const imports: string[] = [];

  if (ext === ".ts" || ext === ".js" || ext === ".tsx" || ext === ".jsx") {
    // ES imports: import ... from "..."
    const esImportRe = /(?:import|from)\s+['"]([^'"]+)['"]/g;
    let m;
    while ((m = esImportRe.exec(content)) !== null) {
      imports.push(m[1]);
    }
    // require()
    const requireRe = /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
    while ((m = requireRe.exec(content)) !== null) {
      imports.push(m[1]);
    }
  } else if (ext === ".py") {
    const pyImportRe = /(?:from\s+(\S+)\s+import|import\s+(\S+))/g;
    let m;
    while ((m = pyImportRe.exec(content)) !== null) {
      imports.push(m[1] || m[2]);
    }
  } else if (ext === ".go") {
    const goImportRe = /import\s+(?:\(\s*([\s\S]*?)\s*\)|"([^"]+)")/g;
    let m;
    while ((m = goImportRe.exec(content)) !== null) {
      if (m[2]) {
        imports.push(m[2]);
      } else if (m[1]) {
        const blockRe = /"([^"]+)"/g;
        let bm;
        while ((bm = blockRe.exec(m[1])) !== null) {
          imports.push(bm[1]);
        }
      }
    }
  }

  return imports;
}

function extractMockedFunctions(content: string): string[] {
  const mocks: string[] = [];
  // jest.mock / vi.mock patterns
  // Require quotes around module paths to avoid matching function body contents
  const mockRe = /(?:jest|vi)\.(?:mock|spyOn)\s*\(\s*['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?\s*\)/g;
  let m;
  while ((m = mockRe.exec(content)) !== null) {
    if (m[2]) mocks.push(m[2]);
    else mocks.push(m[1]);
  }
  // mock(functionName) or .mockImplementation patterns
  const fnMockRe = /\.fn\(\)|\.mock(?:Implementation|ReturnValue|ResolvedValue)\s*\(/g;
  while (fnMockRe.exec(content) !== null) {
    // These indicate mocking but we track the module-level mocks above
  }
  return mocks;
}

function countIndividualTests(content: string, ext: string): number {
  let count = 0;
  if (ext === ".ts" || ext === ".js" || ext === ".tsx" || ext === ".jsx") {
    // Count it() and test() calls, but NOT describe() — those are suites, not tests
    const re = /(?:^|[^.\w])(?:it|test)\s*\(\s*['"`]/gm;
    while (re.exec(content) !== null) count++;
  } else if (ext === ".py") {
    const re = /def\s+test_\w+\s*\(/g;
    while (re.exec(content) !== null) count++;
  } else if (ext === ".go") {
    const re = /func\s+Test\w+\s*\(/g;
    while (re.exec(content) !== null) count++;
  }
  return count;
}

function extractTestNames(content: string): string[] {
  const names: string[] = [];
  // it("...", ...) / test("...", ...) / describe("...", ...)
  const testRe = /(?:it|test|describe)\s*\(\s*['"`]([^'"`]+)['"`]/g;
  let m;
  while ((m = testRe.exec(content)) !== null) {
    names.push(m[1]);
  }
  // def test_xxx(  (Python)
  const pyTestRe = /def\s+(test_\w+)\s*\(/g;
  while ((m = pyTestRe.exec(content)) !== null) {
    names.push(m[1]);
  }
  // func TestXxx(  (Go)
  const goTestRe = /func\s+(Test\w+)\s*\(/g;
  while ((m = goTestRe.exec(content)) !== null) {
    names.push(m[1]);
  }
  return names;
}

function extractFunctionNames(content: string, ext: string): string[] {
  const names: string[] = [];
  let re: RegExp;

  if (ext === ".ts" || ext === ".js" || ext === ".tsx" || ext === ".jsx") {
    // Match: function declarations, const/let/var assignments, and object method shorthand
    re = /(?:export\s+)?(?:async\s+)?function\s+(\w+)|(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(?|^\s+(\w+)\s*(?:<[^>]*>)?\s*\([^)]*\)\s*(?::\s*[^{]+)?\s*\{/gm;
  } else if (ext === ".py") {
    re = /def\s+(\w+)\s*\(/g;
  } else if (ext === ".go") {
    re = /func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(/g;
  } else {
    return names;
  }

  let m;
  while ((m = re.exec(content)) !== null) {
    names.push(m[1] || m[2] || m[3]);
  }
  return names.filter(Boolean);
}

function resolveImportPath(importPath: string, testFileDir: string, projectRoot: string): string | null {
  // Skip node_modules / external packages
  if (!importPath.startsWith(".") && !importPath.startsWith("/")) {
    return null;
  }

  let resolved = importPath.startsWith(".")
    ? join(testFileDir, importPath)
    : join(projectRoot, importPath);

  // Strip .js extension for TS resolution
  if (resolved.endsWith(".js")) {
    resolved = resolved.slice(0, -3);
  }

  return resolved;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function resolveSourceFile(basePath: string): Promise<string | null> {
  const candidates = [
    basePath + ".ts",
    basePath + ".js",
    basePath + ".tsx",
    basePath + ".jsx",
    basePath + "/index.ts",
    basePath + "/index.js",
    basePath,
  ];
  for (const c of candidates) {
    if (await fileExists(c)) return c;
  }
  return null;
}

function testFileToSourceFile(testFile: string): string {
  const base = basename(testFile);
  // foo.test.ts -> foo.ts
  const sourceBase = base
    .replace(/\.test\.([tj]sx?)$/, ".$1")
    .replace(/\.spec\.([tj]sx?)$/, ".$1")
    .replace(/^test_(.+)\.py$/, "$1.py")
    .replace(/(.+)_test\.go$/, "$1.go");
  return join(dirname(testFile), sourceBase);
}

export async function checkTestHealth(projectRoot: string): Promise<TestHealthReport> {
  const startTime = Date.now();
  const allFiles = await walkDir(projectRoot);

  const testFiles: string[] = [];
  const sourceFiles: string[] = [];

  for (const f of allFiles) {
    const name = basename(f);
    if (isTestFile(name)) {
      testFiles.push(f);
    } else if (isSourceFile(name)) {
      sourceFiles.push(f);
    }
  }

  const issues: TestIssue[] = [];
  const staleMocks: string[] = [];
  const now = Date.now();

  // Build a map of source file -> exported function names
  const sourceFunctionMap = new Map<string, string[]>();
  for (const sf of sourceFiles) {
    try {
      const content = await readFile(sf, "utf-8");
      const ext = extname(sf);
      sourceFunctionMap.set(sf, extractFunctionNames(content, ext));
    } catch {
      // Skip unreadable files
    }
  }

  // Analyze each test file
  for (const tf of testFiles) {
    let content: string;
    try {
      content = await readFile(tf, "utf-8");
    } catch {
      continue;
    }

    const ext = extname(tf);
    const testDir = dirname(tf);
    const imports = extractImports(content, ext);
    const mocks = extractMockedFunctions(content);
    const testNames = extractTestNames(content);

    // Check imports still resolve
    for (const imp of imports) {
      const resolved = resolveImportPath(imp, testDir, projectRoot);
      if (resolved === null) continue; // external package

      const sourceFile = await resolveSourceFile(resolved);
      if (!sourceFile) {
        issues.push({
          testFile: relative(projectRoot, tf),
          testName: "",
          issue: "broken_import",
          message: `Import "${imp}" does not resolve to any existing file`,
          suggestion: `Check if the source file was moved or renamed. Original import: "${imp}"`,
          sourceFile: imp,
        });
      }
    }

    // Check if mocked functions still exist in source
    for (const mock of mocks) {
      const resolved = resolveImportPath(mock, testDir, projectRoot);
      if (resolved === null) continue;

      const sourceFile = await resolveSourceFile(resolved);
      if (sourceFile) {
        const fns = sourceFunctionMap.get(sourceFile);
        if (fns && !fns.some((fn) => mock.includes(fn))) {
          staleMocks.push(`${relative(projectRoot, tf)}: mock("${mock}")`);
          issues.push({
            testFile: relative(projectRoot, tf),
            testName: "",
            issue: "stale_mock",
            message: `Mock target "${mock}" may no longer exist in source`,
            suggestion: `Verify the mocked module/function still exists or update the mock`,
            sourceFile: relative(projectRoot, sourceFile),
          });
        }
      }
    }

    // Check if test names reference functions that exist in the corresponding source
    const expectedSourcePath = testFileToSourceFile(tf);
    const correspondingSource = await resolveSourceFile(
      expectedSourcePath.replace(/\.[^.]+$/, "")
    );
    if (correspondingSource) {
      const sourceFns = sourceFunctionMap.get(correspondingSource) ?? [];
      for (const testName of testNames) {
        // Check if test name references a function name that no longer exists
        const referencedFn = sourceFns.length > 0
          ? sourceFns.find((fn) => testName.toLowerCase().includes(fn.toLowerCase()))
          : undefined;

        // If the test name looks like it references a specific function but it's gone
        if (!referencedFn) {
          const wordPattern = /\b([a-zA-Z_]\w+)\b/g;
          let word;
          while ((word = wordPattern.exec(testName)) !== null) {
            const w = word[1];
            // Skip common test description words
            if (["should", "when", "then", "it", "the", "is", "returns", "throws", "handles", "test", "with", "not", "and", "or", "for", "a", "an"].includes(w.toLowerCase())) continue;
            // Check if this word could be a deleted function
            if (w.length > 3 && w[0] === w[0].toLowerCase()) {
              // Only flag if there were source functions and this looks like a function reference
              // that doesn't match any current function
              if (sourceFns.length > 0 && !sourceFns.some((fn) => fn.toLowerCase() === w.toLowerCase())) {
                // Heuristic: only flag if it looks like camelCase or snake_case
                if (/[A-Z]/.test(w) || w.includes("_")) {
                  issues.push({
                    testFile: relative(projectRoot, tf),
                    testName: testName,
                    issue: "missing_function",
                    message: `Test "${testName}" may reference function "${w}" which is not found in ${relative(projectRoot, correspondingSource)}`,
                    suggestion: `Check if "${w}" was renamed. Current functions: ${sourceFns.join(", ")}`,
                    sourceFile: relative(projectRoot, correspondingSource),
                  });
                  break; // One issue per test name
                }
              }
            }
          }
        }
      }
    }

    // Check staleness: test not updated in 90+ days while source was
    try {
      const testStat = await stat(tf);
      if (correspondingSource) {
        const srcStat = await stat(correspondingSource);
        const testAge = now - testStat.mtimeMs;
        if (testAge > NINETY_DAYS_MS && srcStat.mtimeMs > testStat.mtimeMs) {
          issues.push({
            testFile: relative(projectRoot, tf),
            testName: "",
            issue: "outdated_snapshot",
            message: `Test file not updated in ${Math.floor(testAge / (24 * 60 * 60 * 1000))} days, but source was modified more recently`,
            suggestion: `Review and update tests to match current source behavior`,
            sourceFile: relative(projectRoot, correspondingSource),
          });
        }
      }
    } catch {
      // Skip stat errors
    }
  }

  // Find source files without corresponding tests
  const testFileSourcePaths = new Set<string>();
  for (const tf of testFiles) {
    const expected = testFileToSourceFile(tf);
    const resolved = await resolveSourceFile(expected.replace(/\.[^.]+$/, ""));
    if (resolved) testFileSourcePaths.add(resolved);
  }

  const missingTests: string[] = [];
  for (const sf of sourceFiles) {
    const name = basename(sf);
    // Skip index files and type definition files
    if (name === "index.ts" || name === "index.js" || name.endsWith(".d.ts")) continue;
    if (!testFileSourcePaths.has(sf)) {
      missingTests.push(relative(projectRoot, sf));
    }
  }

  const totalSourceFiles = sourceFiles.filter(
    (f) => !basename(f).startsWith("index.") && !basename(f).endsWith(".d.ts")
  ).length;
  const coverageEstimate = totalSourceFiles > 0
    ? Math.round((testFileSourcePaths.size / totalSourceFiles) * 100)
    : 0;

  return {
    totalTests: testFiles.length,
    issues,
    coverageEstimate: Math.min(coverageEstimate, 100),
    staleMocks,
    missingTests,
    durationMs: Date.now() - startTime,
  };
}
