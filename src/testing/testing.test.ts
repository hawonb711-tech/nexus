import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkTestHealth } from "./health-check.js";
import { suggestFixes } from "./test-fixer.js";
import type { TestIssue } from "./types.js";

/**
 * Build a self-contained temp project on disk and hand it to `fn`.
 * `files` maps relative paths to file contents.
 */
async function withProject(
  files: Record<string, string>,
  fn: (root: string) => Promise<void> | void,
): Promise<void> {
  const root = mkdtempSync(join(tmpdir(), "nexus-testing-"));
  try {
    for (const [rel, content] of Object.entries(files)) {
      writeFileSync(join(root, rel), content);
    }
    // Must await so the temp dir is not removed while checkTestHealth is
    // still asynchronously reading files inside it.
    await fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("checkTestHealth returns a well-formed TestHealthReport", async () => {
  await withProject(
    {
      "math.ts": `export function add(a: number, b: number) { return a + b; }\n`,
      "math.test.ts": `import { add } from "./math.js";\nit("add sums two numbers", () => add(1, 2));\n`,
    },
    async (root) => {
      const report = await checkTestHealth(root);

      // Exact shape of TestHealthReport.
      assert.equal(typeof report.totalTests, "number");
      assert.ok(Array.isArray(report.issues));
      assert.equal(typeof report.coverageEstimate, "number");
      assert.ok(Array.isArray(report.staleMocks));
      assert.ok(Array.isArray(report.missingTests));
      assert.equal(typeof report.durationMs, "number");

      // One test file with one `it()` call.
      assert.equal(report.totalTests, 1);
      assert.ok(report.coverageEstimate >= 0 && report.coverageEstimate <= 100);
      assert.ok(report.durationMs >= 0);
    },
  );
});

test("a healthy test file with resolvable imports produces no issues", async () => {
  await withProject(
    {
      "math.ts": `export function add(a: number, b: number) { return a + b; }\n`,
      "math.test.ts": `import { add } from "./math.js";\nit("add sums two numbers", () => add(1, 2));\n`,
    },
    async (root) => {
      const report = await checkTestHealth(root);

      assert.deepEqual(report.issues, []);
      assert.deepEqual(report.staleMocks, []);
      // math.ts has a matching test, so it must not be flagged as missing.
      assert.deepEqual(report.missingTests, []);
      // Single covered source file => 100% estimate.
      assert.equal(report.coverageEstimate, 100);
    },
  );
});

test("embedded fixture imports are not treated as test-file imports", async () => {
  await withProject(
    {
      "parser.ts": `export function parse(value: string) { return value; }\n`,
      "parser.test.ts":
        `import { parse } from "./parser.js";\n` +
        `const fixture = \`import { missing } from "./missing.js";\`;\n` +
        `it("parses fixture source", () => parse(fixture));\n`,
    },
    async (root) => {
      const report = await checkTestHealth(root);
      assert.deepEqual(
        report.issues.filter((issue) => issue.issue === "broken_import"),
        [],
      );
    },
  );
});

test("totalTests counts individual tests rather than test files", async () => {
  await withProject(
    {
      "math.ts": `export function add(a: number, b: number) { return a + b; }\n`,
      "math.test.ts":
        `import { add } from "./math.js";\n` +
        `it("adds", () => add(1, 2));\n` +
        `test("adds again", () => add(2, 3));\n`,
    },
    async (root) => {
      const report = await checkTestHealth(root);
      assert.equal(report.totalTests, 2);
    },
  );
});

test("a source imported by a differently named test counts as tested", async () => {
  await withProject(
    {
      "helper.ts": `export function helper() { return 1; }\n`,
      "feature.test.ts":
        `import { helper } from "./helper.js";\n` +
        `it("uses the helper", () => helper());\n`,
    },
    async (root) => {
      const report = await checkTestHealth(root);
      assert.ok(!report.missingTests.includes("helper.ts"));
      assert.equal(report.coverageEstimate, 100);
    },
  );
});

test("an unresolvable relative import is detected as broken_import", async () => {
  await withProject(
    {
      // Test imports a module that does not exist on disk.
      "orphan.test.ts": `import { gone } from "./gone.js";\nit("gone works", () => gone());\n`,
    },
    async (root) => {
      const report = await checkTestHealth(root);

      const broken = report.issues.filter((i) => i.issue === "broken_import");
      assert.equal(broken.length, 1);
      assert.equal(broken[0].testFile, "orphan.test.ts");
      assert.equal(broken[0].sourceFile, "./gone.js");
      assert.match(broken[0].message, /does not resolve/);
      assert.ok(broken[0].suggestion.length > 0);
    },
  );
});

test("a mock of a relative module is reported as stale_mock", async () => {
  await withProject(
    {
      // Source file the mock points at; its exported function name is `compute`.
      "helpers.ts": `export function compute(a: number, b: number) { return a + b; }\n`,
      // jest.mock("./helpers.js") resolves to helpers.ts, but the mock-target
      // string does not literally contain the function name => flagged stale.
      "main.test.ts":
        `import { compute } from "./helpers.js";\n` +
        `jest.mock("./helpers.js");\n` +
        `it("compute works", () => compute(1, 2));\n`,
    },
    async (root) => {
      const report = await checkTestHealth(root);

      const stale = report.issues.filter((i) => i.issue === "stale_mock");
      assert.equal(stale.length, 1);
      assert.equal(stale[0].testFile, "main.test.ts");
      assert.equal(stale[0].sourceFile, "helpers.ts");
      assert.match(stale[0].message, /no longer exist/);

      // staleMocks array mirrors the issue and names the mock target.
      assert.equal(report.staleMocks.length, 1);
      assert.match(report.staleMocks[0], /main\.test\.ts: mock\("\.\/helpers\.js"\)/);
    },
  );
});

test("source files without a corresponding test land in missingTests", async () => {
  await withProject(
    {
      "covered.ts": `export function f() { return 1; }\n`,
      "covered.test.ts": `import { f } from "./covered.js";\nit("f", () => f());\n`,
      // No test for uncovered.ts (and it is not an index/.d.ts file).
      "uncovered.ts": `export function g() { return 2; }\n`,
    },
    async (root) => {
      const report = await checkTestHealth(root);

      assert.ok(report.missingTests.includes("uncovered.ts"));
      assert.ok(!report.missingTests.includes("covered.ts"));
      // One of two source files covered => 50%.
      assert.equal(report.coverageEstimate, 50);
    },
  );
});

test("suggestFixes turns issues into human-readable, prefixed strings", () => {
  const issues: TestIssue[] = [
    {
      testFile: "a.test.ts",
      testName: "",
      issue: "broken_import",
      message: `Import "./gone.js" does not resolve to any existing file`,
      suggestion: `Check if the source file was moved or renamed.`,
      sourceFile: "./gone.js",
    },
    {
      testFile: "b.test.ts",
      testName: "",
      issue: "stale_mock",
      message: `Mock target "removedHelper" may no longer exist in source`,
      suggestion: `Verify the mocked module/function still exists or update the mock`,
      sourceFile: "b.ts",
    },
  ];

  const fixes = suggestFixes(issues);

  assert.equal(fixes.length, 2);
  // Each suggestion is prefixed with the originating test file.
  assert.ok(fixes[0].startsWith("[a.test.ts]"));
  assert.match(fixes[0], /Broken import/);
  assert.ok(fixes[1].startsWith("[b.test.ts]"));
  assert.match(fixes[1], /Stale mock/);
});
