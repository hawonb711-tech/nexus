import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validateConfig } from "./validator.js";

function makeProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "nexus-config-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

test("returns a ConfigReport with the documented shape", async () => {
  const dir = makeProject({
    ".env": "SAFE_VAR=hello\n",
    "package.json": JSON.stringify({ name: "demo" }),
  });
  try {
    const report = await validateConfig(dir);
    assert.ok(Array.isArray(report.files), "files is an array");
    assert.ok(Array.isArray(report.issues), "issues is an array");
    assert.equal(typeof report.envVarCount, "number");
    // Only the three documented keys exist on the report.
    assert.deepEqual(Object.keys(report).sort(), ["envVarCount", "files", "issues"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("discovers the .env file and counts every env var", async () => {
  const dir = makeProject({
    ".env": "SAFE_VAR=hello\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
  });
  try {
    const report = await validateConfig(dir);
    assert.ok(report.files.includes(".env"), "files lists the .env (relative path)");
    assert.equal(report.envVarCount, 2, "both env entries are counted");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("flags an exposed secret in an un-gitignored .env as a critical issue", async () => {
  const dir = makeProject({
    ".env": "SAFE_VAR=hello\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
  });
  try {
    const report = await validateConfig(dir);
    const secretIssue = report.issues.find(
      (i) => i.severity === "critical" && i.issue === "insecure"
    );
    assert.ok(secretIssue, "an exposed secret produces a critical insecure issue");
    assert.equal(secretIssue!.file, ".env");
    assert.match(secretIssue!.message, /not in \.gitignore/);
    assert.equal(typeof secretIssue!.suggestion, "string");
    // Every issue conforms to the ConfigIssue union shape.
    for (const issue of report.issues) {
      assert.equal(typeof issue.file, "string");
      assert.equal(typeof issue.key, "string");
      assert.ok(
        ["missing", "mismatch", "deprecated", "insecure", "duplicate"].includes(issue.issue)
      );
      assert.ok(["critical", "warning", "info"].includes(issue.severity));
      assert.equal(typeof issue.message, "string");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("does not raise the un-gitignored secret issue when the .env is gitignored", async () => {
  const dir = makeProject({
    ".env": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    ".gitignore": ".env\n",
  });
  try {
    const report = await validateConfig(dir);
    const exposed = report.issues.find(
      (i) => i.severity === "critical" && /not in \.gitignore/.test(i.message)
    );
    assert.equal(exposed, undefined, "gitignored .env should not be flagged as exposed");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("flags an insecure value (DISABLE_AUTH=true) as a warning-level insecure issue", async () => {
  const dir = makeProject({
    ".env": "DISABLE_AUTH=true\n",
  });
  try {
    const report = await validateConfig(dir);
    const authIssue = report.issues.find(
      (i) => i.key === "DISABLE_AUTH" && i.issue === "insecure"
    );
    assert.ok(authIssue, "DISABLE_AUTH=true is reported");
    assert.equal(authIssue!.severity, "warning");
    assert.match(authIssue!.message, /Authentication is disabled/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("reports a clean project with no .env as having no files, issues, or env vars", async () => {
  const dir = makeProject({
    "package.json": JSON.stringify({ name: "demo" }),
    "README.md": "# demo\n",
  });
  try {
    const report = await validateConfig(dir);
    assert.equal(report.envVarCount, 0);
    assert.deepEqual(report.issues, []);
    assert.deepEqual(report.files, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
