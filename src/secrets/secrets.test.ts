import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { redactSecret, redactSecretsInText, scanForSecrets } from "./scanner.js";

test("redactSecret never reveals the full secret", () => {
  const r = redactSecret("AKIAABCD1234EFGH5678");
  assert.ok(!r.includes("ABCD1234EFGH"));
  assert.ok(r.startsWith("AKIA"));
  assert.ok(r.includes("*"));
  // short secrets are mostly masked
  assert.ok(!redactSecret("abcd").includes("bcd"));
});

test("placeholder detection stays bounded on repeated opening brackets", () => {
  const input = "<".repeat(250_000);
  const result = redactSecretsInText(input);
  assert.equal(result.count, 0);
  assert.equal(result.text, input);
});

function fixture(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "nexus-sec-"));
  for (const [name, content] of Object.entries(files)) {
    const p = join(dir, name);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, content);
  }
  return dir;
}

test("detects vendor secrets in the working tree, never leaking the raw value", async () => {
  const awsKey = "AKIA" + "7F3K9Q2M8R4V6X1Z";
  const githubToken =
    "ghp_" + "Z7mQ2vN9pR4xT8cK6wH3yB5sD1fG0jL2aE4u".slice(0, 36);
  const dir = fixture({
    ".env": `AWS_ACCESS_KEY_ID=${awsKey}\nGITHUB_TOKEN=${githubToken}\n`,
  });
  try {
    const res = await scanForSecrets(dir);
    const rules = res.findings.map((f) => f.rule);
    assert.ok(rules.includes("AWS access key ID"));
    assert.ok(rules.includes("GitHub personal access token"));
    const blob = JSON.stringify(res);
    assert.ok(!blob.includes(awsKey));
    assert.ok(!blob.includes(githubToken));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ignores placeholders and env references", async () => {
  const dir = fixture({
    "config.js": [
      'const a = "your_api_key_here";',
      "const b = process.env.SECRET;",
      'const c = "${MY_TOKEN}";',
      'const d = "xxxxxxxxxxxxxxxx";',
      'const e = "sk-1234567890abcdef1234567890abcdef";',
      'const f = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";',
      'const g = "AKIAABCD1234EFGH5678";',
    ].join("\n"),
  });
  try {
    const res = await scanForSecrets(dir);
    assert.equal(res.findings.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("generic api-key value-shape guard rejects paths/URLs", async () => {
  const credentialLikeValue = ["aB3dE6gH9jK2mN5p", "Q8rT1vWx"].join("");
  const dir = fixture({
    "fp.js": 'const apiKey = "prod/database/connection/string/v2";',
    "tp.js": `const apiKey = "${credentialLikeValue}";`,
  });
  try {
    const res = await scanForSecrets(dir);
    const files = res.findings.map((f) => f.file);
    assert.ok(!files.some((f) => f.includes("fp.js"))); // path-like value suppressed
    assert.ok(files.some((f) => f.includes("tp.js")));  // real-looking key kept
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("reports history as unavailable for a non-git directory", async () => {
  const dir = fixture({ "a.txt": "hello world this is fine" });
  try {
    const res = await scanForSecrets(dir, { includeHistory: true });
    assert.ok(res.truncated.historyUnavailable);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
