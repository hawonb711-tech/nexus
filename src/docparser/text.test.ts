import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extractPlainText } from "./text.js";
import { redactSecretsInText } from "../secrets/scanner.js";

function withMarkdown(content: string, run: (filePath: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "nexus-md-"));
  const filePath = join(dir, "doc.md");
  writeFileSync(filePath, content);
  try {
    run(filePath);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// #4: markdown emphasis stripping must not mangle secret-shaped tokens, so the
// downstream redactor can still recognise them.
test("preserves underscore-bearing tokens so they stay redactable", () => {
  const ghp = ["ghp_", "abcdefghijklmnopqrstuvwxyz1234567890"].join(""); // ghp_ + 36
  const finegrained = ["github_pat_", "A".repeat(82)].join("");
  withMarkdown(`Token ${ghp} and fine-grained ${finegrained} were leaked.`, (file) => {
    const stripped = extractPlainText(file, true);
    assert.ok(stripped.includes(ghp), "ghp_ token should survive markdown stripping intact");
    assert.ok(stripped.includes(finegrained), "github_pat_ token should survive intact");

    // And once preserved, the secret scanner masks them.
    const redacted = redactSecretsInText(stripped);
    assert.ok(!redacted.text.includes(ghp));
    assert.ok(!redacted.text.includes(finegrained));
    assert.ok(redacted.count >= 2);
  });
});

test("still strips real markdown emphasis at word boundaries", () => {
  withMarkdown("This is _italic_ and __bold__ and ***strong*** text here.", (file) => {
    const stripped = extractPlainText(file, true);
    assert.ok(!stripped.includes("_italic_"));
    assert.ok(!stripped.includes("__bold__"));
    assert.ok(stripped.includes("italic"));
    assert.ok(stripped.includes("bold"));
    assert.ok(stripped.includes("strong"));
  });
});

test("leaves intra-word underscores (identifiers) intact", () => {
  withMarkdown("The variable user_id_value maps to the column user_id in the table.", (file) => {
    const stripped = extractPlainText(file, true);
    assert.ok(stripped.includes("user_id_value"));
    assert.ok(stripped.includes("user_id"));
  });
});
