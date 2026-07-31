import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, parse } from "node:path";
import { describe, it } from "node:test";
import { backupGeneratedVaultFolders } from "./reorganize.js";

describe("safe vault reorganization", () => {
  it("backs up only generated folders under the selected vault", () => {
    const root = mkdtempSync(join(tmpdir(), "nexus-reorganize-"));
    try {
      const selected = join(root, "selected");
      const other = join(root, "other");
      mkdirSync(join(selected, "Sessions"), { recursive: true });
      mkdirSync(join(selected, "User Notes"), { recursive: true });
      mkdirSync(join(other, "Sessions"), { recursive: true });
      writeFileSync(join(selected, "Sessions", "generated.md"), "generated");
      writeFileSync(join(selected, "User Notes", "keep.md"), "keep");
      writeFileSync(join(other, "Sessions", "keep.md"), "other");

      const result = backupGeneratedVaultFolders(selected);

      assert.ok(result.backupRoot);
      assert.equal(existsSync(join(selected, "Sessions")), false);
      assert.equal(
        readFileSync(join(result.backupRoot!, "Sessions", "generated.md"), "utf8"),
        "generated",
      );
      assert.equal(readFileSync(join(selected, "User Notes", "keep.md"), "utf8"), "keep");
      assert.equal(readFileSync(join(other, "Sessions", "keep.md"), "utf8"), "other");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("refuses a filesystem root", () => {
    assert.throws(
      () => backupGeneratedVaultFolders(parse(process.cwd()).root),
      /Refusing to reorganize a filesystem root/,
    );
  });
});
