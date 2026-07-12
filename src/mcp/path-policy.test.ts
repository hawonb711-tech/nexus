import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, parse } from "node:path";
import { describe, it } from "node:test";
import { createPathValidator, isWithinRoot } from "./path-policy.js";

const canonical = (path: string): string => (realpathSync.native ?? realpathSync)(path);

describe("MCP path policy", () => {
  it("accepts descendants but rejects prefix siblings", () => {
    const base = mkdtempSync(join(tmpdir(), "nexus-path-"));
    const root = join(base, "repo");
    const sibling = join(base, "repo-secret");
    mkdirSync(root);
    mkdirSync(sibling);
    const inside = join(root, "inside.txt");
    const outside = join(sibling, "outside.txt");
    writeFileSync(inside, "inside");
    writeFileSync(outside, "outside");

    try {
      const validate = createPathValidator({ cwd: root, home: join(base, "home"), env: {} });
      assert.equal(validate(inside), canonical(inside));
      assert.throws(() => validate(outside), /outside allowed roots/i);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });

  it("rejects a symlink that escapes an allowed root", () => {
    const base = mkdtempSync(join(tmpdir(), "nexus-symlink-"));
    const root = join(base, "repo");
    const outside = join(base, "outside");
    mkdirSync(root);
    mkdirSync(outside);
    writeFileSync(join(outside, "secret.txt"), "secret");
    const link = join(root, "escape");

    try {
      symlinkSync(outside, link, process.platform === "win32" ? "junction" : "dir");
      const validate = createPathValidator({ cwd: root, home: join(base, "home"), env: {} });
      assert.throws(() => validate(join(link, "secret.txt")), /outside allowed roots/i);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });

  it("accepts only explicitly configured extra roots", () => {
    const base = mkdtempSync(join(tmpdir(), "nexus-extra-"));
    const cwd = join(base, "repo");
    const extraA = join(base, "extra-a");
    const extraB = join(base, "extra-b");
    mkdirSync(cwd);
    mkdirSync(extraA);
    mkdirSync(extraB);
    const fileA = join(extraA, "a.txt");
    const fileB = join(extraB, "b.txt");
    writeFileSync(fileA, "a");
    writeFileSync(fileB, "b");

    try {
      const validate = createPathValidator({
        cwd,
        home: join(base, "home"),
        env: { NEXUS_ALLOWED_ROOTS: `${extraA}${delimiter}${extraB}` },
      });
      assert.equal(validate(fileA), canonical(fileA));
      assert.equal(validate(fileB), canonical(fileB));
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });

  it("keeps AI session roots out of the general file capability", () => {
    const base = mkdtempSync(join(tmpdir(), "nexus-capability-"));
    const cwd = join(base, "repo");
    const home = join(base, "home");
    const sessionRoot = join(home, ".claude");
    mkdirSync(cwd, { recursive: true });
    mkdirSync(sessionRoot, { recursive: true });
    const settings = join(sessionRoot, "settings.json");
    writeFileSync(settings, "secret");

    try {
      const validateFile = createPathValidator({ cwd, home, env: {} });
      const validateSession = createPathValidator({
        cwd,
        home,
        env: {},
        includeCwd: false,
        includeSessionRoots: true,
      });

      assert.throws(() => validateFile(settings), /outside allowed roots/i);
      assert.equal(validateSession(settings), canonical(settings));
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });

  it("does not treat a filesystem-root cwd as an implicit allow-all", () => {
    const filesystemRoot = parse(process.cwd()).root;
    const validate = createPathValidator({ cwd: filesystemRoot, home: join(filesystemRoot, "missing-home"), env: {} });
    assert.throws(() => validate(process.execPath), /outside allowed roots/i);
  });

  it("uses path-component containment rather than string prefixes", () => {
    assert.equal(isWithinRoot(join("a", "repo"), join("a", "repo", "src")), true);
    assert.equal(isWithinRoot(join("a", "repo"), join("a", "repo-secret")), false);
  });
});
