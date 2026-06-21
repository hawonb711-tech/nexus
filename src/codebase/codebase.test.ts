import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { mapCodebase } from "./mapper.js";

/**
 * Builds a small temp project under a `src/` subdir:
 *   src/a.ts -> imports b.js (resolves to src/b.ts) and c.js (-> src/c.ts)
 *   src/b.ts -> imports c.js (resolves to src/c.ts)
 *   src/c.ts -> imports nothing local
 * So: a is an entry point (never imported); c has 2 incoming edges (top hotspot).
 * (Top-level files resolve relative imports too — see the dedicated test below.)
 */
function makeFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), "nexus-codebase-"));
  mkdirSync(join(dir, "src"));
  writeFileSync(
    join(dir, "src", "a.ts"),
    [
      `import { b } from "./b.js";`,
      `import { c } from "./c.js";`,
      `export function aFn() { return b() + c(); }`,
    ].join("\n")
  );
  writeFileSync(
    join(dir, "src", "b.ts"),
    [
      `import { c } from "./c.js";`,
      `export const b = () => c();`,
      `export class BClass {}`,
    ].join("\n")
  );
  writeFileSync(
    join(dir, "src", "c.ts"),
    [`export function c() { return 42; }`].join("\n")
  );
  return dir;
}

test("top-level (flat-repo) files resolve relative imports", async () => {
  const dir = mkdtempSync(join(tmpdir(), "nexus-flat-"));
  try {
    writeFileSync(join(dir, "main.ts"), `import { h } from "./helper.js";\nexport const x = h();`);
    writeFileSync(join(dir, "helper.ts"), `export const h = () => 1;`);
    const map = await mapCodebase({ root: dir });
    assert.ok(map.dependencies.some((e) => e.from === "main.ts" && e.to === "helper.ts"),
      "top-level main.ts should have a resolved edge to helper.ts");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("totalFiles counts the three source files and root is resolved absolute", async () => {
  const dir = makeFixture();
  try {
    const map = await mapCodebase({ root: dir });
    assert.equal(map.totalFiles, 3);
    assert.equal(map.files.length, 3);
    assert.equal(map.root, resolve(dir));
    assert.equal(typeof map.generatedAt, "string");
    assert.ok(!Number.isNaN(Date.parse(map.generatedAt)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("languages tallies TypeScript files by count", async () => {
  const dir = makeFixture();
  try {
    const map = await mapCodebase({ root: dir });
    assert.deepEqual(map.languages, { TypeScript: 3 });
    // totalLines is summed across all files and must be positive.
    assert.ok(map.totalLines > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("dependencies resolve .js ESM specifiers to the local .ts files", async () => {
  const dir = makeFixture();
  try {
    const map = await mapCodebase({ root: dir });
    // Every edge points between known relative file paths with an import type.
    const paths = new Set(map.files.map((f) => f.path));
    for (const edge of map.dependencies) {
      assert.ok(paths.has(edge.from), `from exists: ${edge.from}`);
      assert.ok(paths.has(edge.to), `to exists: ${edge.to}`);
      assert.equal(edge.type, "import");
    }
    const keys = map.dependencies.map((e) => `${e.from}->${e.to}`);
    assert.ok(keys.includes("src/a.ts->src/b.ts"));
    assert.ok(keys.includes("src/a.ts->src/c.ts"));
    assert.ok(keys.includes("src/b.ts->src/c.ts"));
    assert.equal(map.dependencies.length, 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("entryPoints contains files that are never imported", async () => {
  const dir = makeFixture();
  try {
    const map = await mapCodebase({ root: dir });
    // a.ts is imported by nobody -> entry point. b.ts and c.ts are imported.
    assert.deepEqual(map.entryPoints, ["src/a.ts"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("hotspots rank most-imported files first", async () => {
  const dir = makeFixture();
  try {
    const map = await mapCodebase({ root: dir });
    // c.ts has 2 incoming edges (from a and b); b.ts has 1.
    assert.equal(map.hotspots[0], "src/c.ts");
    assert.ok(map.hotspots.includes("src/b.ts"));
    assert.ok(!map.hotspots.includes("src/a.ts"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("per-file nodes capture exports, functions and classes", async () => {
  const dir = makeFixture();
  try {
    const map = await mapCodebase({ root: dir });
    const byPath = new Map(map.files.map((f) => [f.path, f]));
    const a = byPath.get("src/a.ts")!;
    assert.equal(a.type, "file");
    assert.equal(a.language, "TypeScript");
    assert.ok(a.exports.includes("aFn"));
    assert.ok(a.functions.includes("aFn"));
    assert.deepEqual([...a.imports].sort(), ["./b.js", "./c.js"]);

    const b = byPath.get("src/b.ts")!;
    assert.ok(b.classes.includes("BClass"));
    assert.ok(b.exports.includes("b"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ignored directories and external imports are excluded", async () => {
  const dir = makeFixture();
  try {
    // node_modules is in DEFAULT_IGNORE; its files must not be walked.
    mkdirSync(join(dir, "node_modules"));
    writeFileSync(join(dir, "node_modules", "dep.ts"), `export const x = 1;`);
    // d.ts imports an external package (no leading "." or "/") -> no edge.
    writeFileSync(
      join(dir, "src", "d.ts"),
      `import fs from "node:fs";\nexport const d = fs;`
    );
    const map = await mapCodebase({ root: dir });
    assert.equal(map.totalFiles, 4); // a, b, c, d (node_modules skipped)
    assert.ok(!map.files.some((f) => f.path.includes("node_modules")));
    // External import yields no dependency edge from d.ts.
    assert.ok(!map.dependencies.some((e) => e.from === "src/d.ts"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
