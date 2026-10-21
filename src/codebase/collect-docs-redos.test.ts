import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mapCodebase } from "./mapper.js";

/**
 * Five of the mapper's statement scans (Go `import (…)`, Rust `use …;`, Java
 * `import …;`, JS `export {…}`, Python `__all__ = […]`) re-scanned the rest of
 * the file from every unterminated head, so `nexus_map` on such a file was
 * quadratic. They now continue only from the first head before each terminator
 * and must keep exactly the old results: the old extractors are kept below,
 * verbatim, as the oracle and compared on structured fuzz through mapCodebase.
 */

type ImportEntry = { path: string; type: "import" | "require" };

function oldExtractImportsWithType(content: string, language: string | undefined): ImportEntry[] {
  const imports: ImportEntry[] = [];
  if (!language) return imports;
  switch (language) {
    case "TypeScript":
    case "JavaScript": {
      const esImports = content.matchAll(/import\s+.*?\s+from\s+["']([^"']+)["']/g);
      for (const m of esImports) imports.push({ path: m[1], type: "import" });
      const sideEffects = content.matchAll(/import\s+["']([^"']+)["']/g);
      for (const m of sideEffects) imports.push({ path: m[1], type: "import" });
      const requires = content.matchAll(/require\s*\(\s*["']([^"']+)["']\s*\)/g);
      for (const m of requires) imports.push({ path: m[1], type: "require" });
      const reExports = content.matchAll(/export\s+.*?\s+from\s+["']([^"']+)["']/g);
      for (const m of reExports) imports.push({ path: m[1], type: "import" });
      break;
    }
    case "Python": {
      const fromImports = content.matchAll(/from\s+(\S+)\s+import/g);
      for (const m of fromImports) imports.push({ path: m[1], type: "import" });
      const directImports = content.matchAll(/^import\s+(\S+)/gm);
      for (const m of directImports) imports.push({ path: m[1], type: "import" });
      break;
    }
    case "Go": {
      const singleImport = content.matchAll(/import\s+"([^"]+)"/g);
      for (const m of singleImport) imports.push({ path: m[1], type: "import" });
      const blockImport = content.matchAll(/import\s*\(([\s\S]*?)\)/g);
      for (const m of blockImport) {
        const pkgs = m[1].matchAll(/"([^"]+)"/g);
        for (const p of pkgs) imports.push({ path: p[1], type: "import" });
      }
      break;
    }
    case "Rust": {
      const useStmts = content.matchAll(/use\s+([^;]+);/g);
      for (const m of useStmts) imports.push({ path: m[1].trim(), type: "import" });
      break;
    }
    case "Java":
    case "Kotlin": {
      const javaImports = content.matchAll(/import\s+(?:static\s+)?([^;]+);/g);
      for (const m of javaImports) imports.push({ path: m[1].trim(), type: "import" });
      break;
    }
  }
  return imports;
}

function oldExtractExports(content: string, language: string | undefined): string[] {
  const exports: string[] = [];
  if (!language) return exports;
  switch (language) {
    case "TypeScript":
    case "JavaScript": {
      const namedExports = content.matchAll(
        /export\s+(?:default\s+)?(?:function|const|let|var|class|type|interface|enum|abstract\s+class)\s+(\w+)/g
      );
      for (const m of namedExports) exports.push(m[1]);
      const braceExports = content.matchAll(/export\s*\{([^}]+)\}/g);
      for (const m of braceExports) {
        const names = m[1].split(",").map((s) => s.trim().split(/\s+as\s+/).pop()!.trim());
        exports.push(...names.filter(Boolean));
      }
      if (/export\s+default\s/.test(content) && !exports.includes("default")) {
        exports.push("default");
      }
      if (/module\.exports\s*=/.test(content)) {
        exports.push("module.exports");
      }
      break;
    }
    case "Python": {
      const allMatch = content.match(/__all__\s*=\s*\[([^\]]+)\]/);
      if (allMatch) {
        const names = allMatch[1].matchAll(/["'](\w+)["']/g);
        for (const n of names) exports.push(n[1]);
      }
      break;
    }
    case "Rust": {
      const pubItems = content.matchAll(/pub\s+(?:fn|struct|enum|trait|type|const|static|mod)\s+(\w+)/g);
      for (const m of pubItems) exports.push(m[1]);
      break;
    }
    case "Go": {
      const funcs = content.matchAll(/func\s+(?:\([^)]*\)\s+)?([A-Z]\w*)\s*\(/g);
      for (const m of funcs) exports.push(m[1]);
      const types = content.matchAll(/type\s+([A-Z]\w*)\s+/g);
      for (const m of types) exports.push(m[1]);
      break;
    }
  }
  return exports;
}

/** mulberry32: the low bits of a power-of-two LCG cycle too fast for `% n` picks. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  };
}

const SEPARATORS = ["", "", " ", "\n", "\r\n", "\t", "  ", "\n\n"];
const WS = ["", " ", "\t", "\n", "  \n ", " \r\n"];

type Lang = { ext: string; language: string; changed: [string, RegExp][]; units: readonly (readonly (readonly string[])[])[] };

// Each unit is a list of slots; one value is picked per slot. Heads, terminators
// and whitespace are the rewritten regexes' own vocabulary.
const LANGS: Lang[] = [
  { ext: ".go", language: "Go", changed: [["Go import (…)", /import\s*\(([\s\S]*?)\)/]], units: [
    [["import", "import", "imports", "ximport"], WS, ["(", "(", ""], WS, ["\"fmt\"", "\"a/b\"", "", "x \"c\""], WS, [")", ")", "", "("]],
    [["import", "func"], [" ", "\t"], ["\"os\"", "(", "main"]],
    [[")", "(", "\"", "import(", "package main"]],
  ] },
  { ext: ".rs", language: "Rust", changed: [["Rust use …;", /use\s+([^;]+);/]], units: [
    [["use", "use", "because", "reuse", "pub use"], [" ", "\t", "\n", "  ", ""], WS, ["std::io", "crate::{a, b}", "", " x ", ";"], WS, [";", ";", "", ";;"]],
    [["pub fn f()", "fn main() {", "}", ";", "use", " "]],
  ] },
  { ext: ".java", language: "Java", changed: [["Java import …;", /import\s+(?:static\s+)?([^;]+);/]], units: [
    [["import", "import", "imports"], [" ", "\t", "\n", ""], ["static", "static ", "", "staticx"], WS, ["java.util.List", "a.*", "", " "], WS, [";", ";", "", ";;"]],
    [["public class A {", "}", ";", "import", "static", " "]],
  ] },
  { ext: ".ts", language: "TypeScript", changed: [["JS export {…}", /export\s*\{([^}]+)\}/]], units: [
    [["export", "export", "exports"], WS, ["{", "{", "", "}"], WS, ["a", "a, b", "a as b", "x\tas\ty, z", "", ","], WS, ["}", "}", "", "{"]],
    [["export default ", "export const k = 1;", "module.exports = x;", "}", "{", ","]],
  ] },
  { ext: ".py", language: "Python", changed: [["Python __all__ = […]", /__all__\s*=\s*\[([^\]]+)\]/]], units: [
    [["__all__", "__all__", "_all_", "x__all__"], WS, ["=", "=", "", "=="], WS, ["[", "[", "", "]"], WS, ["\"a\"", "'b', \"c\"", "", "[", "1"], WS, ["]", "]", "", "["]],
    [["import os", "from a import b", "]", "[", "=", "__all__ = []", "__all__=[]"]],
  ] },
];

function source(next: () => number, units: Lang["units"]): string {
  const pick = <T,>(xs: readonly T[]): T => xs[next() % xs.length];
  let s = "";
  for (let k = 1 + (next() % 6); k > 0; k--) s += pick(units).map((slot) => pick(slot)).join("") + pick(SEPARATORS);
  return s;
}

test("mapCodebase keeps the old import / export results", async () => {
  const root = mkdtempSync(join(tmpdir(), "nexus-map-redos-"));
  try {
    const next = rng(37);
    const sources = new Map<string, { lang: Lang; text: string }>();
    for (const lang of LANGS) {
      for (let i = 0; i < 800; i++) {
        const text = source(next, lang.units);
        const name = `f${sources.size}${lang.ext}`;
        sources.set(name, { lang, text });
        writeFileSync(join(root, name), text);
      }
    }
    const map = await mapCodebase({ root });
    assert.equal(map.files.length, sources.size);
    const hits = new Map<string, number>();
    for (const file of map.files) {
      const { lang, text } = sources.get(file.path)!;
      for (const [name, re] of lang.changed) if (re.test(text)) hits.set(name, (hits.get(name) ?? 0) + 1);
      assert.deepEqual(file.importInfos, oldExtractImportsWithType(text, lang.language), `imports of ${JSON.stringify(text)}`);
      assert.deepEqual(file.exports, oldExtractExports(text, lang.language), `exports of ${JSON.stringify(text)}`);
    }
    for (const lang of LANGS) {
      for (const [name] of lang.changed) assert.ok((hits.get(name) ?? 0) >= 100, `corpus exercises ${name} (${hits.get(name) ?? 0} hits)`);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ─── Growth ratchet ───────────────────────────────────────────────────────────

const BIG = 200_000;
const SMALL = 25_000; // 8× smaller; the growth ratio compares the two.
const SLACK = Math.max(1, Number(process.env.NEXUS_PERF_SLACK) || 1);
const BIG_BUDGET_MS = 2000 * SLACK;
// 8× the input costs ~8× for a linear pass and ~64× for a quadratic one.
const MAX_GROWTH = 24;
// Below this the 200 KB run is too fast for a quadratic to hide, and the ratio is noise.
const RATIO_FLOOR_MS = 50;
const RUNS = 3;

async function timed(fn: () => Promise<unknown>): Promise<number> {
  const t0 = performance.now();
  await fn();
  return performance.now() - t0;
}

test("mapCodebase stays linear on unterminated statement heads", async () => {
  // Each re-scanned the rest of the file from every repeat (2–9 s at 200 KB).
  const families: [string, string][] = [
    [".go", "import("], [".rs", "use "], [".java", "import "], [".ts", "export{o"], [".py", "__all__=[["],
  ];
  const base = mkdtempSync(join(tmpdir(), "nexus-map-ratchet-"));
  try {
    for (const [ext, chunk] of families) {
      const dirs = [SMALL, BIG].map((bytes) => {
        const dir = join(base, `${ext.slice(1)}-${bytes}`);
        mkdirSync(dir);
        writeFileSync(join(dir, `f${ext}`), chunk.repeat(Math.ceil(bytes / chunk.length)));
        return dir;
      });
      const run = (dir: string) => () => mapCodebase({ root: dir });
      await run(dirs[0])();
      await run(dirs[1])();
      let tSmall = Infinity, tBig = Infinity;
      for (let i = 0; i < RUNS; i++) {
        tSmall = Math.min(tSmall, await timed(run(dirs[0])));
        tBig = Math.min(tBig, await timed(run(dirs[1])));
      }
      const label = `mapCodebase() on ${JSON.stringify(chunk)} (${ext})`;
      const ratio = tBig / Math.max(tSmall, 0.5);
      assert.ok(tBig < RATIO_FLOOR_MS || ratio < MAX_GROWTH,
        `${label}: 8× input grew ${ratio.toFixed(1)}× (${tSmall.toFixed(0)}→${tBig.toFixed(0)}ms) — expected < ${MAX_GROWTH}× (super-linear?)`);
      assert.ok(tBig < BIG_BUDGET_MS, `${label}: 200KB took ${tBig.toFixed(0)}ms (cap ${BIG_BUDGET_MS.toFixed(0)}ms)`);
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
