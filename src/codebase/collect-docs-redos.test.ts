import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extractImportsWithType, mapCodebase } from "./mapper.js";

/**
 * Five of the mapper's statement scans (Go `import (…)`, Rust `use …;`, Java
 * `import …;`, JS `export {…}`, Python `__all__ = […]`) re-scanned the rest of
 * the file from every unterminated head, so `nexus_map` on such a file was
 * quadratic. They now continue only from the first head before each terminator
 * and must keep exactly the old results: the old extractors are kept below,
 * verbatim, as the oracle and compared on structured fuzz through mapCodebase.
 * Rust `use` and Java `import` were also quadratic on one head followed by a
 * whitespace run with no `;`; a `(?=[^;]*;)` after the head now fails that in
 * one scan.
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
const U = (code: number) => String.fromCharCode(code);
// Whitespace that `\s` matches beyond ASCII (no-break, em and ideographic
// spaces, line separator, BOM, vertical tab and form feed), and whitespace runs
// and statement bodies past 900 characters: a narrower class, or a length cap on
// a span the old regexes left unbounded, must fail this test rather than pass it.
const LONG_SPAN = 900;
const UWS = [U(0xa0), U(0x2003), U(0x3000), U(0x2028), U(0xfeff), "\v\f"];
const WS = ["", " ", "\t", "\n", "  \n ", " \r\n", ...UWS];
// Not in TypeScript files: there the still-cubic `import|export … from` scans
// (see mapper.ts) would make a long whitespace run cost seconds.
const LONG_WS = [...WS, " ".repeat(901), "\t \n".repeat(320), U(0x3000).repeat(905)];

type Lang = { ext: string; language: string; changed: [string, RegExp][]; units: readonly (readonly (readonly string[])[])[] };

// Each unit is a list of slots; one value is picked per slot. Heads, terminators
// and whitespace are the rewritten regexes' own vocabulary.
const LANGS: Lang[] = [
  { ext: ".go", language: "Go", changed: [["Go import (…)", /import\s*\(([\s\S]*?)\)/]], units: [
    [["import", "import", "imports", "ximport"], LONG_WS, ["(", "(", ""], LONG_WS,
      ["\"fmt\"", "\"a/b\"", "", "x \"c\"", "\"fmt\"" + "\n\t\"a/b\"".repeat(110)], LONG_WS, [")", ")", "", "("]],
    [["import", "func"], [" ", "\t"], ["\"os\"", "(", "main"]],
    [[")", "(", "\"", "import(", "package main"]],
  ] },
  { ext: ".rs", language: "Rust", changed: [["Rust use …;", /use\s+([^;]+);/]], units: [
    [["use", "use", "because", "reuse", "pub use"], [" ", "\t", "\n", "  ", "", ...UWS], LONG_WS,
      ["std::io", "crate::{a, b}", "", " x ", ";", "crate::{" + "a, ".repeat(310) + "b}"], LONG_WS, [";", ";", "", ";;"]],
    [["pub fn f()", "fn main() {", "}", ";", "use", " "]],
  ] },
  { ext: ".java", language: "Java", changed: [["Java import …;", /import\s+(?:static\s+)?([^;]+);/]], units: [
    [["import", "import", "imports"], [" ", "\t", "\n", "", ...UWS], ["static", "static ", "", "staticx", "static" + U(0x3000)], LONG_WS,
      ["java.util.List", "a.*", "", " ", "java." + "a.".repeat(460) + "List"], LONG_WS, [";", ";", "", ";;"]],
    [["public class A {", "}", ";", "import", "static", " "]],
  ] },
  { ext: ".ts", language: "TypeScript", changed: [["JS export {…}", /export\s*\{([^}]+)\}/]], units: [
    [["export", "export", "exports"], WS, ["{", "{", "", "}"], WS,
      ["a", "a, b", "a as b", "x\tas\ty, z", "", ",", "a, ".repeat(310) + "b as c"], WS, ["}", "}", "", "{"]],
    [["export default ", "export const k = 1;", "module.exports = x;", "}", "{", ","]],
  ] },
  { ext: ".py", language: "Python", changed: [["Python __all__ = […]", /__all__\s*=\s*\[([^\]]+)\]/]], units: [
    [["__all__", "__all__", "_all_", "x__all__"], LONG_WS, ["=", "=", "", "=="], LONG_WS, ["[", "[", "", "]"], LONG_WS,
      ["\"a\"", "'b', \"c\"", "", "[", "1", "'a', ".repeat(190)], LONG_WS, ["]", "]", "", "["]],
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
    const hits = new Map<string, number>(), long = new Map<string, number>(), unicode = new Map<string, number>();
    const bump = (counts: Map<string, number>, name: string) => counts.set(name, (counts.get(name) ?? 0) + 1);
    for (const file of map.files) {
      const { lang, text } = sources.get(file.path)!;
      for (const [name, re] of lang.changed) {
        const matches = [...text.matchAll(new RegExp(re.source, "g"))].map((m) => m[0]);
        if (matches.length) bump(hits, name);
        if (matches.some((m) => m.length > LONG_SPAN)) bump(long, name);
        if (matches.some((m) => UWS.some((c) => m.includes(c)))) bump(unicode, name);
      }
      assert.deepEqual(file.importInfos, oldExtractImportsWithType(text, lang.language), `imports of ${JSON.stringify(text)}`);
      assert.deepEqual(file.exports, oldExtractExports(text, lang.language), `exports of ${JSON.stringify(text)}`);
    }
    for (const lang of LANGS) {
      for (const [name] of lang.changed) {
        const [n, l, u] = [hits, long, unicode].map((counts) => counts.get(name) ?? 0);
        assert.ok(n >= 100 && l >= 50 && u >= 50, `corpus exercises ${name} (${n} hits, ${l} over ${LONG_SPAN} chars, ${u} with non-ASCII whitespace)`);
      }
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

async function once(fn: () => unknown): Promise<number> {
  const t0 = performance.now();
  await fn();
  return performance.now() - t0;
}

/**
 * Asserts that 8× the input (25 KB → 200 KB) costs less than MAX_GROWTH× and
 * stays under the budget, on best-of-RUNS timings sampled alternately after one
 * checked call of each size. A regressed scan costs seconds per 200 KB call and
 * a timeout cannot interrupt synchronous regex work, so the first calls fail
 * fast instead: 25 KB must fit in 1/8 of the budget before 200 KB runs at all,
 * and 200 KB must fit in the budget once before it is timed RUNS more times.
 */
async function assertScales(label: string, small: () => unknown, big: () => unknown): Promise<void> {
  const firstSmall = await once(small);
  assert.ok(firstSmall < BIG_BUDGET_MS / 8,
    `${label}: 25KB took ${firstSmall.toFixed(0)}ms (pre-check cap ${(BIG_BUDGET_MS / 8).toFixed(0)}ms; super-linear?)`);
  const firstBig = await once(big);
  assert.ok(firstBig < BIG_BUDGET_MS, `${label}: 200KB took ${firstBig.toFixed(0)}ms (cap ${BIG_BUDGET_MS.toFixed(0)}ms)`);
  let tSmall = Infinity, tBig = Infinity;
  for (let i = 0; i < RUNS; i++) {
    tSmall = Math.min(tSmall, await once(small));
    tBig = Math.min(tBig, await once(big));
  }
  const ratio = tBig / Math.max(tSmall, 0.5);
  assert.ok(tBig < RATIO_FLOOR_MS || ratio < MAX_GROWTH,
    `${label}: 8× input grew ${ratio.toFixed(1)}× (${tSmall.toFixed(0)}→${tBig.toFixed(0)}ms) — expected < ${MAX_GROWTH}× (super-linear?)`);
  assert.ok(tBig < BIG_BUDGET_MS, `${label}: 200KB took ${tBig.toFixed(0)}ms (cap ${BIG_BUDGET_MS.toFixed(0)}ms)`);
}

test("mapCodebase stays linear on unterminated statement heads", async () => {
  // Each repeated head re-scanned the rest of the file (2–9 s at 200 KB); one
  // `use` before a whitespace run with no `;` re-scanned it for every split of
  // the run (~0.5 s at 25 KB, ~8 s at 100 KB). The heads one per line keep each
  // scan's run boundary honest: one at the newline (firstInRun's default) would
  // try every head again (1–5 s at 200 KB).
  const families: [string, string, string][] = [
    [".go", "", "import("], [".rs", "", "use "], [".java", "", "import "], [".ts", "", "export{o"], [".py", "", "__all__=[["],
    [".rs", "use", " "], [".rs", "use\t", "\t"], [".rs", "use", "\n"],
    [".go", "", "import(\n"], [".rs", "", "use x\n"], [".java", "", "import x\n"], [".ts", "", "export{o\n"], [".py", "", "__all__=[[\n"],
  ];
  const base = mkdtempSync(join(tmpdir(), "nexus-map-ratchet-"));
  try {
    for (const [i, [ext, head, chunk]] of families.entries()) {
      const dirs = [SMALL, BIG].map((bytes) => {
        const dir = join(base, `${i}-${bytes}`);
        mkdirSync(dir);
        writeFileSync(join(dir, `f${ext}`), head + chunk.repeat(Math.ceil(bytes / chunk.length)));
        return dir;
      });
      const run = (dir: string) => () => mapCodebase({ root: dir });
      await assertScales(`mapCodebase() on ${JSON.stringify(head)} + ${JSON.stringify(chunk)}… (${ext})`, run(dirs[0]), run(dirs[1]));
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("Java import extraction stays linear on a head before a whitespace run", async () => {
  // `import` / `import static` + whitespace and no `;` (~0.6 s at 25 KB, ~2.7 s at
  // 50 KB). Timed on the extractor, not mapCodebase: on these files mapCodebase
  // is dominated by the Java method scan, which is still quadratic on whitespace
  // runs (see the note in mapper.ts).
  for (const [head, chunk] of [["import", " "], ["import static", " "], ["import\tstatic\t", "\t"], ["import", "\n"]]) {
    const [small, big] = [SMALL, BIG].map((bytes) => head + chunk.repeat(Math.ceil(bytes / chunk.length)));
    const run = (text: string) => () => extractImportsWithType(text, "Java");
    await assertScales(`extractImportsWithType() on ${JSON.stringify(head)} + ${JSON.stringify(chunk)}… (Java)`, run(small), run(big));
  }
});
