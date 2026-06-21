// Portable test entry: discover src/**/*.test.ts ourselves and hand the explicit
// file list to node:test. node --test only learned to expand glob patterns in
// Node 21, so a bare `node --test "src/**/*.test.ts"` silently finds nothing on
// Node 20 — this keeps the suite running on every supported Node and on Windows.
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

function findTests(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...findTests(p));
    else if (entry.name.endsWith(".test.ts")) out.push(p);
  }
  return out;
}

const files = findTests("src").sort();
if (files.length === 0) {
  console.error("No test files found under src/");
  process.exit(1);
}

const res = spawnSync(process.execPath, ["--import", "tsx", "--test", ...files], { stdio: "inherit" });
process.exit(res.status ?? 1);
