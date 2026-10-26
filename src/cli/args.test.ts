import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs, VALUE_FLAGS, BOOLEAN_FLAGS } from "./args.js";

test("switches never swallow the positional that follows them", () => {
  for (const argv of [
    ["review", "--json", "src/version.ts"],
    ["review", "src/version.ts", "--json"],
  ]) {
    assert.deepEqual(parseArgs(argv), { command: "review", args: ["src/version.ts"], flags: { "--json": undefined } });
  }
  const s = parseArgs(["secrets", "--json", "--history", "/repo", "--entropy"]);
  assert.equal(s.command, "secrets");
  assert.deepEqual(s.args, ["/repo"]);
  assert.deepEqual(Object.keys(s.flags).sort(), ["--entropy", "--history", "--json"]);
  assert.deepEqual(parseArgs(["scan", "--json", "ignore", "previous"]).args, ["ignore", "previous"]);
  assert.deepEqual(parseArgs(["map", "--json", "src/mcp"]).args, ["src/mcp"]);
});

test("value options take the next argument or an =value, before or after positionals", () => {
  const a = parseArgs(["secrets", "--max-commits", "50", "/repo", "--history"]);
  assert.deepEqual(a.args, ["/repo"]);
  assert.equal(a.flags["--max-commits"], "50");
  assert.ok("--history" in a.flags);

  const b = parseArgs(["secrets", "/repo", "--max-commits=50"]);
  assert.deepEqual(b.args, ["/repo"]);
  assert.equal(b.flags["--max-commits"], "50");

  const g = parseArgs(["guard", "install", "--tools=WebFetch,Read", "--project"]);
  assert.deepEqual(g.args, ["install"]);
  assert.equal(g.flags["--tools"], "WebFetch,Read");
  assert.ok("--project" in g.flags);

  assert.equal(parseArgs(["sync", "--vault", "/v"]).flags["--vault"], "/v");
  assert.equal(parseArgs(["sync", "--vault=/a=b"]).flags["--vault"], "/a=b", "only the first = splits");
});

test("`--` ends option parsing", () => {
  assert.deepEqual(parseArgs(["scan", "--", "--not-a-flag", "text"]), { command: "scan", args: ["--not-a-flag", "text"], flags: {} });
});

test("no command means help", () => {
  assert.equal(parseArgs([]).command, "help");
  assert.equal(parseArgs(["--json"]).command, "help");
});

test("bad options fail loudly instead of being ignored", () => {
  assert.throws(() => parseArgs(["secrets", "--max-commits"]), /--max-commits needs a value/);
  assert.throws(() => parseArgs(["secrets", "--max-commits", "--json"]), /--max-commits needs a value/);
  assert.throws(() => parseArgs(["sync", "--vault="]), /--vault needs a value/);
  assert.throws(() => parseArgs(["review", "--json=yes", "x.ts"]), /--json does not take a value/);
  assert.throws(() => parseArgs(["secrets", "--histroy", "."]), /Unknown option: --histroy/);
});

test("every option the CLI reads is declared with the right kind", () => {
  const src = readFileSync(resolve("src/cli/index.ts"), "utf-8");
  const switches = new Set([...src.matchAll(/"(--[a-z-]+)" in flags/g)].map((m) => m[1]));
  const valued = new Set([...src.matchAll(/flags\["(--[a-z-]+)"\]/g)].map((m) => m[1]));
  assert.deepEqual([...switches].sort(), [...BOOLEAN_FLAGS].sort());
  assert.deepEqual([...valued].sort(), [...VALUE_FLAGS].sort());
});

test("--codex and --trust are switches; --agent takes a value for guard install as for guard check", () => {
  const p = parseArgs(["guard", "install", "--codex", "--trust", "--no-integrity"]);
  assert.deepEqual(p.args, ["install"]);
  assert.deepEqual(Object.keys(p.flags).sort(), ["--codex", "--no-integrity", "--trust"]);
  assert.equal(parseArgs(["guard", "status", "--agent", "codex"]).flags["--agent"], "codex");
  assert.throws(() => parseArgs(["guard", "install", "--trust=yes"]), /--trust does not take a value/);
  assert.throws(() => parseArgs(["guard", "install", "--codex=1"]), /--codex does not take a value/);
});
