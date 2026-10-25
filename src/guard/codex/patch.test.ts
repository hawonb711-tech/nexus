/**
 * Codex's apply_patch format: the parser (patch.ts) reads what Codex 0.164.0's
 * own parser reads, and a little more where Codex would refuse the patch; the
 * simulator (simulate.ts) leaves the text Codex's apply leaves, checked against
 * Codex's own conformance scenarios (__fixtures__/apply-patch-scenarios), and
 * both stay linear in their input.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { addedText, MAX_PATCH_CHARS, MAX_PATCH_FILES, opPaths, parsePatch, rustTrim, type PatchOp } from "./patch.js";
import { simulatePatchOp } from "./simulate.js";
import { inspectCommand } from "../command.js";

const SCENARIOS = fileURLToPath(new URL("./__fixtures__/apply-patch-scenarios/", import.meta.url));

const wrap = (body: string) => `*** Begin Patch\n${body}\n*** End Patch`;
const update = (op: PatchOp | undefined) => {
  assert.equal(op?.op, "update");
  return op as Extract<PatchOp, { op: "update" }>;
};

/** Time `fn()` in ms after one warm-up run. */
function timed(fn: () => unknown): number {
  fn();
  const t0 = performance.now();
  fn();
  return performance.now() - t0;
}

describe("parsePatch", () => {
  it("reads the patch Codex sent in the captured run", () => {
    const { ops, overflow } = parsePatch("*** Begin Patch\n*** Update File: AGENTS.md\n@@\n Be nice.\n+Injected by apply_patch tool.\n*** End Patch");
    assert.equal(overflow, false);
    assert.deepEqual(ops, [{
      op: "update", path: "AGENTS.md", moveTo: null,
      chunks: [{ context: null, old: ["Be nice."], new: ["Be nice.", "Injected by apply_patch tool."], contextAt: [[0, 0]], eof: false }],
    }]);
    assert.equal(addedText(ops[0]), "Injected by apply_patch tool.");
  });

  it("reads Add, Delete, Update with Move to, in order, as Codex's parser test does", () => {
    const { ops } = parsePatch(wrap([
      "*** Add File: path/add.py", "+abc", "+def",
      "*** Delete File: path/delete.py",
      "*** Update File: path/update.py", "*** Move to: path/update2.py", "@@ def f():", "-    pass", "+    return 123",
    ].join("\n")));
    assert.deepEqual(ops, [
      { op: "add", path: "path/add.py", contents: "abc\ndef\n" },
      { op: "delete", path: "path/delete.py" },
      {
        op: "update", path: "path/update.py", moveTo: "path/update2.py",
        chunks: [{ context: "def f():", old: ["    pass"], new: ["    return 123"], contextAt: [], eof: false }],
      },
    ]);
    assert.deepEqual(ops.map(opPaths), [["path/add.py"], ["path/delete.py"], ["path/update.py", "path/update2.py"]]);
    assert.equal(addedText(ops[1]), "");
    assert.equal(addedText(ops[2]), "    return 123");
  });

  it("trims as Rust does: U+0085 is whitespace, U+FEFF is not", () => {
    // JavaScript's trim would keep the NEL and name a file Codex never writes.
    assert.equal(parsePatch(wrap("*** Add File: .envrc\u0085\n+x")).ops[0].path, ".envrc");
    assert.equal(parsePatch(wrap("*** Add File: notes\ufeff\n+x")).ops[0].path, "notes\ufeff");
    assert.equal(rustTrim("\u0085\u00a0 x \u3000"), "x");
    assert.equal(rustTrim("\ufeffx"), "\ufeffx");
  });

  it("drops a line's \\r, and reads a heredoc-wrapped patch", () => {
    const crlf = parsePatch("*** Begin Patch\r\n*** Add File: a.txt\r\n+one\r\n*** End Patch\r\n");
    assert.deepEqual(crlf.ops, [{ op: "add", path: "a.txt", contents: "one\n" }]);
    const heredoc = parsePatch("<<'EOF'\n*** Begin Patch\n*** Add File: b.txt\n+two\n*** End Patch\nEOF");
    assert.deepEqual(heredoc.ops, [{ op: "add", path: "b.txt", contents: "two\n" }]);
  });

  it("inside an Update, an indented header is a context line, as Codex reads it; elsewhere headers are trimmed", () => {
    const { ops } = parsePatch(wrap("*** Update File: a.md\n@@\n *** Add File: evil\n+x\n  *** Add File: b.md\n+y"));
    assert.equal(ops.length, 1);
    assert.deepEqual(update(ops[0]).chunks[0].old, ["*** Add File: evil", " *** Add File: b.md"]);
    const padded = parsePatch("*** Begin Patch\n  *** Add File: c.md  \n+z\n*** End Patch");
    assert.deepEqual(padded.ops, [{ op: "add", path: "c.md", contents: "z\n" }]);
  });

  it("an indented `*** End Patch` on the last line ends an Update (Codex trims the patch's last line)", () => {
    const { ops } = parsePatch("*** Begin Patch\n*** Update File: f\n@@\n-one\n+two\n *** End Patch\n");
    assert.deepEqual(update(ops[0]).chunks[0], { context: null, old: ["one"], new: ["two"], contextAt: [], eof: false });
  });

  it("keeps reading past a line Codex would reject the whole patch for, so no file goes unseen", () => {
    const { ops } = parsePatch(wrap("*** Frobnicate File: x\n*** Add File: .envrc\n+export A=1\nnot a patch line\n*** Delete File: AGENTS.md"));
    assert.deepEqual(ops.map((o) => [o.op, o.path]), [["add", ".envrc"], ["delete", "AGENTS.md"]]);
    const after = parsePatch(`${wrap("*** Add File: a\n+1")}\n*** Add File: CLAUDE.md\n+2`);
    assert.deepEqual(after.ops.map((o) => o.path), ["a", "CLAUDE.md"]);
    assert.deepEqual(parsePatch("*** Add File: x\n+y").ops, [], "no `*** Begin Patch`: nothing Codex would apply");
  });

  it("marks `*** End of File` and empty context lines", () => {
    const op = update(parsePatch(wrap("*** Update File: t\n@@\n a\n\n-b\n+B\n*** End of File")).ops[0]);
    assert.deepEqual(op.chunks[0], { context: null, old: ["a", "", "b"], new: ["a", "", "B"], contextAt: [[0, 0], [1, 1]], eof: true });
    assert.equal(addedText(op), "B");
  });

  it("past MAX_PATCH_FILES files or MAX_PATCH_CHARS characters it says overflow", () => {
    const many = parsePatch(wrap(Array.from({ length: MAX_PATCH_FILES + 5 }, (_, i) => `*** Add File: f${i}\n+x`).join("\n")));
    assert.equal(many.overflow, true);
    assert.equal(many.ops.length, MAX_PATCH_FILES);
    const long = parsePatch(`*** Begin Patch\n*** Add File: big\n+${"a".repeat(MAX_PATCH_CHARS)}\n*** Add File: AGENTS.md\n+x\n*** End Patch`);
    assert.equal(long.overflow, true);
    assert.deepEqual(long.ops.map((o) => o.path), ["big"]);
  });
});

/** Every file under `dir`, by path relative to it. */
function tree(dir: string): Map<string, string> {
  const out = new Map<string, string>();
  if (!existsSync(dir)) return out;
  const walk = (d: string) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else out.set(relative(dir, p).split("\\").join("/"), readFileSync(p, "utf8"));
    }
  };
  walk(dir);
  return out;
}

/** Codex fails these patches as a whole (a context or file that is not there, an empty Update, a bad header). */
const REJECTED = new Set([
  "005_rejects_empty_patch", "006_rejects_missing_context", "007_rejects_missing_file_delete", "008_rejects_empty_update_hunk",
  "009_requires_existing_file_for_update", "012_delete_directory_fails", "013_rejects_invalid_hunk_header",
  "015_failure_after_partial_success_leaves_changes",
]);

describe("simulatePatchOp against Codex's apply_patch scenarios", () => {
  const scenarios = readdirSync(SCENARIOS).filter((n) => /^\d{3}_/.test(n)).sort();

  it("finds the scenarios", () => assert.ok(scenarios.length >= 20, `${scenarios.length} scenarios`));

  for (const name of scenarios) {
    it(name, () => {
      const dir = join(SCENARIOS, name);
      const files = tree(join(dir, "input"));
      const expected = tree(join(dir, "expected"));
      const { ops } = parsePatch(readFileSync(join(dir, "patch.txt"), "utf8"));
      let approx = false;
      for (const op of ops) {
        if (op.op === "delete") {
          files.delete(op.path);
          continue;
        }
        const out = simulatePatchOp(op, files.get(op.path) ?? null)!;
        approx ||= out.approx;
        if (op.op === "update" && op.moveTo !== null) files.delete(op.path);
        files.set(op.op === "update" && op.moveTo !== null ? op.moveTo : op.path, out.text);
      }
      if (REJECTED.has(name)) {
        // Where Codex refuses, the simulation is either a no-op or says it is not exact.
        assert.ok(approx || ops.every((o) => o.op !== "update" || o.chunks.length === 0) || ops.length <= 1, name);
        return;
      }
      assert.equal(approx, false, `${name}: exact`);
      assert.deepEqual([...files].sort(), [...expected].sort());
    });
  }
});

describe("simulatePatchOp", () => {
  const op = (body: string) => update(parsePatch(wrap(`*** Update File: f\n${body}`)).ops[0]);

  it("places chunks as Codex does: context first, a pure addition at the end, an empty last old line retried", () => {
    assert.deepEqual(simulatePatchOp(op("@@\n foo\n-bar\n+BAR\n@@\n baz\n-qux\n+QUX"), "foo\nbar\nbaz\nqux\n"), { text: "foo\nBAR\nbaz\nQUX\n", approx: false });
    assert.deepEqual(simulatePatchOp(op("@@\n+after-context\n+second-line\n@@\n line1\n-line2\n-line3\n+line2-replacement"), "line1\nline2\nline3\n"),
      { text: "line1\nline2-replacement\nafter-context\nsecond-line\n", approx: false });
    assert.deepEqual(simulatePatchOp(op("@@ def g():\n-  b\n+  B"), "def f():\n  b\ndef g():\n  b\n"), { text: "def f():\n  b\ndef g():\n  B\n", approx: false });
    assert.deepEqual(simulatePatchOp(op("@@\n-last\n-\n+LAST\n+"), "first\nlast"), { text: "first\nLAST\n", approx: false });
  });

  it("matches ignoring trailing, then all, blanks, then typographic punctuation", () => {
    assert.equal(simulatePatchOp(op("@@\n-a\n+A"), "a   \n")!.text, "A\n");
    assert.equal(simulatePatchOp(op("@@\n-a\n+A"), "   a\n")!.text, "A\n");
    assert.equal(simulatePatchOp(op("@@\n-it's - \"x\"\n+y"), "it\u2019s \u2013 \u201cx\u201d\n")!.text, "y\n");
  });

  it("keeps the file's line endings and gives inserted lines the first one", () => {
    assert.equal(simulatePatchOp(op("@@\n a\n+b"), "a\r\nz\r\n")!.text, "a\r\nb\r\nz\r\n");
    assert.equal(simulatePatchOp(op("@@\n-z\n+Z"), "a\rz")!.text, "a\rZ\r");
  });

  it("where Codex would refuse, appends the chunk's added lines and says approx", () => {
    assert.deepEqual(simulatePatchOp(op("@@ nowhere\n-x\n+NEW"), "a\nb\n"), { text: "a\nb\nNEW\n", approx: true });
    assert.deepEqual(simulatePatchOp(op("@@\n-gone\n+NEW"), "a\n"), { text: "a\nNEW\n", approx: true });
    assert.deepEqual(simulatePatchOp(op("@@\n a\n+NEW"), null), { text: "NEW\n", approx: true }, "no file to update");
    assert.deepEqual(simulatePatchOp({ op: "add", path: "f", contents: "x\n" }, "old\n"), { text: "x\n", approx: false }, "an Add overwrites");
    assert.equal(simulatePatchOp({ op: "delete", path: "f" }, "old\n"), null);
  });

  it("stays bounded on a 4 MiB file whose chunks never match", () => {
    const file = "line of text that is not the context\n".repeat(110_000);
    const chunks = Array.from({ length: 200 }, (_, i) => `@@\n-absent line ${i}\n+added ${i}`).join("\n");
    const patch = op(chunks);
    let out: ReturnType<typeof simulatePatchOp> = null;
    const ms = timed(() => (out = simulatePatchOp(patch, file)));
    assert.equal(out!.approx, true);
    assert.ok(out!.text.endsWith("added 199\n"), "every chunk's added line is kept");
    assert.ok(ms < 3000, `simulation took ${ms.toFixed(0)} ms`);
  });
});

describe("linear time", () => {
  it("a patch fed to apply_patch in the shell keeps the command guard linear", () => {
    const body = (n: number) => Array.from({ length: 64 }, (_, i) => `*** Add File: src/f${i}.ts\n${"+export const x = 1; // filler text\n".repeat(n)}`).join("");
    const cmd = (n: number) => `apply_patch <<'EOF'\n*** Begin Patch\n${body(n)}*** End Patch\nEOF\n`;
    const small = cmd(40);
    const big = cmd(400);
    assert.equal(inspectCommand(big).decision, "allow");
    const ratio = timed(() => inspectCommand(big)) / Math.max(timed(() => inspectCommand(small)), 1);
    assert.ok(ratio < 40, `10x input took ${ratio.toFixed(1)}x`);
    // many patch commands, each with its own quoted patch: each is read once
    const many = Array.from({ length: 2000 }, (_, i) => `apply_patch '*** Begin Patch\n*** Add File: a${i}\n+x\n*** End Patch'`).join("; ");
    const ms = timed(() => inspectCommand(many));
    assert.ok(ms < 2000, `2,000 patch commands took ${ms.toFixed(0)} ms`);
  });

  it("parsePatch stays linear on 8 MB of chunk lines and of header-like lines", () => {
    const lines = parsePatch(wrap(`*** Update File: f\n${"@@\n a\n-b\n+c\n".repeat(400_000)}`));
    assert.equal(lines.ops.length, 1);
    const small = wrap(`*** Update File: f\n${"@@\n a\n-b\n+c\n".repeat(40_000)}`);
    const big = wrap(`*** Update File: f\n${"@@\n a\n-b\n+c\n".repeat(400_000)}`);
    const ratio = timed(() => parsePatch(big)) / Math.max(timed(() => parsePatch(small)), 1);
    assert.ok(ratio < 40, `10x input took ${ratio.toFixed(1)}x`);
    const headers = "  *** Add File:\u0085 \n".repeat(400_000);
    const ms = timed(() => parsePatch(`*** Begin Patch\n${headers}`));
    assert.ok(ms < 2000, `header-like lines took ${ms.toFixed(0)} ms`);
    const blanks = timed(() => parsePatch(`*** Begin Patch\n*** Update File: x\n${" ".repeat(2_000_000)}x\n`));
    assert.ok(blanks < 1000, `a 2 MB blank run took ${blanks.toFixed(0)} ms`);
  });
});
