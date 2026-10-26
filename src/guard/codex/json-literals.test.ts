/**
 * hooks.json's number literals kept as written (codex/json-literals.ts): which
 * ones JSON.stringify would change, where they sit after JSON.parse (duplicate
 * keys, integer-like keys, `__proto__`), the text written back, and time linear
 * in the file.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { numberLiterals, stringifyKeeping } from "./json-literals.js";

/** `text` parsed and written back by stringifyKeeping, as install does. */
const roundTrip = (text: string) => {
  const doc = JSON.parse(text);
  return stringifyKeeping(doc, numberLiterals(text, doc));
};

describe("numberLiterals and stringifyKeeping", () => {
  it("write a document whose numbers JSON.stringify keeps exactly as JSON.stringify does", () => {
    for (const doc of [
      {}, [], { a: 1, b: [1, -2, 0.5, 1e-7, 1e21], c: { d: "1.0", e: null, f: true, g: false, h: [] , i: {} } },
      { hooks: { Stop: [{ hooks: [{ type: "command", command: 'say "1.0" \\ done', timeout: 30 }] }] } },
      [[[[1]]], "x", { "": 0 }],
    ]) {
      const text = JSON.stringify(doc);
      assert.equal(numberLiterals(text, JSON.parse(text)).size, 0, text);
      assert.equal(roundTrip(text), JSON.stringify(doc, null, 2), text);
    }
  });

  it("keep each literal JSON.stringify would change, 1.0 and a 19-digit integer in an MCP hook's input among them", () => {
    const text = '{"hooks": {"PostToolUse": [{"hooks": [{"type": "mcp_tool", "server": "chat", "tool": "echo", ' +
      '"input": {"weight": 1.0, "channel_id": 1234567890123456789, "list": [1e2, -0, 0.10, 1E+2, 2.50e-3, 1.5e400, 7]}}]}]}}';
    const out = roundTrip(text);
    for (const literal of ['"weight": 1.0', '"channel_id": 1234567890123456789', "1e2,", "-0,", "0.10,", "1E+2,", "2.50e-3,", "1.5e400,", "7\n"]) {
      assert.ok(out.includes(literal), `${literal} in ${out}`);
    }
    assert.equal(out.replace(/\s+/g, ""), text.replace(/\s+/g, ""), "the same text, but for the layout");
    assert.equal(roundTrip(out), out, "written again, unchanged");
  });

  it("key each literal where JSON.parse puts its value: the last of a key given twice, integer-like keys first, __proto__ as a key", () => {
    assert.equal(roundTrip('{"a": 1.0, "a": 2}'), '{\n  "a": 2\n}');
    assert.equal(roundTrip('{"a": 1.0, "a": "x"}'), '{\n  "a": "x"\n}');
    assert.equal(roundTrip('{"a": {"b": 1.0}, "a": {"b": 1}}'), '{\n  "a": {\n    "b": 1\n  }\n}');
    assert.equal(roundTrip('{"a": 2, "a": 1.0}'), '{\n  "a": 1.0\n}');
    assert.equal(roundTrip('{"b": 1.0, "2": 3.0}'), '{\n  "2": 3.0,\n  "b": 1.0\n}');
    assert.equal(roundTrip('{"__proto__": {"x": 1.0}}'), '{\n  "__proto__": {\n    "x": 1.0\n  }\n}');
    assert.equal(roundTrip('[1.0, [2.0, {"k\\"": 3.0}], "4.0", 5.0]'), '[\n  1.0,\n  [\n    2.0,\n    {\n      "k\\"": 3.0\n    }\n  ],\n  "4.0",\n  5.0\n]');
    assert.equal(roundTrip(' \n{"s": "a \\" 1.0 \\\\", "n": 1.0}\n'), '{\n  "s": "a \\" 1.0 \\\\",\n  "n": 1.0\n}', "number-like text in a string is not a number");
  });

  it("write a number that changed, or one in an object made since, JSON.stringify's way", () => {
    const text = '{"a": 1.0, "b": [1.0, 2.0], "c": {"d": 1.0}}';
    const doc = JSON.parse(text);
    const literals = numberLiterals(text, doc);
    const c = doc.c;
    doc.a = 3;
    doc.b.shift();
    doc.c = { ...c };
    assert.equal(stringifyKeeping(doc, literals), '{\n  "a": 3,\n  "b": [\n    2\n  ],\n  "c": {\n    "d": 1\n  }\n}',
      "b[0] is 2.0's place no more, and the copy of c has no literals of its own");
    literals.set(doc.c, literals.get(c)!);
    assert.match(stringifyKeeping(doc, literals), /"d": 1\.0/, "a copy given the literals of what it copies keeps them");
  });

  it("read nesting deeper than the call stack, and stay linear in the file", () => {
    const deep = `${"[".repeat(100_000)}1.0${"]".repeat(100_000)}`;
    assert.equal(numberLiterals(deep, JSON.parse(deep)).size, 1);
    const timed = (fn: () => unknown) => {
      fn();
      const t0 = performance.now();
      fn();
      return performance.now() - t0;
    };
    // groups of hooks with literals to keep, strings with escapes, and plain numbers
    const file = (n: number) => JSON.stringify({ hooks: { PostToolUse: Array.from({ length: n }, (_, i) => ({ matcher: `^mcp__s${i}__.*$`, hooks: [{
      type: "mcp_tool", server: "s", tool: `t\\"${i}`, input: { w: "W", id: "ID", n: i, list: [1, 2, 3] }, timeout: 5,
    }] })) } }).replaceAll('"W"', "1.0").replaceAll('"ID"', "1234567890123456789");
    const small = file(2_000);
    const big = file(20_000);
    const both = (text: string) => roundTrip(text);
    assert.equal(numberLiterals(big, JSON.parse(big)).size, 20_000);
    const ms = timed(() => both(big));
    const ratio = ms / Math.max(timed(() => both(small)), 1);
    assert.ok(ratio < 40 && ms < 3000, `20,000 groups took ${ms.toFixed(0)} ms, ${ratio.toFixed(1)}x 2,000`);
    const long = `{"s": "${'\\\\\\"x'.repeat(1_000_000)}", "n": 1.0}`;
    assert.ok(timed(() => roundTrip(long)) < 2000, "a 4 MB string");
  });
});
