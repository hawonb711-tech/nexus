/**
 * The tolerant TOML reader behind Codex's config units (toml.ts): what it reads
 * from config files as Codex writes them, how it keeps going past a line it
 * cannot read, and that hostile input costs linear time and never throws.
 */
import { describe, it, test } from "node:test";
import assert from "node:assert/strict";
import { readToml, tomlPath, tomlStrings, tomlValueText, type TomlDoc } from "./toml.js";
import { unitsOf } from "./units.js";
import { codexHooksOffIn } from "../command.js";

/** `path = value` per entry, in file order. */
const lines = (doc: TomlDoc) => doc.entries.map((e) => `${tomlPath(e.path)} = ${tomlValueText(e.value)}`);

describe("readToml", () => {
  it("reads keys, tables, array tables and dotted and quoted keys", () => {
    const doc = readToml([
      'model = "gpt-5.5" # the model',
      "",
      "[features]",
      "hooks = false",
      "web.search = true",
      '[projects."/home/u/my app"]',
      'trust_level = "trusted"',
      "[[hooks.PreToolUse]]",
      'matcher = "^Bash$"',
      "[[hooks.PreToolUse.hooks]]",
      "type = 'command'",
      "timeout = 30",
      "[ mcp_servers . 'docs' ]",
      'command = "npx"',
    ].join("\n"));
    assert.deepEqual(lines(doc), [
      'model = "gpt-5.5"',
      "features.hooks = false",
      "features.web.search = true",
      'projects."/home/u/my app".trust_level = "trusted"',
      'hooks.PreToolUse.matcher = "^Bash$"',
      'hooks.PreToolUse.hooks.type = "command"',
      "hooks.PreToolUse.hooks.timeout = 30",
      'mcp_servers.docs.command = "npx"',
    ]);
    assert.deepEqual(doc.entries.map((e) => e.line), [1, 4, 5, 7, 9, 11, 12, 14]);
    assert.deepEqual(doc.unparsed, []);
  });

  it("reads multi-line arrays and inline tables, flattening an inline table at a key's place", () => {
    const doc = readToml([
      "args = [",
      '  "-y",   # a comment inside',
      '  "pkg[1]",',
      "]",
      'env = { API_KEY = "k", nested = { deep = 1 } }',
      'list = [{ path = "a", enabled = true }, 2]',
      "multi = {",
      "  a = 1,",
      "}",
    ].join("\n"));
    assert.deepEqual(lines(doc), [
      'args = ["-y", "pkg[1]"]',
      'env.API_KEY = "k"',
      "env.nested.deep = 1",
      'list = [{path = "a", enabled = true}, 2]',
      "multi.a = 1",
    ]);
    assert.deepEqual(tomlStrings(doc.entries[0].value), ["-y", "pkg[1]"]);
    assert.equal(tomlStrings(doc.entries[1].value), null);
  });

  it("decodes the four kinds of string", () => {
    const doc = readToml([
      'basic = "tab\\there \\"q\\" \\u00e9 \\U0001F600 \\x41 \\z"',
      "literal = 'C:\\path\\no escapes'",
      'multi = """',
      "first \\",
      '   joined "quoted" \\n',
      'end"""""',
      "raw = \'\'\'",
      "keep \\n as is\'\'\'",
    ].join("\n"));
    const values = doc.entries.map((e) => (e.value.t === "str" ? e.value.v : null));
    assert.deepEqual(values, [
      'tab\there "q" é 😀 A \\z',
      "C:\\path\\no escapes",
      'first joined "quoted" \n\nend""', // the escaped line break, then the file's own
      "keep \\n as is",
    ]);
  });

  it("records a line it cannot read, every line a failed statement took, and goes on at the next one", () => {
    const doc = readToml([
      "a = 1",
      "this is not toml",
      'b = "unclosed',
      "c = [1, 2",
      "d = 4",
      "e = 5 trailing junk",
      "[unclosed",
      "f = 6",
    ].join("\n"));
    // a bare value runs to the end of the line, as dates with a time do; the broken header leaves the table as it was
    assert.deepEqual(lines(doc), ["a = 1", "e = 5 trailing junk", "f = 6"]);
    assert.deepEqual(doc.unparsed, [
      { line: 2, text: "this is not toml" },
      { line: 3, text: 'b = "unclosed' },
      { line: 4, text: "c = [1, 2" },
      { line: 5, text: "d = 4" },
      { line: 7, text: "[unclosed" },
    ]);
  });

  it("does not read a key path past 32 segments or 1024 characters in all, the table's included", () => {
    const long = "k".repeat(1020);
    const doc = readToml([
      `[${"a.".repeat(30)}b]`,
      "ok = 1",
      `[${"a.".repeat(32)}b]`,
      "c = 1",
      `[t]`,
      `${"x".repeat(1023)} = 1`, // with the table's "t", 1024 characters
      `${"x".repeat(1024)} = 1`,
      `"${long}" = 2`,
      `n = { deep = { "${long}" = 3 } }`,
      `m = [{ "${long}" = 4 }]`,
    ].join("\n"));
    assert.deepEqual(doc.entries.map((e) => [e.path.length, e.path.join(".").length, e.line]), [
      [32, 64, 2], // 31 segments of table, then the key
      [32, 63, 4], // under the table before the header that was too long
      [2, 1025, 6],
      [2, 1022, 8],
      [2, 3, 10], // a key inside an array's inline table is part of the value
    ]);
    assert.deepEqual(doc.unparsed.map((u) => u.line), [3, 7, 9]);
  });

  it("keeps a long unparsed line whole beside the part it shows, so a change past the cut is a change", () => {
    const text = `${"x".repeat(600)} tail`;
    const [u] = readToml(text).unparsed;
    assert.equal(u.text, "x".repeat(512));
    assert.equal(u.whole, text);
    assert.equal(readToml("short garbage").unparsed[0].whole, undefined);
    const hash = { key: Buffer.alloc(32, 7) };
    const ids = (t: string) => unitsOf("codex-user-config", t, hash).units.map((x) => x.id);
    assert.notDeepEqual(ids(text), ids(`${"x".repeat(600)} tale`));
    assert.equal(unitsOf("codex-user-config", text, hash).units[0].text, `(unparsed) ${"x".repeat(512)}`);
  });

  it("drops a BOM and reads CRLF line ends, inside multi-line strings too: a file's line ends are no change", () => {
    const doc = readToml("\ufeffa = 1\r\n[t]\r\nb = 'x'\r\n");
    assert.deepEqual(lines(doc), ["a = 1", 't.b = "x"']);
    assert.deepEqual(doc.unparsed, []);
    const lf = [
      'developer_instructions = """',
      "Be terse.",
      "Use tabs. \\",
      "  Always.",
      '"""',
      "instructions = '''",
      "Line one.",
      "Line two.'''",
      'model = "o4"',
      "",
    ].join("\n");
    const crlf = lf.replace(/\n/g, "\r\n");
    assert.deepEqual(lines(readToml(lf)), [
      'developer_instructions = "Be terse.\\nUse tabs. Always.\\n"',
      'instructions = "Line one.\\nLine two."',
      'model = "o4"',
    ]);
    assert.deepEqual(lines(readToml(crlf)), lines(readToml(lf)));
    assert.deepEqual(lines(readToml(`\ufeff${crlf}`)), lines(readToml(lf)));
    // an escaped \r is the string's own
    assert.deepEqual(lines(readToml('a = """x\\r\ny"""\r\n')), ['a = "x\\r\\ny"']);
    const hash = { key: Buffer.alloc(32, 7) };
    const ids = (t: string) => unitsOf("codex-user-config", t, hash).ids;
    assert.deepEqual(ids(crlf), ids(lf));
  });

  it("never throws on hostile input, and stops nesting past its depth", () => {
    const hostile = [
      "[".repeat(10_000),
      "a = " + "[".repeat(10_000) + "]".repeat(10_000),
      "b = " + "{ x = ".repeat(5_000),
      '"""'.repeat(1000),
      "c = '''never closed",
      "=".repeat(1000),
      "\\".repeat(1000),
    ];
    for (const text of hostile) {
      const doc = readToml(text);
      assert.ok(Array.isArray(doc.entries) && Array.isArray(doc.unparsed));
    }
    const open = readToml("a = ['x', 'y\nb = 'z'\n'k' = 'v'");
    assert.deepEqual(lines(open), ['b = "z"', 'k = "v"'], "a literal string not closed on its line is unparsed; the next line is read");
    assert.deepEqual(open.unparsed.map((u) => u.text), ["a = ['x', 'y"]);
    const deep = readToml(`a = ${"[".repeat(40)}${"]".repeat(40)}\nb = 1`);
    assert.deepEqual(lines(deep), ["b = 1"], "nesting past 32 is not read; the next line is");
    assert.equal(deep.unparsed.length, 1);
  });
});

/** Best-of-five timings of `a` and `b`, after a warm-up, sampled alternately so a burst of load (or a GC pause) hits both. */
function timedPair(a: () => unknown, b: () => unknown): [number, number] {
  a();
  b();
  let ta = Infinity;
  let tb = Infinity;
  for (let i = 0; i < 5; i++) {
    let t0 = performance.now();
    a();
    ta = Math.min(ta, performance.now() - t0);
    t0 = performance.now();
    b();
    tb = Math.min(tb, performance.now() - t0);
  }
  return [ta, tb];
}

const SLACK = Math.max(1, Number(process.env.NEXUS_PERF_SLACK) || 1);
/** Sizes timed in turn, each under its cap before the next is tried, so a super-linear family stops early instead of running for minutes. */
const LADDER = [3_125, 6_250, 12_500, 25_000, 50_000, 100_000, 200_000];
/** A size's cap: a flat floor, then 4 s at 200 KB scaled down (these take a few ms to tens of ms when linear). */
const capFor = (bytes: number) => Math.max(250, (4000 * bytes) / 200_000) * SLACK;
/**
 * Below this the 200 KB run is not held to the growth ratio: the reader's many
 * small objects outgrow V8's young generation between 25 KB and 200 KB, which
 * alone can cost ~20× on a linear family, while a quadratic one takes seconds.
 * A family marked `strict` is held to it whatever the time (see TOML_FAMILIES).
 */
const RATIO_FLOOR_MS = 100 * SLACK;

/** A hostile input of about `n` bytes; `strict`: held to the growth ratio below RATIO_FLOOR_MS too. */
type Family = [name: string, build: (n: number) => string, strict?: "strict"];

/** `run` over each family: every size of the ladder under its cap, then 8× the input costing well under 24× the time. */
function assertLinear(label: string, run: (text: string) => unknown, families: Family[]): void {
  for (const [name, build, strict] of families) {
    for (const bytes of LADDER) {
      const text = build(bytes);
      const t0 = performance.now();
      run(text);
      const ms = performance.now() - t0;
      assert.ok(ms < capFor(bytes), `${label}, ${name}: ${bytes / 1000} KB took ${ms.toFixed(0)}ms (super-linear?)`);
    }
    const [rawSmall, tBig] = timedPair(() => run(build(25_000)), () => run(build(200_000)));
    const tSmall = Math.max(rawSmall, 0.5); // a floor: a few-ms ratio is timer and GC noise
    assert.ok((tBig < RATIO_FLOOR_MS && !strict) || tBig / tSmall < 24, `${label}, ${name}: 8× input grew ${(tBig / tSmall).toFixed(1)}× (${tSmall.toFixed(1)}→${tBig.toFixed(1)}ms)`);
  }
}

/**
 * Configs that are hostile to a reader or to the units cut from it (every key
 * under a table repeats the table's path). The `strict` ones put many short
 * values on one line, the shape where a search ahead from each value to the
 * line's end costs the line's length squared: allocating little, they take a
 * few ms at 200 KB when linear, and a quadratic reader still stays under
 * RATIO_FLOOR_MS there (~60 ms), so only the ratio can catch it.
 */
const TOML_FAMILIES: Family[] = [
  ["a config", (n) => '[mcp_servers.x]\ncommand = "npx"\nargs = ["-y", "pkg"]\n[features]\nhooks = true\n'.repeat(n / 60)],
  ["one long multi-line array", (n) => `a = [\n${'"x",\n'.repeat(n / 5)}]\n`],
  ["unclosed strings on every line", (n) => 'a = "open\n'.repeat(n / 10)],
  ["an unclosed multi-line string", (n) => `a = """${"x\\\n".repeat(n / 3)}`],
  ["lines it cannot read", (n) => "garbage without equals\n".repeat(n / 23)],
  ["nesting at the depth cap", (n) => `a = ${"[".repeat(32)}${"]".repeat(32)}\n`.repeat(n / 70)],
  ["opening brackets", (n) => "[".repeat(n)],
  ["a long table name, then many keys", (n) => `["${"x".repeat(n / 2)}"]\n${"a = 1\n".repeat(n / 12)}`],
  ["a table of many segments, then many keys", (n) => `[${"a.".repeat(n / 4)}b]\n${"a = 1\n".repeat(n / 12)}`],
  ["a long key over a wide inline table", (n) => `${"k".repeat(n / 2)} = { ${"x = 1, ".repeat(n / 14)}y = 2 }\n`],
  ["inline tables nested to the cap, many keys deep", (n) => `a = ${"{ b = ".repeat(31)}{ ${"k = 1, ".repeat(n / 8)}z = 1 }${" }".repeat(31)}\n`],
  ["hook handlers as one inline array", (n) => `[hooks]\nPreToolUse = [{ matcher = "x", hooks = [${'{ type = "command", command = "c" }, '.repeat(n / 38)}] }]\n`],
  ["inline hook groups under a table path at the cap", (n) => `[profiles."${"x".repeat(1000)}".hooks]\nE = [${"{ k = 1 }, ".repeat(n / 11)}{ k = 1 }]\n`],
  ["literal strings on one line", (n) => `a = [${"'x',".repeat(n / 4)}]\n`, "strict"],
  ["basic strings on one line", (n) => `a = [${'"x",'.repeat(n / 4)}]\n`, "strict"],
  ["literal keys in a one-line inline table", (n) => `a = { ${"'k' = 1, ".repeat(n / 10)}z = 1 }\n`, "strict"],
  ["a long unreadable line", (n) => `${"x".repeat(n)}\n`, "strict"],
];

test("readToml stays linear: 8× the input costs well under 24× the time", () => {
  assertLinear("readToml", readToml, TOML_FAMILIES);
});

test("the static rule's comment-aware hooks-off check stays linear", () => {
  assertLinear("codexHooksOffIn", codexHooksOffIn, [
    ["commented switches on every line", (n) => "# hooks = false\n".repeat(n / 16), "strict"],
    ["one long line of strings, then a commented switch", (n) => `x = [${'"a", '.repeat(n / 5)}] # hooks = false\n`, "strict"],
    ["escapes in a long string, then a commented switch", (n) => `x = "${"\\\"".repeat(n / 2)}" # hooks = false\n`, "strict"],
    ["a switch on the last of many lines", (n) => `${"a = 1\n".repeat(n / 6)}hooks = false\n`, "strict"],
  ]);
});

test("the units of a Codex config and of an exec-policy rules file stay linear", () => {
  const hash = { key: Buffer.alloc(32, 7) };
  assertLinear("config units", (text) => unitsOf("codex-user-config", text, hash), TOML_FAMILIES);
  assertLinear("rules units", (text) => unitsOf("codex-user-rules", text, hash), [
    ["many rules", (n) => 'prefix_rule(pattern = ["npm", "test"], decision = "allow")\n'.repeat(n / 58)],
    ["one long line", (n) => `${"x".repeat(n)}\n`],
  ]);
});
