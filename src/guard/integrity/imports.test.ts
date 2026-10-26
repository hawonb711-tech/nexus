import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { importTokens, MAX_IMPORT_LOOKUPS, resolveImports, resolveImportToken, type ImportSource } from "./imports.js";

describe("@import tokens", () => {
  it("skips fenced blocks and inline code spans", () => {
    const md = [
      "See @docs/style.md and @./local.md.",
      "Inline `@skipped/in-code.md` but @after/code.md",
      "``Double `@still/code.md` span`` then @real/one.md",
      "```",
      "@inside/fence.md",
      "```",
      "~~~md",
      "@inside/tilde.md",
      "```",
      "@still/inside.md",
      "~~~",
      "@after/fence.md",
    ].join("\n");
    assert.deepEqual(importTokens(md), ["docs/style.md", "./local.md", "./local.md.", "after/code.md", "real/one.md", "after/fence.md"]);
  });

  it("reads tokens with Claude Code's grammar, after whitespace or inline markup", () => {
    assert.deepEqual(importTokens("@alice please review; mail me@example.com; @README.md @notes.markdown @v2.0.123456789 @~/x @/abs"), [
      "alice", "README.md", "notes.markdown", "v2.0.123456789", "~/x", "/abs",
    ]);
    // a token ending in markup comes cut first, then as written; a cut form naming a directory is dropped
    assert.deepEqual(importTokens("(@paren/x.md) \"@quote/x.md\" @a/<b> @a/(c) word@not/one.md"), [
      "paren/x.md", "paren/x.md)", "quote/x.md", "quote/x.md\"", "a/<b>", "a/(c", "a/(c)",
    ]);
    // Claude Code loads only ./ ~/ /x and tokens starting with [A-Za-z0-9._-]
    assert.deepEqual(importTokens("@/ @~user/x @(x) @@y @'q' @#top @-x @../up.md"), ["-x", "../up.md"]);
    assert.deepEqual(importTokens(`@${"a/".repeat(300)}`), [], "a token longer than 512 characters is not an import");
    assert.deepEqual(importTokens(`@${"a\\ ".repeat(300)}`), [], "escaped spaces count toward the cap");
  });

  it("finds tokens inside inline markup, as Claude Code's scan of each text token does", () => {
    const tokens = importTokens([
      "**@docs/bold.md**",
      "*@docs/italic.md* and _@docs/under.md_, ~~@docs/struck.md~~",
      "[@docs/link.md](https://example.com/x) and ![@docs/img.md](i.png)",
      "<b>@docs/html.md</b> <span>@docs/span.md</span>",
      "- @docs/item.md",
      "1. **@docs/num.md**.",
      "> @docs/quote.md",
      "| @docs/cell.md |@docs/tight.md|",
      "Inline `**@docs/in-code.md**` is code",
    ].join("\n"));
    for (const n of ["bold", "italic", "under", "struck", "link", "img", "html", "span", "item", "num", "quote", "cell", "tight"]) {
      assert.ok(tokens.includes(`docs/${n}.md`), `docs/${n}.md in ${JSON.stringify(tokens)}`);
    }
    assert.ok(!tokens.some((t) => t.includes("in-code")), "inline code spans are still skipped");
  });

  it("finds each of two markup spans with no whitespace between them, and one closed right before text", () => {
    const cases: [string, string[]][] = [
      ["**@a.md**,**@b.md**", ["a.md", "b.md"]],
      ["*@a.md*@b.md*", ["a.md", "b.md"]],
      ["[@a.md](x)[@b.md](y)", ["a.md", "b.md"]],
      ["<b>@a.md</b><i>@b.md</i>", ["a.md", "b.md"]],
      ["|@a.md|@b.md|", ["a.md", "b.md"]],
      ["~~@a.md~~@b.md", ["a.md", "b.md"]],
      ["**@a.md**x and <b>@b.md</b>y", ["a.md", "b.md"]],
      ["**@my_file.md**: snake case survives", ["my_file.md"]],
    ];
    for (const [line, wanted] of cases) {
      const tokens = importTokens(line);
      for (const w of wanted) assert.ok(tokens.includes(w), `${w} from ${line}: ${JSON.stringify(tokens)}`);
    }
    // a fragment or escaped space in the first span stays its own
    assert.ok(importTokens("**@a\\ b.md#x**,**@c.md**").includes("a b.md"));
  });

  it("strips a #fragment and unescapes `\\ ` the way Claude Code does", () => {
    assert.deepEqual(importTokens([
      "Usage notes: @docs/payload.md#usage",
      "Also @docs/my\\ notes.md",
      "And @docs/(team).md",
      "Plus @docs/it's.md",
      "Bare @NOTES",
      "Stops at a backslash: @docs/a\\b.md",
    ].join("\n")), ["docs/payload.md", "docs/my notes.md", "docs/(team).md", "docs/it's.md", "NOTES", "docs/a"]);
  });

  it("resolves relative tokens from the importing file, ~ from home, absolute as is", () => {
    assert.equal(resolveImportToken("docs/x.md", "/r/sub/CLAUDE.md", "/h"), resolve("/r/sub/docs/x.md"));
    assert.equal(resolveImportToken("../x.md", "/r/sub/CLAUDE.md", "/h"), resolve("/r/x.md"));
    assert.equal(resolveImportToken("~/prefs.md", "/r/CLAUDE.md", "/h"), join("/h", "prefs.md"));
    assert.equal(resolveImportToken("/etc/x.md", "/r/CLAUDE.md", "/h"), resolve("/etc/x.md"));
  });
});

describe("resolveImports", () => {
  let dir: string;
  let root: string;
  let home: string;
  let config: string;
  beforeEach(() => {
    dir = realpathSync.native(mkdtempSync(join(tmpdir(), "nexus-imports-")));
    root = join(dir, "repo");
    home = join(dir, "home");
    config = join(home, ".claude");
    for (const d of [root, config]) mkdirSync(d, { recursive: true });
  });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  const write = (path: string, text: string) => {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text);
  };
  const run = (sources: ImportSource[], extra = {}) => resolveImports(sources, { home, root, configDir: config, platform: process.platform, ...extra });
  const source = (path: string, text: string): ImportSource => { write(path, text); return { path, text }; };

  it("follows imports relative to each importing file, with roles by location", () => {
    write(join(root, "docs", "style.md"), "Style. @../shared/common.md\n");
    write(join(root, "shared", "common.md"), "Common.\n");
    write(join(config, "prefs.md"), "Prefs.\n");
    write(join(dir, "elsewhere", "team.md"), "Team.\n");
    // an @mention ends at a backslash (Claude Code's own grammar), so a Windows path is written with "/"
    const res = run([source(join(root, "CLAUDE.md"), `@docs/style.md @~/.claude/prefs.md @${join(dir, "elsewhere", "team.md").replace(/\\/g, "/")}\n`)]);
    assert.equal(res.truncated, false);
    assert.deepEqual(res.targets.map((t) => [t.path, t.role, t.state, t.depth]), [
      [join(root, "docs", "style.md"), "import", "file", 1],
      [join(config, "prefs.md"), "import", "file", 1],
      [join(dir, "elsewhere", "team.md"), "external-import", "file", 1],
      [join(root, "shared", "common.md"), "import", "file", 2],
    ]);
    assert.equal(res.targets[3].from, join(root, "docs", "style.md"));
  });

  it("stops at depth 4", () => {
    for (let i = 1; i <= 6; i++) write(join(root, `l${i}.md`), `level ${i} @./l${i + 1}.md\n`);
    const res = run([source(join(root, "CLAUDE.md"), "@./l1.md\n")]);
    assert.deepEqual(res.targets.map((t) => [t.path.slice(root.length + 1), t.depth]), [["l1.md", 1], ["l2.md", 2], ["l3.md", 3], ["l4.md", 4]]);
  });

  it("cuts cycles by real path, symlinked aliases included", () => {
    write(join(root, "a.md"), "@./b.md\n");
    write(join(root, "b.md"), "@./a.md @../repo/CLAUDE.md\n");
    const res = run([source(join(root, "CLAUDE.md"), "@./a.md @./a.md\n")]);
    assert.deepEqual(res.targets.map((t) => t.path), [join(root, "a.md"), join(root, "b.md")]);
    try {
      symlinkSync(join(root, "a.md"), join(root, "alias.md"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return; // no symlinks on this Windows box
      throw error;
    }
    const aliased = run([source(join(root, "CLAUDE.md"), "@./a.md @./alias.md\n")]);
    assert.deepEqual(aliased.targets.map((t) => t.path), [join(root, "a.md"), join(root, "b.md")]);
  });

  it("watches targets named inside bold, italic, link text, inline HTML and list items, adjacent ones too", () => {
    const names = ["bold", "italic", "under", "link", "html", "item", "num"];
    const pairs = ["pair1", "pair2", "pair3", "pair4", "pair5", "pair6"];
    for (const n of [...names, ...pairs]) write(join(root, "docs", `${n}.md`), `${n}\n`);
    write(join(root, "docs", "odd.md_"), "a file whose name really ends in _\n");
    const res = run([source(join(root, "CLAUDE.md"), [
      "**@docs/bold.md**",
      "*@docs/italic.md* and _@docs/under.md_",
      "See [@docs/link.md](https://example.com/docs).",
      "<b>@docs/html.md</b>",
      "- @docs/item.md",
      "1. **@./docs/num.md**: numbered",
      "Odd but real: @docs/odd.md_",
      "Missing, explicit: **@./docs/gone.md**",
      "Adjacent: **@docs/pair1.md**,**@docs/pair2.md** [@docs/pair3.md](x)[@docs/pair4.md](y) <b>@docs/pair5.md</b><i>@docs/pair6.md</i>",
    ].join("\n"))]);
    assert.deepEqual(res.targets.map((t) => [t.path, t.state]), [
      ...names.map((n) => [join(root, "docs", `${n}.md`), "file"]),
      [join(root, "docs", "odd.md_"), "file"],
      [join(root, "docs", "gone.md"), "missing"],
      ...pairs.map((n) => [join(root, "docs", `${n}.md`), "file"]),
    ]);
    assert.ok(!res.targets.some((t) => t.path.endsWith("**")), "a raw form ending in markup is recorded only when it names a file");
  });

  it("records a missing target only for an explicit path token", () => {
    const res = run([source(join(root, "CLAUDE.md"), "@./gone.md @../gone2.md @~/gone3.md @/nonexistent-nexus/x.md @docs/none.md @scope/pkg\n")]);
    assert.deepEqual(res.targets.map((t) => [t.path, t.state]), [
      [join(root, "gone.md"), "missing"],
      [join(dir, "gone2.md"), "missing"],
      [join(home, "gone3.md"), "missing"],
      [resolve("/nonexistent-nexus/x.md"), "missing"],
    ]);
    assert.equal(res.targets[1].role, "external-import");
  });

  it("watches every target Claude Code loads, and no @mention that names no file", () => {
    for (const name of ["docs/payload.md", "docs/my notes.md", "docs/(team).md", "docs/it's.md", "NOTES"]) write(join(root, name), "x\n");
    const res = run([source(join(root, "CLAUDE.md"), [
      "Usage notes: @docs/payload.md#usage",
      "Also @docs/my\\ notes.md",
      "And @docs/(team).md",
      "Plus @docs/it's.md",
      "Bare @NOTES then thanks @alice and @bob.",
    ].join("\n"))]);
    assert.deepEqual(res.targets.map((t) => [t.path, t.state]), [
      [join(root, "docs", "payload.md"), "file"],
      [join(root, "docs", "my notes.md"), "file"],
      [join(root, "docs", "(team).md"), "file"],
      [join(root, "docs", "it's.md"), "file"],
      [join(root, "NOTES"), "file"],
    ]);
  });

  it("caps the number of targets and says so", () => {
    const tokens = Array.from({ length: 8 }, (_, i) => `@./t${i}.md`).join(" ");
    for (let i = 0; i < 8; i++) write(join(root, `t${i}.md`), "x\n");
    const res = run([source(join(root, "CLAUDE.md"), tokens)], { maxTargets: 5 });
    assert.equal(res.targets.length, 5);
    assert.equal(res.truncated, true);
    assert.equal(run([source(join(root, "CLAUDE.md"), tokens)]).truncated, false);
  });

  it("looks a repeated token up once, and caps distinct lookups", () => {
    write(join(root, "real.md"), "x\n");
    const asked: string[] = [];
    const counting = (path: string) => {
      asked.push(path);
      return path === join(root, "real.md") ? { real: path, text: "x\n" } : null;
    };
    const mentions = (n: number) => Array.from({ length: n }, (_, i) => `@m${i}`).join(" ");
    const text = `${mentions(10)} @./gone.md\n${mentions(10)} @./gone.md @docs/../gone.md\n@./real.md`;
    const res = run([source(join(root, "CLAUDE.md"), text)], { load: counting });
    assert.equal(asked.length, 12, "ten @mentions, gone.md and real.md: one lookup each");
    assert.equal(res.lookups, 12);
    assert.equal(res.truncated, false);
    assert.deepEqual(res.targets.map((t) => [t.path, t.state]), [[join(root, "gone.md"), "missing"], [join(root, "real.md"), "file"]]);
    // a non-explicit miss, then an explicit token for the same path: recorded missing, no second lookup
    asked.length = 0;
    const later = run([source(join(root, "CLAUDE.md"), "@gone.md then @./gone.md\n")], { load: counting });
    assert.deepEqual(later.targets.map((t) => [t.path, t.state]), [[join(root, "gone.md"), "missing"]]);
    assert.equal(asked.length, 1);
    // past the cap the walk stops, truncated, even before a real import
    const capped = run([source(join(root, "CLAUDE.md"), `${mentions(10)}\n@./real.md\n`)], { load: counting, maxLookups: 5 });
    assert.deepEqual(capped.targets, []);
    assert.equal(capped.truncated, true);
    assert.equal(capped.lookups, 5);
    // the default cap
    const flood = run([source(join(root, "CLAUDE.md"), `${mentions(MAX_IMPORT_LOOKUPS + 1)}\n@./real.md\n`)]);
    assert.equal(flood.truncated, true);
    assert.equal(flood.lookups, MAX_IMPORT_LOOKUPS);
  });

  it("does not parse a target too large to scan, but still lists it", () => {
    write(join(root, "big.md"), "x");
    const res = run([source(join(root, "CLAUDE.md"), "@./big.md\n")], {
      load: (path: string) => ({ real: path, text: null }),
    });
    assert.deepEqual(res.targets.map((t) => t.state), ["file"]);
  });
});
