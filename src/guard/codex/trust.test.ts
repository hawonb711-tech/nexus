/**
 * Codex's hook trust (trust.ts): the hash and key, pinned to state the real
 * Codex 0.164.0 binary accepted (__fixtures__/trust); the config.toml scanner;
 * the hook state and feature switch it reads; and the narrow edit of
 * `[hooks.state."<key>"]` tables, which keeps every other byte and refuses hook
 * state in any other form. The scanner stays linear in its input.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  CODEX_EVENT_LABELS, editHookTrust, hookStates, hooksFeatureOff, scanToml, tomlString, trustHash, trustKey,
} from "./trust.js";

const FIXTURES = fileURLToPath(new URL("./__fixtures__/trust/", import.meta.url));
const fixture = (name: string) => readFileSync(FIXTURES + name, "utf-8");

/** Every handler of a hooks.json, with the key and hash trust.ts gives it. */
function computed(hooksText: string, hooksPath: string, platform: NodeJS.Platform = "linux"): Map<string, string | null> {
  const out = new Map<string, string | null>();
  const doc = JSON.parse(hooksText);
  for (const [event, groups] of Object.entries(doc.hooks) as [string, any[]][]) {
    groups.forEach((g, gi) => g.hooks.forEach((h: unknown, hi: number) => out.set(trustKey(hooksPath, event, gi, hi), trustHash(event, g.matcher, h, platform))));
  }
  return out;
}

/** The `trusted_hash` of each `[hooks.state."<key>"]` table in a captured config.toml. */
function captured(tomlText: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const [key, state] of hookStates(scanToml(tomlText))) if (state.trustedHash) out.set(key, state.trustedHash);
  return out;
}

/** The hooks.json path the captured keys name (the text before `:<event>:`). */
const hooksPathOf = (keys: Iterable<string>) => [...keys][0].replace(/:[a-z_]+:\d+:\d+$/, "");

describe("trustHash and trustKey match what the real Codex binary trusted", () => {
  for (const [name, toml, ran] of [
    ["the research run (run3)", "run3-trust.toml", null],
    ["the probe run", "probe-trust.toml", (key: string) => !key.endsWith(":post_tool_use:0:0")],
    ["the e2e install", "install-config.toml", (key: string) => key.includes("hooks.json:")],
  ] as const) {
    it(name, () => {
      const hooks = { "run3-trust.toml": "run3-hooks.json", "probe-trust.toml": "probe-hooks.json", "install-config.toml": "install-hooks.json" }[toml];
      const want = captured(fixture(toml));
      const got = computed(fixture(hooks), hooksPathOf(want.keys()));
      let checked = 0;
      for (const [key, hash] of want) {
        if (ran && !ran(key)) continue;
        assert.equal(got.get(key), hash, key);
        checked++;
      }
      assert.ok(checked >= 4, `${checked} hooks checked`);
    });
  }

  it("the e2e install's hashes cover Nexus's own handlers, SessionStart's context limit included", () => {
    const want = captured(fixture("install-config.toml"));
    const doc = JSON.parse(fixture("install-hooks.json"));
    const ss = doc.hooks.SessionStart.find((g: any) => g.hooks[0].command.endsWith("--agent codex"));
    assert.ok(ss.hooks[0].additionalContextLimit > 2500);
    const key = [...want.keys()].find((k) => k.endsWith(":session_start:0:0"))!;
    assert.equal(trustHash("SessionStart", undefined, ss.hooks[0]), want.get(key));
    // without the limit (or with Codex's default) the hash differs: the limit is part of what is trusted
    assert.notEqual(trustHash("SessionStart", undefined, { ...ss.hooks[0], additionalContextLimit: undefined }), want.get(key));
  });

  it("keys a handler by the hooks.json path, the event's label and its position", () => {
    assert.equal(trustKey("/h/.codex/hooks.json", "PreToolUse", 2, 1), "/h/.codex/hooks.json:pre_tool_use:2:1");
    assert.equal(trustKey("C:\\Users\\me\\.codex\\hooks.json", "SessionStart", 0, 0), "C:\\Users\\me\\.codex\\hooks.json:session_start:0:0");
    assert.equal(Object.keys(CODEX_EVENT_LABELS).length, 14);
  });
});

describe("trustHash normalizes as Codex does", () => {
  const h = { type: "command", command: "node hook.js", timeout: 30 };
  it("leaves out Codex's default context limit, and the limit on events that cannot return context", () => {
    assert.equal(trustHash("SessionStart", undefined, { ...h, additionalContextLimit: 2500 }), trustHash("SessionStart", undefined, h));
    assert.notEqual(trustHash("SessionStart", undefined, { ...h, additionalContextLimit: 2501 }), trustHash("SessionStart", undefined, h));
    assert.equal(trustHash("Stop", undefined, { ...h, additionalContextLimit: 9000 }), trustHash("Stop", undefined, h));
  });
  it("reads the timeout as Codex does: 600 by default, at least 1; SessionEnd 1 by default, held to 1-3", () => {
    assert.equal(trustHash("PreToolUse", "x", { ...h, timeout: undefined }), trustHash("PreToolUse", "x", { ...h, timeout: 600 }));
    assert.equal(trustHash("PreToolUse", "x", { ...h, timeout: 0 }), trustHash("PreToolUse", "x", { ...h, timeout: 1 }));
    assert.equal(trustHash("SessionEnd", undefined, { ...h, timeout: undefined }), trustHash("SessionEnd", undefined, { ...h, timeout: 1 }));
    assert.equal(trustHash("SessionEnd", undefined, { ...h, timeout: 99 }), trustHash("SessionEnd", undefined, { ...h, timeout: 3 }));
  });
  it("hashes the matcher only for events that match on one, and async as a boolean", () => {
    assert.equal(trustHash("Stop", "anything", h), trustHash("Stop", undefined, h));
    assert.notEqual(trustHash("PreToolUse", "^Bash$", h), trustHash("PreToolUse", undefined, h));
    assert.notEqual(trustHash("PreToolUse", "", h), trustHash("PreToolUse", undefined, h), "an empty matcher is still a matcher");
    assert.equal(trustHash("PreToolUse", "x", { ...h, async: false }), trustHash("PreToolUse", "x", h));
    assert.notEqual(trustHash("PreToolUse", "x", { ...h, async: true }), trustHash("PreToolUse", "x", h));
  });
  it("on Windows hashes commandWindows in place of command; elsewhere ignores it", () => {
    const both = { ...h, commandWindows: "node.exe hook.js" };
    assert.equal(trustHash("PreToolUse", "x", both, "linux"), trustHash("PreToolUse", "x", h, "linux"));
    assert.equal(trustHash("PreToolUse", "x", both, "win32"), trustHash("PreToolUse", "x", { ...h, command: "node.exe hook.js" }, "win32"));
  });
  it("is null for a handler Codex would not load as a command hook", () => {
    for (const bad of [
      { type: "mcp_tool", server: "s", tool: "t" }, { type: "command" }, { type: "command", command: "  " },
      { ...h, timeout: -1 }, { ...h, timeout: 1.5 }, { ...h, async: "yes" }, { ...h, statusMessage: 3 }, null, "node hook.js",
    ]) assert.equal(trustHash("PreToolUse", "x", bad), null, JSON.stringify(bad));
    assert.equal(trustHash("NotAnEvent", "x", h), null);
    assert.equal(trustHash("PreToolUse", 42, h), null);
  });
});

describe("scanToml", () => {
  it("finds headers and key/values, and skips what only looks like one inside multi-line values", () => {
    const text = [
      'title = "x" # a comment',
      'ml = """',
      '[hooks.state."fake"]',
      'trusted_hash = "no"',
      '"""',
      "lit = '''",
      "[hooks]",
      "'''",
      "arr = [",
      '  "[hooks.state.\\"also-fake\\"]", # a comment in an array',
      "  [1, 2],",
      "]",
      "inline = { a = 1, b.c = 'x' }",
      "",
      "[ hooks . state . \"real\" ]",
      "trusted_hash = 'sha256:abc'",
      "[[hooks.PreToolUse]]",
      'matcher = "^Bash$"',
      "when = 1979-05-27 07:32:00Z",
    ].join("\n");
    const scan = scanToml(text);
    assert.equal(scan.error, null);
    assert.deepEqual(scan.statements.map((s) => [s.kind, s.key.join("."), s.line]), [
      ["keyval", "title", 1], ["keyval", "ml", 2], ["keyval", "lit", 6], ["keyval", "arr", 9], ["keyval", "inline", 13],
      ["table", "hooks.state.real", 15], ["keyval", "trusted_hash", 16], ["array", "hooks.PreToolUse", 17], ["keyval", "matcher", 18], ["keyval", "when", 19],
    ]);
    assert.deepEqual(scan.statements[1].value, { type: "string", value: '[hooks.state."fake"]\ntrusted_hash = "no"\n' });
    assert.deepEqual([...hookStates(scan).keys()], ["real"]);
  });

  it("decodes strings as TOML does: escapes, literal strings, line-ending backslashes", () => {
    const scan = scanToml('a = "x\\ty\\u00e9\\U0001F600\\"\\\\"\nb = \'C:\\path\'\nc = """\\\n   joined"""\n');
    assert.deepEqual(scan.statements.map((s) => (s.value as { value: string }).value), ["x\ty\u00e9\u{1F600}\"\\", "C:\\path", "joined"]);
  });

  it("reports the line it cannot read", () => {
    for (const [text, line] of [
      ["a = 1\nb = \n", 2], ["a = 1\n\n[hooks\n", 3], ['a = "open\n', 1], ["x = yes\n", 1], ["a = 1 2\n", 1], ['m = """never closed\n', 1],
      [`deep = ${"[".repeat(100)}${"]".repeat(100)}\n`, 1],
    ] as const) {
      assert.equal(scanToml(text).error?.line, line, JSON.stringify(text));
    }
  });

  it("keeps the file's line breaks, and takes a leading byte-order mark", () => {
    assert.equal(scanToml("a = 1\r\nb = 2\r\n").newline, "\r\n");
    assert.equal(scanToml("a = 1\nb = 2\n").newline, "\n");
    assert.equal(scanToml("\ufeffa = 1\n").error, null);
  });

  it("stays linear on long values, many tables and deep-but-bounded nesting", () => {
    const timed = (fn: () => unknown) => {
      fn();
      const t0 = performance.now();
      fn();
      return performance.now() - t0;
    };
    const tables = (n: number) => Array.from({ length: n }, (_, i) => `[hooks.state."/h/hooks.json:pre_tool_use:${i}:0"]\ntrusted_hash = "sha256:${"ab".repeat(32)}"\n`).join("\n");
    const small = tables(2_000);
    const big = tables(20_000);
    assert.equal(scanToml(big).statements.length, 40_000);
    const ratio = timed(() => scanToml(big)) / Math.max(timed(() => scanToml(small)), 1);
    assert.ok(ratio < 40, `10x the tables took ${ratio.toFixed(1)}x`);
    const shapes = [
      `s = """${"x\\\"\"".repeat(200_000)}"""\n`,
      `a = [${'"[x]", '.repeat(150_000)}]\n`,
      `t = {${Array.from({ length: 50_000 }, (_, i) => `k${i} = ${i}`).join(", ")}}\n`,
      `n = ${"[".repeat(64)}${"]".repeat(64)}\n`.repeat(10_000),
      `${"# comment line\n".repeat(100_000)}`,
    ];
    for (const text of shapes) {
      const ms = timed(() => scanToml(text));
      assert.ok(ms < 2000, `${text.slice(0, 12)}…: ${ms.toFixed(0)} ms`);
    }
    const edit = timed(() => editHookTrust(big, { set: new Map([["/h/hooks.json:pre_tool_use:1:0", "sha256:new"]]), remove: new Set(["/h/hooks.json:pre_tool_use:2:0"]) }));
    assert.ok(edit < 3000, `editing a 20,000-table file took ${edit.toFixed(0)} ms`);
  });
});

describe("hookStates and hooksFeatureOff read config.toml as Codex does", () => {
  it("reads hook state in every form, keys trimmed as Codex trims them", () => {
    const text = [
      'hooks.state."dotted".trusted_hash = "h1"',
      'hooks.state." spaced ".enabled = false',
      "[hooks.state]",
      '"inline" = { trusted_hash = "h2", enabled = true }',
      '[hooks.state."table"]',
      'trusted_hash = "h3"',
    ].join("\n");
    assert.deepEqual(Object.fromEntries(hookStates(scanToml(text))), {
      dotted: { trustedHash: "h1", enabled: null },
      spaced: { trustedHash: null, enabled: false },
      inline: { trustedHash: "h2", enabled: true },
      table: { trustedHash: "h3", enabled: null },
    });
  });

  it("finds the hooks feature turned off, by [features], a dotted key, an inline table, the old alias or the profile", () => {
    const off = (text: string) => hooksFeatureOff(scanToml(text));
    assert.equal(off(""), null, "on by default");
    assert.equal(off("[features]\nhooks = false\n"), "features.hooks = false (line 2)");
    assert.equal(off("features.codex_hooks = false\n"), "features.codex_hooks = false (line 1)");
    assert.equal(off("features = { hooks = false }\n"), "features.hooks = false (line 1)");
    assert.equal(off("[features]\ncodex_hooks = false\nhooks = true\n"), null, "hooks is applied after codex_hooks");
    assert.equal(off("[features]\nhooks = true\ncodex_hooks = false\n"), null, "whatever their order in the file");
    assert.equal(off("[features]\nother = false\n[hooks]\nfeatures = false\n"), null);
    assert.equal(off('profile = "work"\n[profiles.work.features]\nhooks = false\n'), "profiles.work.features.hooks = false (line 3)");
    assert.equal(off('[profiles.other.features]\nhooks = false\n'), null, "a profile that is not selected");
    assert.equal(off('profile = "work"\n[features]\nhooks = false\n[profiles.work.features]\nhooks = true\n'), null, "the profile's switch wins");
  });
});

describe("editHookTrust", () => {
  const set = (entries: [string, string][]) => ({ set: new Map(entries) });
  const ok = (r: ReturnType<typeof editHookTrust>) => {
    assert.ok(r.ok, r.ok ? "" : r.reason);
    return r;
  };

  it("appends tables after the rest of the file, which stays byte for byte; removing them restores it", () => {
    for (const original of ['model = "x"\n', 'model = "x"\n\n[features]\nweb = true # keep\n', "", 'a = 1\r\n[t]\r\nb = 2\r\n']) {
      const r = ok(editHookTrust(original, set([["/h/hooks.json:pre_tool_use:1:0", "sha256:a"], ["/h/hooks.json:session_start:0:0", "sha256:b"]])));
      assert.ok(r.text.startsWith(original), "the file's own text comes first, unchanged");
      assert.deepEqual(r.set, ["/h/hooks.json:pre_tool_use:1:0", "/h/hooks.json:session_start:0:0"]);
      const nl = original.includes("\r\n") ? "\r\n" : "\n";
      assert.ok(r.text.endsWith(`[hooks.state."/h/hooks.json:session_start:0:0"]${nl}trusted_hash = "sha256:b"${nl}`));
      assert.deepEqual(Object.fromEntries(hookStates(scanToml(r.text))), {
        "/h/hooks.json:pre_tool_use:1:0": { trustedHash: "sha256:a", enabled: null },
        "/h/hooks.json:session_start:0:0": { trustedHash: "sha256:b", enabled: null },
      });
      const back = ok(editHookTrust(r.text, { remove: new Set(r.set) }));
      assert.equal(back.text, original, JSON.stringify(original));
    }
  });

  it("adds a final line break the file lacked before appending", () => {
    const r = ok(editHookTrust('model = "x"', set([["k", "h"]])));
    assert.equal(r.text, 'model = "x"\n\n[hooks.state."k"]\ntrusted_hash = "h"\n');
  });

  it("replaces only the value of an existing trusted_hash, keeping its comment and the table's other keys", () => {
    const text = '[hooks.state."k"]\nenabled = false\ntrusted_hash = "old" # by me\n\n[mcp_servers.x]\ncommand = "y"\n';
    const r = ok(editHookTrust(text, set([["k", "new"]])));
    assert.equal(r.text, '[hooks.state."k"]\nenabled = false\ntrusted_hash = "new" # by me\n\n[mcp_servers.x]\ncommand = "y"\n');
    assert.deepEqual(ok(editHookTrust(r.text, set([["k", "new"]]))).set, [], "nothing to do when it already matches");
  });

  it("adds trusted_hash under an existing table that has none", () => {
    const r = ok(editHookTrust('[hooks.state."k"]\nenabled = false\n[other]\nx = 1\n', set([["k", "h"]])));
    assert.equal(r.text, '[hooks.state."k"]\ntrusted_hash = "h"\nenabled = false\n[other]\nx = 1\n');
  });

  it("removes a table between others, and only the tables named", () => {
    const text = 'a = 1\n\n[hooks.state."mine"]\ntrusted_hash = "u"\n\n[hooks.state."nexus"]\ntrusted_hash = "n"\n\n[projects."/w"]\ntrust_level = "trusted"\n';
    const r = ok(editHookTrust(text, { remove: new Set(["nexus", "absent"]) }));
    assert.equal(r.text, 'a = 1\n\n[hooks.state."mine"]\ntrusted_hash = "u"\n\n[projects."/w"]\ntrust_level = "trusted"\n');
    assert.deepEqual(r.removed, ["nexus"]);
  });

  it("writes keys as TOML basic strings: quotes, backslashes and control characters escaped", () => {
    const key = 'C:\\Users\\me\\"x"\u0001\u007f\\.codex\\hooks.json:pre_tool_use:0:0';
    const r = ok(editHookTrust("", set([[key, "h"]])));
    assert.ok(r.text.startsWith(`[hooks.state.${tomlString(key)}]`));
    assert.ok(!/[\u0001\u007f]/.test(r.text));
    assert.deepEqual([...hookStates(scanToml(r.text)).keys()], [key]);
  });

  it("refuses hook state in any other form, leaving the file to the user", () => {
    for (const [text, why] of [
      ['hooks = { state = { k = { trusted_hash = "x" } } }\n', /dotted key or an inline table/],
      ['hooks.state."k".trusted_hash = "x"\n', /dotted key or an inline table/],
      ['[hooks]\nstate = { k = { trusted_hash = "x" } }\n', /hook state with a dotted key or an inline table/],
      ['[hooks.state]\n"k" = { trusted_hash = "x" }\n', /hook state with a dotted key or an inline table/],
      ['[hooks.state."k"]\ntrusted_hash = "x"\n[hooks.state."k"]\nenabled = true\n', /a second time/],
      ['[hooks.state."k"]\ntrusted_hash = "x"\ntrusted_hash = "y"\n', /twice/],
      ['[[hooks.state]]\nk = 1\n', /array of tables/],
      ['[hooks.state."k".more]\nx = 1\n', /inside a hook's state/],
      ["a = [1,\n", /cannot read line 1/],
    ] as const) {
      const r = editHookTrust(text, set([["k", "h"]]));
      assert.equal(r.ok, false, text);
      assert.match((r as { reason: string }).reason, why, text);
    }
  });

  it("does not mistake other tables for hook state: [hooks] keys, inline hooks, profiles", () => {
    const text = '[hooks]\nnote = 1\n[[hooks.PreToolUse]]\nmatcher = "^Bash$"\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "x"\n[profiles.p]\nhooks.state = 1\n';
    const r = ok(editHookTrust(text, set([["k", "h"]])));
    assert.ok(r.text.startsWith(text));
  });
});
