/**
 * Codex's hooks switch (hooks-switch.ts): the rule Codex 0.164.0 applies, and
 * that every check of it agrees on a real config: the install and `guard
 * status --codex` (trust.ts `hooksFeatureOff`), the integrity layer's units
 * (units.ts, which `guard integrity status` and a Claude Code session's
 * hooks-off warning read) and the static write guard (command.ts).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { codexHooksOffIn, inspectFileWrite } from "../command.js";
import { unitsOf } from "../integrity/units.js";
import { hooksOffSwitches, isCodexRequirements } from "./hooks-switch.js";
import { hooksFeatureOff, scanToml } from "./trust.js";

const set = (path: string, value: boolean) => ({ path: path.split("."), value, at: path });

describe("hooksOffSwitches", () => {
  it("applies codex_hooks, then hooks, from [features] only", () => {
    assert.deepEqual(hooksOffSwitches([]), [], "on by default");
    assert.deepEqual(hooksOffSwitches([set("features.hooks", false)]), ["features.hooks"]);
    assert.deepEqual(hooksOffSwitches([set("features.codex_hooks", false)]), ["features.codex_hooks"]);
    assert.deepEqual(hooksOffSwitches([set("features.codex_hooks", false), set("features.hooks", true)]), []);
    assert.deepEqual(hooksOffSwitches([set("features.hooks", true), set("features.codex_hooks", false)]), [], "hooks decides wherever it is");
    assert.deepEqual(hooksOffSwitches([set("features.codex_hooks", false), set("features.hooks", false)]), ["features.hooks"]);
    assert.deepEqual(hooksOffSwitches([set("features.hooks", false), set("features.hooks", true)]), [], "the last one set");
    assert.deepEqual(hooksOffSwitches([set("profiles.ci.features.hooks", false), set("mcp_servers.x.hooks", false), set("hooks", false)]), []);
  });

  it("reads allow_managed_hooks_only in a managed file, and an edit's top-level keys as the feature's", () => {
    assert.deepEqual(hooksOffSwitches([set("allow_managed_hooks_only", true)]), []);
    assert.deepEqual(hooksOffSwitches([set("allow_managed_hooks_only", true)], { managed: true }), ["allow_managed_hooks_only"]);
    assert.deepEqual(hooksOffSwitches([set("allow_managed_hooks_only", false)], { managed: true }), []);
    assert.deepEqual(hooksOffSwitches([set("features.hooks", false), set("allow_managed_hooks_only", true)], { managed: true }), ["features.hooks", "allow_managed_hooks_only"]);
    assert.deepEqual(hooksOffSwitches([set("hooks", false)], { fragment: true }), ["hooks"]);
    assert.deepEqual(hooksOffSwitches([set("codex_hooks", false), set("hooks", true)], { fragment: true }), []);
    assert.deepEqual(hooksOffSwitches([set("x.hooks", false)], { fragment: true }), []);
    assert.deepEqual(hooksOffSwitches([set("allow_managed_hooks_only", true)], { fragment: true, managed: true }), ["allow_managed_hooks_only"]);
  });
});

describe("every check of Codex's hooks switch agrees on a real config", () => {
  const KEY = { key: Buffer.alloc(32, 3) };
  /** A whole config.toml, and whether Codex 0.164.0 runs no hook under it. */
  const USER: [string, boolean][] = [
    ["", false],
    ['model = "gpt-5.5"\n', false],
    ["[features]\nhooks = false\n", true],
    ["[features]\ncodex_hooks = false\n", true],
    ["features.hooks = false\n", true],
    ["features = { hooks = false, web_search_request = true }\n", true],
    ['[features]\n"hooks" = false\n', true],
    ['model = "gpt-5.5"\n\n[features]\nweb_search_request = true\ncodex_hooks = false # quiet\n', true],
    ["[features]\ncodex_hooks = false\nhooks = true\n", false],
    ["[features]\nhooks = true\ncodex_hooks = false\n", false],
    ["[features]\ncodex_hooks = false\nhooks = false\n", true],
    ["[profiles.ci.features]\nhooks = false\n", false],
    ['profile = "ci"\n[profiles.ci.features]\nhooks = false\n', false],
    ['[mcp_servers.docs]\ncommand = "docs-mcp"\nhooks = false\n', false],
    ["allow_managed_hooks_only = true\n", false],
    ["# hooks = false\n[features]\nhooks = true # not hooks = false\n", false],
    ['[hooks.state."/home/u/.codex/hooks.json:session_start:0:0"]\ntrusted_hash = "sha256:00"\n[features]\nhooks = true\n', false],
    // a multi-line string's lines are text, not keys
    ['[features]\nhooks = false\n[notes]\ntext = """\n[features]\nhooks = true\n"""\n', true],
  ];

  it("the install, the integrity units and the write guard give the same answer", () => {
    for (const [text, off] of USER) {
      assert.equal(hooksFeatureOff(scanToml(text)) !== null, off, `install: ${text}`);
      assert.equal(unitsOf("codex-user-config", text, KEY).units.some((u) => u.hooksOff), off, `integrity: ${text}`);
      assert.equal(codexHooksOffIn(text), off, `write guard: ${text}`);
      assert.equal(inspectFileWrite("/home/u/.codex/config.toml", text).decision, off ? "deny" : "ask", `write: ${text}`);
    }
  });

  it("in requirements.toml, allow_managed_hooks_only too; in Codex's other managed files, which are config layers, it is no switch", () => {
    for (const path of ["/etc/codex/requirements.toml", "/etc/codex/config.toml", "/etc/codex/managed_config.toml"]) {
      const requirements = path.endsWith("/requirements.toml");
      for (const [text, off] of [["allow_managed_hooks_only = true\n", requirements], ["allow_managed_hooks_only = false\n", false], ["[features]\nhooks = false\n", true]] as const) {
        assert.equal(unitsOf("codex-managed-config", text, { ...KEY, path }).units.some((u) => u.hooksOff), off, `integrity: ${path}: ${text}`);
        assert.equal(codexHooksOffIn(text, { managed: isCodexRequirements(path) }), off, `write guard: ${path}: ${text}`);
        assert.equal(inspectFileWrite(path, text).decision, off ? "deny" : "ask", `write: ${path}: ${text}`);
      }
    }
    assert.equal(unitsOf("codex-managed-config", "allow_managed_hooks_only = true\n", KEY).units.some((u) => u.hooksOff), true, "no path: read as requirements");
    assert.equal(isCodexRequirements("C:\\ProgramData\\OpenAI\\Codex\\requirements.toml"), true, "either separator");
    assert.equal(isCodexRequirements("/etc/codex/old-requirements.toml"), false, "by the whole name");
  });

  it("the write guard reads an edit's new text as a piece of the file, and errs toward the deny where it cannot place a switch", () => {
    assert.equal(codexHooksOffIn("hooks = false"), true, "it may sit under [features]");
    assert.equal(codexHooksOffIn("codex_hooks = false\nhooks = true\n"), false, "on wherever it sits");
    assert.equal(codexHooksOffIn("features = {\n  hooks = false,\n}\n"), true, "an inline table across lines");
    assert.equal(codexHooksOffIn('[a."b\\"c"]\nhooks = false\n'), true, "a header it cannot read");
    assert.equal(codexHooksOffIn('x = """\nhooks = false\n"""\n'), true, "a multi-line string");
  });
});
