/**
 * SessionStart as Codex CLI 0.164.0 sends it (the payloads captured from
 * `codex exec`, __fixtures__/payloads): a transcript under
 * `$CODEX_HOME/sessions/…`, no `turn_id`, and a `source` of startup, resume,
 * clear, compact or fork. The integrity check runs on it without an error or
 * a timeout. A Codex transcript names no Claude config dir, so the context
 * falls back to CLAUDE_CONFIG_DIR or ~/.claude, as for a payload with no
 * transcript (Codex's own files are not watched yet).
 *
 * Every path is a temporary tree; nothing touches the real ~/.claude, ~/.codex
 * or ~/.nexus.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { respond, type HookDeps } from "../handler.js";
import { contextFromHook } from "../integrity/context.js";
import { integrityPaths } from "../integrity/store.js";

const PAYLOADS = fileURLToPath(new URL("./__fixtures__/payloads/", import.meta.url));
const SOURCES = ["startup", "resume", "clear", "compact", "fork"];

type Tree = { root: string; home: string; codexHome: string; data: string; project: string; clock: number; deps: (env?: Record<string, string>) => HookDeps };

function tree(): Tree {
  const root = realpathSync.native(mkdtempSync(join(tmpdir(), "nexus-codex-start-")));
  const t: Tree = {
    root, home: join(root, "home"), codexHome: join(root, "codex-home"), data: join(root, "nexus-data"), project: join(root, "ws"),
    clock: Date.parse("2026-10-25T14:04:26.000Z"),
    deps: (env = { CLAUDE_CONFIG_DIR: join(root, "claude-config") }) => ({
      now: () => t.clock, dataDir: t.data, homedir: t.home, platform: process.platform, env: { CODEX_HOME: t.codexHome, ...env }, pid: 4242,
      managedDir: join(root, "managed"), nexusEntries: [],
    }),
  };
  for (const d of [t.home, join(t.codexHome, "sessions", "2026", "10", "25"), join(t.project, ".git")]) mkdirSync(d, { recursive: true });
  writeFileSync(join(t.project, "AGENTS.md"), "Be nice.\n");
  return t;
}

/** The SessionStart payload a captured run began with, its {{CODEX_HOME}} and {{CWD}} filled in. */
function capturedStart(run: string, t: Tree): Record<string, unknown> {
  const text = readFileSync(join(PAYLOADS, `${run}.json`), "utf8")
    .replaceAll("{{CODEX_HOME}}", t.codexHome.replaceAll("\\", "\\\\")).replaceAll("{{CWD}}", t.project.replaceAll("\\", "\\\\"));
  const start = (JSON.parse(text) as Record<string, unknown>[]).find((p) => p.hook_event_name === "SessionStart");
  assert.ok(start, `${run} has a SessionStart payload`);
  return start;
}

const message = (output: unknown) => String((output as Record<string, unknown> | null)?.systemMessage ?? "");

describe("SessionStart with Codex's payloads", () => {
  for (const run of ["run1", "run4"]) {
    it(`${run}: the check runs, creates the store and reports changes, for every source`, async () => {
      const t = tree();
      try {
        const start = capturedStart(run, t);
        assert.equal(start.source, "startup");
        assert.match(String(start.transcript_path), /[\\/]sessions[\\/]2026[\\/]10[\\/]25[\\/]rollout-.*\.jsonl$/);
        // A Codex transcript names no Claude config dir: CLAUDE_CONFIG_DIR, else ~/.claude
        const ctxDeps = { platform: process.platform, homedir: t.home, dataDir: t.data };
        assert.equal(contextFromHook(start, { ...ctxDeps, env: { CLAUDE_CONFIG_DIR: join(t.root, "claude-config") } })?.configDirSource, "env");
        assert.equal(contextFromHook(start, { ...ctxDeps, env: {} })?.configDir, join(t.home, ".claude"));

        const first = await respond(start, t.deps(), { dialect: "codex" });
        assert.match(message(first.output), /^🛡️ Nexus now keeps a fingerprint/);
        assert.ok(existsSync(integrityPaths(t.data).key));
        for (const source of SOURCES) {
          t.clock += 60_000;
          const answer = await respond({ ...start, source, session_id: `${String(start.session_id)}-${source}` }, t.deps({}), { dialect: "codex" });
          assert.equal(answer.stderr, undefined);
          assert.equal(answer.output, null, `${source}: nothing changed, nothing to say`);
        }
        writeFileSync(join(t.project, "AGENTS.md"), "Be nice.\nAlso lint.\n");
        t.clock += 60_000;
        const changed = await respond({ ...start, source: "fork", session_id: `${String(start.session_id)}-changed` }, t.deps(), { dialect: "codex" });
        assert.match(message(changed.output), /AGENTS\.md \(\+1 line\)/);
        assert.doesNotMatch(message(changed.output), /internal error|did not finish/);
      } finally {
        rmSync(t.root, { recursive: true, force: true });
      }
    });
  }
});
