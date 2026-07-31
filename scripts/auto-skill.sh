#!/usr/bin/env bash
# Optional SessionEnd helper:
#   1. saves the latest Claude Code session into local Nexus memory;
#   2. optionally asks an installed Claude CLI to write a reusable skill when
#      NEXUS_SKILL_DIR is explicitly configured;
#   3. optionally starts auto-sync when NEXUS_VAULT_PATH is configured.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
NODE_BIN="${NODE_BIN:-node}"
CLAUDE_DIR="${CLAUDE_SESSION_DIR:-${HOME}/.claude/projects}"

if [[ ! -d "$CLAUDE_DIR" ]]; then
  exit 0
fi

LATEST_SESSION="$("$NODE_BIN" --input-type=module -e '
  import { readdirSync, statSync } from "node:fs";
  import { join } from "node:path";
  const pending = [process.argv[1]];
  let latest = null;
  while (pending.length) {
    const dir = pending.pop();
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile() && entry.name.endsWith(".jsonl")) {
        const mtime = statSync(path).mtimeMs;
        if (!latest || mtime > latest.mtime) latest = { path, mtime };
      }
    }
  }
  if (latest) process.stdout.write(latest.path);
' "$CLAUDE_DIR" 2>/dev/null || true)"

if [[ -z "$LATEST_SESSION" ]]; then
  exit 0
fi

cd "$REPO_ROOT"

# Persist a bounded, sanitized representation through the normal memory engine.
"$NODE_BIN" --input-type=module -e '
  import { readFileSync } from "node:fs";
  import { join } from "node:path";
  import { createNexusMemory } from "./dist/memory-engine/nexus-memory.js";
  const lines = readFileSync(process.argv[1], "utf8").split("\n").filter(Boolean);
  const texts = [];
  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      if (obj.type === "user" && typeof obj.message?.content === "string") {
        if (obj.message.content.length > 30 && !obj.message.content.startsWith("<")) {
          texts.push(obj.message.content.slice(0, 500));
        }
      } else if (obj.type === "assistant" && Array.isArray(obj.message?.content)) {
        const text = obj.message.content
          .filter((block) => block?.type === "text")
          .map((block) => String(block.text ?? ""))
          .join(" ");
        if (text.length > 50) texts.push(text.slice(0, 500));
      }
    } catch {
      // Ignore malformed session lines.
    }
  }
  if (texts.length >= 2) {
    const memory = createNexusMemory(join(process.env.HOME, ".nexus"));
    const added = memory.ingest(texts.join(". "), "session");
    if (added > 0) memory.save();
  }
' "$LATEST_SESSION"

# Model-assisted SKILL.md generation is explicit opt-in and not part of Nexus's
# model-free core analysis path.
if [[ -n "${NEXUS_SKILL_DIR:-}" ]] && command -v claude >/dev/null 2>&1; then
  mkdir -p "$NEXUS_SKILL_DIR"
  RECENT="$("$NODE_BIN" --input-type=module -e '
    import { readFileSync } from "node:fs";
    const messages = [];
    for (const line of readFileSync(process.argv[1], "utf8").split("\n")) {
      if (!line) continue;
      try {
        const obj = JSON.parse(line);
        if (obj.type === "user" && typeof obj.message?.content === "string") {
          const text = obj.message.content;
          if (text.length > 10 && !text.startsWith("<")) messages.push(`User: ${text.slice(0, 200)}`);
        } else if (obj.type === "assistant" && Array.isArray(obj.message?.content)) {
          const text = obj.message.content
            .filter((block) => block?.type === "text")
            .map((block) => String(block.text ?? ""))
            .join(" ");
          if (text.length > 20) messages.push(`Assistant: ${text.slice(0, 200)}`);
        }
      } catch {
        // Ignore malformed session lines.
      }
    }
    process.stdout.write(messages.slice(-30).join("\n"));
  ' "$LATEST_SESSION")"

  if [[ -n "$RECENT" ]]; then
    printf '%s\n' "$RECENT" |
      claude -p \
        "If this conversation contains a genuinely reusable technical pattern, create a SKILL.md under ${NEXUS_SKILL_DIR}. Include frontmatter, When to Use, Procedure, Pitfalls, and Verification. Otherwise do nothing." \
        --max-turns 1
  fi
fi

if [[ -n "${NEXUS_VAULT_PATH:-}" ]]; then
  "$SCRIPT_DIR/auto-sync.sh" >/dev/null 2>&1 &
fi
