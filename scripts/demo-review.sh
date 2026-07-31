#!/usr/bin/env bash
# Screenshot 2: Code Review showcase
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
NODE_BIN="${NODE_BIN:-node}"

clear 2>/dev/null || true
printf '\n\033[1m━━━ nexus — Code Review ━━━\033[0m\n\n'
printf '\033[36m$ node examples/code-review.mjs\033[0m\n'
cd "$REPO_ROOT"
"$NODE_BIN" examples/code-review.mjs
printf '\n'
