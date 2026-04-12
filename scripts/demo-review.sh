#!/bin/bash
# Screenshot 2: Code Review showcase
export PATH="/home/hawon/.local/share/fnm:$PATH"
eval "$(fnm env)" && fnm use lts-latest 2>/dev/null
NEXUS="node /home/hawon/claude-vault/dist/cli/index.js"

clear
echo ""
echo -e "\033[1m━━━ nexus — Code Review ━━━\033[0m"
echo ""

# Create a sample bad file to review
cat > /tmp/nexus-demo-review.ts << 'SAMPLE'
import { readFileSync } from "fs";
import { join } from "path";
import { existsSync } from "fs";  // unused

const API_KEY = "sk-1234567890abcdef";
const password = "admin123";

export async function loadUserData(userId: string) {
  // get the user data from the database
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  console.log("Loading user:", userId);

  try {
    const data = eval(query);
    return data;
  } catch (e) {}

  const file = readFileSync(join("/data", userId), "utf-8");
  // TODO: fix this later
  // HACK: temporary workaround
  return JSON.parse(file);
}
SAMPLE

echo -e "\033[36m$ nexus review /tmp/nexus-demo-review.ts\033[0m"
$NEXUS review /tmp/nexus-demo-review.ts
echo ""
