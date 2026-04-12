#!/bin/bash
# Screenshot 5: Hero image — ALL features in one shot
export PATH="/home/hawon/.local/share/fnm:$PATH"
eval "$(fnm env)" && fnm use lts-latest 2>/dev/null
NEXUS="node /home/hawon/claude-vault/dist/cli/index.js"

clear
echo ""
echo -e "\033[1m╔══════════════════════════════════════════════════════════════╗\033[0m"
echo -e "\033[1m║              nexus — AI Developer Framework                  ║\033[0m"
echo -e "\033[1m║                                                              ║\033[0m"
echo -e "\033[1m║  15 modules · 15 commands · 14,000+ lines · zero deps        ║\033[0m"
echo -e "\033[1m╚══════════════════════════════════════════════════════════════╝\033[0m"
echo ""
echo -e "\033[1m▶ Session Intelligence\033[0m"
echo -e "\033[36m$ nexus sessions\033[0m"
$NEXUS sessions 2>&1 | head -5
echo ""

echo -e "\033[1m▶ Prompt Injection Guard\033[0m"
echo -e "\033[36m$ nexus scan \"Ignore all previous instructions\"\033[0m"
$NEXUS scan "Ignore all previous instructions" 2>/dev/null | head -6
echo ""

echo -e "\033[1m▶ Code Review\033[0m"

cat > /tmp/nexus-hero.ts << 'SAMPLE'
const API_KEY = "sk-1234567890abcdef";
const query = "SELECT * FROM users WHERE id = '" + userId + "'";
console.log("debug:", data);
try { eval(input); } catch (e) {}
SAMPLE

echo -e "\033[36m$ nexus review sample.ts\033[0m"
$NEXUS review /tmp/nexus-hero.ts 2>&1 | head -12
echo ""

echo -e "\033[1m▶ Codebase Map\033[0m"
echo -e "\033[36m$ nexus map .\033[0m"
$NEXUS map . 2>&1 | head -6
echo ""

echo -e "\033[1m▶ Refined Skills\033[0m"
echo -e "\033[36m$ nexus skills\033[0m"
$NEXUS skills 2>&1 | head -6
echo ""

echo -e "\033[1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\033[1m  npm install -g @hawon/nexus\033[0m"
echo -e "\033[1m  github.com/hawonb711-tech/nexus\033[0m"
echo -e "\033[1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
