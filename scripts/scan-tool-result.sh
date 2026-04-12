#!/bin/bash
# Nexus PostToolUse Hook — Auto-scan tool results for prompt injection
# Reads tool result JSON from stdin, extracts text content, scans with nexus

export PATH="/home/hawon/.local/share/fnm:$PATH"
eval "$(fnm env)" 2>/dev/null
fnm use lts-latest 2>/dev/null

INPUT=$(cat)

# Extract the tool result text from the JSON
TEXT=$(echo "$INPUT" | node -e "
const data = JSON.parse(require('fs').readFileSync('/dev/stdin','utf-8'));
const result = data.tool_result ?? data.output ?? '';
const text = typeof result === 'string' ? result : JSON.stringify(result);
// Only scan if there's meaningful content (>50 chars)
if (text.length < 50) process.exit(0);
process.stdout.write(text.slice(0, 5000));
" 2>/dev/null)

# If no text extracted, pass through
if [ -z "$TEXT" ]; then
  exit 0
fi

# Run nexus scan
RESULT=$(echo "$TEXT" | node -e "
const { scan } = require('/home/hawon/claude-vault/dist/promptguard/scanner.js');
const text = require('fs').readFileSync('/dev/stdin', 'utf-8');
const result = scan(text, { context: 'tool_result', minSeverity: 'high' });
if (result.injected && (result.maxSeverity === 'critical' || result.maxSeverity === 'high')) {
  const findings = result.findings.slice(0, 3).map(f => f.ruleId + ': ' + f.message).join('; ');
  process.stderr.write('⚠️ INJECTION DETECTED: ' + findings + '\n');
  // Exit code 2 = block the result
  process.exit(2);
}
" 2>&1)

EXIT_CODE=$?

if [ $EXIT_CODE -eq 2 ]; then
  echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PostToolUse\",\"decision\":\"block\",\"reason\":\"Prompt injection detected in tool result: $RESULT\"}}"
  exit 2
fi

exit 0
