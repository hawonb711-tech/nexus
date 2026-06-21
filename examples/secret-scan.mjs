// Scan a directory for leaked credentials — working tree (+ optionally git
// history). Every finding is redacted; the raw secret is never returned.
// Run: npm run build && node examples/secret-scan.mjs [dir]
import { scanForSecrets } from "../dist/secrets/index.js";

const dir = process.argv[2] ?? ".";
const result = await scanForSecrets(dir, { includeHistory: false });

console.log(`Scanned ${result.filesScanned} files — ${result.summary}`);
for (const f of result.findings) {
  console.log(`  [${f.severity}] ${f.file}:${f.line}  ${f.rule}`);
  console.log(`      ${f.redacted}   (${f.source})`);
}
if (result.truncated.historyUnavailable) {
  console.log(`  note: git history not scanned (${result.truncated.historyUnavailable})`);
}
