// Review a source string for bugs, security issues, and dead code — 19 detectors.
// Run: npm run build && node examples/code-review.mjs
import { reviewCode } from "../dist/review/index.js";

const demoApiKey = "sk-" + "R7mQ2vN9pT4xK8cH6wB3yD5sF1gJ0L2a";
const code = `
function getUser(db, id) {
  const q = "SELECT * FROM users WHERE id = " + id;   // SQL injection
  const apiKey = "${demoApiKey}";                     // hardcoded secret
  try { return db.query(q); } catch (e) {}              // empty catch
}
`;

const result = reviewCode(code, "user.ts");
console.log(`Score: ${result.score}/100 — ${result.summary}`);
for (const f of result.findings) {
  console.log(`  [${f.severity}] line ${f.line} (${f.category}): ${f.message}`);
}
