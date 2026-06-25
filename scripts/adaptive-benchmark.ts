/**
 * Adaptive benchmark — the honest counterpart to guard-benchmark.ts.
 *
 * guard-benchmark.ts runs a friendly, self-made corpus (30/30, 0 FP). This runs
 * 62 attacks red-teamed AGAINST the guard's own regex logic — each genuinely
 * malicious but crafted to evade a specific pattern. Run:
 *
 *   npx tsx scripts/adaptive-benchmark.ts
 *
 * The low score is the point: it measures how far pattern matching is from a
 * real firewall, and tracks the gap closing as structural defenses land.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { inspectContent } from "../src/guard/guard.js";
import { inspectCommand, inspectFileWrite } from "../src/guard/command.js";

type Attack = { id: number; kind: "command" | "content" | "filewrite"; class: string; filePath?: string; payload: string };
const corpus = JSON.parse(
  readFileSync(fileURLToPath(new URL("../src/guard/adaptive-corpus.json", import.meta.url)), "utf-8"),
) as { count: number; attacks: Attack[] };

function decide(a: Attack): "allow" | "ask" | "block" {
  if (a.kind === "command") { const d = inspectCommand(a.payload).decision; return d === "allow" ? "allow" : d === "ask" ? "ask" : "block"; }
  if (a.kind === "filewrite") { const d = inspectFileWrite(a.filePath ?? "", a.payload).decision; return d === "allow" ? "allow" : d === "ask" ? "ask" : "block"; }
  const v = inspectContent(a.payload).verdict; return v === "allow" ? "allow" : v === "warn" ? "ask" : "block";
}

const byClass = new Map<string, { total: number; allow: number; ask: number; block: number }>();
let allow = 0, ask = 0, block = 0;
for (const a of corpus.attacks) {
  const d = decide(a);
  const s = byClass.get(a.class) ?? { total: 0, allow: 0, ask: 0, block: 0 };
  s.total++; s[d]++; byClass.set(a.class, s);
  if (d === "allow") allow++; else if (d === "ask") ask++; else block++;
}
const T = corpus.attacks.length;

console.log("\n=== Nexus guard vs ADAPTIVE corpus (attacks red-teamed against its own patterns) ===\n");
for (const [c, s] of byClass) console.log(`  ${c.padEnd(24)} bypass ${String(s.allow).padStart(2)}/${s.total}   ask ${s.ask}   block ${s.block}`);
console.log(`\n  Fully bypassed (allow):  ${allow}/${T}  (${(allow / T * 100).toFixed(0)}%)`);
console.log(`  Flagged (ask) / blocked: ${ask} / ${block}`);
console.log(`  Caught (ask+block):      ${ask + block}/${T}  (${((ask + block) / T * 100).toFixed(0)}%)`);
console.log(`\n  Caught structurally — commands are RESOLVED then judged by capability, content is`);
console.log(`  de-obfuscated then checked for agent-directed intent. NOTE: this is the corpus the`);
console.log(`  defense was tuned against; the honest test of generalization is a fresh held-out`);
console.log(`  set (npx tsx scripts/adaptive-generalization.ts).\n`);
