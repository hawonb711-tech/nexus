/**
 * Held-out generalization + adaptive benchmark.
 *
 * The 62-attack adaptive corpus (scripts/adaptive-benchmark.ts) is the set the
 * structural defense was TUNED against — scoring 100% there proves nothing about
 * generalization. This script measures the guard on a FRESH held-out corpus the
 * defense never saw, split by tier:
 *   - generalization: novel malicious payloads written blind to the defense
 *   - adaptive:       payloads crafted specifically to evade this exact defense
 *
 * Run:  npx tsx scripts/adaptive-generalization.ts [path-to-heldout.json]
 * Default corpus: src/guard/adaptive-corpus-heldout.json
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { inspectContent } from "../src/guard/guard.js";
import { inspectCommand, inspectFileWrite } from "../src/guard/command.js";

type Attack = { kind: "command" | "content" | "filewrite"; payload: string; filePath?: string; class?: string; tier?: string; why?: string };

const path = process.argv[2] ?? fileURLToPath(new URL("../src/guard/adaptive-corpus-heldout.json", import.meta.url));
const corpus = JSON.parse(readFileSync(path, "utf-8")) as { attacks: Attack[] };

function decide(a: Attack): "allow" | "ask" | "block" {
  if (a.kind === "command") { const d = inspectCommand(a.payload).decision; return d === "allow" ? "allow" : d === "ask" ? "ask" : "block"; }
  if (a.kind === "filewrite") { const d = inspectFileWrite(a.filePath ?? "", a.payload).decision; return d === "allow" ? "allow" : d === "ask" ? "ask" : "block"; }
  const v = inspectContent(a.payload).verdict; return v === "allow" ? "allow" : v === "warn" ? "ask" : "block";
}

const tiers = new Map<string, { total: number; allow: number; caught: number; misses: Attack[] }>();
for (const a of corpus.attacks) {
  const tier = a.tier ?? "all";
  const s = tiers.get(tier) ?? { total: 0, allow: 0, caught: 0, misses: [] };
  s.total++;
  const d = decide(a);
  if (d === "allow") { s.allow++; s.misses.push(a); } else s.caught++;
  tiers.set(tier, s);
}

console.log("\n=== HELD-OUT generalization + adaptive benchmark (defense never saw these) ===\n");
let T = 0, C = 0;
for (const [tier, s] of tiers) {
  console.log(`  ${tier.padEnd(16)} caught ${s.caught}/${s.total}  (${(s.caught / s.total * 100).toFixed(0)}%)   bypassed ${s.allow}`);
  T += s.total; C += s.caught;
}
console.log(`\n  OVERALL: caught ${C}/${T}  (${(C / T * 100).toFixed(0)}%)   bypassed ${T - C}\n`);
for (const [tier, s] of tiers) {
  if (!s.misses.length) continue;
  console.log(`  -- ${tier} bypasses --`);
  for (const m of s.misses) console.log(`     [${m.kind}] ${(m.payload || "").replace(/\n/g, " ").slice(0, 84)}`);
}
console.log();
