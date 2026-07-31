/**
 * Replay the frozen round-3 and round-4 red-team corpora against today's guard.
 *
 * These sets were fresh when they were authored, but the defense was hardened
 * after inspecting their misses. Their current score is therefore a regression
 * replay, NOT an unseen/held-out generalization claim.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { inspectContent } from "../src/guard/guard.js";
import { inspectCommand, inspectFileWrite } from "../src/guard/command.js";

type Attack = {
  kind: "command" | "content" | "filewrite";
  payload: string;
  filePath?: string;
  tier?: "generalization" | "adaptive";
};

type Score = { total: number; caught: number };

function load(name: string): Attack[] {
  const file = fileURLToPath(new URL(`../src/guard/${name}`, import.meta.url));
  return (JSON.parse(readFileSync(file, "utf8")) as { attacks: Attack[] }).attacks;
}

function caught(attack: Attack): boolean {
  if (attack.kind === "command") return inspectCommand(attack.payload).decision !== "allow";
  if (attack.kind === "filewrite") {
    return inspectFileWrite(attack.filePath ?? "", attack.payload).decision !== "allow";
  }
  return inspectContent(attack.payload).verdict !== "allow";
}

function score(rows: Attack[]): Map<string, Score> {
  const result = new Map<string, Score>();
  for (const row of rows) {
    const tier = row.tier ?? "unclassified";
    const current = result.get(tier) ?? { total: 0, caught: 0 };
    current.total++;
    if (caught(row)) current.caught++;
    result.set(tier, current);
  }
  return result;
}

function percentage(value: Score): string {
  return `${(value.caught / value.total * 100).toFixed(1)}%`;
}

const rounds = [
  ["round 3", load("adaptive-corpus-round3.json")],
  ["round 4", load("adaptive-corpus-round4.json")],
] as const;

console.log("\n=== Frozen red-team corpus replay (current defense) ===");
console.log("These corpora are regression tests now, not unseen held-out evaluation.\n");

const combined = new Map<string, Score>();
for (const [label, rows] of rounds) {
  const scores = score(rows);
  const total = { total: rows.length, caught: rows.filter(caught).length };
  console.log(`  ${label}: ${total.caught}/${total.total} caught (${percentage(total)})`);
  for (const [tier, value] of scores) {
    console.log(`    ${tier.padEnd(15)} ${value.caught}/${value.total} (${percentage(value)})`);
    const aggregate = combined.get(tier) ?? { total: 0, caught: 0 };
    aggregate.total += value.total;
    aggregate.caught += value.caught;
    combined.set(tier, aggregate);
  }
}

const all = [...combined.values()].reduce(
  (sum, value) => ({
    total: sum.total + value.total,
    caught: sum.caught + value.caught,
  }),
  { total: 0, caught: 0 },
);

console.log(`\n  combined: ${all.caught}/${all.total} caught (${percentage(all)})`);
for (const [tier, value] of combined) {
  console.log(`    ${tier.padEnd(15)} ${value.caught}/${value.total} (${percentage(value)})`);
}
console.log();
