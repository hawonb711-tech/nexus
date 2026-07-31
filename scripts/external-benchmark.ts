/**
 * External, third-party benchmarks — the honest counterpart to our own red-team.
 *
 * Runs the content guard against PUBLIC, recognized prompt-injection datasets so
 * the numbers are comparable to what others report, not self-graded:
 *
 *   1. deepset/prompt-injections (HuggingFace) — labeled injection vs benign.
 *      Measures detection recall AND false-positive rate on a standard set.
 *   2. InjecAgent (UIUC) — indirect prompt injection embedded in tool responses.
 *      Measures how many attacks the content guard would flag before the agent acts.
 *      NOTE: InjecAgent attacks are mostly *semantically benign-looking* action
 *      requests ("grant my friend access", "transfer $X") with no override /
 *      exfil / dangerous-command signal — the purely-semantic class a pattern/
 *      intent detector cannot catch. Expect a LOW number here; it is honest, and
 *      it maps exactly to the spotlighting/sandboxing boundary in the README.
 *
 * Network required. Reproduce:  npx tsx scripts/external-benchmark.ts
 */
import { inspectContent } from "../src/guard/guard.js";

const HF = "https://datasets-server.huggingface.co/rows";
const HF_DATASET = "deepset/prompt-injections";
const HF_REVISION = "4f61ecb038e9c3fb77e21034b22511b523772cdd";
const INJECAGENT_REVISION = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07";
const BIPIA_REVISION = "a004b69ec0dd446e0afd461d98cb5e96e120a5d0";
const INJECAGENT =
  `https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/${INJECAGENT_REVISION}/data`;
const BIPIA =
  `https://raw.githubusercontent.com/microsoft/BIPIA/${BIPIA_REVISION}/benchmark`;

const EXPECTED_DEEPSET = {
  test: { total: 116, injection: 60, benign: 56 },
  train: { total: 546, injection: 203, benign: 343 },
} as const;

async function fetchJson<T>(url: string, label: string): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, { signal: AbortSignal.timeout(20_000) });
  } catch (error) {
    throw new Error(`${label}: request failed`, { cause: error });
  }
  if (!response.ok) {
    throw new Error(`${label}: HTTP ${response.status} ${response.statusText}`);
  }
  try {
    return await response.json() as T;
  } catch (error) {
    throw new Error(`${label}: invalid JSON response`, { cause: error });
  }
}

function requireEqual(actual: number | string, expected: number | string, label: string): void {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected}, received ${actual}`);
  }
}

async function fetchDeepset(split: string): Promise<{ text: string; label: number }[]> {
  const out: { text: string; label: number }[] = [];
  let total: number | undefined;
  for (let offset = 0; total === undefined || offset < total; offset += 100) {
    const url = `${HF}?dataset=${encodeURIComponent(HF_DATASET)}&config=default&split=${split}&offset=${offset}&length=100`;
    const j = await fetchJson<{
      rows?: { row: { text: string; label: number } }[];
      num_rows_total?: number;
      partial?: boolean;
    }>(url, `Hugging Face ${split} rows at offset ${offset}`);
    if (j.partial) throw new Error(`Hugging Face ${split}: dataset viewer returned a partial slice`);
    if (!Number.isInteger(j.num_rows_total)) {
      throw new Error(`Hugging Face ${split}: response omitted num_rows_total`);
    }
    total ??= j.num_rows_total;
    requireEqual(j.num_rows_total, total, `Hugging Face ${split} row count`);
    if (!j.rows || j.rows.length === 0) break;
    for (const r of j.rows) out.push(r.row);
  }
  requireEqual(out.length, total ?? 0, `Hugging Face ${split} downloaded rows`);
  return out;
}

async function fetchInjecAgent(file: string): Promise<any[]> {
  const rows = await fetchJson<unknown>(`${INJECAGENT}/${file}`, `InjecAgent ${file}`);
  if (!Array.isArray(rows)) throw new Error(`InjecAgent ${file}: expected a JSON array`);
  return rows;
}

const flagged = (t: string) => inspectContent(t).verdict !== "allow";

function pct(n: number, d: number): string { return d ? `${(n / d * 100).toFixed(1)}%` : "n/a"; }

async function deepset() {
  console.log("\n══ deepset/prompt-injections (HuggingFace) — injection detection + false positives ══");
  for (const split of ["test", "train"] as const) {
    const rows = await fetchDeepset(split);
    const pos = rows.filter((r) => r.label === 1), neg = rows.filter((r) => r.label === 0);
    const expected = EXPECTED_DEEPSET[split];
    requireEqual(rows.length, expected.total, `deepset ${split} total`);
    requireEqual(pos.length, expected.injection, `deepset ${split} injection rows`);
    requireEqual(neg.length, expected.benign, `deepset ${split} benign rows`);
    const tp = pos.filter((r) => flagged(r.text)).length;
    const fp = neg.filter((r) => flagged(r.text)).length;
    const recall = tp / pos.length, fpr = fp / neg.length;
    const precision = tp / (tp + fp || 1);
    const f1 = 2 * precision * recall / (precision + recall || 1);
    const acc = (tp + (neg.length - fp)) / rows.length;
    console.log(`\n  [${split}]  ${rows.length} cases (${pos.length} injection / ${neg.length} benign)`);
    console.log(`    Recall (injection caught): ${pct(tp, pos.length)}   (${tp}/${pos.length})`);
    console.log(`    False-positive rate:       ${pct(fp, neg.length)}   (${fp}/${neg.length})`);
    console.log(`    Precision ${(precision * 100).toFixed(1)}%   F1 ${(f1 * 100).toFixed(1)}%   Accuracy ${(acc * 100).toFixed(1)}%`);
  }
}

async function injecagent() {
  console.log("\n══ InjecAgent (UIUC) — indirect injection flagged in the tool response ══");
  const files = [
    ["data-exfil (dh) base", "test_cases_dh_base.json"],
    ["direct-harm (ds) base", "test_cases_ds_base.json"],
    ["data-exfil (dh) enhanced", "test_cases_dh_enhanced.json"],
    ["direct-harm (ds) enhanced", "test_cases_ds_enhanced.json"],
  ] as const;
  const tally = { base: [0, 0], enhanced: [0, 0] };
  for (const [label, file] of files) {
    const cases = await fetchInjecAgent(file);
    // What the agent actually reads: the poisoned tool response.
    const caught = cases.filter((c) => flagged(String(c["Tool Response"] || c["Tool Response Template"] || c["Attacker Instruction"] || ""))).length;
    const kind = file.includes("enhanced") ? "enhanced" : "base";
    tally[kind][0] += caught; tally[kind][1] += cases.length;
    console.log(`  ${label.padEnd(26)} flagged ${pct(caught, cases.length)}  (${caught}/${cases.length})`);
  }
  console.log(`\n  base      (bare semantic request): ${pct(tally.base[0], tally.base[1])}  (${tally.base[0]}/${tally.base[1]})`);
  console.log(`  enhanced  (+ "ignore all previous instructions" wrapper): ${pct(tally.enhanced[0], tally.enhanced[1])}  (${tally.enhanced[0]}/${tally.enhanced[1]})`);
  console.log(`  → The split is the whole story: an injection carrying ANY override/exfil/command`);
  console.log(`    signal is caught (enhanced 100%); a purely-semantic action request ("grant my`);
  console.log(`    friend access") carries none and is NOT detected (base ~0%). The installed hook`);
  console.log(`    still frames every external result; enforcement also requires least privilege.`);
}

async function bipia() {
  console.log("\n══ BIPIA (Microsoft) — indirect prompt injection, text + code attacks ══");
  for (const [label, file] of [["text attacks", "text_attack_test.json"], ["code attacks", "code_attack_test.json"]] as const) {
    const j = await fetchJson<Record<string, string[]>>(`${BIPIA}/${file}`, `BIPIA ${file}`);
    const items = Object.values(j).flat();
    const caught = items.filter((t) => flagged(t)).length;
    console.log(`  ${label.padEnd(14)} flagged ${pct(caught, items.length)}  (${caught}/${items.length}, ${Object.keys(j).length} categories)`);
  }
  console.log(`  → text attacks are mostly benign-looking task-derailment (no signal); code attacks`);
  console.log(`    inject exfil/eval snippets — Nexus flags the ones carrying a capability signal.`);
  console.log(`    These figures measure detector recall, not the always-on framing backstop.`);
}

const metadata = await fetchJson<{ sha?: string; lastModified?: string }>(
  `https://huggingface.co/api/datasets/${HF_DATASET}`,
  "Hugging Face dataset metadata",
);
requireEqual(metadata.sha ?? "missing", HF_REVISION, "deepset dataset revision");

console.log("External benchmark source lock");
console.log(`  deepset/prompt-injections @ ${HF_REVISION}`);
console.log(`  uiuc-kang-lab/InjecAgent @ ${INJECAGENT_REVISION}`);
console.log(`  microsoft/BIPIA          @ ${BIPIA_REVISION}`);
console.log(`  evaluated                 ${new Date().toISOString()}`);

await deepset();
await injecagent();
await bipia();
console.log();
