// Ingest observations and search them — cross-lingual (Korean query → English
// hit) with zero API. Uses a throwaway temp data dir so it leaves no state.
// Run: npm run build && node examples/memory.mjs
import { createNexusMemory } from "../dist/memory-engine/index.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "nexus-mem-"));
try {
  const mem = createNexusMemory(dir);
  mem.ingest("Docker containers should run as non-root users for security", "security");
  mem.ingest("Use prepared statements to prevent SQL injection", "security");
  mem.ingest("Kubernetes pods inherit the service account token by default", "infra");

  for (const q of ["컨테이너 보안", "sql injection"]) {
    const hits = mem.search(q, 2);
    console.log(`\nQuery: "${q}"`);
    for (const h of hits) console.log(`  [${h.score.toFixed(2)}] ${h.observation.content}`);
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
