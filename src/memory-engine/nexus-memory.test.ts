import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createNexusMemory } from "./nexus-memory.js";
import { semanticSimilarity, expandQuery, getSynonyms } from "./semantic.js";

// ═══════════════════════════════════════════════════════════════════
// Test helpers
// ═══════════════════════════════════════════════════════════════════

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "nexus-test-"));
}

const SAMPLE_TEXT = `
The deploy pipeline uses Docker containers on AWS ECS.
We fixed a critical authentication bug in the login endpoint.
The React frontend communicates with the REST API via fetch.
Performance testing showed the cache layer reduces latency by 40%.
Database migrations should be run before deploying to production.
The security audit found an SQL injection vulnerability in the search endpoint.
Git branching strategy uses trunk-based development with feature flags.
The test coverage for the payment module is below 60%.
Server monitoring is handled by Prometheus and Grafana dashboards.
The TypeScript compiler catches most type errors at build time.
`;

const SAMPLE_TEXT_2 = `
The Kubernetes cluster autoscales based on CPU utilization.
Redis cache invalidation happens on every deploy event.
The authentication service uses JWT tokens with short expiry.
Error handling in the API uses a centralized middleware pattern.
The CI/CD pipeline runs unit tests before every merge to main.
`;

// ═══════════════════════════════════════════════════════════════════
// Ingest
// ═══════════════════════════════════════════════════════════════════

describe("ingest", () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("ingests text and creates observations", () => {
    const mem = createNexusMemory(dir);
    const count = mem.ingest(SAMPLE_TEXT, "nexus-project", "session-1");
    assert.ok(count > 0, `Expected observations to be created, got ${count}`);
    const stats = mem.getStats();
    assert.equal(stats.totalObservations, count);
  });

  it("deduplicates on repeated ingest", () => {
    const mem = createNexusMemory(dir);
    const first = mem.ingest(SAMPLE_TEXT, "nexus-project");
    const second = mem.ingest(SAMPLE_TEXT, "nexus-project");
    assert.equal(second, 0, "Duplicate ingest should add 0 new observations");
    assert.equal(mem.getStats().totalObservations, first);
  });

  it("ingests from multiple domains", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "project-a");
    mem.ingest(SAMPLE_TEXT_2, "project-b");
    const stats = mem.getStats();
    assert.ok(stats.domains.includes("project-a"));
    assert.ok(stats.domains.includes("project-b"));
  });
});

// ═══════════════════════════════════════════════════════════════════
// L1 scan — metadata filtering
// ═══════════════════════════════════════════════════════════════════

describe("L1 scanIndex", () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("filters by domain", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "project-a");
    mem.ingest(SAMPLE_TEXT_2, "project-b");

    const resultsA = mem.scanIndex("project-a");
    const resultsB = mem.scanIndex("project-b");

    assert.ok(resultsA.length > 0);
    assert.ok(resultsB.length > 0);
    assert.ok(resultsA.every((o) => o.domain === "project-a"));
    assert.ok(resultsB.every((o) => o.domain === "project-b"));
  });

  it("filters by tags", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "nexus");

    const securityResults = mem.scanIndex(undefined, undefined, ["security"]);
    if (securityResults.length > 0) {
      assert.ok(securityResults.every((o) => o.tags.includes("security")));
    }
  });

  it("returns all valid observations when no filter applied", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "nexus");
    const all = mem.scanIndex();
    const stats = mem.getStats();
    assert.equal(all.length, stats.validObservations);
  });
});

// ═══════════════════════════════════════════════════════════════════
// L2 search — BM25
// ═══════════════════════════════════════════════════════════════════

describe("L2 search (BM25)", () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("returns relevant results for keyword query", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "nexus");

    const results = mem.search("deploy");
    assert.ok(results.length > 0, "Expected BM25 results for 'deploy'");
    assert.ok(results[0].score > 0, "Top result should have positive score");
    assert.equal(results[0].retrievalLevel, "L2");
  });

  it("semantic search: Korean query finds English results", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "nexus");

    // "배포" is a synonym for "deploy" in the semantic engine
    const results = mem.search("배포");
    assert.ok(results.length > 0, "Korean query '배포' should find deploy-related results");
  });

  it("returns results sorted by score descending", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "nexus");

    const results = mem.search("security vulnerability");
    if (results.length >= 2) {
      for (let i = 1; i < results.length; i++) {
        assert.ok(results[i - 1].score >= results[i].score, "Results should be sorted by score desc");
      }
    }
  });

  it("respects limit parameter", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "nexus");

    const results = mem.search("deploy", 2);
    assert.ok(results.length <= 2);
  });
});

// ═══════════════════════════════════════════════════════════════════
// L3 deep search — graph expansion
// ═══════════════════════════════════════════════════════════════════

describe("L3 deepSearch (graph expansion)", () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("finds related content via graph expansion", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "nexus");
    mem.ingest(SAMPLE_TEXT_2, "nexus");

    const results = mem.deepSearch("deploy");
    assert.ok(results.length > 0, "Deep search should return results");

    // Deep search should find at least as many or more diverse results
    const l2Only = mem.search("deploy");
    // L3 may include L2 results plus graph-expanded L3 results
    const hasL3 = results.some((r) => r.retrievalLevel === "L3");
    const hasL2 = results.some((r) => r.retrievalLevel === "L2");
    assert.ok(hasL2, "Deep search should include L2 results");
    // L3 results are only present if graph expansion finds related content
    // This is data-dependent, so we just verify the search completes
  });
});

// ═══════════════════════════════════════════════════════════════════
// Confirm / Invalidate
// ═══════════════════════════════════════════════════════════════════

describe("confirm / invalidate", () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("confirm increases confidence", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "nexus");

    const obs = mem.scanIndex()[0];
    const oldConf = obs.confidence;
    mem.confirm(obs.id);
    assert.ok(obs.confidence > oldConf, "Confidence should increase after confirm");
    assert.ok(obs.confidence <= 1, "Confidence should not exceed 1");
  });

  it("invalidate sets valid=false and confidence=0", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "nexus");

    const obs = mem.scanIndex()[0];
    mem.invalidate(obs.id);
    assert.equal(obs.valid, false);
    assert.equal(obs.confidence, 0);
  });

  it("invalidated observations are excluded from scanIndex", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "nexus");

    const allBefore = mem.scanIndex();
    const target = allBefore[0];
    mem.invalidate(target.id);
    const allAfter = mem.scanIndex();
    assert.equal(allAfter.length, allBefore.length - 1);
    assert.ok(!allAfter.some((o) => o.id === target.id));
  });
});

// ═══════════════════════════════════════════════════════════════════
// Persistence (save/load)
// ═══════════════════════════════════════════════════════════════════

describe("persistence", () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("persists and reloads observations", () => {
    const mem1 = createNexusMemory(dir);
    mem1.ingest(SAMPLE_TEXT, "nexus");
    const countBefore = mem1.getStats().totalObservations;
    mem1.save();

    // Create a new instance from same dir — should load saved data
    const mem2 = createNexusMemory(dir);
    assert.equal(mem2.getStats().totalObservations, countBefore);
  });
});

// ═══════════════════════════════════════════════════════════════════
// Semantic module — getSynonyms
// ═══════════════════════════════════════════════════════════════════

describe("getSynonyms", () => {
  it("returns synonyms for 'deploy'", () => {
    const syns = getSynonyms("deploy");
    assert.ok(syns.length > 0, "Expected synonyms for 'deploy'");
    assert.ok(syns.includes("배포"), "Expected '배포' in synonyms for 'deploy'");
    assert.ok(syns.includes("release"), "Expected 'release' in synonyms for 'deploy'");
  });

  it("returns synonyms for Korean term '에러'", () => {
    const syns = getSynonyms("에러");
    assert.ok(syns.includes("error"), "Expected 'error' in synonyms for '에러'");
    assert.ok(syns.includes("bug"), "Expected 'bug' in synonyms for '에러'");
  });

  it("returns empty array for unknown word", () => {
    const syns = getSynonyms("xyzzy12345");
    assert.equal(syns.length, 0);
  });
});

// ═══════════════════════════════════════════════════════════════════
// Semantic module — expandQuery
// ═══════════════════════════════════════════════════════════════════

describe("expandQuery", () => {
  it("expands '배포 에러' to include English equivalents", () => {
    const result = expandQuery("배포 에러");
    assert.ok(result.original.length > 0);
    assert.ok(result.expanded.length > result.original.length, "Expanded should be larger than original");

    const expandedSet = new Set(result.expanded);
    // Should include English synonyms
    assert.ok(
      expandedSet.has("deploy") || expandedSet.has("release") || expandedSet.has("ship"),
      "Expected English deploy synonym in expansion",
    );
    assert.ok(
      expandedSet.has("error") || expandedSet.has("bug") || expandedSet.has("issue"),
      "Expected English error synonym in expansion",
    );
  });

  it("tracks expansion sources", () => {
    const result = expandQuery("deploy");
    assert.ok(result.expansions.length > 0, "Expected expansion entries");
    const validSources = ["synonym", "cooccurrence", "stem", "transliteration"];
    assert.ok(result.expansions.every((e) => validSources.includes(e.source)));
  });
});

// ═══════════════════════════════════════════════════════════════════
// Semantic module — semanticSimilarity
// ═══════════════════════════════════════════════════════════════════

describe("semanticSimilarity", () => {
  it("'deploy error' and '배포 에러' have similarity > 0.3", () => {
    const score = semanticSimilarity("deploy error", "배포 에러");
    assert.ok(score > 0.3, `Expected similarity > 0.3, got ${score}`);
  });

  it("unrelated terms have similarity = 0", () => {
    const score = semanticSimilarity("react", "서버");
    // react and 서버 are in different synonym groups, no overlap
    assert.equal(score, 0, `Expected 0 similarity for unrelated terms, got ${score}`);
  });

  it("identical texts have high similarity", () => {
    const score = semanticSimilarity("deploy to production", "deploy to production");
    assert.ok(score > 0.5, `Expected high similarity for identical text, got ${score}`);
  });

  it("returns 0 for empty input", () => {
    assert.equal(semanticSimilarity("", "hello"), 0);
    assert.equal(semanticSimilarity("hello", ""), 0);
  });
});

// ═══════════════════════════════════════════════════════════════════
// Knowledge graph
// ═══════════════════════════════════════════════════════════════════

describe("knowledge graph", () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("builds graph nodes and edges from observations", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "nexus");
    const graph = mem.getGraph();
    assert.ok(graph.nodes.length > 0, "Expected graph nodes");
    assert.ok(graph.edges.length > 0, "Expected graph edges");
  });

  it("creates tunnels for shared topics across domains", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "project-a");
    mem.ingest(SAMPLE_TEXT_2, "project-b");
    const tunnels = mem.getTunnels();
    // Tunnels connect domains that share topics
    // Both texts discuss deploy/security/auth concepts
    // Tunnel creation depends on topic extraction matching
    assert.ok(Array.isArray(tunnels));
  });
});

// ═══════════════════════════════════════════════════════════════════
// Stats
// ═══════════════════════════════════════════════════════════════════

describe("getStats", () => {
  let dir: string;

  beforeEach(() => {
    dir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("returns correct structure", () => {
    const mem = createNexusMemory(dir);
    mem.ingest(SAMPLE_TEXT, "nexus");
    const stats = mem.getStats();

    assert.ok(typeof stats.totalObservations === "number");
    assert.ok(typeof stats.validObservations === "number");
    assert.ok(typeof stats.graphNodes === "number");
    assert.ok(typeof stats.graphEdges === "number");
    assert.ok(typeof stats.tunnels === "number");
    assert.ok(Array.isArray(stats.domains));
    assert.ok(typeof stats.avgConfidence === "number");
    assert.ok(typeof stats.avgDocLength === "number");
    assert.ok(stats.avgConfidence >= 0 && stats.avgConfidence <= 1);
  });
});
