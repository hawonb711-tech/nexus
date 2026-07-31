import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { reviewCode } from "./analyzer.js";

// ═══════════════════════════════════════════════════════════════════
// Security detections
// ═══════════════════════════════════════════════════════════════════

describe("detects hardcoded secrets", () => {
  it("detects API key", () => {
    const code = `const API_KEY = "sk-abc123def456ghi789jkl012mno345pqr678";`;
    const result = reviewCode(code, "test.ts");
    assert.ok(
      result.findings.some((f) => f.category === "security" && /secret|key|token/i.test(f.message)),
      "Expected security finding for API key",
    );
  });

  it("detects hardcoded password", () => {
    const fixtureValue = ["SuperS3cret", "P@ss!"].join("");
    const code = `const password = "${fixtureValue}";`;
    const result = reviewCode(code, "config.ts");
    assert.ok(
      result.findings.some((f) => f.category === "security" && /password/i.test(f.message)),
      "Expected security finding for hardcoded password",
    );
  });

  it("detects AWS access key", () => {
    const code = `const awsKey = "AKIAIOSFODNN7EXAMPLE";`;
    const result = reviewCode(code, "aws.ts");
    assert.ok(
      result.findings.some((f) => f.category === "security" && /aws/i.test(f.message)),
      "Expected security finding for AWS key",
    );
  });

  it("detects GitHub PAT", () => {
    const code = `const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";`;
    const result = reviewCode(code, "gh.ts");
    assert.ok(
      result.findings.some((f) => f.category === "security"),
      "Expected security finding for GitHub PAT",
    );
  });
});

describe("detects SQL injection", () => {
  it("template literal in exec", () => {
    const code = 'db.exec(`DELETE FROM sessions WHERE user = ${userName}`);';
    const result = reviewCode(code, "db.ts");
    assert.ok(
      result.findings.some((f) => f.category === "security" && /sql/i.test(f.message)),
      "Expected SQL injection finding for exec template literal",
    );
  });

  it("template literal in query", () => {
    const code = 'db.execute(`SELECT * FROM users WHERE name = ${userName}`);';
    const result = reviewCode(code, "db.ts");
    assert.ok(
      result.findings.some((f) => f.category === "security" && /sql/i.test(f.message)),
      "Expected SQL injection finding for template literal",
    );
  });
});

describe("detects eval", () => {
  it("eval() usage", () => {
    const code = `const result = eval(userInput);`;
    const result = reviewCode(code, "exec.ts");
    assert.ok(
      result.findings.some((f) => f.category === "security" && /eval|code injection/i.test(f.message)),
      "Expected eval finding",
    );
  });

  it("Function() constructor", () => {
    const code = `const fn = new Function("return " + expr);`;
    const result = reviewCode(code, "exec.ts");
    assert.ok(
      result.findings.some((f) => f.category === "security" && /eval|Function|code injection/i.test(f.message)),
      "Expected Function constructor finding",
    );
  });
});

// ═══════════════════════════════════════════════════════════════════
// Bug detections
// ═══════════════════════════════════════════════════════════════════

describe("detects empty catch", () => {
  it("catch(e) {} is flagged", () => {
    const code = `
try {
  doSomething();
} catch(e) {}
`;
    const result = reviewCode(code, "handler.ts");
    assert.ok(
      result.findings.some((f) => f.category === "error_handling" && /empty catch/i.test(f.message)),
      "Expected empty catch finding",
    );
  });
});

describe("detects TODO comments", () => {
  it("TODO is flagged", () => {
    const code = `
function process() {
  // TODO fix this before release
  return null;
}
`;
    const result = reviewCode(code, "process.ts");
    assert.ok(
      result.findings.some((f) => /TODO/i.test(f.message)),
      "Expected TODO finding",
    );
  });

  it("FIXME is flagged", () => {
    const code = `
// FIXME: memory leak here
setInterval(() => {}, 1000);
`;
    const result = reviewCode(code, "timer.ts");
    assert.ok(
      result.findings.some((f) => /FIXME/i.test(f.message)),
      "Expected FIXME finding",
    );
  });
});

describe("avoids structural false positives", () => {
  it("does not treat a multiline returned object as unreachable code", () => {
    const code = `
function load() {
  return {
    enabled: true,
    count: 1,
  };
}
`;
    const result = reviewCode(code, "config.ts");
    assert.ok(
      !result.findings.some((f) => /unreachable/i.test(f.message)),
    );
  });

  it("does not treat fetch text inside a string as a missing await", () => {
    const code =
      'const label = "Ordinary fetch (not piped to a shell)";\n' +
      'console.info(label);\n';
    const result = reviewCode(code, "demo.ts");
    assert.ok(
      !result.findings.some((f) => /missing await/i.test(f.message)),
    );
  });

  it("does not treat indented multiline template text as deeply nested code", () => {
    const code = `
function showHelp() {
  if (process.stdout.isTTY) {
    console.info(\`
            Agent firewall — local-first command inspection
            Scan prompts before they reach a coding agent
    \`);
  }
}
`;
    const result = reviewCode(code, "cli.ts");
    assert.ok(
      !result.findings.some((f) => /nested .* levels deep/i.test(f.message)),
    );
  });
});

// ═══════════════════════════════════════════════════════════════════
// Clean code passes
// ═══════════════════════════════════════════════════════════════════

describe("clean code", () => {
  it("well-written code gets high score", () => {
    const code = `
import { readFile } from "node:fs/promises";

interface Config {
  port: number;
  host: string;
}

async function loadConfig(path: string): Promise<Config> {
  const raw = await readFile(path, "utf-8");
  return JSON.parse(raw) as Config;
}

export { loadConfig };
`;
    const result = reviewCode(code, "config.ts");
    assert.ok(result.score >= 80, `Expected score >= 80 for clean code, got ${result.score}`);
  });

  it("returns summary string", () => {
    const result = reviewCode("const x = 1;", "simple.ts");
    assert.ok(typeof result.summary === "string");
    assert.ok(result.summary.length > 0);
  });
});

// ═══════════════════════════════════════════════════════════════════
// Scoring
// ═══════════════════════════════════════════════════════════════════

describe("scoring", () => {
  it("score is between 0 and 100", () => {
    const badCode = `
const api_key = "sk-abcdefghijklmnopqrstuvwxyz123456";
eval(userInput);
db.query("SELECT * FROM users WHERE id = " + id);
try { x(); } catch(e) {}
// TODO fix everything
console.log("debug");
`;
    const result = reviewCode(badCode, "bad.ts");
    assert.ok(result.score >= 0, `Score should be >= 0, got ${result.score}`);
    assert.ok(result.score <= 100, `Score should be <= 100, got ${result.score}`);
  });

  it("more issues = lower score (diminishing returns)", () => {
    const fixtureValue = ["hunter2", "abc1234"].join("");
    const oneIssue = `const password = "${fixtureValue}";`;
    const manyIssues = `
const password = "${fixtureValue}";
const api_key = "sk-abcdefghijklmnopqrstuvwxyz123456";
eval(userInput);
db.query("SELECT * FROM users WHERE id = " + id);
try { x(); } catch(e) {}
`;
    const r1 = reviewCode(oneIssue, "a.ts");
    const r2 = reviewCode(manyIssues, "b.ts");
    assert.ok(r1.score > r2.score, `One issue (${r1.score}) should score higher than many (${r2.score})`);
  });

  it("durationMs is reported", () => {
    const result = reviewCode("const x = 1;", "test.ts");
    assert.ok(typeof result.durationMs === "number");
    assert.ok(result.durationMs >= 0);
  });
});

// ═══════════════════════════════════════════════════════════════════
// Filtering options
// ═══════════════════════════════════════════════════════════════════

describe("review options", () => {
  const messyCode = `
const api_key = "sk-abcdefghijklmnopqrstuvwxyz123456";
eval(userInput);
// TODO fix this
console.log("debug");
try { x(); } catch(e) {}
`;

  it("minSeverity filters lower severity findings", () => {
    const all = reviewCode(messyCode, "test.ts");
    const criticalOnly = reviewCode(messyCode, "test.ts", { minSeverity: "critical" });
    assert.ok(criticalOnly.findings.length <= all.findings.length);
    assert.ok(criticalOnly.findings.every((f) => f.severity === "critical"));
  });

  it("categories filter limits to specific categories", () => {
    const secOnly = reviewCode(messyCode, "test.ts", { categories: ["security"] });
    assert.ok(secOnly.findings.every((f) => f.category === "security"));
  });

  it("maxFindings limits result count", () => {
    const result = reviewCode(messyCode, "test.ts", { maxFindings: 2 });
    assert.ok(result.findings.length <= 2);
  });
});

// ═══════════════════════════════════════════════════════════════════
// AI slop detection
// ═══════════════════════════════════════════════════════════════════

describe("AI slop detection", () => {
  it("detects obvious comments", () => {
    const code = `
// increment counter by 1
counter++;
// set name to empty string
let name = "";
`;
    const result = reviewCode(code, "slop.ts");
    assert.ok(
      result.findings.some((f) => f.category === "ai_slop" && /comment/i.test(f.message)),
      "Expected AI slop comment detection",
    );
  });

  it("detects unnecessary type assertions", () => {
    const code = `const data = response as any;`;
    const result = reviewCode(code, "cast.ts");
    assert.ok(
      result.findings.some((f) => f.category === "ai_slop" && /type assertion/i.test(f.message)),
      "Expected type assertion finding",
    );
  });
});

// ═══════════════════════════════════════════════════════════════════
// Performance detection
// ═══════════════════════════════════════════════════════════════════

describe("performance detection", () => {
  it("detects innerHTML assignment", () => {
    const code = `element.innerHTML = userInput;`;
    const result = reviewCode(code, "dom.ts");
    assert.ok(
      result.findings.some((f) => f.category === "security" && /innerHTML|XSS/i.test(f.message)),
      "Expected innerHTML/XSS finding",
    );
  });
});
