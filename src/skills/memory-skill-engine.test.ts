import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { sessionDomainFromPaths } from "./memory-skill-engine.js";

describe("sessionDomainFromPaths", () => {
  it("extracts the project name from Windows and POSIX paths", () => {
    assert.equal(sessionDomainFromPaths("C:\\Users\\alice\\code\\nexus"), "nexus");
    assert.equal(sessionDomainFromPaths("/home/alice/code/nexus"), "nexus");
  });

  it("falls back to projectPath and then unknown", () => {
    assert.equal(sessionDomainFromPaths(undefined, "D:\\work\\project"), "project");
    assert.equal(sessionDomainFromPaths(undefined, undefined), "unknown");
  });
});
