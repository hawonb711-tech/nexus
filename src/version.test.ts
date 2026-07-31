import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { VERSION } from "./version.js";

describe("runtime version", () => {
  it("comes from package.json", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf-8")) as { version: string };
    assert.equal(VERSION, pkg.version);
  });
});
