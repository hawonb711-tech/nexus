import { readFileSync } from "node:fs";

type PackageMetadata = { version?: unknown };

const metadata = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf-8"),
) as PackageMetadata;

if (typeof metadata.version !== "string" || metadata.version.length === 0) {
  throw new Error("Nexus package version is missing or invalid.");
}

/** Runtime version sourced from the published package metadata. */
export const VERSION = metadata.version;
