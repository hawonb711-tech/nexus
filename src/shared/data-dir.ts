/**
 * Where Nexus keeps its state (memory observations, status, keys).
 *
 * One definition for every entry point — the CLI, the MCP server and the guard
 * hook — so they agree on the directory. `NEXUS_DATA` overrides the default
 * `~/.nexus`; the result is always absolute, so a relative override resolves
 * once against the process cwd instead of again on every later `join`.
 */

import { homedir } from "node:os";
import { join, resolve } from "node:path";

export function nexusDataDir(): string {
  return resolve(process.env.NEXUS_DATA ?? join(homedir(), ".nexus"));
}
