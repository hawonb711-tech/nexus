/**
 * Where Nexus keeps its state (memory observations, status, keys).
 *
 * One definition for every entry point — the CLI, the MCP server and the guard
 * hook — so they agree on the directory. `NEXUS_DATA` overrides the default
 * `~/.nexus`, read the same way everywhere:
 * - empty is unset (an `export NEXUS_DATA=` left in a dotfile or env template);
 * - a leading `~/` (also `~\` on Windows) is the home directory: Claude Code
 *   hands a settings `env` value to its hooks without a shell to expand it;
 * - any other value that is not absolute is ignored for `~/.nexus`. A hook runs
 *   in the user's repository, where a relative value would put the integrity
 *   key and stores as untracked files one `git add .` from a commit. The CLI
 *   ignores it too rather than resolve it against its own cwd, so it never
 *   installs into or reports on a store the hooks do not use; `guard status`
 *   and `guard integrity status` say when a value was ignored.
 * The hook entry loads this on every call: node: builtins only.
 */

import { homedir } from "node:os";
import { posix, win32 } from "node:path";

/** D and, when `NEXUS_DATA` was set but not used, its value. */
export type DataDirChoice = { dir: string; ignored: string | null };

/** D for a `NEXUS_DATA` value (undefined when unset), as every entry point reads it. */
export function dataDirFrom(value: string | undefined, home: string, platform: NodeJS.Platform = process.platform): DataDirChoice {
  const path = platform === "win32" ? win32 : posix;
  const fallback = path.resolve(home, ".nexus");
  if (value === undefined || value === "") return { dir: fallback, ignored: null };
  const tilde = value === "~" || value.startsWith("~/") || (platform === "win32" && value.startsWith("~\\"));
  if (tilde) return { dir: path.resolve(home, value.slice(2)), ignored: null };
  return path.isAbsolute(value) ? { dir: path.resolve(value), ignored: null } : { dir: fallback, ignored: value };
}

export function nexusDataDir(): string {
  return dataDirFrom(process.env.NEXUS_DATA, homedir()).dir;
}
