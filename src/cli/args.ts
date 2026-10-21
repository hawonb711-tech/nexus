/**
 * Argument parsing for the `nexus` CLI. Every option is declared: a value option
 * takes the next argument (or `--opt=value`), a switch never does — so
 * `nexus secrets --json <dir>` scans <dir> instead of reading it as the value of
 * --json and silently scanning the cwd. Unknown options are rejected rather than
 * ignored, so a typo like `--histroy` can't quietly skip the history scan.
 */

/** Options that take a value: `--vault <path>` or `--vault=<path>`. */
export const VALUE_FLAGS: ReadonlySet<string> = new Set([
  "--vault",                          // sync, export, skills, status, reorganize, train, memory, …
  "--max-commits",                    // secrets
  "--tools",                          // guard install
  "--dim", "--epochs", "--min-count", // train
  "--k", "--n",                       // eval-search, dense-eval
  "--max",                            // neighbors, feed
  "--domain",                         // collect, feed, ingest
  "--query",                          // forget
]);

/** On/off switches: present or absent, never followed by a value. */
export const BOOLEAN_FLAGS: ReadonlySet<string> = new Set([
  "--json",                // review, scan, secrets, map, onboard, test-health, config, neighbors, memory
  "--history", "--entropy", // secrets
  "--project",             // guard install / uninstall / status
  "--help", "--version",
]);

export type ParsedArgs = { command: string; args: string[]; flags: Record<string, string | undefined> };

/** Throws on an unknown option, a value option without a value, or a value
 *  given to a switch; the message is meant to be shown to the user as-is. */
export function parseArgs(argv: string[]): ParsedArgs {
  const flags: Record<string, string | undefined> = {};
  const positional: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    // `--` ends option parsing: `nexus scan -- "--looks like a flag"`.
    if (arg === "--") {
      positional.push(...argv.slice(i + 1));
      break;
    }
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }

    const eq = arg.indexOf("=");
    const name = eq < 0 ? arg : arg.slice(0, eq);
    if (VALUE_FLAGS.has(name)) {
      const value = eq < 0 ? argv[i + 1] : arg.slice(eq + 1);
      if (value === undefined || value === "" || (eq < 0 && value.startsWith("--"))) {
        throw new Error(`${name} needs a value`);
      }
      flags[name] = value;
      if (eq < 0) i++;
    } else if (BOOLEAN_FLAGS.has(name)) {
      if (eq >= 0) throw new Error(`${name} does not take a value`);
      flags[name] = undefined;
    } else {
      throw new Error(`Unknown option: ${name}`);
    }
  }

  const command = positional[0] ?? "help";
  const args = positional.slice(1);
  return { command, args, flags };
}
