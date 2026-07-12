import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, isAbsolute, join, parse, relative, resolve, sep } from "node:path";

export type PathPolicyOptions = {
  cwd?: string;
  home?: string;
  env?: NodeJS.ProcessEnv;
  allowedRoots?: string[];
  /** Include the current working directory (default: true). */
  includeCwd?: boolean;
  /** Include the two discovered AI-session roots (default: false). */
  includeSessionRoots?: boolean;
};

function canonicalExistingPath(path: string): string {
  const absolute = resolve(path);
  const nativeRealpath = realpathSync.native ?? realpathSync;
  return nativeRealpath(absolute);
}

function isFilesystemRoot(path: string): boolean {
  const parsed = parse(path);
  return resolve(path) === resolve(parsed.root);
}

export function isWithinRoot(root: string, target: string): boolean {
  const rel = relative(root, target);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function configuredRoots(options: PathPolicyOptions): string[] {
  const cwd = resolve(options.cwd ?? process.cwd());
  const home = resolve(options.home ?? homedir());
  const env = options.env ?? process.env;
  const roots: string[] = [];

  // Running from a filesystem root must not silently grant access to the whole
  // machine. Users can still opt in explicitly through NEXUS_ALLOWED_ROOTS.
  if ((options.includeCwd ?? true) && !isFilesystemRoot(cwd)) roots.push(cwd);

  if (options.includeSessionRoots ?? false) {
    // These roots are privileged and must only be enabled for session tools,
    // never for general review/map/config/document file access.
    roots.push(join(home, ".claude"), join(home, ".openclaw"));
  }

  if (env.NEXUS_ALLOWED_ROOTS) {
    roots.push(...env.NEXUS_ALLOWED_ROOTS.split(delimiter).filter(Boolean));
  }
  roots.push(...(options.allowedRoots ?? []));
  return roots;
}

/** Build a validator that canonicalizes both roots and targets before testing containment. */
export function createPathValidator(options: PathPolicyOptions = {}): (filePath: string) => string {
  const roots = configuredRoots(options).flatMap((candidate) => {
    try {
      return [canonicalExistingPath(candidate)];
    } catch {
      return [];
    }
  });
  const uniqueRoots = [...new Set(roots)];

  return (filePath: string): string => {
    let target: string;
    try {
      target = canonicalExistingPath(filePath);
    } catch {
      throw new Error(`Path does not exist or cannot be resolved safely: ${filePath}`);
    }

    if (uniqueRoots.some((root) => isWithinRoot(root, target))) return target;
    throw new Error(
      `Path outside allowed roots: ${filePath}. ` +
      "Set NEXUS_ALLOWED_ROOTS to an explicit path list when additional roots are required.",
    );
  };
}
