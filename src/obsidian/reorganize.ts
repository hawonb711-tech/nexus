import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  renameSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { basename, join, parse, resolve } from "node:path";

const GENERATED_FOLDERS = [
  "Sessions",
  "Skills",
  "Evolved Skills",
  "Wisdom",
  "Refined Skills",
  "skills",
  "evolved-skills",
  "wisdom",
] as const;

export type VaultBackupResult = {
  backupRoot: string | null;
  moved: { folder: string; entries: number }[];
};

/**
 * Move Nexus-generated vault folders into a recoverable backup before a rebuild.
 *
 * Only exact generated-folder names under the explicitly selected vault are
 * touched. Older/guessed vault locations are never scanned.
 */
export function backupGeneratedVaultFolders(vaultPath: string): VaultBackupResult {
  const vaultRoot = resolve(vaultPath);
  if (vaultRoot === parse(vaultRoot).root) {
    throw new Error(`Refusing to reorganize a filesystem root: ${vaultRoot}`);
  }

  const present = GENERATED_FOLDERS
    .map((folder) => ({ folder, path: join(vaultRoot, folder) }))
    .filter(({ path }) => existsSync(path));
  if (present.length === 0) return { backupRoot: null, moved: [] };

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupRoot = join(
    vaultRoot,
    ".nexus-backups",
    `${stamp}-${randomUUID().slice(0, 8)}`,
  );
  mkdirSync(backupRoot, { recursive: true });

  const moved: VaultBackupResult["moved"] = [];
  for (const item of present) {
    const stat = lstatSync(item.path);
    const entries = stat.isDirectory() && !stat.isSymbolicLink()
      ? readdirSync(item.path).length
      : 1;
    renameSync(item.path, join(backupRoot, basename(item.path)));
    moved.push({ folder: item.folder, entries });
  }
  return { backupRoot, moved };
}
