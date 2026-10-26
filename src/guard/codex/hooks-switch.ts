/**
 * Codex CLI's switch for its hooks (0.164.0): which settings of a config turn
 * every Codex hook off, Nexus's included. The one reader of it, kept apart
 * from the TOML scanners so the static write guard can ask it without loading
 * them: the install and `guard status --codex` (trust.ts `hooksFeatureOff`),
 * the integrity layer's units of Codex's config files (units.ts, which
 * `guard integrity status` and a Claude Code session's hooks-off warning read)
 * and the write guard (command.ts `codexHooksOffIn`) each read a file their
 * own way and hand it the booleans it sets.
 */

/**
 * Is `path` a requirements.toml, the one managed file Codex reads
 * `allow_managed_hooks_only` from (`hooksOffSwitches`' `managed`)? Codex maps a
 * legacy managed_config.toml to requirements for its approval and sandbox
 * keys alone (config/src/loader/mod.rs `legacy_requirements_to_toml_value`),
 * and its system config.toml is a config layer. Told apart by the file's name,
 * either separator.
 */
export const isCodexRequirements = (path: string): boolean => /(?:^|[\\/])requirements\.toml$/i.test(path);

/** A boolean a Codex config sets: its full key path, its value, and the caller's handle on where it is set. */
export type ConfigBoolean<T> = { path: readonly string[]; value: boolean; at: T };

/**
 * Which of a config's booleans turn every Codex hook off. Codex 0.164.0's
 * rule, from its source:
 * - the hooks feature, `[features] hooks = false` or the deprecated
 *   `codex_hooks`. Codex applies `codex_hooks`, then `hooks`
 *   (codex-rs/features/src/lib.rs `apply_map` walks the table in key order),
 *   so `hooks` decides when the file sets it, and `codex_hooks` only when it
 *   does not. Only `[features]` counts: Codex builds its features from that
 *   table alone (core/src/config/mod.rs `Features::from_sources`), never from
 *   `[profiles.<name>.features]`, and refuses to start on a config.toml that
 *   selects a profile (`profile = "…"`), which it says itself;
 * - `allow_managed_hooks_only = true`, which runs managed hooks only. Codex
 *   reads it from requirements alone (config_requirements.rs), so it counts
 *   only in requirements.toml (`managed`, `isCodexRequirements`).
 * `fragment`: the text may be a piece of a file (an edit's new text), whose
 * top-level `hooks` and `codex_hooks` may sit under `[features]` there, so
 * they count as the feature's. A key set twice counts as last set (Codex
 * refuses such a file anyway). Returns the switches, the feature's first.
 */
export function hooksOffSwitches<T>(sets: Iterable<ConfigBoolean<T>>, where: { managed?: boolean; fragment?: boolean } = {}): T[] {
  let legacy: ConfigBoolean<T> | null = null;
  let hooks: ConfigBoolean<T> | null = null;
  const managedOnly: T[] = [];
  for (const set of sets) {
    const p = where.fragment && set.path.length === 1 && (set.path[0] === "hooks" || set.path[0] === "codex_hooks") ? ["features", set.path[0]] : set.path;
    if (p.length === 2 && p[0] === "features" && p[1] === "codex_hooks") legacy = set;
    else if (p.length === 2 && p[0] === "features" && p[1] === "hooks") hooks = set;
    else if (where.managed && p.length === 1 && p[0] === "allow_managed_hooks_only" && set.value) managedOnly.push(set.at);
  }
  const feature = hooks ?? legacy;
  return [...(feature && !feature.value ? [feature.at] : []), ...managedOnly];
}
