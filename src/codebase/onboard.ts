import type { CodebaseMap } from "./types.js";

function buildDirectoryTree(files: string[], maxDepth: number): string {
  const tree = new Map<string, Set<string>>();

  for (const filePath of files) {
    const parts = filePath.split("/");
    for (let i = 0; i < parts.length && i < maxDepth; i++) {
      const dir = parts.slice(0, i).join("/") || ".";
      const child = parts[i];
      if (!tree.has(dir)) tree.set(dir, new Set());
      tree.get(dir)!.add(child);
    }
  }

  function renderTree(dir: string, prefix: string, isLast: boolean, depth: number): string {
    if (depth > maxDepth) return "";

    const children = tree.get(dir);
    if (!children) return "";

    const sorted = [...children].sort();
    const lines: string[] = [];

    for (let i = 0; i < sorted.length; i++) {
      const child = sorted[i];
      const last = i === sorted.length - 1;
      const connector = last ? "└── " : "├── ";
      const childPrefix = last ? "    " : "│   ";
      const childPath = dir === "." ? child : `${dir}/${child}`;
      const isDir = tree.has(childPath);

      lines.push(`${prefix}${connector}${child}${isDir ? "/" : ""}`);

      if (isDir) {
        lines.push(renderTree(childPath, prefix + childPrefix, last, depth + 1));
      }
    }

    return lines.filter(Boolean).join("\n");
  }

  return renderTree(".", "", false, 0);
}

function describeEntryPoint(path: string, map: CodebaseMap): string {
  const file = map.files.find((f) => f.path === path);
  if (!file) return path;

  const parts: string[] = [];
  if (file.language) parts.push(file.language);
  if (file.functions.length > 0) {
    parts.push(`functions: ${file.functions.slice(0, 5).join(", ")}${file.functions.length > 5 ? "..." : ""}`);
  }
  if (file.classes.length > 0) {
    parts.push(`classes: ${file.classes.join(", ")}`);
  }
  if (file.exports.length > 0) {
    parts.push(`exports: ${file.exports.slice(0, 5).join(", ")}${file.exports.length > 5 ? "..." : ""}`);
  }

  return parts.length > 0 ? `${path} (${parts.join(" | ")})` : path;
}

function summarizeDependencies(map: CodebaseMap): string {
  const lines: string[] = [];

  if (map.dependencies.length === 0) {
    lines.push("No internal dependencies detected.");
    return lines.join("\n");
  }

  // Group by source file
  const bySource = new Map<string, string[]>();
  for (const edge of map.dependencies) {
    if (!bySource.has(edge.from)) bySource.set(edge.from, []);
    bySource.get(edge.from)!.push(edge.to);
  }

  // Show top importers
  const topImporters = [...bySource.entries()]
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 10);

  for (const [source, targets] of topImporters) {
    lines.push(`- **${source}** imports from ${targets.length} file(s): ${targets.slice(0, 5).join(", ")}${targets.length > 5 ? "..." : ""}`);
  }

  return lines.join("\n");
}

export function generateOnboardingGuide(map: CodebaseMap): string {
  const sections: string[] = [];

  // Header
  sections.push(`# Codebase Onboarding Guide`);
  sections.push(`> Generated at ${map.generatedAt}`);
  sections.push("");

  // Project overview
  sections.push(`## Project Overview`);
  sections.push("");
  sections.push(`| Metric | Value |`);
  sections.push(`|--------|-------|`);
  sections.push(`| Root | \`${map.root}\` |`);
  sections.push(`| Total Files | ${map.totalFiles} |`);
  sections.push(`| Total Lines | ${map.totalLines.toLocaleString()} |`);
  sections.push(`| Languages | ${Object.keys(map.languages).length} |`);
  sections.push(`| Internal Dependencies | ${map.dependencies.length} |`);
  sections.push("");

  // Language breakdown
  sections.push(`## Languages`);
  sections.push("");
  const sortedLangs = Object.entries(map.languages).sort((a, b) => b[1] - a[1]);
  for (const [lang, count] of sortedLangs) {
    const pct = ((count / map.totalFiles) * 100).toFixed(1);
    sections.push(`- **${lang}**: ${count} files (${pct}%)`);
  }
  sections.push("");

  // Directory structure
  sections.push(`## Directory Structure`);
  sections.push("");
  sections.push("```");
  sections.push(buildDirectoryTree(map.files.map((f) => f.path), 3));
  sections.push("```");
  sections.push("");

  // Entry points
  sections.push(`## Entry Points`);
  sections.push("");
  if (map.entryPoints.length === 0) {
    sections.push("No clear entry points detected (all files are imported by something).");
  } else {
    sections.push("These files are not imported by any other file in the project, making them likely entry points:");
    sections.push("");
    const displayEntryPoints = map.entryPoints.slice(0, 20);
    for (const ep of displayEntryPoints) {
      sections.push(`- ${describeEntryPoint(ep, map)}`);
    }
    if (map.entryPoints.length > 20) {
      sections.push(`- ...and ${map.entryPoints.length - 20} more`);
    }
  }
  sections.push("");

  // Hotspots
  sections.push(`## Hotspot Files (Start Reading Here)`);
  sections.push("");
  if (map.hotspots.length === 0) {
    sections.push("No hotspots detected.");
  } else {
    sections.push("These files are imported most frequently, making them core modules:");
    sections.push("");
    for (const hp of map.hotspots) {
      const incomingCount = map.dependencies.filter((e) => e.to === hp).length;
      sections.push(`- **${hp}** (imported by ${incomingCount} files)`);
    }
  }
  sections.push("");

  // Dependency graph summary
  sections.push(`## Dependency Graph`);
  sections.push("");
  sections.push(summarizeDependencies(map));
  sections.push("");

  // Key modules
  const moduleGroups = new Map<string, string[]>();
  for (const file of map.files) {
    if (!file.language) continue;
    const topDir = file.path.includes("/") ? file.path.split("/")[0] : ".";
    if (!moduleGroups.has(topDir)) moduleGroups.set(topDir, []);
    moduleGroups.get(topDir)!.push(file.path);
  }

  if (moduleGroups.size > 1) {
    sections.push(`## Key Modules`);
    sections.push("");
    const sortedModules = [...moduleGroups.entries()].sort((a, b) => b[1].length - a[1].length);
    for (const [dir, modulePaths] of sortedModules.slice(0, 15)) {
      const langCounts = new Map<string, number>();
      for (const p of modulePaths) {
        const file = map.files.find((f) => f.path === p);
        if (file?.language) {
          langCounts.set(file.language, (langCounts.get(file.language) ?? 0) + 1);
        }
      }
      const langSummary = [...langCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([l, c]) => `${l}: ${c}`)
        .join(", ");
      sections.push(`- **${dir}/**: ${modulePaths.length} files (${langSummary})`);
    }
    sections.push("");
  }

  return sections.join("\n");
}
