import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, extname, resolve, sep } from "node:path";
import type { FileNode, DependencyEdge, CodebaseMap, MapOptions } from "./types.js";

const DEFAULT_IGNORE = [
  "node_modules",
  ".git",
  "dist",
  "build",
  "__pycache__",
  ".next",
  ".nuxt",
  "coverage",
  ".cache",
  ".venv",
  "venv",
  "target",
];

const LANGUAGE_MAP: Record<string, string> = {
  ".ts": "TypeScript",
  ".tsx": "TypeScript",
  ".js": "JavaScript",
  ".jsx": "JavaScript",
  ".mjs": "JavaScript",
  ".cjs": "JavaScript",
  ".py": "Python",
  ".go": "Go",
  ".rs": "Rust",
  ".java": "Java",
  ".kt": "Kotlin",
  ".rb": "Ruby",
  ".php": "PHP",
  ".c": "C",
  ".cpp": "C++",
  ".cc": "C++",
  ".h": "C",
  ".hpp": "C++",
  ".cs": "C#",
  ".swift": "Swift",
  ".scala": "Scala",
  ".lua": "Lua",
  ".sh": "Shell",
  ".bash": "Shell",
  ".zsh": "Shell",
  ".json": "JSON",
  ".yaml": "YAML",
  ".yml": "YAML",
  ".toml": "TOML",
  ".xml": "XML",
  ".html": "HTML",
  ".css": "CSS",
  ".scss": "SCSS",
  ".sql": "SQL",
  ".md": "Markdown",
  ".vue": "Vue",
  ".svelte": "Svelte",
};

/**
 * Codebase maps use POSIX-style relative paths as stable identifiers, even
 * when the repository is scanned on Windows. Keep the absolute root native,
 * but normalize paths before they enter files, edges, entry points or
 * hotspots so every consumer sees the same representation.
 */
function toPortableRelativePath(filePath: string): string {
  return sep === "/" ? filePath : filePath.split(sep).join("/");
}

function detectLanguage(filePath: string): string | undefined {
  const ext = extname(filePath).toLowerCase();
  return LANGUAGE_MAP[ext];
}

type ImportEntry = { path: string; type: "import" | "require" };

function extractImports(content: string, language: string | undefined): string[] {
  return extractImportsWithType(content, language).map((e) => e.path);
}

function extractImportsWithType(content: string, language: string | undefined): ImportEntry[] {
  const imports: ImportEntry[] = [];

  if (!language) return imports;

  switch (language) {
    case "TypeScript":
    case "JavaScript": {
      // import ... from "..."
      const esImports = content.matchAll(/import\s+.*?\s+from\s+["']([^"']+)["']/g);
      for (const m of esImports) imports.push({ path: m[1], type: "import" });

      // import "..."
      const sideEffects = content.matchAll(/import\s+["']([^"']+)["']/g);
      for (const m of sideEffects) imports.push({ path: m[1], type: "import" });

      // require("...")
      const requires = content.matchAll(/require\s*\(\s*["']([^"']+)["']\s*\)/g);
      for (const m of requires) imports.push({ path: m[1], type: "require" });

      // export ... from "..."
      const reExports = content.matchAll(/export\s+.*?\s+from\s+["']([^"']+)["']/g);
      for (const m of reExports) imports.push({ path: m[1], type: "import" });
      break;
    }
    case "Python": {
      const fromImports = content.matchAll(/from\s+(\S+)\s+import/g);
      for (const m of fromImports) imports.push({ path: m[1], type: "import" });

      const directImports = content.matchAll(/^import\s+(\S+)/gm);
      for (const m of directImports) imports.push({ path: m[1], type: "import" });
      break;
    }
    case "Go": {
      const singleImport = content.matchAll(/import\s+"([^"]+)"/g);
      for (const m of singleImport) imports.push({ path: m[1], type: "import" });

      const blockImport = content.matchAll(/import\s*\(([\s\S]*?)\)/g);
      for (const m of blockImport) {
        const pkgs = m[1].matchAll(/"([^"]+)"/g);
        for (const p of pkgs) imports.push({ path: p[1], type: "import" });
      }
      break;
    }
    case "Rust": {
      const useStmts = content.matchAll(/use\s+([^;]+);/g);
      for (const m of useStmts) imports.push({ path: m[1].trim(), type: "import" });
      break;
    }
    case "Java":
    case "Kotlin": {
      const javaImports = content.matchAll(/import\s+(?:static\s+)?([^;]+);/g);
      for (const m of javaImports) imports.push({ path: m[1].trim(), type: "import" });
      break;
    }
  }

  return imports;
}

function extractExports(content: string, language: string | undefined): string[] {
  const exports: string[] = [];

  if (!language) return exports;

  switch (language) {
    case "TypeScript":
    case "JavaScript": {
      // export function/const/class/type/interface/enum NAME
      const namedExports = content.matchAll(
        /export\s+(?:default\s+)?(?:function|const|let|var|class|type|interface|enum|abstract\s+class)\s+(\w+)/g
      );
      for (const m of namedExports) exports.push(m[1]);

      // export { ... }
      const braceExports = content.matchAll(/export\s*\{([^}]+)\}/g);
      for (const m of braceExports) {
        const names = m[1].split(",").map((s) => s.trim().split(/\s+as\s+/).pop()!.trim());
        exports.push(...names.filter(Boolean));
      }

      // export default
      if (/export\s+default\s/.test(content) && !exports.includes("default")) {
        exports.push("default");
      }

      // module.exports
      if (/module\.exports\s*=/.test(content)) {
        exports.push("module.exports");
      }
      break;
    }
    case "Python": {
      // __all__ = [...]
      const allMatch = content.match(/__all__\s*=\s*\[([^\]]+)\]/);
      if (allMatch) {
        const names = allMatch[1].matchAll(/["'](\w+)["']/g);
        for (const n of names) exports.push(n[1]);
      }
      break;
    }
    case "Rust": {
      const pubItems = content.matchAll(/pub\s+(?:fn|struct|enum|trait|type|const|static|mod)\s+(\w+)/g);
      for (const m of pubItems) exports.push(m[1]);
      break;
    }
    case "Go": {
      // Exported identifiers start with uppercase
      const funcs = content.matchAll(/func\s+(?:\([^)]*\)\s+)?([A-Z]\w*)\s*\(/g);
      for (const m of funcs) exports.push(m[1]);
      const types = content.matchAll(/type\s+([A-Z]\w*)\s+/g);
      for (const m of types) exports.push(m[1]);
      break;
    }
  }

  return exports;
}

function extractFunctions(content: string, language: string | undefined): string[] {
  const functions: string[] = [];

  if (!language) return functions;

  switch (language) {
    case "TypeScript":
    case "JavaScript": {
      // function name(
      const funcDecls = content.matchAll(/function\s+(\w+)\s*\(/g);
      for (const m of funcDecls) functions.push(m[1]);

      // const/let/var name = ( | => | function
      const arrowFuncs = content.matchAll(
        /(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=])\s*=>/g
      );
      for (const m of arrowFuncs) functions.push(m[1]);

      // const name = function
      const funcExprs = content.matchAll(/(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function/g);
      for (const m of funcExprs) functions.push(m[1]);

      // method definitions in classes: name(
      const methods = content.matchAll(/^\s+(?:async\s+)?(\w+)\s*\([^)]*\)\s*(?::\s*\w+)?\s*\{/gm);
      for (const m of methods) {
        if (!["if", "for", "while", "switch", "catch", "constructor"].includes(m[1])) {
          functions.push(m[1]);
        }
      }
      break;
    }
    case "Python": {
      const defs = content.matchAll(/def\s+(\w+)\s*\(/g);
      for (const m of defs) functions.push(m[1]);
      break;
    }
    case "Go": {
      const goFuncs = content.matchAll(/func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(/g);
      for (const m of goFuncs) functions.push(m[1]);
      break;
    }
    case "Rust": {
      const rsFuncs = content.matchAll(/fn\s+(\w+)\s*[(<]/g);
      for (const m of rsFuncs) functions.push(m[1]);
      break;
    }
    case "Java":
    case "Kotlin": {
      const javaMethods = content.matchAll(
        /(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(/g
      );
      for (const m of javaMethods) {
        if (!["if", "for", "while", "switch", "catch", "class"].includes(m[1])) {
          functions.push(m[1]);
        }
      }
      break;
    }
  }

  return [...new Set(functions)];
}

function extractClasses(content: string, language: string | undefined): string[] {
  const classes: string[] = [];

  if (!language) return classes;

  switch (language) {
    case "TypeScript":
    case "JavaScript":
    case "Java":
    case "Kotlin":
    case "Python": {
      const classDecls = content.matchAll(/class\s+(\w+)/g);
      for (const m of classDecls) classes.push(m[1]);
      break;
    }
    case "Rust": {
      const structs = content.matchAll(/(?:struct|enum|trait)\s+(\w+)/g);
      for (const m of structs) classes.push(m[1]);
      break;
    }
    case "Go": {
      const goTypes = content.matchAll(/type\s+(\w+)\s+struct/g);
      for (const m of goTypes) classes.push(m[1]);
      break;
    }
    case "C++":
    case "C#": {
      const cppClasses = content.matchAll(/(?:class|struct)\s+(\w+)/g);
      for (const m of cppClasses) classes.push(m[1]);
      break;
    }
  }

  return [...new Set(classes)];
}

async function walkDirectory(
  dir: string,
  rootDir: string,
  ignoreSet: Set<string>,
  maxFiles: number,
  maxDepth: number,
  currentDepth: number,
  files: FileNode[]
): Promise<void> {
  if (currentDepth > maxDepth || files.length >= maxFiles) return;

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (files.length >= maxFiles) break;
    if (ignoreSet.has(entry.name)) continue;
    if (entry.name.startsWith(".") && entry.name !== ".") continue;

    const fullPath = join(dir, entry.name);
    const relPath = toPortableRelativePath(relative(rootDir, fullPath));

    if (entry.isDirectory()) {
      await walkDirectory(fullPath, rootDir, ignoreSet, maxFiles, maxDepth, currentDepth + 1, files);
    } else if (entry.isFile()) {
      const language = detectLanguage(entry.name);
      let fileStat;
      try {
        fileStat = await stat(fullPath);
      } catch {
        continue;
      }

      // Skip binary/large files
      if (fileStat.size > 1_000_000) continue;

      let content = "";
      let lineCount = 0;
      let imports: string[] = [];
      let importInfos: ImportEntry[] = [];
      let exports: string[] = [];
      let functions: string[] = [];
      let classes: string[] = [];

      if (language) {
        try {
          content = await readFile(fullPath, "utf-8");
          lineCount = content.split("\n").length;
          importInfos = extractImportsWithType(content, language);
          imports = importInfos.map((e) => e.path);
          exports = extractExports(content, language);
          functions = extractFunctions(content, language);
          classes = extractClasses(content, language);
        } catch {
          // Binary file or encoding issue
        }
      }

      files.push({
        path: relPath,
        type: "file",
        language,
        size: fileStat.size,
        imports,
        importInfos,
        exports,
        functions,
        classes,
        lineCount,
      });
    }
  }
}

function resolveImportPath(
  fromFile: string,
  importSpecifier: string,
  allFilePaths: Set<string>
): string | null {
  // Skip external/node modules
  if (
    !importSpecifier.startsWith(".") &&
    !importSpecifier.startsWith("/")
  ) {
    return null;
  }

  // Top-level files have no directory prefix; using "." here would leak a "."
  // segment into the resolved path and break edge resolution for flat repos.
  const fromDir = fromFile.includes("/")
    ? fromFile.substring(0, fromFile.lastIndexOf("/"))
    : "";

  let resolved: string;
  if (importSpecifier.startsWith("/")) {
    resolved = importSpecifier.substring(1);
  } else {
    // Resolve relative path
    const parts = fromDir.split("/").filter(Boolean);
    const importParts = importSpecifier.split("/");
    for (const p of importParts) {
      if (p === "..") parts.pop();
      else if (p !== ".") parts.push(p);
    }
    resolved = parts.join("/");
  }

  // Try exact match first, then with extensions
  const extensions = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"];
  for (const ext of extensions) {
    const candidate = resolved + ext;
    // Strip .js extension that TypeScript ESM uses for .ts files
    const tsCandidate = candidate.replace(/\.js$/, ".ts");
    if (allFilePaths.has(candidate)) return candidate;
    if (allFilePaths.has(tsCandidate)) return tsCandidate;
  }

  return null;
}

function buildDependencyGraph(
  files: FileNode[]
): DependencyEdge[] {
  const edges: DependencyEdge[] = [];
  const allPaths = new Set(files.map((f) => f.path));

  for (const file of files) {
    const infos = file.importInfos ?? file.imports.map((p) => ({ path: p, type: "import" as const }));
    for (const info of infos) {
      const resolved = resolveImportPath(file.path, info.path, allPaths);
      if (resolved) {
        edges.push({ from: file.path, to: resolved, type: info.type });
      }
    }
  }

  return edges;
}

function findEntryPoints(files: FileNode[], edges: DependencyEdge[]): string[] {
  const imported = new Set(edges.map((e) => e.to));
  return files
    .filter((f) => f.language && !imported.has(f.path))
    .map((f) => f.path);
}

function findHotspots(files: FileNode[], edges: DependencyEdge[], topN: number = 10): string[] {
  const incomingCount = new Map<string, number>();
  for (const edge of edges) {
    incomingCount.set(edge.to, (incomingCount.get(edge.to) ?? 0) + 1);
  }

  return [...incomingCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN)
    .map(([path]) => path);
}

export async function mapCodebase(options: MapOptions): Promise<CodebaseMap> {
  const root = resolve(options.root);
  const ignorePatterns = options.ignore ?? DEFAULT_IGNORE;
  const ignoreSet = new Set(ignorePatterns);
  const maxFiles = options.maxFiles ?? 10_000;
  const maxDepth = options.maxDepth ?? 50;

  const files: FileNode[] = [];
  await walkDirectory(root, root, ignoreSet, maxFiles, maxDepth, 0, files);

  const edges = buildDependencyGraph(files);

  // Compute language stats
  const languages: Record<string, number> = {};
  let totalLines = 0;
  for (const file of files) {
    if (file.language) {
      languages[file.language] = (languages[file.language] ?? 0) + 1;
    }
    totalLines += file.lineCount;
  }

  const entryPoints = findEntryPoints(files, edges);
  const hotspots = findHotspots(files, edges);

  return {
    root,
    files,
    dependencies: edges,
    languages,
    totalFiles: files.length,
    totalLines,
    entryPoints,
    hotspots,
    generatedAt: new Date().toISOString(),
  };
}
