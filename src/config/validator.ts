import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, basename } from "node:path";
import type { ConfigReport, ConfigIssue } from "./types.js";

const CONFIG_FILE_PATTERNS = [
  /^\.env$/,
  /^\.env\..+$/,
  /\.config\.[jt]s$/,
  /\.config\.mjs$/,
  /\.config\.cjs$/,
  /^docker-compose\.ya?ml$/,
  /^Dockerfile$/,
  /^\.dockerignore$/,
  /^tsconfig.*\.json$/,
  /^\.eslintrc/,
  /^\.prettierrc/,
  /^jest\.config/,
  /^vitest\.config/,
  /^\.babelrc/,
  /^webpack\.config/,
  /^rollup\.config/,
  /^vite\.config/,
  /^next\.config/,
  /^nuxt\.config/,
  /^tailwind\.config/,
  /^postcss\.config/,
];

const INSECURE_PATTERNS: Array<{ key: RegExp; value: RegExp; message: string }> = [
  { key: /^DEBUG$/i, value: /^true$/i, message: "DEBUG=true should not be enabled in production" },
  { key: /^NODE_ENV$/i, value: /^development$/i, message: "NODE_ENV=development found — verify this is not a production config" },
  { key: /^LOG_LEVEL$/i, value: /^(debug|trace)$/i, message: "Verbose logging enabled — may leak sensitive data in production" },
  { key: /^CORS_ORIGIN$/i, value: /^\*$/, message: "CORS_ORIGIN=* allows all origins — restrict in production" },
  { key: /^DISABLE_AUTH/i, value: /^(true|1|yes)$/i, message: "Authentication is disabled" },
  { key: /^VERIFY_SSL$/i, value: /^(false|0|no)$/i, message: "SSL verification is disabled" },
  { key: /^TLS_REJECT_UNAUTHORIZED$/i, value: /^0$/, message: "TLS certificate verification is disabled" },
];

const SECRET_PATTERNS = [
  /password/i,
  /secret/i,
  /api[_-]?key/i,
  /token/i,
  /private[_-]?key/i,
  /access[_-]?key/i,
  /auth/i,
  /credential/i,
  /database[_-]?url/i,
  /connection[_-]?string/i,
  /smtp/i,
  /aws[_-]?/i,
  /stripe/i,
  /twilio/i,
  /sendgrid/i,
];

const DEPRECATED_KEYS: Record<string, string> = {
  "REACT_APP_": "Create React App is deprecated; consider using VITE_ prefix with Vite",
  "EXPERIMENTAL_": "Experimental flags should be reviewed and either promoted or removed",
};

function isEnvFile(name: string): boolean {
  return /^\.env(\..*)?$/.test(name);
}

function isConfigFile(name: string): boolean {
  return CONFIG_FILE_PATTERNS.some((p) => p.test(name));
}

function parseEnvFile(content: string): Array<{ key: string; value: string; line: number }> {
  const entries: Array<{ key: string; value: string; line: number }> = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;
    const eqIndex = line.indexOf("=");
    if (eqIndex === -1) continue;
    const key = line.slice(0, eqIndex).trim();
    let value = line.slice(eqIndex + 1).trim();
    // Strip quotes
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    entries.push({ key, value, line: i + 1 });
  }
  return entries;
}

function extractEnvReferences(content: string, extension: string): string[] {
  const refs = new Set<string>();

  const processEnvDot = /process\.env\.([A-Z_][A-Z0-9_]*)/g;
  const processEnvBracket = /process\.env\[['"]([A-Z_][A-Z0-9_]*)['"]\]/g;
  const importMetaEnv = /import\.meta\.env\.([A-Z_][A-Z0-9_]*)/g;
  const osEnviron = /os\.(?:environ\[['"]|getenv\(['"])([A-Z_][A-Z0-9_]*)/g;
  const goEnv = /os\.(?:Getenv|LookupEnv)\(\s*["']([A-Z_][A-Z0-9_]*)["']/g;

  const patterns =
    extension === ".py"
      ? [osEnviron]
      : extension === ".go"
        ? [goEnv]
        : [processEnvDot, processEnvBracket, importMetaEnv];

  for (const re of patterns) {
    let m;
    while ((m = re.exec(content)) !== null) {
      refs.add(m[1]);
    }
  }

  return [...refs];
}

async function walkDir(
  dir: string,
  ignore: Set<string> = new Set(["node_modules", ".git", "dist", "build", "__pycache__", ".venv", ".next", "coverage"])
): Promise<string[]> {
  const results: string[] = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    if (ignore.has(entry.name)) continue;
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      const sub = await walkDir(fullPath, ignore);
      results.push(...sub);
    } else if (entry.isFile()) {
      results.push(fullPath);
    }
  }
  return results;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

export async function validateConfig(projectRoot: string): Promise<ConfigReport> {
  const allFiles = await walkDir(projectRoot);
  const configFiles: string[] = [];
  const issues: ConfigIssue[] = [];
  let envVarCount = 0;

  // Collect config files
  for (const f of allFiles) {
    const name = basename(f);
    if (isConfigFile(name)) {
      configFiles.push(f);
    }
  }

  // Check if .gitignore exists and what it ignores
  const gitignorePath = join(projectRoot, ".gitignore");
  let gitignoreContent = "";
  if (await fileExists(gitignorePath)) {
    try {
      gitignoreContent = await readFile(gitignorePath, "utf-8");
    } catch {
      // ignore
    }
  }

  const gitignorePatterns = gitignoreContent
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));

  function isGitignored(relPath: string): boolean {
    const name = basename(relPath);
    return gitignorePatterns.some((pattern) => {
      if (pattern === name) return true;
      if (pattern === relPath) return true;
      if (pattern.endsWith("/") && relPath.startsWith(pattern)) return true;
      // Simple glob: *.env
      if (pattern.startsWith("*") && name.endsWith(pattern.slice(1))) return true;
      // .env* pattern
      if (pattern.endsWith("*") && name.startsWith(pattern.slice(0, -1))) return true;
      return false;
    });
  }

  // Collect all env entries across files for duplicate detection
  const allEnvEntries: Map<string, Array<{ file: string; value: string; line: number }>> = new Map();
  const envFileEntries: Map<string, Map<string, string>> = new Map();

  // Process env files
  const envFiles = configFiles.filter((f) => isEnvFile(basename(f)));
  for (const ef of envFiles) {
    const relPath = relative(projectRoot, ef);
    let content: string;
    try {
      content = await readFile(ef, "utf-8");
    } catch {
      continue;
    }

    const entries = parseEnvFile(content);
    envVarCount += entries.length;
    const fileMap = new Map<string, string>();

    for (const entry of entries) {
      fileMap.set(entry.key, entry.value);

      // Track for duplicate detection across files
      if (!allEnvEntries.has(entry.key)) {
        allEnvEntries.set(entry.key, []);
      }
      allEnvEntries.get(entry.key)!.push({ file: relPath, value: entry.value, line: entry.line });

      // Check for insecure defaults
      for (const pattern of INSECURE_PATTERNS) {
        if (pattern.key.test(entry.key) && pattern.value.test(entry.value)) {
          issues.push({
            file: relPath,
            key: entry.key,
            issue: "insecure",
            message: pattern.message,
            severity: "warning",
            suggestion: `Review the value of ${entry.key} for production safety`,
          });
        }
      }

      // Check for deprecated key prefixes
      for (const [prefix, msg] of Object.entries(DEPRECATED_KEYS)) {
        if (entry.key.startsWith(prefix)) {
          issues.push({
            file: relPath,
            key: entry.key,
            issue: "deprecated",
            message: msg,
            severity: "info",
          });
        }
      }
    }

    envFileEntries.set(relPath, fileMap);

    // Check if .env files containing secrets are in .gitignore
    const name = basename(ef);
    if (name === ".env" || (name.startsWith(".env.") && !name.endsWith(".example") && !name.endsWith(".template") && !name.endsWith(".sample"))) {
      const hasSecrets = entries.some((e) =>
        SECRET_PATTERNS.some((p) => p.test(e.key)) && e.value.length > 0
      );

      if (hasSecrets && !isGitignored(relPath) && !isGitignored(name)) {
        issues.push({
          file: relPath,
          key: "",
          issue: "insecure",
          message: `${relPath} contains secret values but is not in .gitignore`,
          severity: "critical",
          suggestion: `Add "${name}" to .gitignore to prevent committing secrets`,
        });
      }
    }
  }

  // Check for duplicate keys across env files (same key, different values)
  for (const [key, locations] of allEnvEntries) {
    if (locations.length > 1) {
      const uniqueValues = new Set(locations.map((l) => l.value));
      if (uniqueValues.size > 1) {
        const fileList = locations.map((l) => `${l.file}:${l.line}`).join(", ");
        issues.push({
          file: locations[0].file,
          key,
          issue: "duplicate",
          message: `Key "${key}" defined in multiple env files with different values: ${fileList}`,
          severity: "warning",
          suggestion: `Ensure "${key}" has consistent values or document why they differ`,
        });
      }
    }
  }

  // Compare .env.example with .env
  const envExamplePath = join(projectRoot, ".env.example");
  const envPath = join(projectRoot, ".env");
  if (await fileExists(envExamplePath) && await fileExists(envPath)) {
    try {
      const exampleContent = await readFile(envExamplePath, "utf-8");
      const exampleEntries = parseEnvFile(exampleContent);
      const envContent = await readFile(envPath, "utf-8");
      const envEntries = parseEnvFile(envContent);
      const envKeys = new Set(envEntries.map((e) => e.key));

      for (const entry of exampleEntries) {
        if (!envKeys.has(entry.key)) {
          issues.push({
            file: ".env",
            key: entry.key,
            issue: "missing",
            message: `Key "${entry.key}" is defined in .env.example but missing from .env`,
            severity: "warning",
            suggestion: `Add "${entry.key}" to .env with an appropriate value`,
          });
        }
      }
    } catch {
      // ignore read errors
    }
  }

  // Find env vars referenced in code but not defined in any .env file
  const allDefinedKeys = new Set<string>();
  for (const [, fileMap] of envFileEntries) {
    for (const key of fileMap.keys()) {
      allDefinedKeys.add(key);
    }
  }

  const sourceExtensions = new Set([".ts", ".js", ".tsx", ".jsx", ".py", ".go", ".mjs", ".cjs"]);
  const allReferencedVars = new Set<string>();

  for (const f of allFiles) {
    const ext = f.slice(f.lastIndexOf("."));
    if (!sourceExtensions.has(ext)) continue;
    // Skip test files and config files themselves
    const name = basename(f);
    if (name.includes(".test.") || name.includes(".spec.") || isConfigFile(name)) continue;

    try {
      const content = await readFile(f, "utf-8");
      const refs = extractEnvReferences(content, ext);
      for (const ref of refs) {
        allReferencedVars.add(ref);
      }
    } catch {
      // skip unreadable
    }
  }

  // Skip common built-in env vars
  const builtinVars = new Set([
    "NODE_ENV", "PATH", "HOME", "USER", "PWD", "SHELL", "LANG", "TERM",
    "CI", "PORT", "HOST", "HOSTNAME", "TMPDIR", "TMP", "TEMP",
  ]);

  // A library or CLI can legitimately expose optional environment overrides
  // without shipping an env file. Only enforce documentation completeness when
  // the project has opted into an .env/.env.example contract.
  if (envFileEntries.size > 0) {
    for (const varName of allReferencedVars) {
      if (builtinVars.has(varName)) continue;
      if (!allDefinedKeys.has(varName)) {
        issues.push({
          file: "",
          key: varName,
          issue: "missing",
          message: `Environment variable "${varName}" is referenced in code but not defined in any .env file`,
          severity: "info",
          suggestion: `Add "${varName}" to .env or .env.example`,
        });
      }
    }
  }

  return {
    files: configFiles.map((f) => relative(projectRoot, f)),
    issues,
    envVarCount,
  };
}
