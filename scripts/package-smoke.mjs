import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const smokeRoot = mkdtempSync(join(tmpdir(), "nexus-package-smoke-"));
const packDir = join(smokeRoot, "pack");
const installDir = join(smokeRoot, "install");
const dataDir = join(smokeRoot, "data");

mkdirSync(packDir);
mkdirSync(installDir);
mkdirSync(dataDir);

function run(command, args, cwd, env = process.env) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed with exit ${result.status}\n` +
      `${result.stdout}${result.stderr}`,
    );
  }
  return result.stdout.trim();
}

function npm(args, cwd) {
  const npmEntry = process.env.npm_execpath;
  if (npmEntry) return run(process.execPath, [npmEntry, ...args], cwd);
  return run(process.platform === "win32" ? "npm.cmd" : "npm", args, cwd);
}

function collectDependencyVersions(tree, names, found = new Map()) {
  for (const name of names) {
    if (!found.has(name)) found.set(name, new Set());
  }
  for (const [name, dependency] of Object.entries(tree?.dependencies ?? {})) {
    if (found.has(name) && typeof dependency?.version === "string") {
      found.get(name).add(dependency.version);
    }
    collectDependencyVersions(dependency, names, found);
  }
  return found;
}

function isCompatibleMinimum(version, minimum) {
  const parse = (value) => {
    const match = /^(\d+)\.(\d+)\.(\d+)/.exec(value);
    if (!match) throw new Error(`unsupported dependency version: ${value}`);
    return match.slice(1).map(Number);
  };
  const actual = parse(version);
  const floor = parse(minimum);
  if (actual[0] !== floor[0]) return false;
  for (let index = 1; index < actual.length; index += 1) {
    if (actual[index] !== floor[index]) return actual[index] > floor[index];
  }
  return true;
}

try {
  const packed = JSON.parse(
    npm(["pack", "--json", "--ignore-scripts", "--pack-destination", packDir], repoRoot),
  );
  const filename = packed?.[0]?.filename;
  if (typeof filename !== "string" || !filename.endsWith(".tgz")) {
    throw new Error("npm pack did not return a tarball filename");
  }
  const publishedFiles = new Set(packed[0].files?.map((file) => file.path));
  if (publishedFiles.has("npm-shrinkwrap.json") || publishedFiles.has("package-lock.json")) {
    throw new Error("published tarball included a dependency lockfile");
  }

  writeFileSync(
    join(installDir, "package.json"),
    JSON.stringify({ name: "nexus-package-smoke", private: true, type: "module" }),
  );
  npm(
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      join(packDir, filename),
    ],
    installDir,
  );

  const packageRoot = join(installDir, "node_modules", "@hawon", "nexus");
  const cliPath = join(packageRoot, "dist", "cli", "index.js");
  const mcpPath = join(packageRoot, "dist", "mcp", "server.js");

  const minimumCoreDependencies = new Map([
    ["@hono/node-server", "2.0.12"],
    ["@modelcontextprotocol/sdk", "1.30.0"],
    ["body-parser", "2.3.0"],
    ["fast-uri", "3.1.5"],
    ["hono", "4.12.34"],
    ["ip-address", "10.4.0"],
  ]);
  const installedTree = JSON.parse(
    npm(["ls", "--all", "--json"], installDir),
  );
  if (installedTree.problems?.length) {
    throw new Error(`installed dependency tree has problems: ${installedTree.problems.join("; ")}`);
  }
  const installedVersions = collectDependencyVersions(
    installedTree,
    minimumCoreDependencies.keys(),
  );
  for (const [name, minimum] of minimumCoreDependencies) {
    const actual = installedVersions.get(name);
    if (!actual?.size || [...actual].some((version) => !isCompatibleMinimum(version, minimum))) {
      throw new Error(
        `installed ${name} versions ${JSON.stringify([...(actual ?? [])])} did not satisfy >=${minimum} within the supported major`,
      );
    }
  }
  const consumerAudit = JSON.parse(
    npm(["audit", "--omit=dev", "--omit=optional", "--audit-level=high", "--json"], installDir),
  );
  if (consumerAudit.metadata?.vulnerabilities?.total !== 0) {
    throw new Error("installed package dependency audit was not clean");
  }

  const version = run(process.execPath, [cliPath, "--version"], installDir);
  if (!/^nexus v\d+\.\d+\.\d+/.test(version)) {
    throw new Error(`unexpected CLI version output: ${version}`);
  }

  const demo = run(process.execPath, [cliPath, "guard", "demo"], installDir);
  if (!demo.includes("Nexus agent firewall") || !demo.includes("FRAMED") || !demo.includes("DENIED")) {
    throw new Error("installed guard demo omitted expected content/command decisions");
  }

  const publicImports = [
    "@hawon/nexus",
    "@hawon/nexus/promptguard",
    "@hawon/nexus/memory-engine",
    "@hawon/nexus/review",
    "@hawon/nexus/secrets",
    "@hawon/nexus/guard",
    "@hawon/nexus/ml",
    "@hawon/nexus/encoder",
    "@hawon/nexus/codebase",
    "@hawon/nexus/config",
    "@hawon/nexus/collector",
    "@hawon/nexus/docparser",
  ];
  run(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `await Promise.all(${JSON.stringify(publicImports)}.map((id) => import(id)));`,
    ],
    installDir,
  );

  const mcpProbe = `
    import { Client } from "@modelcontextprotocol/sdk/client/index.js";
    import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [process.argv[1]],
      env: { ...process.env, NEXUS_DATA: process.argv[2] },
      stderr: "pipe",
    });
    const client = new Client({ name: "nexus-package-smoke", version: "1.0.0" });
    try {
      await client.connect(transport);
      const listed = await client.listTools();
      if (listed.tools.length !== 17) {
        throw new Error("expected 17 MCP tools, received " + listed.tools.length);
      }
      const names = new Set(listed.tools.map((tool) => tool.name));
      if (!names.has("nexus_guard") || !names.has("nexus_memory_search")) {
        throw new Error("installed MCP server omitted required tools");
      }
    } finally {
      await client.close();
    }
  `;
  run(
    process.execPath,
    ["--input-type=module", "-e", mcpProbe, mcpPath, dataDir],
    installDir,
  );

  process.stdout.write(
    `${version} package smoke: clean consumer tree, audit, CLI, demo, 12 public imports, and 17 MCP tools OK\n`,
  );
} finally {
  rmSync(smokeRoot, { recursive: true, force: true });
}
