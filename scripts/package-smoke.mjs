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
    ["@modelcontextprotocol/sdk", "1.31.0"],
    ["body-parser", "2.3.0"],
    ["fast-uri", "3.1.8"],
    ["hono", "4.13.7"],
    ["ip-address", "10.7.1"],
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

    const EXPERIMENTAL = ["nexus_review", "nexus_map", "nexus_onboard", "nexus_test_health", "nexus_config"];

    async function listNames(extraEnv) {
      const transport = new StdioClientTransport({
        command: process.execPath,
        args: [process.argv[1]],
        env: { ...process.env, NEXUS_DATA: process.argv[2], ...extraEnv },
        stderr: "pipe",
      });
      const client = new Client({ name: "nexus-package-smoke", version: "1.0.0" });
      try {
        await client.connect(transport);
        return new Set((await client.listTools()).tools.map((tool) => tool.name));
      } finally {
        await client.close();
      }
    }

    // Default: 13 tools, with the 5 experimental ones gated off.
    const def = await listNames({});
    if (def.size !== 13) {
      throw new Error("expected 13 default MCP tools, received " + def.size);
    }
    if (!def.has("nexus_guard") || !def.has("nexus_memory_search") || !def.has("nexus_forget")) {
      throw new Error("installed MCP server omitted required default tools");
    }
    for (const name of EXPERIMENTAL) {
      if (def.has(name)) throw new Error("experimental tool " + name + " was registered by default");
    }

    // NEXUS_EXPERIMENTAL_TOOLS=1: all 18 tools, including the 5 experimental.
    const exp = await listNames({ NEXUS_EXPERIMENTAL_TOOLS: "1" });
    if (exp.size !== 18) {
      throw new Error("expected 18 MCP tools with NEXUS_EXPERIMENTAL_TOOLS=1, received " + exp.size);
    }
    for (const name of EXPERIMENTAL) {
      if (!exp.has(name)) throw new Error("experimental tool " + name + " missing with the flag set");
    }
  `;
  run(
    process.execPath,
    ["--input-type=module", "-e", mcpProbe, mcpPath, dataDir],
    installDir,
  );

  process.stdout.write(
    `${version} package smoke: clean consumer tree, audit, CLI, demo, 12 public imports, and 13 default (18 with NEXUS_EXPERIMENTAL_TOOLS) MCP tools OK\n`,
  );
} finally {
  rmSync(smokeRoot, { recursive: true, force: true });
}
