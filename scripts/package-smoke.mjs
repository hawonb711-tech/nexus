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

try {
  const packed = JSON.parse(
    npm(["pack", "--json", "--ignore-scripts", "--pack-destination", packDir], repoRoot),
  );
  const filename = packed?.[0]?.filename;
  if (typeof filename !== "string" || !filename.endsWith(".tgz")) {
    throw new Error("npm pack did not return a tarball filename");
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
    `${version} package smoke: CLI, demo, 12 public imports, and 17 MCP tools OK\n`,
  );
} finally {
  rmSync(smokeRoot, { recursive: true, force: true });
}
