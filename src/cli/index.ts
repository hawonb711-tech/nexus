#!/usr/bin/env node

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { discoverSessions } from "../parser/discover.js";
import { parseSession } from "../parser/parse.js";
import type { ParsedSession } from "../parser/types.js";
import { exportSession } from "../obsidian/exporter.js";
import { extractSkills } from "../skills/extractor.js";
import {
  addSkills,
  exportToObsidian,
  loadSkillLibrary,
  saveSkillLibrary,
  searchSkills,
} from "../skills/library.js";
import type { SkillLibrary } from "../skills/types.js";

// ── ANSI Colors ──────────────────────────────────────────────────

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
};

function log(msg: string): void {
  process.stdout.write(msg + "\n");
}

function logError(msg: string): void {
  process.stderr.write(`${c.red}Error:${c.reset} ${msg}\n`);
}

function logSuccess(msg: string): void {
  log(`${c.green}OK${c.reset} ${msg}`);
}

function logInfo(msg: string): void {
  log(`${c.cyan}::${c.reset} ${msg}`);
}

function logProgress(current: number, total: number, label: string): void {
  process.stdout.write(
    `\r${c.yellow}[${current}/${total}]${c.reset} ${label}${" ".repeat(20)}`,
  );
  if (current === total) process.stdout.write("\n");
}

// ── Config ───────────────────────────────────────────────────────

const VERSION = "0.1.0";

type VaultConfig = {
  vaultPath: string;
  dataDir: string;
};

function resolveConfig(flags: Record<string, string | undefined>): VaultConfig {
  const vaultPath =
    flags["--vault"] ??
    process.env["CLAUDE_VAULT_PATH"] ??
    join(homedir(), "ObsidianVault", "Claude");

  const dataDir = join(vaultPath, ".claude-vault");
  return { vaultPath, dataDir };
}

// ── Status file ──────────────────────────────────────────────────

type SyncStatus = {
  lastSync: string;
  totalSessions: number;
  totalSkills: number;
  sessionsExported: string[];
};

function loadStatus(dataDir: string): SyncStatus {
  const statusFile = join(dataDir, "status.json");
  if (!existsSync(statusFile)) {
    return {
      lastSync: "",
      totalSessions: 0,
      totalSkills: 0,
      sessionsExported: [],
    };
  }
  try {
    return JSON.parse(readFileSync(statusFile, "utf-8")) as SyncStatus;
  } catch {
    return { lastSync: "", totalSessions: 0, totalSkills: 0, sessionsExported: [] };
  }
}

function saveStatus(status: SyncStatus, dataDir: string): void {
  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true });
  }
  writeFileSync(join(dataDir, "status.json"), JSON.stringify(status, null, 2), "utf-8");
}

// ── Obsidian export (session markdown) ───────────────────────────

function exportSessionToObsidian(session: ParsedSession, vaultPath: string): string {
  const result = exportSession(session, {
    vaultPath,
    folderStructure: "flat",
    includeToolCalls: true,
    includeTimestamps: true,
    createMOC: false,
    createDailyNotes: false,
    tagPrefix: "claude/",
  });
  const filePath = result.filesCreated[0] ?? result.filesUpdated[0] ?? "";
  return filePath;
}

// ── MOC & Daily notes ────────────────────────────────────────────

function updateMOC(sessions: ParsedSession[], vaultPath: string): void {
  const mocPath = join(vaultPath, "Claude MOC.md");

  let content = `---
type: moc
tags: [claude/moc]
updated: ${new Date().toISOString()}
---

# Claude Sessions - Map of Content

Total sessions: ${sessions.length}

## By Date

`;

  const byDate = new Map<string, ParsedSession[]>();
  for (const s of sessions) {
    const date = s.startedAt ? s.startedAt.slice(0, 10) : "unknown";
    if (!byDate.has(date)) byDate.set(date, []);
    byDate.get(date)!.push(s);
  }

  const sortedDates = Array.from(byDate.keys()).sort().reverse();
  for (const date of sortedDates) {
    content += `### ${date}\n\n`;
    for (const s of byDate.get(date)!) {
      const safeName = s.sessionId.replace(/[<>:"/\\|?*]/g, "-").slice(0, 60);
      content += `- [[${date}-${safeName}]] - ${s.summary ?? "no summary"}\n`;
    }
    content += "\n";
  }

  writeFileSync(mocPath, content, "utf-8");
}

function updateDailyNotes(sessions: ParsedSession[], vaultPath: string): void {
  const dailyDir = join(vaultPath, "Daily");
  if (!existsSync(dailyDir)) {
    mkdirSync(dailyDir, { recursive: true });
  }

  const byDate = new Map<string, ParsedSession[]>();
  for (const s of sessions) {
    const date = s.startedAt ? s.startedAt.slice(0, 10) : "unknown";
    if (!byDate.has(date)) byDate.set(date, []);
    byDate.get(date)!.push(s);
  }

  for (const [date, dateSessions] of byDate) {
    if (date === "unknown") continue;
    const filePath = join(dailyDir, `${date}.md`);

    let content = `---
type: daily-note
date: ${date}
tags: [claude/daily]
---

# Claude Sessions: ${date}

`;

    for (const s of dateSessions) {
      const safeName = s.sessionId.replace(/[<>:"/\\|?*]/g, "-").slice(0, 60);
      content += `## [[${date}-${safeName}]]\n\n`;
      content += `${s.summary ?? "no summary"}\n\n`;
      if (s.toolsUsed.length > 0) {
        content += `Tools: ${s.toolsUsed.join(", ")}\n\n`;
      }
    }

    writeFileSync(filePath, content, "utf-8");
  }
}

// ── Commands ─────────────────────────────────────────────────────

function cmdSync(flags: Record<string, string | undefined>): void {
  const config = resolveConfig(flags);
  logInfo(`Vault path: ${c.bold}${config.vaultPath}${c.reset}`);

  // 1. Discover sessions
  logInfo("Discovering sessions...");
  const discovery = discoverSessions();

  if (discovery.totalSessions === 0) {
    logError("No sessions found in ~/.claude");
    process.exit(1);
  }

  logInfo(`Found ${c.bold}${discovery.totalSessions}${c.reset} sessions across ${discovery.projects.length} projects`);

  // Ensure vault directory exists
  if (!existsSync(config.vaultPath)) {
    mkdirSync(config.vaultPath, { recursive: true });
  }

  // 2. Parse & export each session
  const allSessionPaths: string[] = [];
  for (const proj of discovery.projects) {
    allSessionPaths.push(...proj.sessions);
  }

  const parsedSessions: ParsedSession[] = [];
  const exportedFiles: string[] = [];
  let skillsExtracted = 0;

  const library = loadSkillLibrary(config.dataDir);

  for (let i = 0; i < allSessionPaths.length; i++) {
    const sessionPath = allSessionPaths[i];
    logProgress(i + 1, allSessionPaths.length, `Syncing session ${i + 1}/${allSessionPaths.length}...`);

    try {
      const session = parseSession(sessionPath);
      parsedSessions.push(session);

      // 3. Export to Obsidian
      const filePath = exportSessionToObsidian(session, config.vaultPath);
      exportedFiles.push(filePath);

      // 4. Extract skills
      const skills = extractSkills(session);
      const added = addSkills(library, skills);
      skillsExtracted += added;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log(`\n${c.yellow}Warning:${c.reset} Failed to parse ${sessionPath}: ${msg}`);
    }
  }

  // 5. Save skill library & export to Obsidian
  saveSkillLibrary(library, config.dataDir);
  const skillFiles = exportToObsidian(library, config.vaultPath);

  // 6. Update MOC and daily notes
  logInfo("Updating MOC and daily notes...");
  updateMOC(parsedSessions, config.vaultPath);
  updateDailyNotes(parsedSessions, config.vaultPath);

  // 7. Save status
  const status: SyncStatus = {
    lastSync: new Date().toISOString(),
    totalSessions: parsedSessions.length,
    totalSkills: library.skills.length,
    sessionsExported: parsedSessions.map((s) => s.sessionId),
  };
  saveStatus(status, config.dataDir);

  // Summary
  log("");
  log(`${c.bold}${c.green}Sync complete!${c.reset}`);
  log(`  ${c.cyan}Sessions exported:${c.reset}  ${exportedFiles.length}`);
  log(`  ${c.cyan}New skills found:${c.reset}   ${skillsExtracted}`);
  log(`  ${c.cyan}Total skills:${c.reset}       ${library.skills.length}`);
  log(`  ${c.cyan}Skill files:${c.reset}        ${skillFiles.length}`);
  log(`  ${c.cyan}Vault path:${c.reset}         ${config.vaultPath}`);
}

function cmdSessions(): void {
  const discovery = discoverSessions();

  if (discovery.totalSessions === 0) {
    logInfo("No sessions found.");
    return;
  }

  log(`\n${c.bold}Claude Sessions${c.reset} (${discovery.totalSessions} total)\n`);
  log(`${"Session ID".padEnd(40)} ${"Date".padEnd(12)} ${"Project".padEnd(30)} Messages`);
  log(`${"-".repeat(40)} ${"-".repeat(12)} ${"-".repeat(30)} ${"-".repeat(8)}`);

  for (const proj of discovery.projects) {
    for (const sessionPath of proj.sessions) {
      try {
        const session = parseSession(sessionPath);
        const date = session.startedAt ? session.startedAt.slice(0, 10) : "unknown";
        const id = session.sessionId.slice(0, 38).padEnd(40);
        const projName = proj.projectId.slice(0, 28).padEnd(30);
        log(`${c.cyan}${id}${c.reset} ${date.padEnd(12)} ${projName} ${session.messages.length}`);
      } catch {
        const shortPath = sessionPath.split("/").pop() ?? sessionPath;
        log(`${c.dim}${shortPath.padEnd(40)} (parse error)${c.reset}`);
      }
    }
  }
  log("");
}

function cmdExport(sessionId: string | undefined, flags: Record<string, string | undefined>): void {
  if (!sessionId) {
    logError("Usage: claude-vault export <session-id> [--vault <path>]");
    process.exit(1);
  }

  const config = resolveConfig(flags);
  const discovery = discoverSessions();

  // Find matching session
  let matchedPath: string | undefined;
  for (const proj of discovery.projects) {
    for (const sp of proj.sessions) {
      if (sp.includes(sessionId)) {
        matchedPath = sp;
        break;
      }
    }
    if (matchedPath) break;
  }

  if (!matchedPath) {
    logError(`Session "${sessionId}" not found.`);
    process.exit(1);
  }

  if (!existsSync(config.vaultPath)) {
    mkdirSync(config.vaultPath, { recursive: true });
  }

  const session = parseSession(matchedPath);
  const filePath = exportSessionToObsidian(session, config.vaultPath);
  logSuccess(`Exported to ${filePath}`);

  // Extract skills too
  const library = loadSkillLibrary(config.dataDir);
  const skills = extractSkills(session);
  const added = addSkills(library, skills);
  if (added > 0) {
    saveSkillLibrary(library, config.dataDir);
    logSuccess(`Extracted ${added} new skill(s)`);
  }
}

function cmdSkills(flags: Record<string, string | undefined>): void {
  const config = resolveConfig(flags);
  const library = loadSkillLibrary(config.dataDir);

  if (library.skills.length === 0) {
    logInfo("No skills extracted yet. Run `claude-vault sync` first.");
    return;
  }

  log(`\n${c.bold}Extracted Skills${c.reset} (${library.skills.length} total)\n`);
  log(`${"Name".padEnd(45)} ${"Confidence".padEnd(12)} Tools`);
  log(`${"-".repeat(45)} ${"-".repeat(12)} ${"-".repeat(30)}`);

  for (const skill of library.skills) {
    const name = skill.name.slice(0, 43).padEnd(45);
    const conf = `${(skill.confidence * 100).toFixed(0)}%`.padEnd(12);
    const tools = skill.toolsUsed.join(", ");
    log(`${c.cyan}${name}${c.reset} ${c.yellow}${conf}${c.reset} ${tools}`);
  }
  log("");
}

function cmdSkillsSearch(query: string | undefined, flags: Record<string, string | undefined>): void {
  if (!query) {
    logError("Usage: claude-vault skills search <query>");
    process.exit(1);
  }

  const config = resolveConfig(flags);
  const library = loadSkillLibrary(config.dataDir);
  const results = searchSkills(library, query);

  if (results.length === 0) {
    logInfo(`No skills matching "${query}".`);
    return;
  }

  log(`\n${c.bold}Skills matching "${query}"${c.reset} (${results.length} results)\n`);

  for (const skill of results) {
    log(`${c.cyan}${c.bold}${skill.name}${c.reset} ${c.dim}(${(skill.confidence * 100).toFixed(0)}% confidence)${c.reset}`);
    log(`  ${c.dim}Trigger:${c.reset} ${skill.trigger}`);
    log(`  ${c.dim}Tools:${c.reset}   ${skill.toolsUsed.join(", ")}`);
    log(`  ${c.dim}Steps:${c.reset}   ${skill.steps.length}`);
    log("");
  }
}

function cmdStatus(flags: Record<string, string | undefined>): void {
  const config = resolveConfig(flags);
  const status = loadStatus(config.dataDir);
  const library = loadSkillLibrary(config.dataDir);

  log(`\n${c.bold}Claude Vault Status${c.reset}\n`);
  log(`  ${c.cyan}Vault path:${c.reset}      ${config.vaultPath}`);
  log(`  ${c.cyan}Last sync:${c.reset}       ${status.lastSync || "never"}`);
  log(`  ${c.cyan}Total sessions:${c.reset}  ${status.totalSessions}`);
  log(`  ${c.cyan}Total skills:${c.reset}    ${library.skills.length}`);
  log(`  ${c.cyan}Library ver:${c.reset}     ${library.version}`);
  log("");
}

function cmdHelp(): void {
  log(`
${c.bold}claude-vault${c.reset} v${VERSION} — Export Claude Code sessions to Obsidian with skill extraction

${c.bold}Usage:${c.reset}
  claude-vault <command> [options]

${c.bold}Commands:${c.reset}
  ${c.cyan}sync${c.reset}                           Discover, parse, export sessions & extract skills
  ${c.cyan}sessions${c.reset}                       List all discovered sessions
  ${c.cyan}export${c.reset} <session-id>             Export a single session
  ${c.cyan}skills${c.reset}                         List all extracted skills
  ${c.cyan}skills search${c.reset} <query>           Search skills by keyword
  ${c.cyan}status${c.reset}                         Show vault stats
  ${c.cyan}--help${c.reset}                         Show this help
  ${c.cyan}--version${c.reset}                      Show version

${c.bold}Options:${c.reset}
  --vault <path>                  Obsidian vault path (default: ~/ObsidianVault/Claude)

${c.bold}Environment:${c.reset}
  CLAUDE_VAULT_PATH               Override default vault path

${c.bold}Examples:${c.reset}
  claude-vault sync --vault ~/my-vault
  claude-vault sessions
  claude-vault export abc-123
  claude-vault skills search "fix lint"
`);
}

// ── Arg parsing ──────────────────────────────────────────────────

function parseArgs(argv: string[]): { command: string; args: string[]; flags: Record<string, string | undefined> } {
  const flags: Record<string, string | undefined> = {};
  const positional: string[] = [];

  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        flags[arg] = next;
        i += 2;
      } else {
        flags[arg] = undefined;
        i++;
      }
    } else {
      positional.push(arg);
      i++;
    }
  }

  const command = positional[0] ?? "help";
  const args = positional.slice(1);
  return { command, args, flags };
}

// ── Main ─────────────────────────────────────────────────────────

function main(): void {
  const { command, args, flags } = parseArgs(process.argv.slice(2));

  if ("--version" in flags || command === "version") {
    log(`claude-vault v${VERSION}`);
    return;
  }

  if ("--help" in flags || command === "help") {
    cmdHelp();
    return;
  }

  switch (command) {
    case "sync":
      cmdSync(flags);
      break;
    case "sessions":
      cmdSessions();
      break;
    case "export":
      cmdExport(args[0], flags);
      break;
    case "skills":
      if (args[0] === "search") {
        cmdSkillsSearch(args.slice(1).join(" ") || undefined, flags);
      } else {
        cmdSkills(flags);
      }
      break;
    case "status":
      cmdStatus(flags);
      break;
    default:
      logError(`Unknown command: ${command}`);
      cmdHelp();
      process.exit(1);
  }
}

main();
