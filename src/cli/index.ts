#!/usr/bin/env node

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { discoverSessions } from "../parser/discover.js";
import { discoverAllSessions } from "../parser/unified.js";
import { parseSession } from "../parser/parse.js";
import type { ParsedSession } from "../parser/types.js";
import { exportSession } from "../obsidian/exporter.js";
import { extractSkills } from "../skills/extractor.js";
import { reviewCode } from "../review/analyzer.js";
import { mapCodebase } from "../codebase/mapper.js";
import { generateOnboardingGuide } from "../codebase/onboard.js";
import { checkTestHealth } from "../testing/health-check.js";
import { suggestFixes } from "../testing/test-fixer.js";
import { validateConfig } from "../config/validator.js";
import { createCostTracker } from "../cost/tracker.js";
import { importSessionCosts, summarizeCosts } from "../cost/import-sessions.js";
import { createMemoryStore } from "../memory-engine/store.js";
import { scan as scanPrompt } from "../promptguard/scanner.js";
import {
  addSkills,
  exportToObsidian,
  loadSkillLibrary,
  saveSkillLibrary,
  searchSkills,
} from "../skills/library.js";
import type { SkillLibrary } from "../skills/types.js";
import { extractMemorySkills, renderKnowledgeBase } from "../skills/memory-skill-engine.js";
import { readdirSync, rmSync, statSync } from "node:fs";

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
    process.env["NEXUS_VAULT_PATH"] ??
    join(homedir(), "ObsidianVault", "Claude");

  const dataDir = join(vaultPath, ".nexus");
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

  // 1. Discover sessions (unified: Claude Code + OpenClaw)
  logInfo("Discovering sessions...");
  const discovery = discoverAllSessions();

  if (discovery.totalSessions === 0) {
    logError("No sessions found in ~/.claude");
    process.exit(1);
  }

  logInfo(`Found ${c.bold}${discovery.totalSessions}${c.reset} sessions across ${discovery.platforms.length} platform(s)`);

  // Ensure vault directory exists
  if (!existsSync(config.vaultPath)) {
    mkdirSync(config.vaultPath, { recursive: true });
  }

  // 2. Parse & export each session
  const allSessionPaths: { path: string; platform: string }[] = [];
  for (const platform of discovery.platforms) {
    for (const session of platform.sessions) {
      allSessionPaths.push({ path: session.path, platform: platform.platform });
    }
  }

  const parsedSessions: ParsedSession[] = [];
  const exportedFiles: string[] = [];
  let skillsExtracted = 0;

  const library = loadSkillLibrary(config.dataDir);

  for (let i = 0; i < allSessionPaths.length; i++) {
    const { path: sessionPath } = allSessionPaths[i];
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
    logError("Usage: nexus export <session-id> [--vault <path>]");
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
    logInfo("No skills extracted yet. Run `nexus sync` first.");
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
    logError("Usage: nexus skills search <query>");
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

function cmdReorganize(flags: Record<string, string | undefined>): void {
  const config = resolveConfig(flags);

  logInfo("Starting full vault reorganization...");
  logInfo(`Vault: ${c.bold}${config.vaultPath}${c.reset}`);

  // Step 1: Clean ALL known noise folders (current vault + any old vault paths)
  const foldersToClean = [
    "Sessions", "Skills", "Evolved Skills", "Wisdom", "Refined Skills",
    "skills", "evolved-skills", "wisdom",  // lowercase variants
  ];

  // Clean current vault
  for (const folder of foldersToClean) {
    const folderPath = join(config.vaultPath, folder);
    if (existsSync(folderPath)) {
      const count = readdirSync(folderPath).length;
      rmSync(folderPath, { recursive: true, force: true });
      logInfo(`Removed ${folder}/ (${count} files)`);
    }
  }

  // Also scan for and clean any other vault paths that might have old data
  const possibleOldVaults = [
    join(homedir(), "ObsidianVault", "Claude"),
    join(homedir(), "OneDrive", "문서", "Obsidian Vault"),
    "/mnt/c/Obsidian Vault",
    "/mnt/c/Users/" + (process.env.USER ?? "user") + "/OneDrive/문서/Obsidian Vault",
  ].filter((p) => p !== config.vaultPath && existsSync(p));

  for (const oldVault of possibleOldVaults) {
    for (const folder of foldersToClean) {
      const folderPath = join(oldVault, folder);
      if (existsSync(folderPath)) {
        const count = readdirSync(folderPath).length;
        rmSync(folderPath, { recursive: true, force: true });
        logInfo(`Cleaned old vault: ${oldVault}/${folder} (${count} files)`);
      }
    }
  }

  // Step 2: Re-export all sessions with latest exporter
  logInfo("Discovering sessions...");
  const discovery = discoverSessions();
  logInfo(`Found ${c.bold}${discovery.totalSessions}${c.reset} sessions`);

  const parsedSessions: ParsedSession[] = [];
  let exportCount = 0;

  for (const project of discovery.projects) {
    for (const sessionPath of project.sessions) {
      try {
        const session = parseSession(sessionPath);
        parsedSessions.push(session);
        exportSessionToObsidian(session, config.vaultPath);
        exportCount++;
        process.stdout.write(`\r${c.yellow}[${exportCount}/${discovery.totalSessions}]${c.reset} Exporting sessions...`);
      } catch {
        // Skip unparseable sessions
      }
    }
  }
  process.stdout.write("\n");
  logInfo(`Exported ${exportCount} sessions`);

  // Step 3: Memory-based knowledge extraction (Skills + Tips + Facts)
  logInfo("Extracting knowledge from observations...");
  const knowledgeResult = extractMemorySkills(parsedSessions, config.dataDir, 2);

  logInfo(`Observations: ${knowledgeResult.observationsIngested} | Clusters: ${knowledgeResult.clustersFormed}`);
  logInfo(`Skills: ${knowledgeResult.skills.length} | Tips: ${knowledgeResult.tips.length} | Facts: ${knowledgeResult.facts.length}`);

  // Step 4: Export knowledge base to Obsidian
  const kbPath = join(config.vaultPath, "Knowledge Base.md");
  writeFileSync(kbPath, renderKnowledgeBase(knowledgeResult), "utf-8");
  // Also save as JSON for MCP tool access
  const knowledgeJson = {
    skills: knowledgeResult.skills,
    tips: knowledgeResult.tips,
    facts: knowledgeResult.facts,
  };
  writeFileSync(join(config.dataDir, "knowledge.json"), JSON.stringify(knowledgeJson, null, 2), "utf-8");
  logInfo("Exported Knowledge Base to Obsidian + MCP cache");

  // Step 5: Update MOC and daily notes
  logInfo("Updating MOC and daily notes...");
  updateMOC(parsedSessions, config.vaultPath);
  updateDailyNotes(parsedSessions, config.vaultPath);

  // Step 6: Save status
  const totalKnowledge = knowledgeResult.skills.length + knowledgeResult.tips.length + knowledgeResult.facts.length;
  const status = {
    lastSync: new Date().toISOString(),
    lastReorg: new Date().toISOString(),
    sessionsExported: exportCount,
    skills: knowledgeResult.skills.length,
    tips: knowledgeResult.tips.length,
    facts: knowledgeResult.facts.length,
    totalKnowledge,
    observations: knowledgeResult.observationsIngested,
    durationMs: knowledgeResult.durationMs,
  };
  mkdirSync(config.dataDir, { recursive: true });
  writeFileSync(join(config.dataDir, "status.json"), JSON.stringify(status, null, 2), "utf-8");

  // Summary
  log("");
  logSuccess("Reorganization complete!");
  log(`  ${c.cyan}Sessions:${c.reset}           ${exportCount}`);
  log(`  ${c.cyan}Observations:${c.reset}       ${knowledgeResult.observationsIngested}`);
  log(`  ${c.cyan}Skills:${c.reset}             ${knowledgeResult.skills.length}`);
  log(`  ${c.cyan}Tips:${c.reset}               ${knowledgeResult.tips.length}`);
  log(`  ${c.cyan}Facts:${c.reset}              ${knowledgeResult.facts.length}`);
  log(`  ${c.cyan}Total knowledge:${c.reset}    ${totalKnowledge}`);
  log(`  ${c.cyan}Vault:${c.reset}              ${config.vaultPath}`);
}

function cmdReview(filePath: string | undefined, flags: Record<string, string | undefined>): void {
  if (!filePath) {
    logError("Usage: nexus review <file>");
    process.exit(1);
  }

  if (!existsSync(filePath)) {
    logError(`File not found: ${filePath}`);
    process.exit(1);
  }

  const code = readFileSync(filePath, "utf-8");
  const result = reviewCode(code, filePath);

  if ("--json" in flags) {
    log(JSON.stringify(result, null, 2));
    return;
  }

  const scoreColor = result.score >= 80 ? c.green : result.score >= 50 ? c.yellow : c.red;
  log(`\n${c.bold}Code Review: ${filePath}${c.reset}\n`);
  log(`  ${c.cyan}Score:${c.reset}    ${scoreColor}${result.score}/100${c.reset}`);
  log(`  ${c.cyan}Findings:${c.reset} ${result.findings.length}`);
  log(`  ${c.cyan}Duration:${c.reset} ${result.durationMs}ms`);
  log(`\n${c.bold}Summary:${c.reset} ${result.summary}\n`);

  for (const f of result.findings) {
    const sevColor = f.severity === "critical" ? c.red : f.severity === "warning" ? c.yellow : c.dim;
    log(`  ${sevColor}[${f.severity.toUpperCase()}]${c.reset} ${c.cyan}${f.category}${c.reset} line ${f.line}: ${f.message}`);
    if (f.suggestion) {
      log(`    ${c.dim}Suggestion: ${f.suggestion}${c.reset}`);
    }
  }
  log("");
}

async function cmdMap(dir: string | undefined, flags: Record<string, string | undefined>): Promise<void> {
  const root = dir ?? process.cwd();

  if (!existsSync(root)) {
    logError(`Directory not found: ${root}`);
    process.exit(1);
  }

  logInfo(`Mapping codebase at ${c.bold}${root}${c.reset}...`);
  const map = await mapCodebase({ root });

  if ("--json" in flags) {
    log(JSON.stringify(map, null, 2));
    return;
  }

  log(`\n${c.bold}Codebase Map${c.reset}\n`);
  log(`  ${c.cyan}Root:${c.reset}         ${map.root}`);
  log(`  ${c.cyan}Total files:${c.reset}  ${map.totalFiles}`);
  log(`  ${c.cyan}Total lines:${c.reset}  ${map.totalLines}`);

  log(`\n${c.bold}Languages:${c.reset}`);
  for (const [lang, count] of Object.entries(map.languages)) {
    log(`  ${c.yellow}${lang}${c.reset}: ${count} files`);
  }

  if (map.entryPoints.length > 0) {
    log(`\n${c.bold}Entry Points:${c.reset}`);
    for (const ep of map.entryPoints) {
      log(`  ${c.green}${ep}${c.reset}`);
    }
  }

  if (map.hotspots.length > 0) {
    log(`\n${c.bold}Hotspots:${c.reset} (most connected files)`);
    for (const hs of map.hotspots) {
      log(`  ${c.red}${hs}${c.reset}`);
    }
  }
  log("");
}

async function cmdOnboard(dir: string | undefined, flags: Record<string, string | undefined>): Promise<void> {
  const root = dir ?? process.cwd();

  if (!existsSync(root)) {
    logError(`Directory not found: ${root}`);
    process.exit(1);
  }

  logInfo(`Generating onboarding guide for ${c.bold}${root}${c.reset}...`);
  const map = await mapCodebase({ root });
  const guide = generateOnboardingGuide(map);

  if ("--json" in flags) {
    log(JSON.stringify({ root, guide }, null, 2));
    return;
  }

  log(`\n${c.bold}Onboarding Guide${c.reset}\n`);
  log(guide);
}

async function cmdTestHealth(dir: string | undefined, flags: Record<string, string | undefined>): Promise<void> {
  const root = dir ?? process.cwd();

  if (!existsSync(root)) {
    logError(`Directory not found: ${root}`);
    process.exit(1);
  }

  logInfo(`Checking test health in ${c.bold}${root}${c.reset}...`);
  const report = await checkTestHealth(root);
  const fixes = suggestFixes(report.issues);

  if ("--json" in flags) {
    log(JSON.stringify({ ...report, suggestedFixes: fixes }, null, 2));
    return;
  }

  log(`\n${c.bold}Test Health Report${c.reset}\n`);
  log(`  ${c.cyan}Total tests:${c.reset}        ${report.totalTests}`);
  log(`  ${c.cyan}Coverage estimate:${c.reset}  ${report.coverageEstimate}%`);
  log(`  ${c.cyan}Issues:${c.reset}             ${report.issues.length}`);
  log(`  ${c.cyan}Stale mocks:${c.reset}        ${report.staleMocks.length}`);
  log(`  ${c.cyan}Missing tests:${c.reset}      ${report.missingTests.length}`);
  log(`  ${c.cyan}Duration:${c.reset}           ${report.durationMs}ms`);

  if (report.issues.length > 0) {
    log(`\n${c.bold}Issues:${c.reset}`);
    for (const issue of report.issues) {
      const sevColor = issue.issue === "broken_import" ? c.red : c.yellow;
      log(`  ${sevColor}[${issue.issue}]${c.reset} ${issue.testFile}: ${issue.message}`);
      log(`    ${c.dim}${issue.suggestion}${c.reset}`);
    }
  }

  if (fixes.length > 0) {
    log(`\n${c.bold}Suggested Fixes:${c.reset}`);
    for (const fix of fixes) {
      log(`  ${c.green}-${c.reset} ${fix}`);
    }
  }
  log("");
}

async function cmdConfig(dir: string | undefined, flags: Record<string, string | undefined>): Promise<void> {
  const root = dir ?? process.cwd();

  if (!existsSync(root)) {
    logError(`Directory not found: ${root}`);
    process.exit(1);
  }

  logInfo(`Validating config files in ${c.bold}${root}${c.reset}...`);
  const report = await validateConfig(root);

  if ("--json" in flags) {
    log(JSON.stringify(report, null, 2));
    return;
  }

  log(`\n${c.bold}Config Validation Report${c.reset}\n`);
  log(`  ${c.cyan}Config files:${c.reset}  ${report.files.length}`);
  log(`  ${c.cyan}Env vars:${c.reset}      ${report.envVarCount}`);
  log(`  ${c.cyan}Issues:${c.reset}        ${report.issues.length}`);

  if (report.files.length > 0) {
    log(`\n${c.bold}Files:${c.reset}`);
    for (const f of report.files) {
      log(`  ${c.dim}${f}${c.reset}`);
    }
  }

  if (report.issues.length > 0) {
    log(`\n${c.bold}Issues:${c.reset}`);
    for (const issue of report.issues) {
      const sevColor = issue.severity === "critical" ? c.red : issue.severity === "warning" ? c.yellow : c.dim;
      log(`  ${sevColor}[${issue.severity.toUpperCase()}]${c.reset} ${c.cyan}${issue.file}${c.reset} — ${issue.key}: ${issue.message}`);
      if (issue.suggestion) {
        log(`    ${c.dim}Suggestion: ${issue.suggestion}${c.reset}`);
      }
    }
  }
  log("");
}

function cmdCost(flags: Record<string, string | undefined>): void {
  // Import directly from Claude Code session files
  const sessions = importSessionCosts();
  const summary = summarizeCosts(sessions);

  if ("--json" in flags) {
    log(JSON.stringify(summary, null, 2));
    return;
  }

  log(`\n${c.bold}AI Cost Report${c.reset} (from ${summary.sessionCount} sessions)\n`);
  log(`  ${c.cyan}Total cost:${c.reset}        $${summary.totalCost.toFixed(2)}`);
  log(`  ${c.cyan}Avg per session:${c.reset}   $${(summary.totalCost / Math.max(summary.sessionCount, 1)).toFixed(2)}`);
  log(`  ${c.cyan}Input tokens:${c.reset}      ${summary.totalInput.toLocaleString()}`);
  log(`  ${c.cyan}Output tokens:${c.reset}     ${summary.totalOutput.toLocaleString()}`);
  log(`  ${c.cyan}Cache read:${c.reset}        ${summary.totalCacheRead.toLocaleString()}`);
  log(`  ${c.cyan}Cache write:${c.reset}       ${summary.totalCacheWrite.toLocaleString()}`);

  const models = Object.entries(summary.byModel).sort(([, a], [, b]) => b.cost - a.cost);
  if (models.length > 0) {
    log(`\n${c.bold}By Model:${c.reset}`);
    for (const [model, data] of models) {
      log(`  ${c.yellow}${model}${c.reset}: $${data.cost.toFixed(2)} (${data.sessions} sessions)`);
    }
  }

  log("");
}

function cmdMemory(subcommand: string | undefined, query: string | undefined, flags: Record<string, string | undefined>): void {
  const config = resolveConfig(flags);
  const store = createMemoryStore(config.dataDir);

  if (subcommand === "search") {
    if (!query) {
      logError("Usage: nexus memory search <query>");
      process.exit(1);
    }

    const results = store.search({ query });

    if ("--json" in flags) {
      log(JSON.stringify(results, null, 2));
      return;
    }

    if (results.length === 0) {
      logInfo(`No memories matching "${query}".`);
      return;
    }

    log(`\n${c.bold}Memory Search: "${query}"${c.reset} (${results.length} results)\n`);
    for (const entry of results) {
      log(`  ${c.cyan}${c.bold}${entry.id}${c.reset} ${c.dim}[${entry.tier}]${c.reset}`);
      log(`    ${c.dim}Tags:${c.reset} ${entry.tags.join(", ")}`);
      log(`    ${entry.content.slice(0, 120)}${entry.content.length > 120 ? "..." : ""}`);
      log("");
    }
  } else if (subcommand === "stats") {
    const stats = store.getStats();

    if ("--json" in flags) {
      log(JSON.stringify(stats, null, 2));
      return;
    }

    log(`\n${c.bold}Memory Stats${c.reset}\n`);
    log(`  ${c.cyan}Total entries:${c.reset}      ${stats.totalEntries}`);
    log(`  ${c.cyan}Total size:${c.reset}         ${(stats.totalSizeBytes / 1024).toFixed(1)} KB`);
    log(`  ${c.cyan}Compression ratio:${c.reset}  ${(stats.compressionRatio * 100).toFixed(1)}%`);
    log(`\n${c.bold}By Tier:${c.reset}`);
    for (const [tier, count] of Object.entries(stats.byTier)) {
      log(`  ${c.yellow}${tier}${c.reset}: ${count}`);
    }
    log("");
  } else {
    logError("Usage: nexus memory <search|stats> [query]");
    process.exit(1);
  }
}

function cmdScan(text: string | undefined, flags: Record<string, string | undefined>): void {
  if (!text) {
    logError("Usage: nexus scan <text>");
    process.exit(1);
  }

  const result = scanPrompt(text);

  if ("--json" in flags) {
    log(JSON.stringify(result, null, 2));
    return;
  }

  log(`\n${c.bold}Prompt Injection Scan${c.reset}\n`);
  log(`  ${c.cyan}Injected:${c.reset}     ${result.injected ? `${c.red}YES${c.reset}` : `${c.green}NO${c.reset}`}`);
  log(`  ${c.cyan}Max severity:${c.reset} ${result.maxSeverity ?? "none"}`);
  log(`  ${c.cyan}Findings:${c.reset}     ${result.findings.length}`);
  log(`  ${c.cyan}Duration:${c.reset}     ${result.durationMs}ms`);

  if (result.findings.length > 0) {
    log(`\n${c.bold}Findings:${c.reset}`);
    for (const f of result.findings) {
      const sevColor = f.severity === "critical" ? c.red : f.severity === "high" ? c.red : f.severity === "medium" ? c.yellow : c.dim;
      log(`  ${sevColor}[${f.severity.toUpperCase()}]${c.reset} ${c.cyan}${f.ruleId}${c.reset}: ${f.message}`);
      log(`    ${c.dim}Evidence: ${f.evidence.slice(0, 80)}${f.evidence.length > 80 ? "..." : ""}${c.reset}`);
    }
  }
  log("");
}

function cmdHelp(): void {
  log(`
${c.bold}nexus${c.reset} v${VERSION} — Export Claude Code sessions to Obsidian with skill extraction

${c.bold}Usage:${c.reset}
  nexus <command> [options]

${c.bold}Commands:${c.reset}
  ${c.cyan}sync${c.reset}                           Discover, parse, export sessions & extract skills
  ${c.cyan}sessions${c.reset}                       List all discovered sessions
  ${c.cyan}export${c.reset} <session-id>             Export a single session
  ${c.cyan}skills${c.reset}                         List all extracted skills
  ${c.cyan}skills search${c.reset} <query>           Search skills by keyword
  ${c.cyan}reorganize${c.reset}                     Clean vault & rebuild with wisdom pipeline
  ${c.cyan}status${c.reset}                         Show vault stats
  ${c.cyan}review${c.reset} <file>                   Review a source file for issues
  ${c.cyan}map${c.reset} [dir]                       Map codebase architecture
  ${c.cyan}onboard${c.reset} [dir]                   Generate onboarding guide
  ${c.cyan}test-health${c.reset} [dir]               Check test suite health
  ${c.cyan}config${c.reset} [dir]                    Validate config files
  ${c.cyan}cost${c.reset}                           Show AI cost report
  ${c.cyan}memory${c.reset} <search|stats> [query]   Memory operations
  ${c.cyan}scan${c.reset} <text>                     Scan text for prompt injection
  ${c.cyan}--help${c.reset}                         Show this help
  ${c.cyan}--version${c.reset}                      Show version

${c.bold}Options:${c.reset}
  --vault <path>                  Obsidian vault path (default: ~/ObsidianVault/Claude)

${c.bold}Environment:${c.reset}
  NEXUS_VAULT_PATH               Override default vault path

${c.bold}Examples:${c.reset}
  nexus sync --vault ~/my-vault
  nexus sessions
  nexus export abc-123
  nexus skills search "fix lint"
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

async function main(): Promise<void> {
  const { command, args, flags } = parseArgs(process.argv.slice(2));

  if ("--version" in flags || command === "version") {
    log(`nexus v${VERSION}`);
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
    case "reorganize":
    case "reorg":
      cmdReorganize(flags);
      break;
    case "review":
      cmdReview(args[0], flags);
      break;
    case "map":
      await cmdMap(args[0], flags);
      break;
    case "onboard":
      await cmdOnboard(args[0], flags);
      break;
    case "test-health":
      await cmdTestHealth(args[0], flags);
      break;
    case "config":
      await cmdConfig(args[0], flags);
      break;
    case "cost":
      cmdCost(flags);
      break;
    case "memory":
      cmdMemory(args[0], args.slice(1).join(" ") || undefined, flags);
      break;
    case "scan":
      cmdScan(args.join(" ") || undefined, flags);
      break;
    default:
      logError(`Unknown command: ${command}`);
      cmdHelp();
      process.exit(1);
  }
}

main().catch((err) => {
  logError(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
