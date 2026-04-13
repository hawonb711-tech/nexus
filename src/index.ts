// Parser (multi-platform)
export { discoverSessions } from "./parser/discover.js";
export { parseSession } from "./parser/parse.js";
export { discoverAllSessions, parseAnySession } from "./parser/unified.js";
export { discoverOpenClawSessions, parseOpenClawSession } from "./parser/openclaw-parser.js";
export type { ParsedMessage, ParsedSession, ToolCall, PlatformDiscovery, UnifiedDiscovery } from "./parser/types.js";

// Obsidian Export
export { exportSession } from "./obsidian/exporter.js";
export { updateMOC } from "./obsidian/moc.js";
export { appendToDailyNote } from "./obsidian/daily-note.js";

// Skills — Memory-based Knowledge Extraction
export { extractMemorySkills, renderKnowledgeBase } from "./skills/memory-skill-engine.js";
export type { MemorySkill, Tip, Fact, SkillExtractionResult } from "./skills/memory-skill-engine.js";

// Prompt Injection Detection
export { scan, isInjected, guard, scanBatch, PromptInjectionError } from "./promptguard/scanner.js";
export { BUILTIN_RULES } from "./promptguard/rules.js";
export { ADVANCED_RULES } from "./promptguard/advanced-rules.js";
export { MULTILINGUAL_RULES } from "./promptguard/multilingual-rules.js";
export { normalizeText } from "./promptguard/normalize.js";

// Memory Engine
export { createNexusMemory } from "./memory-engine/nexus-memory.js";
export { semanticSimilarity, expandQuery, getSynonyms } from "./memory-engine/semantic.js";

// Code Review
export { reviewCode } from "./review/analyzer.js";
export { reviewDiff } from "./review/diff-reviewer.js";

// Codebase Mapping
export { mapCodebase } from "./codebase/mapper.js";
export { generateOnboardingGuide } from "./codebase/onboard.js";

// Test Health
export { checkTestHealth } from "./testing/health-check.js";
export { suggestFixes } from "./testing/test-fixer.js";

// Config Validator
export { validateConfig } from "./config/validator.js";
