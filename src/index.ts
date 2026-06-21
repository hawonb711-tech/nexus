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

// Secret Scanner
export { scanForSecrets, redactSecret } from "./secrets/scanner.js";
export { SECRET_RULES } from "./secrets/patterns.js";
export type { SecretFinding, SecretScanResult, SecretScanOptions, SecretSeverity, SecretSource } from "./secrets/types.js";

// Learned models (pure-TS ML kernel — Phase 1: SGNS embeddings from your own corpus)
export { trainWord2Vec, EmbeddingModel, evalSynonymRecall, loadEmbeddingModel, saveEmbeddingArtifact } from "./ml/index.js";
export type { EmbeddingArtifact, ModelManifest, RecallReport } from "./ml/index.js";

// Codebase Mapping
export { mapCodebase } from "./codebase/mapper.js";
export { generateOnboardingGuide } from "./codebase/onboard.js";

// Test Health
export { checkTestHealth } from "./testing/health-check.js";
export { suggestFixes } from "./testing/test-fixer.js";

// Config Validator
export { validateConfig } from "./config/validator.js";

// Web Data Collector
export { collectUrl, collectFeed, collectUrls } from "./collector/fetch.js";
export { extractText, extractTitle } from "./collector/html.js";
export { parseFeed } from "./collector/feed.js";
export type { CollectorResult, FetchOptions, FeedItem, FeedResult } from "./collector/types.js";

// Document Parser
export { parseDocument, parseDocuments, detectFormat } from "./docparser/parse-document.js";
export { chunkText } from "./docparser/chunker.js";
export { extractPdfText, isPdfSupported } from "./docparser/pdf.js";
export { extractDocxText } from "./docparser/docx.js";
export type { ParsedDocument, DocumentChunk, ParseOptions, DocumentFormat } from "./docparser/types.js";
