export { extractSkills } from "./extractor.js";
export {
  addSkills,
  exportToObsidian,
  loadSkillLibrary,
  saveSkillLibrary,
  searchSkills,
} from "./library.js";
export type { ExtractedSkill, SkillLibrary } from "./types.js";

// Pattern Evolution Engine
export {
  analyzePatternEvolution,
  extractContextualPatterns,
  fingerprintPattern,
  findSimilarPatterns,
  analyzeDrift,
  buildEvolvedSkill,
} from "./pattern-engine.js";
export type {
  ContextWindow,
  TaskSequence,
  PatternFingerprint,
  DriftAnalysis,
  DriftReason,
  EvolvedSkill,
  EvolutionEntry,
} from "./pattern-engine.js";
export { exportEvolvedSkills, renderEvolvedSkillMarkdown } from "./render-evolved.js";
