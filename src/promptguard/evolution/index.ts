export {
  loadCorpus,
  saveCorpus,
  addSample,
  getMissedSamples,
  getSamplesByCategory,
  generateReport,
} from "./corpus.js";
export type { AttackSample, AttackCategory, AttackSource, Corpus, CorpusStats } from "./corpus.js";

export {
  evolveRules,
  reevaluateCorpus,
  exportEvolvedRules,
} from "./rule-evolver.js";
export type { CandidateRule, EvolutionConfig } from "./rule-evolver.js";

export {
  evolve,
  loadEvolvedRules,
  createEvolvingScanner,
} from "./auto-update.js";
export type { UpdateResult, FeedEntry } from "./auto-update.js";
