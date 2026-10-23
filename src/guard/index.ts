export { inspectContent } from "./guard.js";
export { sanitizeExternalContent } from "./sanitize.js";
export type { SanitizedExternalContent } from "./sanitize.js";
export { inspectCommand, inspectFileWrite } from "./command.js";
export type { CommandDecision, CommandResult } from "./command.js";
export { DEFAULT_POLICY } from "./types.js";
export type { GuardVerdict, GuardResult, GuardPolicy } from "./types.js";
// Instruction-file integrity, read-only. Approving changes and resetting the
// baseline are the human-gated CLI's alone: those functions are not exported here.
export { integrityStatus, integrityDiff } from "./integrity/index.js";
export type {
  IntegrityOptions, IntegrityStatus, IntegrityStatusState, IntegrityDiff, IntegrityDiffItem, SettingsScope,
} from "./integrity/index.js";
