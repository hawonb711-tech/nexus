export type {
  SecretSeverity,
  SecretSource,
  SecretDetector,
  SecretFinding,
  SecretScanResult,
  SecretScanOptions,
} from "./types.js";

export { scanForSecrets, redactSecret } from "./scanner.js";
export { SECRET_RULES } from "./patterns.js";
export type { SecretRule } from "./patterns.js";
