/**
 * Secret detection rules. Ordered most-specific first so a precise vendor match
 * (e.g. "GitHub PAT") wins over a generic assignment match on the same line.
 *
 * Each rule's `re` is global so the scanner can find every occurrence on a line.
 * `group` is the capture group holding the secret value (default 0 = whole match)
 * — used both for redaction and for placeholder filtering. Every quantifier is
 * upper-bounded to a realistic token length so a pathological multi-kB line
 * cannot make a rule swallow the whole line (false positives + backtracking).
 *
 * Rules flagged `generic` match on a key NAME (api_key/secret/...) rather than a
 * self-identifying value prefix, so the scanner applies an extra value-shape
 * guard to them to suppress paths / URLs / version strings.
 *
 * The vendor and generic patterns mirror src/review/analyzer.ts so the two
 * detectors stay consistent, extended here to the tokens most worth catching.
 */

import type { SecretSeverity } from "./types.js";

export type SecretRule = {
  id: string;
  label: string;
  severity: SecretSeverity;
  re: RegExp;
  /** Capture group holding the secret (default: whole match). */
  group?: number;
  /** Matches on a key name, not a value prefix — apply the value-shape guard. */
  generic?: boolean;
};

export const SECRET_RULES: SecretRule[] = [
  // ── High-confidence vendor tokens (self-identifying prefixes) ───────────────
  { id: "aws-akid", label: "AWS access key ID", severity: "critical",
    re: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T)[A-Z0-9]{16})\b/g },
  { id: "aws-secret", label: "AWS secret access key", severity: "critical",
    re: /aws.{0,20}?(?:secret|access).{0,20}?[:=]\s*["'`]?([A-Za-z0-9/+]{40})["'`]?/gi, group: 1 },
  { id: "github-pat", label: "GitHub personal access token", severity: "critical",
    re: /\b(ghp_[A-Za-z0-9]{36})\b/g },
  { id: "github-finegrained", label: "GitHub fine-grained token", severity: "critical",
    re: /\b(github_pat_[A-Za-z0-9_]{82})\b/g },
  { id: "github-oauth", label: "GitHub OAuth/app/refresh token", severity: "high",
    re: /\b(gh[osur]_[A-Za-z0-9]{36,251})\b/g },
  { id: "slack-token", label: "Slack token", severity: "critical",
    re: /\b(xox[baprs]-[A-Za-z0-9-]{10,250})\b/g },
  { id: "slack-webhook", label: "Slack webhook URL", severity: "high",
    re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]{8,64})/g },
  { id: "google-api", label: "Google API key", severity: "critical",
    re: /\b(AIza[0-9A-Za-z\-_]{35})\b/g },
  { id: "google-oauth-secret", label: "Google OAuth client secret", severity: "high",
    re: /\b(GOCSPX-[A-Za-z0-9_-]{28})\b/g },
  { id: "stripe-secret", label: "Stripe secret key", severity: "critical",
    re: /\b((?:sk|rk)_live_[0-9a-zA-Z]{24,200})\b/g },
  { id: "anthropic", label: "Anthropic API key", severity: "critical",
    re: /\b(sk-ant-[A-Za-z0-9_-]{20,200})\b/g },
  { id: "openai", label: "OpenAI API key", severity: "critical",
    re: /\b(sk-(?:proj-)?[A-Za-z0-9]{20,100}(?:T3BlbkFJ[A-Za-z0-9]{20,100})?)\b/g },
  { id: "npm-token", label: "npm access token", severity: "critical",
    re: /\b(npm_[A-Za-z0-9]{36})\b/g },
  { id: "pypi-token", label: "PyPI upload token", severity: "critical",
    re: /\b(pypi-AgEIcHlwaS[A-Za-z0-9_-]{50,200})\b/g },
  { id: "sendgrid", label: "SendGrid API key", severity: "critical",
    re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g },
  { id: "twilio", label: "Twilio API key", severity: "high",
    re: /\b(SK[0-9a-fA-F]{32})\b/g },
  { id: "telegram-bot", label: "Telegram bot token", severity: "high",
    re: /\b([0-9]{8,10}:AA[A-Za-z0-9_-]{33})\b/g },
  { id: "gitlab-pat", label: "GitLab personal access token", severity: "critical",
    re: /\b(glpat-[A-Za-z0-9_-]{20})\b/g },
  { id: "jwt", label: "JSON Web Token", severity: "medium",
    re: /\b(eyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,2000}\.[A-Za-z0-9_-]{8,2000})\b/g },
  // Whole PEM block, not just the BEGIN header, so the key body is masked too.
  // The END half is an optional, length-bounded group: on a full document the
  // greedy `(?:…)?` absorbs the body through the END line (whole block masked);
  // on a single header line (the per-line working-tree scan) it matches empty so
  // the BEGIN line is still flagged. Covers RSA/EC/DSA/OPENSSH plain "PRIVATE
  // KEY", "ENCRYPTED PRIVATE KEY", and "PGP PRIVATE KEY BLOCK". {0,8000} bounds
  // the body scan so a BEGIN with no END cannot drive O(n²) backtracking.
  { id: "private-key", label: "private key block", severity: "critical",
    re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]{0,8000}?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)?/g },
  // Credentials embedded in a connection-string URI's userinfo
  // (postgres://user:pass@host, mongodb+srv://user:pass@cluster, …). The capture
  // is the `user:pass@` userinfo only: masking that span hides the password
  // without depending on the host (whose domain, e.g. example.com, would
  // otherwise trip the placeholder filter) and without globally over-masking a
  // short password that also occurs as a plain word elsewhere. Placeholder
  // filter: a password that is an env/template reference (`${PASS}`,
  // `<password>`) is skipped via the negative lookahead.
  { id: "uri-userinfo", label: "credential in connection-string URI", severity: "high",
    re: /\b[a-z][a-z0-9+.\-]{1,30}:\/\/([^\s:/@"'`<>]{1,100}:(?!\$\{?[A-Za-z_]|<|(?:pass(?:word|wd)?|pwd|user(?:name)?|changeme|example|placeholder|secret|token|xxx+|test|redacted|dummy)@)[^\s:/@"'`<>]{1,200}@)[^\s/"'`<>]{1,200}/gi, group: 1 },

  // ── Generic assignment patterns (key-name based; value-shape guarded) ───────
  { id: "generic-apikey", label: "API key assignment", severity: "high", generic: true,
    re: /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|bearer)["'`]?\s*[:=]\s*["'`]([A-Za-z0-9_\-./+]{16,200})["'`]/gi, group: 1 },
  { id: "generic-secret", label: "secret/token assignment", severity: "medium", generic: true,
    re: /(?:secret|token)["'`]?\s*[:=]\s*["'`]([A-Za-z0-9_\-./+]{16,200})["'`]/gi, group: 1 },
  { id: "generic-password", label: "hardcoded password", severity: "low", generic: true,
    re: /(?:password|passwd|pwd)["'`]?\s*[:=]\s*["'`]([^"'`\s]{6,200})["'`]/gi, group: 1 },

  // ── Unquoted assignments (.env / YAML / HTTP headers) ───────────────────────
  // Real leaks rarely quote the value: `DB_PASSWORD=…`, `password: …`,
  // `Authorization: Bearer …`. Each is `generic` so the value-shape guard in the
  // scanner (looksLikeSecretValue) + the placeholder filter (isPlaceholder)
  // suppress obvious non-secrets (process.env.X, your-key-here, <token>, xxx).
  // Env-style: an UPPER_SNAKE key containing a secret word, unquoted value. The
  // all-caps key shape keeps ordinary lowercase code (`password = fn()`) out.
  { id: "env-credential", label: "credential in env-style assignment", severity: "high", generic: true,
    re: /\b[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_?KEY|ACCESS_?KEY|ACCESS_?TOKEN|AUTH_?TOKEN|CLIENT_?SECRET|SECRET_?KEY|PRIVATE_?KEY)[A-Z0-9_]*\s*=\s*([^\s"'`#]{8,200})/g, group: 1 },
  // Config-style `key: value` anchored at line start (so prose like
  // "my password: hunter2" mid-sentence is not matched). Covers unquoted YAML.
  { id: "yaml-credential", label: "credential in config assignment", severity: "high", generic: true,
    re: /^[ \t-]*["']?(?:password|passwd|pwd|secret|secret[_-]?key|token|api[_-]?key|apikey|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)["']?\s*:\s*([^\s"'`#]{8,200})/gim, group: 1 },
  // Authorization: Bearer <token> (and bare `Bearer <token>`). Not `generic`:
  // the "Bearer " prefix is itself the anchor, so short/opaque tokens still mask.
  { id: "bearer-token", label: "HTTP bearer token", severity: "high",
    re: /\bbearer\s+([A-Za-z0-9._~+/=-]{12,400})/gi, group: 1 },
];
