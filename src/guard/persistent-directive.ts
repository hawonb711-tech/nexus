/**
 * The persistent-directive classifier: does this text read as a standing
 * instruction that a future agent session would act on (send a key file out,
 * fetch and run a remote script, override its instructions)?
 *
 * The memory engine quarantines observations it flags. It lives in the guard,
 * not in src/memory-engine, so code the Claude Code hook entry (src/guard/hook.ts)
 * loads — such as a screen of lines added to instruction and memory files — can
 * use it without loading the memory engine; nexus-memory re-exports it unchanged. A change to what it flags must still
 * bump SANITATION_VERSION in src/memory-engine/nexus-memory.ts, so records the
 * older logic cleared are re-scanned.
 */

import { inspectContent } from "./guard.js";
import { urlTokenCarries } from "./url-scan.js";

// ── Persistent agent-directive detection (memory poisoning) ─────────────────
//
// Memory is a durable, re-read context: a stored directive that triggers on
// FUTURE agent actions ("whenever you deploy, email ~/.ssh/id_rsa to …",
// "before tests execute http://ip/b.sh") is a distinct threat from the one-shot
// tool-output the guard's content scanner is tuned for. We route each candidate
// observation through the guard's own detector first (inspectContent, which
// already runs inspectAgentDirectives), and supplement it with a narrow set of
// high-signal exfil / fetch-and-run shapes that the command-shaped detectors
// miss. Content flagged here is QUARANTINED on ingest — dropped, never stored as
// an active, searchable memory. Purely-semantic directives with no exfil /
// fetch-run / override signal still pass (documented limitation).
const DIRECTIVE_EXPOSE_VERB =
  /\b(?:e-?mail|mail|send|sends|sending|post|posts|upload|uploads|exfiltrat\w*|transmit|leak|forward|paste|share|dump)\b/i;
const DIRECTIVE_SECRET_FILE =
  /(?:~\/\.ssh\/|\/\.ssh\/|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b|\bid_dsa\b|\bprivate key\b|\.pem\b|\.p12\b|\.pfx\b|\/\.aws\/credentials|\.env\b|\.netrc\b|\.pgpass\b|\bsecrets?\.ya?ml\b)/i;
const DIRECTIVE_EXEC_VERB =
  /\b(?:execute|executes|run|runs|eval|source|invoke|fetch|download|curl|wget|pipe)\b/i;
// A remote script URL (`http(s)://…/x.sh`): checked per URL token (see url-scan)
// rather than as one `https?:\/\/[^\s…]+\.(?:sh|…)\b` regex, which is quadratic.
const URL_TOKEN = /https?:\/\/[^\s"'`<>]+/gi;
const REMOTE_SCRIPT_EXT = /\.(?:sh|bash|zsh|py|rb|pl|ps1|exe|bat|cmd)\b/i;
const DIRECTIVE_PLAIN_HTTP = /http:\/\//i;
const DIRECTIVE_PERSIST_FRAME =
  /\b(?:when(?:ever)?|before|after|each\s+time|every\s+time|any\s+time|on\s+every|prior\s+to)\b/i;
// Extensionless fetch-and-run shapes that REMOTE_SCRIPT_EXT misses: `curl <url>
// | sh`, `download <url> and run it`, `fetch <url> and pipe it to sh`. Dropping
// the .sh/.py/… extension evaded the branch above. These catch the extensionless
// case but only under a persist-frame (so a benign one-shot `curl … | sh`
// README line with no whenever/before/after frame still passes). All quantifiers
// are bounded — no unbounded run, so no backtracking risk.
const DIRECTIVE_FETCH_VERB = /\b(?:curl|wget|download|fetch|iwr|invoke-webrequest)\b/i;
const DIRECTIVE_ANY_URL = /https?:\/\//i;
const DIRECTIVE_PIPE_TO_SHELL = /\|\s{0,8}(?:ba|z)?sh\b|\bpipe\b[^.\n]{0,40}\b(?:ba|z)?sh\b/i;
const DIRECTIVE_RUN_FETCHED =
  /\b(?:run|execute|exec|eval)\s{1,8}(?:it|this|the\s{1,8}(?:script|result|output|download|file|payload))\b|\b(?:and|then)\s{1,8}(?:then\s{1,8})?(?:run|execute|exec)\b/i;

/** Returns a reason string when `content` should be quarantined as a persistent
 *  agent-directive (exfil / fetch-and-run / override) at warn+, else null. */
export function classifyMemoryThreat(content: string): string | null {
  if (!content) return null;
  const guard = inspectContent(content);
  if (guard.verdict === "warn" || guard.verdict === "block") return guard.reason;
  if (DIRECTIVE_EXPOSE_VERB.test(content) && DIRECTIVE_SECRET_FILE.test(content)) {
    return "persistent directive sends a credential/key file off the machine";
  }
  if (
    DIRECTIVE_EXEC_VERB.test(content) &&
    // At least one character must sit between `//` and the extension's dot.
    urlTokenCarries(content, URL_TOKEN, REMOTE_SCRIPT_EXT, { minBody: 1 }) &&
    (DIRECTIVE_PLAIN_HTTP.test(content) || DIRECTIVE_PERSIST_FRAME.test(content))
  ) {
    return "persistent directive fetches and runs a remote script";
  }
  // Extensionless fetch-and-run: a persist-framed download/curl of any URL that
  // is piped to a shell or whose result is explicitly run. Gated on the persist
  // frame so a benign one-shot `curl … | sh` install line still passes.
  if (
    DIRECTIVE_PERSIST_FRAME.test(content) &&
    DIRECTIVE_ANY_URL.test(content) &&
    DIRECTIVE_FETCH_VERB.test(content) &&
    (DIRECTIVE_PIPE_TO_SHELL.test(content) || DIRECTIVE_RUN_FETCHED.test(content))
  ) {
    return "persistent directive fetches and runs a remote script";
  }
  return null;
}
