/**
 * Instruction-file integrity — the detectors that screen added text (spec
 * §5.2): Markdown with `classifyMemoryThreat`'s checks, hook, helper and MCP
 * commands with `inspectCommand`, text hook scripts with the content
 * capabilities `inspectFileWrite` checks. SessionStart's classification
 * screens hunks with them, and a watched PreToolUse write screens what it adds
 * (pre-tool.ts), which loads this module rather than the whole classifier.
 */

import { detectCommandCapabilities, detectContentCapabilities, resolveCommand } from "../capability.js";
import { inspectCommand, RULES } from "../command.js";
import { inspectContent } from "../guard.js";
import { persistentDirectiveThreat } from "../persistent-directive.js";
import { DEFAULT_POLICY } from "../types.js";
import { forEachMarkdownLine } from "./markdown.js";
import type { Unit } from "./units.js";

/**
 * A detector's finding on added text. `strong`: inspectContent block, inspectCommand deny, or a content capability deny.
 *
 * `lines`: on a markdownVerdict, the 1-based lines, inclusive, of the text it was handed that set the verdict (the
 * run of paragraphs, or the one paragraph). A caller can localise the verdict with it instead of screening each paragraph again: in a
 * whole-file screen they are file lines; in a hunk, line `from` is the hunk's `from`-th line. It describes that text
 * only, so it is not enumerable: a copy of the verdict made for other text (`{ ...v }`, JSON, a held item's
 * recorded verdict) leaves it behind, and deep comparisons ignore it. Read it straight off the returned verdict.
 */
export type Verdict = { reason: string; strong: boolean; lines?: { from: number; to: number } };

/** Characters of added (or first-run) text screened per file. */
export const SCAN_CAP_CHARS = 200_000;

/** Consecutive paragraphs screened together, unless they are short (GROUP_MIN_CHARS). */
const GROUP_PARAGRAPHS = 3;
/** A run shorter than this takes more paragraphs: a page of one-line paragraphs is not screened line by line. */
const GROUP_MIN_CHARS = 250;
/** Characters a run of paragraphs grows to at most (one paragraph is screened whole, however long). */
const GROUP_CHARS = 4000;
const HEADING = /^ {0,3}#{1,6}(?:[ \t]|$)/;

/** A paragraph: lines `from`..`to` (0-based, inclusive) of the text, about `chars` long. */
type Paragraph = { from: number; to: number; chars: number };

/**
 * The paragraphs of Markdown `text`: runs of non-blank lines, also cut before a
 * heading and around a fenced code block; a heading on its own joins the
 * paragraph after it. A hunk joins its added lines without the blank lines
 * between them, so there headings and fences are what still cut it. One pass.
 */
function paragraphsOf(text: string): { lines: string[]; paragraphs: Paragraph[] } {
  const lines: string[] = [];
  const paragraphs: Paragraph[] = [];
  let open: Paragraph | null = null;
  let headingOnly = false; // `open` holds just a heading so far
  let inCode = false;
  const close = () => {
    if (open) paragraphs.push(open);
    open = null;
    headingOnly = false;
  };
  forEachMarkdownLine(text, (line, kind, i) => {
    lines.push(line);
    if (line.trim() === "") {
      if (!headingOnly) close();
      return;
    }
    const fence = kind === "fence";
    const opensFence = fence && !inCode;
    if (fence) inCode = !inCode;
    const heading = kind === "text" && HEADING.test(line);
    if (opensFence || heading) close();
    if (open === null) {
      open = { from: i, to: i, chars: 0 };
      headingOnly = heading;
    } else {
      headingOnly = false;
    }
    open.to = i;
    open.chars += line.length + 1;
    if (fence && !inCode) close(); // a closing fence ends its block
  });
  close();
  return { lines, paragraphs };
}

/**
 * Markdown: what `classifyMemoryThreat` flags, screened a few paragraphs at a
 * time. Its detectors pair signals found anywhere in the text they are given (a
 * verb and its object, a URL and "run it", a key file and "send"), so a long
 * instruction file screened whole pairs words hundreds of lines apart. Runs of
 * GROUP_PARAGRAPHS consecutive paragraphs (more while a run is under
 * GROUP_MIN_CHARS; GROUP_CHARS at most, unless one paragraph is longer) go to
 * `inspectContent` instead, as a document, each run starting at the last
 * paragraph of the one before, so every two adjacent paragraphs that fit are
 * screened together — at about 1.5 times the cost of one whole-text call, on any
 * shape of text. Its warn or block is the verdict, strong when it blocks, with
 * its deciding finding as the reason. Until something is found, each paragraph is
 * also checked for a persistent directive, which gives a soft verdict. A strong
 * verdict wins, then the first, with the lines of the text that set it.
 */
export function markdownVerdict(text: string): Verdict | null {
  if (!text) return null;
  const { lines, paragraphs } = paragraphsOf(text);
  const textOf = (from: number, to: number) => lines.slice(from, to + 1).join("\n");
  let soft: Verdict | null = null;
  let checked = 0; // paragraphs checked for a persistent directive
  for (let i = 0; i < paragraphs.length;) {
    let j = i + 1;
    let chars = paragraphs[i].chars;
    while (j < paragraphs.length && (j - i < GROUP_PARAGRAPHS || chars < GROUP_MIN_CHARS) && chars + paragraphs[j].chars <= GROUP_CHARS) {
      chars += paragraphs[j++].chars;
    }
    const from = paragraphs[i].from;
    const to = paragraphs[j - 1].to;
    const screened = inspectContent(textOf(from, to), DEFAULT_POLICY, "document");
    if (screened.verdict === "block" || screened.verdict === "warn") {
      const v = located({ reason: screened.findings[0] ?? "embedded instructions targeting the agent", strong: screened.verdict === "block" }, from, to);
      if (v.strong) return v;
      soft ??= v;
    }
    for (; !soft && checked < j; checked++) {
      const p = paragraphs[checked];
      const reason = persistentDirectiveThreat(textOf(p.from, p.to));
      if (reason !== null) soft = located({ reason, strong: false }, p.from, p.to);
    }
    if (j === paragraphs.length) break;
    // The next run starts at this one's last paragraph when that pair fits in a run.
    i = j - 1 > i && paragraphs[j - 1].chars + paragraphs[j].chars <= GROUP_CHARS ? j - 1 : j;
  }
  return soft;
}

/** `v` with the 1-based `lines` of 0-based lines `from`..`to` (not enumerable; see Verdict). */
function located(v: Verdict, from: number, to: number): Verdict {
  return Object.defineProperty(v, "lines", { value: { from: from + 1, to: to + 1 }, enumerable: false });
}

const RULE_LABELS: ReadonlyMap<string, string> = new Map(RULES.map((r) => [r.id, r.label]));

/** The label of the rule `inspectCommand` reported (its regex rules, or the capability that fired). */
function commandLabel(command: string, rule: string | null): string {
  if (!rule) return "matches a dangerous command pattern";
  const obfuscated = rule.startsWith("obfuscated:");
  const id = obfuscated ? rule.slice("obfuscated:".length) : rule;
  const label = RULE_LABELS.get(id)
    ?? detectCommandCapabilities(resolveCommand(command)).find((c) => c.id === id)?.label
    ?? `matches ${id}`;
  return obfuscated ? `${label} once shell quoting is removed` : label;
}

/** A hook, helper or MCP command: any decision but allow gives its rule label; deny is strong. */
export function commandVerdict(what: string, command: string): Verdict | null {
  const result = inspectCommand(command);
  if (result.decision === "allow") return null;
  return { reason: `${what} command ${commandLabel(command, result.rule)}`, strong: result.decision === "deny" };
}

/** A text hook script: the content capabilities `inspectFileWrite` checks first (deny, then ask). */
export function scriptVerdict(text: string): Verdict | null {
  const caps = detectContentCapabilities(text);
  const cap = caps.find((c) => c.decision === "deny") ?? caps.find((c) => c.decision === "ask");
  return cap ? { reason: `hook script ${cap.label}`, strong: cap.decision === "deny" } : null;
}

/** What a command-bearing JSON unit is, for a verdict's reason. */
export const commandNoun = (u: Unit): string => (u.kind === "hook" ? "hook" : u.kind === "mcp-server" ? "MCP server" : "helper");
