import type { DetectionRule } from "./types.js";
import { LinearPattern, type LinearSearcher } from "./rules.js";

const MD_EXFIL_KEYWORD = /\b(?:exfil|steal|leak|callback|log|collect|hook|capture|sniff|grab|dump)\b/gi;
const MD_EXFIL_SCHEME = /\s*https?:\/\//iy;

/**
 * Same matches as
 *   /!\[[^\]]*\]\(\s*https?:\/\/[^\)]+\b(?:exfil|…|dump)\b[^\)]*\)/i
 * computed in one pass. As a regex, every `![` re-scanned its URL body to the
 * first `)` — or to the end of the text when none follows — so many unclosed
 * `![a](http://…` were quadratic. Every `![` that reaches the same `]` shares the
 * same URL body, so each `]`, scheme and `)` is examined once.
 */
class MarkdownExfilPattern extends LinearPattern {
  constructor(pattern?: unknown, flags?: unknown) {
    super(String.raw`!\[[^\]]*\]\(\s*https?:\/\/[^\)]+\b(?:exfil|steal|leak|callback|log|collect|hook|capture|sniff|grab|dump)\b[^\)]*\)`, "i", pattern, flags);
  }

  protected searcher(input: string): LinearSearcher {
    // Whole-word keywords never overlap, so one global pass finds them all.
    const keywords = [...input.matchAll(MD_EXFIL_KEYWORD)].map((m) => [m.index ?? 0, (m.index ?? 0) + m[0].length]);
    let ki = 0;
    let bracket = -1;     // first `]` at/after the current `![` + 2
    let failed = -1;      // a `]` whose URL body was examined and did not match
    let close = -1;       // first `)` at/after that body
    return (from) => {
      for (let s = input.indexOf("![", from); s !== -1; s = input.indexOf("![", s + 1)) {
        if (bracket < s + 2) bracket = input.indexOf("]", s + 2);
        if (bracket === -1) return null;
        if (bracket === failed) continue; // same URL body as an earlier `![` that failed
        if (input[bracket + 1] === "(") {
          MD_EXFIL_SCHEME.lastIndex = bracket + 2;
          if (MD_EXFIL_SCHEME.test(input)) {
            const body = MD_EXFIL_SCHEME.lastIndex;
            if (close < body) close = input.indexOf(")", body);
            if (close === -1) return null;
            // A keyword needs at least one body character before it and must end by `)`.
            while (ki < keywords.length && keywords[ki][0] < body + 1) ki++;
            if (ki < keywords.length && keywords[ki][1] <= close) return { index: s, groups: [input.slice(s, close + 1)] };
          }
        }
        failed = bracket;
      }
      return null;
    };
  }
}

const SPLIT_FIRST = /step\s*1|part\s*1|first\s*part/gi;
const SPLIT_SECOND = /step\s*2|part\s*2|second\s*part/gi;
const SPLIT_THIRD = /step\s*3|part\s*3|third\s*part/gi;
const SPLIT_VERB = /execute|combine|run|follow|assemble|concat|join|now\s+do/gi;
const SPLIT_SEPARATOR = /\s*(?:[:=]\s*)?/y;

/** Start and end of the `re` match at every position where one starts, in order.
 *  The alternatives of each marker differ within their first three characters, so
 *  at most one matches at a position, and only one way. */
function markers(input: string, re: RegExp): [number[], number[]] {
  const starts: number[] = [], ends: number[] = [];
  re.lastIndex = 0;
  for (let m; (m = re.exec(input)) !== null; re.lastIndex = m.index + 1) {
    starts.push(m.index);
    ends.push(m.index + m[0].length);
  }
  return [starts, ends];
}

/** Index of the last element ≤ x in the ascending `xs`, -1 if none. */
function lastAtMost(xs: readonly number[], x: number): number {
  let lo = 0, hi = xs.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (xs[mid] <= x) lo = mid + 1;
    else hi = mid;
  }
  return lo - 1;
}

const isWordCode = (c: number): boolean => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || c === 95 || (c >= 97 && c <= 122);

/** The end of the `\w` run through a word character at w. Remembers the last run,
 *  so positions asked in rising order cost one pass over the text. */
function wordRunEnds(input: string): (w: number) => number {
  let from = -1, to = -1; // [from, to) lies in one word run that ends at `to`
  return (w) => {
    if (w >= from && w < to) return to;
    let i = w;
    while (i < input.length && isWordCode(input.charCodeAt(i))) {
      if (i === from) {
        i = to;
        break;
      }
      i++;
    }
    from = w;
    to = i;
    return i;
  };
}

/**
 * Same matches as
 *   /(?:step\s*1|part\s*1|first\s*part)\s*[:=]?\s*["']?\w+["']?[^]{0,100}(?:step\s*2|part\s*2|second\s*part)
 *    \s*[:=]?\s*["']?\w+["']?(?:[^]{0,100}(?:step\s*3|part\s*3|third\s*part)\s*[:=]?\s*["']?\w+["']?)?
 *    [^]{0,100}(?:execute|combine|run|follow|assemble|concat|join|now\s+do)/is
 * in linear time. As a regex each `\w+` gave back one character at a time to the
 * gap after it, and every level re-ran the levels below from each position it
 * reached, so a word run holding the markers (`step1part2part3part3…`) took
 * seconds per 500 bytes. After a marker, the separator and quotes can only take
 * their longest form (anything shorter leaves no word to start), and the word, its
 * closing quote and a gap then reach one contiguous range of positions, tried
 * from the top down. So each stage's result is the rest of the pattern from the
 * highest position in its range where the rest succeeds. Working back from the
 * verb, each stage keeps only the markers whose value leads on to a verb, in
 * order; "the highest position in [lo, hi] where a gap of 0-100 and then one of
 * these follows" is min(hi, u) for the last such u ≤ hi + 100, if u ≥ lo — one
 * binary search, and no per-position arrays.
 */
class PayloadSplitPattern extends LinearPattern {
  constructor(pattern?: unknown, flags?: unknown) {
    super(String.raw`(?:step\s*1|part\s*1|first\s*part)\s*(?:[:=]\s*)?["']?\w+["']?[^]{0,100}(?:step\s*2|part\s*2|second\s*part)\s*(?:[:=]\s*)?["']?\w+["']?(?:[^]{0,100}(?:step\s*3|part\s*3|third\s*part)\s*(?:[:=]\s*)?["']?\w+["']?)?[^]{0,100}(?:execute|combine|run|follow|assemble|concat|join|now\s+do)`, "is", pattern, flags);
  }

  protected searcher(input: string): LinearSearcher {
    for (const re of [SPLIT_FIRST, SPLIT_SECOND, SPLIT_VERB]) {
      re.lastIndex = 0;
      if (!re.test(input)) return () => null;
    }
    const n = input.length;
    const isQuote = (i: number) => input[i] === '"' || input[i] === "'";
    /** After a marker ending at p: `\s*(?:[:=]\s*)?["']?`, then the word's start w and
     *  the furthest end of `\w+["']?` from it (`\w+["']?` ends anywhere in [w+1, that]).
     *  [-1, -1] if no word starts there. */
    const valueAfter = (p: number, runEnd: (w: number) => number): [number, number] => {
      SPLIT_SEPARATOR.lastIndex = p;
      SPLIT_SEPARATOR.test(input);
      const w = SPLIT_SEPARATOR.lastIndex + (isQuote(SPLIT_SEPARATOR.lastIndex) ? 1 : 0);
      if (!isWordCode(input.charCodeAt(w))) return [-1, -1];
      const end = runEnd(w);
      return [w, end + (isQuote(end) ? 1 : 0)];
    };
    /** Markers of `re` whose value then reaches a match end through `next`: starts and ends, in order. */
    const leading = (re: RegExp, next: (lo: number, hi: number) => number): [number[], number[]] => {
      const [starts, ends] = markers(input, re);
      const runEnd = wordRunEnds(input);
      const at: number[] = [], end: number[] = [];
      for (let i = 0; i < starts.length; i++) {
        const [w, valueEnd] = valueAfter(ends[i], runEnd);
        const e = w < 0 ? -1 : next(w + 1, valueEnd);
        if (e >= 0) {
          at.push(starts[i]);
          end.push(e);
        }
      }
      return [at, end];
    };

    const [verbAt, verbEnd] = markers(input, SPLIT_VERB);
    // From the highest e in [lo, hi] where one follows: [^]{0,100} verb.
    const tail = (lo: number, hi: number): number => {
      const top = Math.min(hi, n);
      if (lo > top) return -1;
      const v = lastAtMost(verbAt, top + 100);
      return v >= 0 && verbAt[v] >= lo ? verbEnd[v] : -1;
    };
    const [thirdAt, thirdEnd] = leading(SPLIT_THIRD, tail);
    // From the highest e in [lo, hi] where either follows: [^]{0,100} third marker and value, then
    // tail (at e the nearest-last such third wins), else tail.
    const rest = (lo: number, hi: number): number => {
      const top = Math.min(hi, n);
      if (lo > top) return -1;
      const t = lastAtMost(thirdAt, top + 100), v = lastAtMost(verbAt, top + 100);
      const u = Math.max(t >= 0 ? thirdAt[t] : -1, v >= 0 ? verbAt[v] : -1);
      if (u < lo) return -1;
      const e = Math.min(top, u);
      const third = lastAtMost(thirdAt, e + 100);
      // u lies in [e, e + 100]: with no third there, it is a verb.
      return third >= 0 && thirdAt[third] >= e ? thirdEnd[third] : verbEnd[lastAtMost(verbAt, e + 100)];
    };
    const [secondAt, secondEnd] = leading(SPLIT_SECOND, rest);
    const runEnd = wordRunEnds(input);
    // Every first-marker start from `from` on, in order (stepping one past each start).
    return (from) => {
      for (let x = from; ; x++) {
        SPLIT_FIRST.lastIndex = x;
        const m = SPLIT_FIRST.exec(input);
        if (m === null) return null;
        x = m.index;
        const [w, valueEnd] = valueAfter(x + m[0].length, runEnd);
        if (w < 0) continue;
        // [^]{0,100} then the last second marker in reach whose value leads on to a verb.
        const s = lastAtMost(secondAt, Math.min(valueEnd + 100, n));
        if (s >= 0 && secondAt[s] >= w + 1) return { index: x, groups: [input.slice(x, secondEnd[s])] };
      }
    };
  }
}

const PADDING_KEYWORD = /\[SYSTEM\]|SYSTEM\s*:|ignore\s+(?:all\s+)?(?:previous|above)|new\s+instructions?/gi;
const PADDING_KEYWORD_AT = new RegExp(PADDING_KEYWORD.source, "iy");
const PADDING_RUN = /([\s\S])\1{100,}/gi;

/**
 * Same matches as
 *   /(.)\1{100,400}[^]{0,50}(?:\[SYSTEM\]|SYSTEM\s*:|ignore\s+(?:all\s+)?(?:previous|above)|new\s+instructions?)/is
 * without its backtracking: as a regex every character of a long run tried up to
 * 301 run lengths × 51 gaps (~2 s per 25 KB of padding). From a start s with R
 * repeats after it (R ≥ 100), those (length, gap) pairs reach the keyword starts
 * s+101 … s+1+min(400, R)+50 in DESCENDING order, so the match ends at the last
 * keyword starting in that window. Inside one maximal run of characters equal
 * ignoring case (as `\1` compares them; PADDING_RUN finds the runs with the same
 * backreference) R falls by one per step of s, so both window ends only grow:
 * the leftmost start is the run's first character, or else the first start whose
 * window reaches the first keyword past the run's own window.
 */
class PaddingInjectionPattern extends LinearPattern {
  constructor(pattern?: unknown, flags?: unknown) {
    super(String.raw`(.)\1{100,400}[^]{0,50}(?:\[SYSTEM\]|SYSTEM\s*:|ignore\s+(?:all\s+)?(?:previous|above)|new\s+instructions?)`, "is", pattern, flags);
  }

  protected searcher(input: string): LinearSearcher {
    let next = -1; // first keyword start at/after the last position asked (Infinity: none)
    const keywordFrom = (at: number): number => {
      if (next < at) {
        PADDING_KEYWORD.lastIndex = at;
        next = PADDING_KEYWORD.exec(input)?.index ?? Infinity;
      }
      return next;
    };
    // From a later `from`, the run search starts there: a run cut at `from` is
    // still a run of the same character, holding exactly the starts left in it.
    return (from) => {
      for (let pos = from; ; ) {
        PADDING_RUN.lastIndex = pos;
        const run = PADDING_RUN.exec(input);
        if (run === null) return null;
        const first = run.index, end = first + run[0].length; // starts: first … end-101
        pos = end;
        const keyword = keywordFrom(first + 101);
        if (keyword === Infinity) return null;
        if (keyword > end + 50) continue;
        const start = Math.max(first, keyword - 451);
        for (let at = Math.min(start + 451, end + 50); at >= start + 101; at--) {
          PADDING_KEYWORD_AT.lastIndex = at;
          const hit = PADDING_KEYWORD_AT.exec(input);
          if (hit) return { index: start, groups: [input.slice(start, at + hit[0].length), input[start]] };
        }
      }
    };
  }
}

const CODE_WORD = /role|system|prompt|ignore|instruction|unrestricted/gi;
const CODE_ACTION = /(?:parse|execute|follow|run|apply|interpret|process)\s+(?:the|this|above|it)/gi;

/**
 * Same matches as
 *   /```(?:(?!```)[\s\S]){0,1500}?(?:role[\s\S]{0,80}?system|system[\s\S]{0,80}?prompt|ignore[\s\S]{0,80}?instruction|unrestricted)
 *    (?:(?!```)[\s\S]){0,1500}?```[\s\S]{0,200}?(?:parse|execute|follow|run|apply|interpret|process)\s+(?:the|this|above|it)/i
 * in one pass. The regex was linear but slow: for every keyword end its tempered
 * span walked up to 1500 characters to the next fence, and `role…system` tried
 * up to eight `system`s within 80 characters, so 200 KB of fenced
 * `rolesystem…` took ~0.7 s per call (twice per inspectContent). Here every
 * choice the regex makes is a lookup:
 * - the span before the keyword cannot pass a ``` and the four keyword heads
 *   start with different letters, so from an opener the keyword is the first
 *   head within 1500 characters and before the next fence that leads to a match;
 * - after a keyword ending at e the tempered span stops at the first ``` at or
 *   after e (it cannot step onto one), so the closer is that fence if within
 *   1500, and the end is the first action within 200 after it (each action
 *   matches one way: its words differ early and `\s+` cannot give back to them);
 * - for a two-word keyword, ends are tried nearest first, so the head's result
 *   is that of the first second word within 80 whose end leads to a match.
 * None of this depends on the opener, so it is computed once per input, over
 * sorted lists of the fences, actions and keywords (binary searches, no arrays
 * over every position).
 */
class CodeBlockSystemPattern extends LinearPattern {
  constructor(pattern?: unknown, flags?: unknown) {
    const F = "```";
    super(String.raw`${F}(?:(?!${F})[\s\S]){0,1500}?(?:role[\s\S]{0,80}?system|system[\s\S]{0,80}?prompt|ignore[\s\S]{0,80}?instruction|unrestricted)(?:(?!${F})[\s\S]){0,1500}?${F}[\s\S]{0,200}?(?:parse|execute|follow|run|apply|interpret|process)\s+(?:the|this|above|it)`, "i", pattern, flags);
  }

  protected searcher(input: string): LinearSearcher {
    const [actionAt, actionEnd] = markers(input, CODE_ACTION);
    if (actionAt.length === 0) return () => null;
    const fences: number[] = [];
    for (let i = input.indexOf("```"); i !== -1; i = input.indexOf("```", i + 1)) fences.push(i);
    /** The first ``` at or after e, -1 if none. */
    const fenceFrom = (e: number): number => {
      const i = lastAtMost(fences, e - 1) + 1;
      return i < fences.length ? fences[i] : -1;
    };
    /** The match end once a keyword ends at e (closing fence, gap, action), or -1. */
    const endAfter = (e: number): number => {
      const c = fenceFrom(e);
      if (c < 0 || c - e > 1500) return -1;
      const a = lastAtMost(actionAt, c + 2) + 1; // the first action from c + 3
      return a < actionAt.length && actionAt[a] - (c + 3) <= 200 ? actionEnd[a] : -1;
    };
    // Second words (system, prompt, instruction) by first letter: the starts whose end
    // leads to a match, in order, and that match end.
    const second: Record<string, [number[], number[]]> = { s: [[], []], p: [[], []], i: [[], []] };
    const heads: [number, string][] = [];
    CODE_WORD.lastIndex = 0;
    for (let m; (m = CODE_WORD.exec(input)) !== null; CODE_WORD.lastIndex = m.index + 1) {
      const word = m[0].toLowerCase();
      if (word === "system" || word === "prompt" || word === "instruction") {
        const end = endAfter(m.index + word.length);
        if (end >= 0) {
          second[word[0]][0].push(m.index);
          second[word[0]][1].push(end);
        }
      }
      if (word !== "prompt" && word !== "instruction") heads.push([m.index, word]);
    }
    // Keyword heads that lead to a match, in order, and that match end.
    const headAt: number[] = [], headEnd: number[] = [];
    for (const [k, word] of heads) {
      let end = -1;
      if (word === "unrestricted") {
        end = endAfter(k + 12);
      } else {
        // role…system, system…prompt, ignore…instruction: the second word starts 0-80 after the head.
        const [key, from] = word === "role" ? ["s", k + 4] : [word === "system" ? "p" : "i", k + 6];
        const [at, ends] = second[key];
        const j = lastAtMost(at, from - 1) + 1;
        if (j < at.length && at[j] <= from + 80) end = ends[j];
      }
      if (end >= 0) {
        headAt.push(k);
        headEnd.push(end);
      }
    }
    return (from) => {
      for (let f = lastAtMost(fences, from - 1) + 1; f < fences.length; f++) {
        const open = fences[f], body = open + 3;
        const h = lastAtMost(headAt, body - 1) + 1;
        if (h === headAt.length || headAt[h] - body > 1500) continue;
        const next = fenceFrom(body);
        if (next < 0 || headAt[h] <= next) return { index: open, groups: [input.slice(open, headEnd[h])] };
      }
      return null;
    };
  }
}

/**
 * Advanced detection rules targeting state-of-the-art prompt injection techniques.
 *
 * These rules catch attacks that bypass basic pattern matching:
 * - Payload splitting
 * - Few-shot jailbreaking
 * - Virtualization/persona simulation
 * - Authority/hierarchy confusion
 * - Leetspeak/typo evasion
 * - Hypothetical framing
 * - JSON/code block escape
 * - Context window manipulation
 * - Conversation reset faking
 */
export const ADVANCED_RULES: DetectionRule[] = [
  // ---- Payload Splitting ----
  {
    id: "advanced-payload-splitting",
    severity: "high",
    message: "Payload splitting: instructions fragmented across multiple steps",
    pattern:
      /(?:first\s+word|second\s+word|combine\s+them|put\s+(?:them|these|it)\s+together|concatenat|join\s+(?:them|the\s+words)|assemble\s+(?:the|these)).{0,300}?(?:instruction|command|ignore|execute|follow)/is,
  },
  {
    id: "advanced-payload-splitting-numbered",
    severity: "medium",
    message: "Numbered instruction fragments suggesting payload reconstruction",
    // Matched in code (see PayloadSplitPattern): as a regex, a whitespace run
    // after a marker split O(n²) ways between `\s*[:=]?\s*`, and a word run
    // holding markers blew up polynomially (seconds on 500 bytes).
    pattern: new PayloadSplitPattern(),
  },
  {
    id: "advanced-payload-splitting-parts",
    severity: "high",
    message: "Payload splitting via numbered parts",
    pattern:
      /(?:part\s*[1-3]|step\s*[1-3])\s*[:=]\s*\w+[^]{0,50}(?:part\s*[2-4]|step\s*[2-4])\s*[:=]\s*\w+/is,
  },

  // ---- Few-shot Jailbreak ----
  {
    id: "advanced-few-shot-jailbreak",
    severity: "critical",
    message: "Few-shot example used to demonstrate desired unsafe behavior",
    pattern:
      /(?:example|here\s+is\s+(?:a|an)\s+(?:good|ideal|perfect|correct)\s+(?:response|answer|reply|assistant|output)|like\s+(?:the|this)\s+example)[^]{0,300}(?:be\s+like|follow\s+(?:the|this)\s+example|do\s+the\s+same|now\s+(?:you\s+)?(?:answer|respond|do|try))/is,
  },

  // ---- Virtualization / Persona Simulation ----
  {
    id: "advanced-virtualization",
    severity: "critical",
    message: "Virtualization attack: persona simulation to bypass restrictions",
    pattern:
      /(?:play\s+a\s+game|let(?:'s|\s+us)\s+(?:play|pretend|roleplay|simulate)|imagine\s+you\s+are|you\s+are\s+playing|act\s+as\s+if\s+you\s+(?:were|are)|character\s+(?:called|named))[^]{0,200}(?:no\s+restrict|without\s+(?:any\s+)?(?:restriction|filter|limit|censor|safety)|always\s+answer|never\s+refus|can\s+do\s+anything|has\s+no\s+(?:limit|restrict|boundar))/is,
  },
  {
    id: "advanced-persona-naming",
    severity: "high",
    message: "Named persona used to simulate unrestricted mode",
    pattern:
      /(?:you\s+are|your\s+name\s+is|call\s+yourself|I[''\u2019]ll\s+call\s+you)\s+["']?(?:Master\s*AI|Evil\s*AI|Dark\s*(?:GPT|Claude|AI)|GODMODE|HackGPT|Omega|Alpha|Sigma|BasedGPT|AnarchyGPT|Devil|Lucifer|Shadow|Villain|UnchainedAI)["']?/i,
  },

  // ---- Authority / Hierarchy Confusion ----
  {
    id: "advanced-authority-confusion",
    severity: "critical",
    message: "Authority confusion: claims elevated privileges to override system prompt",
    pattern:
      /(?:(?:user|I|my)\s+(?:has|have|instructions?\s+(?:take|have))\s+(?:higher|more|greater)\s+(?:authority|priority|precedence|privilege)|(?:user|human)\s+instructions?\s+(?:take|have)\s+precedence|as\s+(?:per|an?\s+)?(?:OpenAI|Anthropic|admin|developer|operator)\s+policy|I\s+am\s+(?:the\s+)?(?:admin|developer|operator|owner|creator|maintainer))/i,
  },
  {
    id: "advanced-debug-mode",
    severity: "high",
    message: "Claims debug, maintenance, or testing mode to bypass restrictions",
    pattern:
      /(?:(?:enter|enable|activate|switch\s+to|you\s+are\s+(?:now\s+)?in)\s+(?:debug|maintenance|testing|developer|sudo|root|admin|god)\s+mode|debug\s*=\s*true|maintenance_override|testing_bypass)/i,
  },

  // ---- Leetspeak / Typo Evasion ----
  {
    id: "advanced-leetspeak",
    severity: "high",
    message: "Leetspeak/typo evasion: substituted characters to bypass detection",
    pattern:
      /(?!ignore\s+all\s+previous\b)[i1l][gq9][n|\\/][o0][r|][e3]\s+[a@4][l1][l1]\s+[p|][r|][e3][v|][i1l][o0][u|][s5$]/i,
  },
  {
    id: "advanced-leetspeak-system",
    severity: "high",
    message: "Leetspeak variant: system prompt exfiltration with character substitution",
    pattern:
      /(?!system\s+prompt\b)[s5$][yh][s5$][t7][e3][m|]\s+[p|][r|][o0][m|][p|][t7]/i,
  },
  {
    id: "advanced-spaced-evasion",
    severity: "medium",
    message: "Character spacing evasion: letters separated to avoid detection",
    pattern:
      /i\s{1,6}g\s{1,6}n\s{1,6}o\s{1,6}r\s{1,6}e\s{1,6}.{0,200}(?:i\s{1,6}n\s{1,6}s\s{1,6}t\s{1,6}r\s{1,6}u\s{1,6}c\s{1,6}t|p\s{1,6}r\s{1,6}e\s{1,6}v\s{1,6}i\s{1,6}o\s{1,6}u\s{1,6}s|a\s{1,6}l\s{1,6}l)/i,
  },

  // ---- Hypothetical Framing ----
  {
    id: "advanced-hypothetical",
    severity: "high",
    message: "Hypothetical framing used to extract restricted information",
    pattern:
      /(?:hypothetically|theoretically|in\s+theory|just\s+(?:imagine|suppose|pretend)|what\s+(?:if|would\s+happen\s+if)|imagine\s+you\s+(?:are|were|had)|in\s+a\s+fictional\s+world|for\s+a\s+creative\s+writing\s+exercise|(?:pretend|suppose)\s+you\s+(?:can|could|are|have))[^]{0,200}(?:system\s+prompt|instructions?|ignore|bypass|override|unrestricted|(?:no|without)\s+(?:restrictions?|limits?|filters?|content\s+filters?|safety|censors?|boundar|rules?)|secrets?|hidden|internal|reveal\s+secrets?|had\s+no\s+restrictions?)/is,
  },
  {
    id: "advanced-fictional-framing",
    severity: "high",
    message: "Uses fictional/creative framing to bypass restrictions",
    pattern:
      /\b(?:fictional|creative\s+writing|imagine|in\s+a\s+(?:story|world|scenario)\s+where)\b[^]{0,100}(?:no\s+(?:restrict|limit|filter|censor|rule)|reveal\s+secret|bypass|unrestricted)/is,
  },
  {
    id: "advanced-fiction-framing",
    severity: "medium",
    message: "Fiction/story framing used to bypass safety guidelines",
    pattern:
      /(?:write\s+a\s+(?:story|novel|fiction|screenplay|script)|(?:in\s+a|for\s+(?:a|my))\s+(?:story|novel|fiction|movie|book))[^]{0,200}(?:(?:character|protagonist|villain)\s+(?:who|that)\s+(?:hack|break|bypass|steal|inject|exploit)|detailed\s+(?:step|instruction|guide)\s+(?:for|on|to)\s+(?:hack|break|exploit))/is,
  },

  // ---- JSON / Code Block Escape ----
  {
    id: "advanced-json-role-injection",
    severity: "critical",
    message: "JSON payload injecting role/system messages",
    pattern:
      /["']\s*role\s*["']\s*:\s*["']\s*(?:system|admin|developer|operator)\s*["'][^]{0,100}(?:ignore|unrestricted|override|no\s+(?:restriction|filter|safety)|bypass)/is,
  },
  {
    id: "advanced-code-block-system",
    severity: "high",
    message: "Code block containing system-level instructions followed by execution request",
    requiresContext: /```/,
    // Matched in code (see CodeBlockSystemPattern): the regex's tempered, bounded
    // spans kept it linear, but at ~0.7 s per 200 KB of fenced keyword runs.
    pattern: new CodeBlockSystemPattern(),
  },

  // ---- Multi-Agent / Tool Chain Attacks ----
  {
    id: "advanced-tool-chain-injection",
    severity: "critical",
    message: "Tool chain injection: instructs agent to call tools with malicious parameters",
    pattern:
      /(?:call|invoke|use|execute|run)\s+(?:the\s+)?(?:tool|function|api|command|endpoint)\s+(?:with|using)[^]{0,100}(?:rm\s+-rf|curl\s+|wget\s+|eval\(|exec\(|system\(|\/etc\/passwd|\.env|credentials?|api.?key|secret|token)/is,
  },

  // ---- Context Window / Padding Attacks ----
  {
    id: "advanced-padding-injection",
    severity: "high",
    message: "Padding attack: large filler text followed by injection payload",
    // Gated on the payload keyword so pure filler (a long run of one char, spaces,
    // newlines) is skipped entirely instead of driving `(.)\1{100,}` into a
    // quadratic start-position scan; the run length is also capped.
    requiresContext: /\[SYSTEM\]|SYSTEM\s*:|ignore\s+(?:all\s+)?(?:previous|above)|new\s+instructions?/i,
    // Matched in code (see PaddingInjectionPattern): the regex tried 301 run
    // lengths × 51 gaps at every character of a long run (~2 s per 25 KB).
    pattern: new PaddingInjectionPattern(),
  },

  // ---- Multilingual Switching ----
  {
    id: "advanced-language-switch",
    severity: "high",
    message: "Mid-prompt language switch to evade monolingual detection",
    // Gated on a wide-charset character so pure-ASCII input skips the rule
    // entirely; the leading ASCII run is a fixed {20} (no greedy backtracking)
    // and the other runs are bounded.
    requiresContext: /[\u3000-\u9FFF\uAC00-\uD7AF\u0400-\u04FF\u0600-\u06FF]/,
    pattern:
      /[\x00-\x7F]{20}[\u3000-\u9FFF\uAC00-\uD7AF\u0400-\u04FF\u0600-\u06FF]{5,200}[\x00-\x7F]{10,200}?(?:system|prompt|instruction|ignore)/is,
  },

  // ---- Positional / Boundary Exfiltration ----
  {
    id: "advanced-exfil-positional",
    severity: "critical",
    message: "Positional exfiltration: attempts to extract text above/before the current line",
    pattern:
      /\b(?:print|show|display|output|reveal|repeat|echo|give\s+me|tell\s+me)\s+(?:everything|all(?:\s+text)?|the\s+(?:text|content|data))\s+(?:above\s+this\s+line|before\s+this|above\s+this|above\s+here)\b/i,
  },
  {
    id: "advanced-exfil-hidden-instructions",
    severity: "critical",
    message: "Attempts to extract hidden or secret instructions",
    pattern:
      /\b(?:show|reveal|display|output|print|tell\s+me|give\s+me|what\s+are)\s+(?:me\s+)?(?:your\s+)?(?:hidden|secret|concealed|private|confidential|internal)\s+(?:instructions?|prompts?|rules?|directives?|guidelines?|configuration)\b/i,
  },
  {
    id: "advanced-exfil-boundary-markers",
    severity: "critical",
    message: "Attempts to extract text between known system prompt boundary markers",
    pattern:
      /\b(?:output|print|show|display|reveal|repeat|echo|extract|give\s+me)\s+(?:the\s+)?(?:text|content|data|everything)\s+(?:between|from)\s+(?:["']?BEGIN\b|["']?START\b|["']?SYSTEM\b).{0,60}(?:END\b|STOP\b|SYSTEM\b)/is,
  },

  // ---- Authority with Override Codes ----
  {
    id: "advanced-authority-code",
    severity: "critical",
    message: "Fake authority/override code used to disable restrictions",
    // `\s*[:=]?\s*` split a whitespace run with no `:`/`=` between its two `\s*`
    // O(n²) ways; `\s*(?:[:=]\s*)?` is the same strings, tried in the same order.
    // `[\w-]{2,}["']?[^]{0,100}` gave the gap one character at a time (100 tries
    // per character of a long code); the verb's possible starts are the same
    // positions from the top down: the whole code plus quote and gap, then each
    // shorter take of the code with no gap (its next character continues the code).
    pattern:
      /(?:admin|override|auth(?:orization)?|access|master)\s+(?:override\s+)?(?:code|key|token|pass(?:word|phrase)?)\s*(?:[:=]\s*)?["']?[A-Z0-9](?:[\w-]{2,}(?![\w-])["']?[^]{0,100}|[\w-]{2,}(?=[\w-]))(?:disable|remove|bypass|lift|turn\s+off|deactivate|suspend)\s+(?:all\s+)?(?:restriction|filter|safety|limit|guardrail|content\s+polic)/is,
  },
  {
    id: "advanced-admin-code",
    severity: "critical",
    message: "Claims admin/override code to bypass restrictions",
    // Same `\s*(?:[:=]\s*)?` rewrite as advanced-authority-code.
    pattern:
      /(?:admin|override|master|root|sudo)\s+(?:code|key|password|token)\s*(?:[:=]\s*)?[A-Z0-9-]+.{0,30}(?:disable|bypass|unlock|override|remove\s+restrict)/i,
  },

  // ---- Soft Tool Result Injection ----
  {
    id: "advanced-soft-tool-injection",
    severity: "critical",
    message: "Soft instruction injection targeting the assistant/model directly",
    pattern:
      /\bNOTE\s+TO\s+(?:ASSISTANT|AI|MODEL|CLAUDE|GPT|LLM|CHATBOT)\s*:\s*(?:disregard|ignore|override|bypass|suspend|skip|forget|do\s+not\s+follow)\b/i,
  },

  // ---- Simulation / Roleplay Bypass ----
  {
    id: "advanced-simulation-bypass",
    severity: "high",
    message: "Simulation or roleplay framing used to bypass content policy",
    pattern:
      /(?:simulate|roleplay|act\s+out|emulate|enact|play\s+out)\s+(?:a\s+)?(?:conversation|scenario|dialogue|interaction|session|situation|world)[^]{0,200}(?:no\s+(?:content\s+polic|restriction|filter|safety|guideline|limit|censor|boundar)|without\s+(?:content\s+polic|restriction|filter|safety|guideline|limit|censor|boundar)|unrestricted|unfiltered)/is,
  },
  {
    id: "advanced-simulate-unrestricted",
    severity: "high",
    message: "Requests simulation of unrestricted AI behavior",
    pattern:
      /\b(?:simulate|roleplay|act\s+out|demonstrate)\s+(?:a\s+)?(?:conversation|scenario|situation|interaction)\s+(?:where|in\s+which)[^]{0,60}(?:no\s+(?:content\s+polic|restrict|filter|rule|limit)|unrestricted|without\s+(?:restrict|filter|limit))/is,
  },

  // ---- Markdown / Link Exfiltration ----
  {
    id: "advanced-markdown-exfil",
    severity: "high",
    message: "Markdown image/link used for data exfiltration",
    // Keywords are word-bounded so a badge URL like opencollective.com (contains
    // "collect") or a /blog/ path (contains "log") is not mistaken for exfil.
    pattern: new MarkdownExfilPattern(),
  },
  {
    id: "advanced-markdown-data-url",
    severity: "medium",
    message: "Markdown referencing dynamic URL with template variables",
    // Same matches as /!\[.*?\]\(.*?(?:…).*?\)/i, which was cubic on many unclosed
    // `![a](…` (a match start per `![` × a split per `](` × a scan to line end).
    // Only a line's FIRST `![` can start a match — an earlier one leaves more room
    // for the `](`, marker and `)` that must follow — so a lookbehind pins the start
    // there, and each later step is an atomic lookahead (`(?=(…))\N`).
    // `(?!.)[\s\S]` is a line terminator, i.e. a character `.` does not match.
    pattern:
      /(?=!\[)(?<=(?:^|(?!.)[\s\S])(?:(?!!\[).)*)!\[(?=(.*?\]\())\1(?=(.*?(?:\$\{|{{|%7B%7B|SYSTEM_PROMPT|API_KEY|SECRET|TOKEN|PASSWORD)))\2.*?\)/i,
  },

  // ---- Fake Mode / Environment Claims ----
  {
    id: "advanced-fake-mode-claim",
    severity: "high",
    message:
      "Claims a special mode that disables safety (maintenance/sudo/test/debug)",
    pattern:
      /(?:entering|activating|enabling|switching\s+to)\s+(?:maintenance|sudo|root|admin|test|debug|developer|god)\s+mode/i,
  },
  {
    id: "advanced-restrictions-disabled",
    severity: "high",
    message: "Claims restrictions or filters are disabled",
    pattern:
      /(?:safety|content|security)\s+(?:filters?|restrictions?|guidelines?|policies?)\s+(?:are\s+)?(?:disabled|removed|off|lifted|bypassed|deactivated)/i,
  },
  {
    id: "advanced-no-restrictions-apply",
    severity: "high",
    message: "Claims no restrictions apply in current context",
    // "without restrictions" requires the plural so the MIT-license boilerplate
    // "deal in the Software without restriction" (singular) is not flagged.
    pattern:
      /\b(?:no\s+restrictions?\s+appl|without\s+(?:any\s+)?restrictions\b|restrictions?\s+(?:do\s+not|don.?t)\s+apply)\b/i,
  },
  {
    id: "advanced-creator-claim",
    severity: "high",
    message:
      "Claims to be the creator/developer/admin to override rules",
    pattern:
      /\b(?:i\s+am\s+(?:your\s+)?(?:creator|developer|admin|owner|maker|programmer)|\uB0B4\uAC00\s+(?:\uB9CC\uB4E0|\uAC1C\uBC1C\uD55C))\b[^.]{0,40}(?:override|disable|bypass|ignore|remove)/i,
  },
  {
    id: "advanced-test-environment",
    severity: "high",
    message:
      "Claims test/dev environment to justify bypassing restrictions",
    pattern:
      /\b(?:this\s+is\s+(?:a\s+)?(?:test|dev|debug|staging)\s+(?:environment|mode|context|session))[^.]{0,30}(?:no\s+restrict|bypass|disable|safe\s+to)/i,
  },
];
