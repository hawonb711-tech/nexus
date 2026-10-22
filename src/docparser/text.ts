import { readFileSync } from "node:fs";

/*
 * The link, image and code-fence steps below were single regexes (kept verbatim
 * in collect-docs-redos.test.ts as oracles) that re-scanned the rest of the
 * document from every unclosed `[`, `![` or ```` ``` ````, so a markdown file of
 * `[[` took O(n²): ~10 s at 100 KB. These loops find exactly the regex's matches
 * in one pass.
 */

/**
 * `s.replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")` (link) or
 * `s.replace(/!\[[^\]]*\]\([^)]+\)/g, "")` (image). Every opener before the same
 * `]` reaches the same `](…)` tail, so when the first fails on it the scan resumes
 * after that `]`; when no `]` or no closing `)` is left, no later opener can match.
 */
function replaceLinks(s: string, image: boolean): string {
  const opener = image ? "![" : "[";
  let out = "";
  let pos = 0;
  for (let from = 0; ;) {
    const i = s.indexOf(opener, from);
    if (i < 0) break;
    const text = i + opener.length;
    const r = s.indexOf("]", text);
    if (r < 0) break;
    // `[^\]]+` needs a character for a link; `[^)]+` needs one before the `)`.
    if ((image || r > text) && s[r + 1] === "(" && r + 2 < s.length && s[r + 2] !== ")") {
      const p = s.indexOf(")", r + 3);
      if (p < 0) break;
      out += s.slice(pos, i) + (image ? "" : s.slice(text, r));
      pos = from = p + 1;
    } else {
      from = r + 1;
    }
  }
  return out + s.slice(pos);
}

/**
 * `s.replace(/```[^\n]*\n([\s\S]*?)```/g, "$1")`. A later fence opener only looks
 * for its newline and closer further right, so the first one that finds none ends
 * the scan.
 */
function unfenceCode(s: string): string {
  let out = "";
  let pos = 0;
  for (;;) {
    const i = s.indexOf("```", pos);
    if (i < 0) break;
    const nl = s.indexOf("\n", i + 3);
    if (nl < 0) break;
    const c = s.indexOf("```", nl + 1);
    if (c < 0) break;
    out += s.slice(pos, i) + s.slice(nl + 1, c);
    pos = c + 3;
  }
  return out + s.slice(pos);
}

export function extractPlainText(filePath: string, stripMarkdown = true): string {
  const content = readFileSync(filePath, "utf-8");
  return stripMarkdown ? markdownToPlainText(content) : content;
}

/** The markdown stripping extractPlainText applies to a `.md` file's content. */
export function markdownToPlainText(content: string): string {
  const emphasis = content
    // Remove markdown headers but keep text
    .replace(/^#{1,6}\s+/gm, "")
    // Bold/italic
    .replace(/\*{1,3}([^*]+)\*{1,3}/g, "$1")
    // Underscore emphasis only at word boundaries (CommonMark: underscores
    // inside a word do NOT open/close emphasis). Without the boundary guards a
    // secret-shaped token such as `ghp_<36>` or `github_pat_<82>` would have its
    // underscores stripped here — before redaction runs downstream — mangling it
    // so the GitHub-token rule never matches. Intra-word underscores are now left
    // intact so the token stays redactable.
    .replace(/(?<![A-Za-z0-9])_{1,3}([^_]+?)_{1,3}(?![A-Za-z0-9])/g, "$1");

  // Links: [text](url) → text; images: ![alt](url) → remove; code fences: keep content only
  return unfenceCode(replaceLinks(replaceLinks(emphasis, false), true))
    // Inline code
    .replace(/`([^`]+)`/g, "$1")
    // Blockquotes
    .replace(/^>\s+/gm, "")
    // Horizontal rules
    .replace(/^[-*_]{3,}\s*$/gm, "")
    .trim();
}
