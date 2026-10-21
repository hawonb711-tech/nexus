import { readFileSync } from "node:fs";

export function extractPlainText(filePath: string, stripMarkdown = true): string {
  const content = readFileSync(filePath, "utf-8");
  if (!stripMarkdown) return content;

  return content
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
    .replace(/(?<![A-Za-z0-9])_{1,3}([^_]+?)_{1,3}(?![A-Za-z0-9])/g, "$1")
    // Links: [text](url) → text
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    // Images: ![alt](url) → remove
    .replace(/!\[[^\]]*\]\([^)]+\)/g, "")
    // Code fences: keep content only
    .replace(/```[^\n]*\n([\s\S]*?)```/g, "$1")
    // Inline code
    .replace(/`([^`]+)`/g, "$1")
    // Blockquotes
    .replace(/^>\s+/gm, "")
    // Horizontal rules
    .replace(/^[-*_]{3,}\s*$/gm, "")
    .trim();
}
