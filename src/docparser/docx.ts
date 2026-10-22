import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { firstInRun } from "../guard/line-scan.js";

// `/<w:t[^>]*>([^<]*)<\/w:t>/g`, tried only from the first `<w:t` before each `>`.
// As written, every `<w:t` re-scanned up to the next `>`, so a 200 KB paragraph of
// `<w:t<w:t…` took ~9 s. A later `<w:t` before the same `>` reaches the same text
// and fails or succeeds with it, and a match ends at a `>`, so the scan never
// resumes inside such a run: exec() sees the same matches and captures.
const TEXT_RUN = new RegExp(`${firstInRun(/<w:t/, ">")}[^>]*>([^<]*)<\\/w:t>`, "g");

export function extractDocxText(filePath: string): string {
  let xml: string;
  try {
    xml = execFileSync("unzip", ["-p", resolve(filePath), "word/document.xml"], {
      maxBuffer: 20 * 1024 * 1024,
      encoding: "utf-8",
    });
  } catch {
    throw new Error(`Failed to extract DOCX: ${filePath}`);
  }
  return docxXmlToText(xml);
}

/** The paragraph text extractDocxText reads out of `word/document.xml`. */
export function docxXmlToText(xml: string): string {
  const lines: string[] = [];
  // Split by paragraph markers
  const paragraphs = xml.split(/<\/w:p>/);

  for (const para of paragraphs) {
    const texts: string[] = [];
    let match;
    TEXT_RUN.lastIndex = 0;
    while ((match = TEXT_RUN.exec(para)) !== null) {
      texts.push(match[1]);
    }
    if (texts.length > 0) {
      lines.push(texts.join(""));
    }
  }

  return lines.join("\n").trim();
}
