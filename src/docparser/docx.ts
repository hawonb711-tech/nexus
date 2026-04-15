import { execSync } from "node:child_process";

export function extractDocxText(filePath: string): string {
  let xml: string;
  try {
    xml = execSync(`unzip -p "${filePath}" word/document.xml`, {
      maxBuffer: 20 * 1024 * 1024,
      encoding: "utf-8",
    });
  } catch {
    throw new Error(`Failed to extract DOCX: ${filePath}`);
  }

  const lines: string[] = [];
  // Split by paragraph markers
  const paragraphs = xml.split(/<\/w:p>/);

  for (const para of paragraphs) {
    const texts: string[] = [];
    const textRe = /<w:t[^>]*>([^<]*)<\/w:t>/g;
    let match;
    while ((match = textRe.exec(para)) !== null) {
      texts.push(match[1]);
    }
    if (texts.length > 0) {
      lines.push(texts.join(""));
    }
  }

  return lines.join("\n").trim();
}
