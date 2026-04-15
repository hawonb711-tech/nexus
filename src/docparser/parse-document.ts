import { existsSync } from "node:fs";
import { extname, basename } from "node:path";
import { chunkText } from "./chunker.js";
import { extractPdfText, isPdfSupported } from "./pdf.js";
import { extractDocxText } from "./docx.js";
import { extractPlainText } from "./text.js";
import type { NexusMemory } from "../memory-engine/nexus-memory.js";
import type { ParsedDocument, ParseOptions, DocumentFormat } from "./types.js";

export function detectFormat(filePath: string): DocumentFormat | null {
  const ext = extname(filePath).toLowerCase();
  switch (ext) {
    case ".pdf": return "pdf";
    case ".docx": case ".doc": return "docx";
    case ".md": case ".markdown": return "markdown";
    case ".txt": case ".text": case ".log": case ".csv": return "txt";
    default: return null;
  }
}

export function parseDocument(
  filePath: string,
  memory: NexusMemory,
  options?: ParseOptions,
): ParsedDocument {
  if (!existsSync(filePath)) throw new Error(`File not found: ${filePath}`);

  const format = options?.format ?? detectFormat(filePath);
  if (!format) throw new Error(`Unsupported format: ${extname(filePath)}`);

  let text: string;
  let pageCount: number | undefined;

  switch (format) {
    case "pdf": {
      if (!isPdfSupported()) throw new Error("PDF requires python3 + pymupdf");
      const result = extractPdfText(filePath);
      text = result.text;
      pageCount = result.pageCount;
      break;
    }
    case "docx":
      text = extractDocxText(filePath);
      break;
    case "markdown":
    case "txt":
      text = extractPlainText(filePath, format === "markdown");
      break;
  }

  // Truncate if needed
  const maxChars = options?.maxChars ?? 500_000;
  if (text.length > maxChars) text = text.slice(0, maxChars);

  const chunks = chunkText(text, options?.chunkSize, options?.chunkOverlap);
  const domain = options?.domain ?? basename(filePath, extname(filePath)).replace(/[^a-z0-9-]/gi, "-").slice(0, 30);
  const title = text.split("\n")[0]?.trim().slice(0, 100) ?? basename(filePath);

  let totalAdded = 0;
  for (const chunk of chunks) {
    totalAdded += memory.ingest(chunk.text, domain);
  }
  if (totalAdded > 0) memory.save();

  return {
    filePath,
    format,
    title,
    text,
    chunks,
    observationsAdded: totalAdded,
    pageCount,
    parsedAt: new Date().toISOString(),
  };
}

export function parseDocuments(
  filePaths: string[],
  memory: NexusMemory,
  options?: ParseOptions,
): ParsedDocument[] {
  return filePaths.map((fp) => {
    try {
      return parseDocument(fp, memory, options);
    } catch {
      return null;
    }
  }).filter((d): d is ParsedDocument => d !== null);
}
