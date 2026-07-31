import { existsSync } from "node:fs";
import { extname, basename } from "node:path";
import { chunkText } from "./chunker.js";
import { extractPdfText, isPdfSupported } from "./pdf.js";
import { extractDocxText } from "./docx.js";
import { extractPlainText } from "./text.js";
import { convertWithMarkItDown, isMarkItDownSupported, isMarkItDownFormat } from "./markitdown.js";
import { sanitizeExternalContent } from "../guard/sanitize.js";
import type { NexusMemory } from "../memory-engine/nexus-memory.js";
import type { ParsedDocument, ParseOptions, DocumentFormat } from "./types.js";

export function detectFormat(filePath: string): DocumentFormat | null {
  const ext = extname(filePath).toLowerCase();
  switch (ext) {
    case ".pdf": return "pdf";
    case ".docx": case ".doc": return "docx";
    case ".md": case ".markdown": return "markdown";
    case ".txt": case ".text": case ".log": case ".csv": return "txt";
    default:
      // MarkItDown handles PPTX, XLSX, HTML, images, audio, etc.
      if (isMarkItDownFormat(ext)) return "txt";
      return null;
  }
}

/** Check if a file should use MarkItDown instead of built-in parsers. */
function shouldUseMarkItDown(filePath: string): boolean {
  const ext = extname(filePath).toLowerCase();
  return isMarkItDownFormat(ext);
}

export function parseDocument(
  filePath: string,
  memory: NexusMemory,
  options?: ParseOptions,
): ParsedDocument {
  if (!existsSync(filePath)) throw new Error(`File not found: ${filePath}`);

  const ext = extname(filePath).toLowerCase();
  const useMarkItDown = shouldUseMarkItDown(filePath);
  const format = options?.format ?? detectFormat(filePath);
  if (!format && !useMarkItDown) throw new Error(`Unsupported format: ${ext}`);

  let text: string;
  let pageCount: number | undefined;

  if (useMarkItDown) {
    // PPTX, XLSX, HTML, images, audio, etc. → MarkItDown
    if (!isMarkItDownSupported()) throw new Error("Install markitdown for this format: pip install markitdown");
    text = convertWithMarkItDown(filePath);
  } else {
    switch (format) {
      case "pdf": {
        // Try pymupdf first, fall back to markitdown
        if (isPdfSupported()) {
          const result = extractPdfText(filePath);
          text = result.text;
          pageCount = result.pageCount;
        } else if (isMarkItDownSupported()) {
          text = convertWithMarkItDown(filePath);
        } else {
          throw new Error("PDF requires python3 + pymupdf or markitdown");
        }
        break;
      }
      case "docx":
        try {
          text = extractDocxText(filePath);
        } catch {
          // Fall back to markitdown if unzip fails
          if (isMarkItDownSupported()) {
            text = convertWithMarkItDown(filePath);
          } else {
            throw new Error(`Failed to parse DOCX: ${filePath}`);
          }
        }
        break;
      case "markdown":
      case "txt":
        text = extractPlainText(filePath, format === "markdown");
        break;
      default:
        if (isMarkItDownSupported()) {
          text = convertWithMarkItDown(filePath);
        } else {
          throw new Error(`Unsupported format: ${ext}`);
        }
        break;
    }
  }

  // Truncate if needed
  const maxChars = options?.maxChars ?? 500_000;
  if (text.length > maxChars) text = text.slice(0, maxChars);

  // Documents are an external trust boundary. Never let embedded agent
  // instructions or raw credentials flow straight into durable memory.
  const sanitized = sanitizeExternalContent(text);
  text = sanitized.displayText;
  const chunks = sanitized.persistText === null
    ? []
    : chunkText(sanitized.persistText, options?.chunkSize, options?.chunkOverlap);
  const domain = options?.domain ?? basename(filePath, extname(filePath)).replace(/[^a-z0-9-]/gi, "-").slice(0, 30);
  const title = text.split("\n")[0]?.trim().slice(0, 100) ?? basename(filePath);

  let totalAdded = 0;
  for (const chunk of chunks) {
    totalAdded += memory.ingest(chunk.text, domain, undefined, options?.tags ?? []);
  }
  if (totalAdded > 0) memory.save();

  return {
    filePath,
    format: format ?? "txt",
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
