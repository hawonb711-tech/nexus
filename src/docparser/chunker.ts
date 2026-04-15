import type { DocumentChunk } from "./types.js";

const SECTION_BREAK = /^(?:#{1,6}\s|[A-Z][A-Z\s]{5,}$|\d+\.\s+[A-Z]|={3,}$|-{3,}$)/m;

export function chunkText(
  text: string,
  chunkSize = 1000,
  chunkOverlap = 200,
): DocumentChunk[] {
  if (!text.trim()) return [];

  // Split into paragraphs
  const paragraphs = text.split(/\n{2,}/);
  const chunks: DocumentChunk[] = [];

  let current = "";
  let currentStart = 0;
  let offset = 0;

  for (const para of paragraphs) {
    const trimmed = para.trim();
    if (!trimmed) {
      offset += para.length + 2; // +2 for \n\n
      continue;
    }

    const isNewSection = SECTION_BREAK.test(trimmed);

    // If adding this paragraph exceeds chunk size, or new section starts, flush
    if (current && (current.length + trimmed.length > chunkSize || isNewSection)) {
      chunks.push({
        index: chunks.length,
        text: current.trim(),
        startOffset: currentStart,
      });

      // Start new chunk with overlap
      if (chunkOverlap > 0 && current.length > chunkOverlap) {
        const overlapText = current.slice(-chunkOverlap);
        current = overlapText + "\n\n" + trimmed;
        currentStart = offset - chunkOverlap;
      } else {
        current = trimmed;
        currentStart = offset;
      }
    } else {
      if (!current) currentStart = offset;
      current = current ? current + "\n\n" + trimmed : trimmed;
    }

    offset += para.length + 2;
  }

  // Flush remaining
  if (current.trim()) {
    chunks.push({
      index: chunks.length,
      text: current.trim(),
      startOffset: currentStart,
    });
  }

  return chunks;
}
