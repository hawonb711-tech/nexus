export type DocumentFormat = "pdf" | "docx" | "txt" | "markdown";

export type ParseOptions = {
  format?: DocumentFormat;
  domain?: string;
  tags?: string[];
  maxChars?: number;
  chunkSize?: number;
  chunkOverlap?: number;
};

export type DocumentChunk = {
  index: number;
  text: string;
  pages?: number[];
  startOffset: number;
};

export type ParsedDocument = {
  filePath: string;
  format: DocumentFormat;
  title: string;
  text: string;
  chunks: DocumentChunk[];
  observationsAdded: number;
  pageCount?: number;
  parsedAt: string;
};
