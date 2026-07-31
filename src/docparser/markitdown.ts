import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

let _supported: boolean | null = null;

export function isMarkItDownSupported(): boolean {
  if (_supported !== null) return _supported;
  try {
    execFileSync("markitdown", ["--help"], { stdio: "ignore" });
    _supported = true;
  } catch {
    _supported = false;
  }
  return _supported;
}

/**
 * Convert any file to markdown using Microsoft MarkItDown.
 * Supports: PDF, DOCX, PPTX, XLSX, HTML, images, audio, ZIP, etc.
 */
export function convertWithMarkItDown(filePath: string): string {
  if (!isMarkItDownSupported()) {
    throw new Error("markitdown not installed. Run: pip install markitdown");
  }

  const result = execFileSync("markitdown", [resolve(filePath)], {
    maxBuffer: 50 * 1024 * 1024,
    encoding: "utf-8",
    timeout: 60_000,
  });

  return result.trim();
}

/** Formats that MarkItDown supports beyond our built-in parsers. */
const MARKITDOWN_EXTENSIONS = new Set([
  ".pptx", ".ppt", ".xlsx", ".xls",
  ".html", ".htm", ".xml",
  ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
  ".mp3", ".wav", ".m4a",
  ".zip", ".tar", ".gz",
  ".json", ".yaml", ".yml",
  ".rst", ".org", ".rtf",
  ".epub",
]);

export function isMarkItDownFormat(ext: string): boolean {
  return MARKITDOWN_EXTENSIONS.has(ext.toLowerCase());
}
