import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

let _supported: boolean | null = null;

export function isPdfSupported(): boolean {
  if (_supported !== null) return _supported;
  try {
    execFileSync("python3", ["-c", "import fitz"], { stdio: "ignore" });
    _supported = true;
  } catch {
    _supported = false;
  }
  return _supported;
}

export function extractPdfText(filePath: string): { text: string; pageCount: number } {
  if (!isPdfSupported()) {
    throw new Error("PDF support requires python3 + pymupdf. Install: pip install pymupdf");
  }

  const script = `
import fitz, sys, json
doc = fitz.open(sys.argv[1])
pages = []
for page in doc:
    pages.append(page.get_text())
print(json.dumps({"text": "\\n\\n".join(pages), "pageCount": len(pages)}))
`.trim();

  const result = execFileSync("python3", ["-c", script, resolve(filePath)], {
    maxBuffer: 50 * 1024 * 1024,
    encoding: "utf-8",
  });

  return JSON.parse(result.trim());
}
