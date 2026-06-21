import { test } from "node:test";
import assert from "node:assert/strict";
import { chunkText } from "./chunker.js";

// Helper: build a single paragraph (no blank lines, no section-break markers)
// of a given character length using lowercase letters/spaces.
function para(label: string, length: number): string {
  // Start with a lowercase letter so SECTION_BREAK (which requires leading
  // markdown markers / ALL-CAPS / numbered headings) never matches.
  let s = label + " ";
  while (s.length < length) s += "word ";
  return s.slice(0, length).trimEnd() || label;
}

test("empty or whitespace-only text yields no chunks", () => {
  assert.deepEqual(chunkText(""), []);
  assert.deepEqual(chunkText("   \n\n  \t  "), []);
});

test("short text yields exactly one chunk with the expected shape", () => {
  const text = "just a small note about something";
  const chunks = chunkText(text);

  assert.equal(chunks.length, 1);
  const c = chunks[0];
  // Shape: index, text, startOffset are always present.
  assert.equal(c.index, 0);
  assert.equal(c.text, text);
  assert.equal(typeof c.startOffset, "number");
  assert.equal(c.startOffset, 0);
  // `pages` is optional and not set by chunkText.
  assert.equal(c.pages, undefined);
});

test("long text splits into multiple chunks with sequential indices", () => {
  // Three paragraphs that together exceed chunkSize=1000.
  // Each ~600 chars: first two fit (600), adding the second (600+600>1000)
  // forces a flush, etc.
  const p1 = para("alpha", 600);
  const p2 = para("beta", 600);
  const p3 = para("gamma", 600);
  const text = `${p1}\n\n${p2}\n\n${p3}`;

  const chunks = chunkText(text);

  assert.ok(chunks.length > 1, "expected more than one chunk");
  // Indices are sequential starting at 0.
  chunks.forEach((c, i) => assert.equal(c.index, i));
  // Every chunk text is trimmed (no leading/trailing whitespace).
  for (const c of chunks) {
    assert.equal(c.text, c.text.trim());
    assert.ok(c.text.length > 0);
  }
});

test("a new section heading forces a chunk boundary even below chunkSize", () => {
  // Two small paragraphs that easily fit within chunkSize, but the second
  // is a markdown heading -> SECTION_BREAK matches -> flush before it.
  const text = "first short paragraph here\n\n# A New Heading";
  const chunks = chunkText(text);

  assert.equal(chunks.length, 2);
  assert.equal(chunks[0].text, "first short paragraph here");
  assert.equal(chunks[1].text, "# A New Heading");
  assert.equal(chunks[0].index, 0);
  assert.equal(chunks[1].index, 1);
});

test("overlap carries the tail of the previous chunk into the next one", () => {
  // Force a size-based flush, then verify the overlap tail is prepended.
  // p1 length 600, p2 length 600 -> 600+600 > 1000 triggers flush on p2.
  // chunkOverlap defaults to 200, and current.length (600) > 200, so the
  // last 200 chars of p1 are prepended to the new chunk.
  const p1 = para("alpha", 600);
  const p2 = para("beta", 600);
  const text = `${p1}\n\n${p2}`;

  const chunks = chunkText(text);
  assert.equal(chunks.length, 2);

  // First chunk is exactly p1 (trimmed).
  assert.equal(chunks[0].text, p1.trim());

  // Second chunk begins with the last 200 chars of p1, then "\n\n", then p2.
  const overlapTail = p1.slice(-200);
  assert.ok(
    chunks[1].text.startsWith(overlapTail.trim()) ||
      chunks[1].text.startsWith(overlapTail),
    "second chunk should start with the overlap tail of the first",
  );
  assert.ok(chunks[1].text.includes(p2.trim()), "second chunk should contain p2");
});

test("overlap is disabled when chunkOverlap is 0", () => {
  const p1 = para("alpha", 600);
  const p2 = para("beta", 600);
  const text = `${p1}\n\n${p2}`;

  const chunks = chunkText(text, 1000, 0);
  assert.equal(chunks.length, 2);

  // With no overlap, the second chunk is exactly p2 (no tail of p1).
  assert.equal(chunks[1].text, p2.trim());
  // startOffset of second chunk equals the byte offset where p2 begins,
  // i.e. length of p1 + 2 (for the "\n\n" separator).
  assert.equal(chunks[1].startOffset, p1.length + 2);
});

test("startOffset of the first chunk is always 0", () => {
  const chunks = chunkText("hello world paragraph one\n\nparagraph two text");
  assert.ok(chunks.length >= 1);
  assert.equal(chunks[0].startOffset, 0);
});
