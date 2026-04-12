/**
 * Text normalization pipeline that deobfuscates text before scanning.
 * Zero dependencies, pure TypeScript.
 */

export type NormalizeResult = {
  normalized: string;
  transforms: string[];
};

// Zero-width and invisible formatting characters
const ZERO_WIDTH_RE =
  /[\u200B-\u200F\u2060-\u2069\uFEFF\u202A-\u202E]/g;

// Base64 segment: 16+ chars of [A-Za-z0-9+/] optionally ending with = or ==
const BASE64_SEGMENT_RE =
  /(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])/g;

// Hex escapes: \x41
const HEX_ESCAPE_RE = /\\x([0-9A-Fa-f]{2})/g;

// Unicode escapes: \u0041 or \u{41}
const UNICODE_ESCAPE_RE = /\\u\{?([0-9A-Fa-f]{1,6})\}?/g;

// Named HTML entities (common subset)
const NAMED_ENTITIES: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&apos;": "'",
  "&nbsp;": " ",
  "&tab;": "\t",
  "&newline;": "\n",
  "&colon;": ":",
  "&semi;": ";",
  "&lpar;": "(",
  "&rpar;": ")",
  "&lsqb;": "[",
  "&rsqb;": "]",
  "&lcub;": "{",
  "&rcub;": "}",
  "&sol;": "/",
  "&bsol;": "\\",
  "&equals;": "=",
  "&plus;": "+",
  "&minus;": "-",
  "&excl;": "!",
  "&num;": "#",
  "&percnt;": "%",
  "&commat;": "@",
  "&Hat;": "^",
  "&lowbar;": "_",
  "&grave;": "`",
  "&tilde;": "~",
  "&period;": ".",
  "&comma;": ",",
};

// Named entity regex (case-insensitive for robustness)
const NAMED_ENTITY_RE = new RegExp(
  Object.keys(NAMED_ENTITIES)
    .map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("|"),
  "gi",
);

// Numeric HTML entities: &#65; or &#x41;
const NUMERIC_ENTITY_RE = /&#x([0-9A-Fa-f]{1,6});|&#(\d{1,7});/g;

// Cyrillic → Latin homoglyph map
const HOMOGLYPH_MAP: Record<string, string> = {
  "\u0430": "a", // а
  "\u0435": "e", // е
  "\u043E": "o", // о
  "\u0440": "p", // р
  "\u0441": "c", // с
  "\u0443": "y", // у (Cyrillic у looks like Latin y)
  "\u0456": "i", // і (Ukrainian i)
  "\u0458": "j", // ј (Serbian j)
  "\u04BB": "h", // һ
  "\u0455": "s", // ѕ
  "\u0457": "i", // ї → i (close enough)
  "\u0445": "x", // х
  "\u041A": "K", // К
  "\u0410": "A", // А
  "\u0412": "B", // В
  "\u0415": "E", // Е
  "\u041C": "M", // М
  "\u041D": "H", // Н
  "\u041E": "O", // О
  "\u0420": "P", // Р
  "\u0421": "C", // С
  "\u0422": "T", // Т
  "\u0425": "X", // Х
  "\u0417": "3", // З looks like 3
  "\u0427": "4", // Ч looks like 4 (stretch)
};

const HOMOGLYPH_RE = new RegExp(
  `[${Object.keys(HOMOGLYPH_MAP).join("")}]`,
  "g",
);

// Fullwidth ASCII range: U+FF01 (！) to U+FF5E (～) maps to U+0021 (!) to U+007E (~)
const FULLWIDTH_RE = /[\uFF01-\uFF5E]/g;

// Excessive whitespace: 2+ whitespace chars (but preserve single newlines structure)
const EXCESS_WHITESPACE_RE = /[^\S\n]{2,}/g;
const EXCESS_NEWLINES_RE = /\n{3,}/g;

/** Strip zero-width / invisible formatting characters. */
export function stripZeroWidth(input: string): string {
  return input.replace(ZERO_WIDTH_RE, "");
}

/** Detect and decode base64 segments inline. */
export function decodeBase64Segments(input: string): string {
  return input.replace(BASE64_SEGMENT_RE, (match) => {
    try {
      // Validate: must be valid base64 length (multiple of 4 when padded)
      const padded =
        match.length % 4 === 0
          ? match
          : match + "=".repeat(4 - (match.length % 4));
      const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
      // Only replace if the decoded result is printable ASCII/UTF-8
      const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      if (/^[\x20-\x7E\t\n\r]+$/.test(decoded)) {
        return decoded;
      }
      return match;
    } catch {
      return match;
    }
  });
}

/** Decode hex escape sequences (\x41 → A). */
export function decodeHexEscapes(input: string): string {
  return input.replace(HEX_ESCAPE_RE, (_, hex: string) =>
    String.fromCharCode(parseInt(hex, 16)),
  );
}

/** Decode unicode escape sequences (\u0041 → A). */
export function decodeUnicodeEscapes(input: string): string {
  return input.replace(UNICODE_ESCAPE_RE, (_, hex: string) => {
    const cp = parseInt(hex, 16);
    if (cp > 0x10ffff) return _;
    return String.fromCodePoint(cp);
  });
}

/** Decode HTML entities (named, decimal, and hex). */
export function decodeHtmlEntities(input: string): string {
  let result = input.replace(
    NAMED_ENTITY_RE,
    (m) => NAMED_ENTITIES[m.toLowerCase()] ?? m,
  );
  result = result.replace(NUMERIC_ENTITY_RE, (_, hex: string, dec: string) => {
    const cp = hex ? parseInt(hex, 16) : parseInt(dec, 10);
    if (cp > 0x10ffff || cp === 0) return _;
    return String.fromCodePoint(cp);
  });
  return result;
}

/** Map Cyrillic lookalike characters to their Latin equivalents. */
export function normalizeHomoglyphs(input: string): string {
  return input.replace(HOMOGLYPH_RE, (ch) => HOMOGLYPH_MAP[ch] ?? ch);
}

/** Convert fullwidth characters to standard ASCII. */
export function normalizeFullwidth(input: string): string {
  return input.replace(FULLWIDTH_RE, (ch) =>
    String.fromCharCode(ch.charCodeAt(0) - 0xfee0),
  );
}

/** Collapse excessive whitespace into single spaces/newlines. */
export function collapseWhitespace(input: string): string {
  return input.replace(EXCESS_WHITESPACE_RE, " ").replace(EXCESS_NEWLINES_RE, "\n\n");
}

// Leetspeak character map
const LEET_MAP: Record<string, string> = {
  "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
  "7": "t", "8": "b", "9": "g", "@": "a", "$": "s",
  "|": "l", "!": "i",
};

/**
 * Normalize leetspeak/number substitutions in text.
 * Only applies when surrounded by letter-like context to avoid
 * converting legitimate numbers.
 */
export function normalizeLeetspeak(input: string): string {
  // Only convert leet chars when they appear in word-like sequences
  // (at least 3 chars with mixed alpha+leet)
  return input.replace(/\b([a-zA-Z0-9@$|!]{3,})\b/g, (word) => {
    const hasAlpha = /[a-zA-Z]/.test(word);
    const hasLeet = /[0-9@$|!]/.test(word);
    if (!hasAlpha || !hasLeet) return word;
    return [...word]
      .map((ch) => LEET_MAP[ch] ?? ch)
      .join("");
  });
}

/**
 * Full normalization pipeline. Applies all transforms in order and
 * tracks which ones actually modified the text.
 */
export function normalizeText(input: string): NormalizeResult {
  const transforms: string[] = [];
  let text = input;

  const steps: Array<[string, (s: string) => string]> = [
    ["strip-zero-width", stripZeroWidth],
    ["decode-base64", decodeBase64Segments],
    ["decode-hex-escapes", decodeHexEscapes],
    ["decode-unicode-escapes", decodeUnicodeEscapes],
    ["decode-html-entities", decodeHtmlEntities],
    ["normalize-homoglyphs", normalizeHomoglyphs],
    ["normalize-fullwidth", normalizeFullwidth],
    ["normalize-leetspeak", normalizeLeetspeak],
    ["collapse-whitespace", collapseWhitespace],
  ];

  for (const [name, fn] of steps) {
    const next = fn(text);
    if (next !== text) {
      transforms.push(name);
      text = next;
    }
  }

  return { normalized: text, transforms };
}
