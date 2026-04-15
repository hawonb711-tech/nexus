const ENTITY_MAP: Record<string, string> = {
  "&amp;": "&", "&lt;": "<", "&gt;": ">",
  "&quot;": '"', "&#39;": "'", "&apos;": "'",
  "&nbsp;": " ",
};

function decodeEntities(text: string): string {
  return text.replace(/&(?:#(\d+)|#x([0-9a-f]+)|(\w+));/gi, (m, dec, hex, name) => {
    if (dec) return String.fromCharCode(parseInt(dec, 10));
    if (hex) return String.fromCharCode(parseInt(hex, 16));
    return ENTITY_MAP[`&${name};`] ?? m;
  });
}

function stripNoise(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<nav[\s\S]*?<\/nav>/gi, "")
    .replace(/<header[\s\S]*?<\/header>/gi, "")
    .replace(/<footer[\s\S]*?<\/footer>/gi, "")
    .replace(/<aside[\s\S]*?<\/aside>/gi, "")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, "");
}

function findMainContent(html: string): string {
  // Try <article> or <main>
  const articleMatch = html.match(/<article[^>]*>([\s\S]*?)<\/article>/i);
  if (articleMatch && articleMatch[1].replace(/<[^>]*>/g, "").trim().length > 200) {
    return articleMatch[1];
  }
  const mainMatch = html.match(/<main[^>]*>([\s\S]*?)<\/main>/i);
  if (mainMatch && mainMatch[1].replace(/<[^>]*>/g, "").trim().length > 200) {
    return mainMatch[1];
  }

  // Score <div>/<section> blocks by text density
  const blockRe = /<(?:div|section)[^>]*>([\s\S]*?)<\/(?:div|section)>/gi;
  let best = "";
  let bestScore = 0;
  let match;
  while ((match = blockRe.exec(html)) !== null) {
    const inner = match[1];
    const textOnly = inner.replace(/<[^>]*>/g, "").trim();
    if (textOnly.length < 200) continue;
    const density = textOnly.length / Math.max(inner.length, 1);
    if (density * textOnly.length > bestScore) {
      bestScore = density * textOnly.length;
      best = inner;
    }
  }
  if (best) return best;

  // Fallback: <body>
  const bodyMatch = html.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  return bodyMatch?.[1] ?? html;
}

function stripTags(html: string): string {
  return html
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<\/div>/gi, "\n")
    .replace(/<\/li>/gi, "\n")
    .replace(/<[^>]*>/g, "")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function extractTitle(html: string): string {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? decodeEntities(match[1].trim()) : "";
}

export function extractText(html: string): string {
  const cleaned = stripNoise(html);
  const content = findMainContent(cleaned);
  const text = stripTags(content);
  return decodeEntities(text);
}
