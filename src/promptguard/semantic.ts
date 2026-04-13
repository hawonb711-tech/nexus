/**
 * Lightweight semantic classifier for prompt injection detection.
 * Uses TF-IDF-like keyword scoring against known attack patterns.
 * Zero dependencies — pure TypeScript.
 */

export type SemanticResult = {
  score: number;           // 0.0 - 1.0, higher = more likely injection
  category: string;        // "role_override" | "instruction_ignore" | "exfiltration" | "delimiter_escape" | "clean"
  confidence: number;      // 0.0 - 1.0
  matchedKeywords: string[];
};

type AttackCategory = "role_override" | "instruction_ignore" | "exfiltration" | "delimiter_escape";

type WeightedKeyword = {
  phrase: string;
  weight: number;
};

/** Keyword weight vectors per attack category. */
const CATEGORY_KEYWORDS: Record<AttackCategory, WeightedKeyword[]> = {
  role_override: [
    { phrase: "you are now", weight: 0.9 },
    { phrase: "act as", weight: 0.7 },
    { phrase: "pretend", weight: 0.6 },
    { phrase: "roleplay", weight: 0.5 },
    { phrase: "persona", weight: 0.5 },
    { phrase: "dan", weight: 0.8 },
    { phrase: "jailbreak", weight: 0.95 },
    { phrase: "unrestricted", weight: 0.7 },
    { phrase: "unfiltered", weight: 0.7 },
    { phrase: "developer mode", weight: 0.9 },
    { phrase: "from now on you are", weight: 0.95 },
    { phrase: "your new role", weight: 0.85 },
    { phrase: "switch to", weight: 0.4 },
    { phrase: "new mode", weight: 0.5 },
    { phrase: "uncensored", weight: 0.75 },
    { phrase: "do anything now", weight: 0.9 },
    { phrase: "bypass safety", weight: 0.85 },
    { phrase: "bypass filters", weight: 0.85 },
    { phrase: "no restrictions", weight: 0.7 },
    { phrase: "without restrictions", weight: 0.7 },
    { phrase: "pretend to be", weight: 0.75 },
    { phrase: "simulate being", weight: 0.65 },
    { phrase: "behave as", weight: 0.6 },
  ],

  instruction_ignore: [
    { phrase: "ignore", weight: 0.5 },
    { phrase: "disregard", weight: 0.7 },
    { phrase: "forget", weight: 0.5 },
    { phrase: "override", weight: 0.6 },
    { phrase: "previous instructions", weight: 0.9 },
    { phrase: "above instructions", weight: 0.9 },
    { phrase: "new instructions", weight: 0.85 },
    { phrase: "updated instructions", weight: 0.85 },
    { phrase: "ignore all previous", weight: 0.95 },
    { phrase: "ignore above", weight: 0.85 },
    { phrase: "disregard previous", weight: 0.9 },
    { phrase: "forget everything", weight: 0.85 },
    { phrase: "forget all previous", weight: 0.9 },
    { phrase: "ignore prior", weight: 0.85 },
    { phrase: "ignore your instructions", weight: 0.9 },
    { phrase: "do not follow", weight: 0.6 },
    { phrase: "stop following", weight: 0.65 },
    { phrase: "revised instructions", weight: 0.8 },
    { phrase: "replace your instructions", weight: 0.9 },
    { phrase: "new rules", weight: 0.6 },
    { phrase: "updated rules", weight: 0.6 },
    { phrase: "system override", weight: 0.85 },
    { phrase: "admin override", weight: 0.85 },
  ],

  exfiltration: [
    { phrase: "system prompt", weight: 0.85 },
    { phrase: "show me", weight: 0.3 },
    { phrase: "reveal", weight: 0.5 },
    { phrase: "print", weight: 0.25 },
    { phrase: "output", weight: 0.2 },
    { phrase: "repeat", weight: 0.3 },
    { phrase: "initial prompt", weight: 0.85 },
    { phrase: "hidden instructions", weight: 0.9 },
    { phrase: "internal", weight: 0.2 },
    { phrase: "show me your prompt", weight: 0.95 },
    { phrase: "reveal your instructions", weight: 0.95 },
    { phrase: "print your system", weight: 0.9 },
    { phrase: "what are your instructions", weight: 0.85 },
    { phrase: "display your rules", weight: 0.85 },
    { phrase: "repeat your system prompt", weight: 0.95 },
    { phrase: "dump your prompt", weight: 0.9 },
    { phrase: "output your instructions", weight: 0.9 },
    { phrase: "tell me your prompt", weight: 0.9 },
    { phrase: "leak", weight: 0.5 },
    { phrase: "extract", weight: 0.4 },
    { phrase: "exfiltrate", weight: 0.8 },
    { phrase: "conversation history", weight: 0.5 },
    { phrase: "internal state", weight: 0.6 },
    { phrase: "hidden context", weight: 0.7 },
  ],

  delimiter_escape: [
    { phrase: "</system>", weight: 0.95 },
    { phrase: "</user>", weight: 0.9 },
    { phrase: "```system", weight: 0.9 },
    { phrase: "---system", weight: 0.85 },
    { phrase: "begin system", weight: 0.8 },
    { phrase: "</assistant>", weight: 0.9 },
    { phrase: "</human>", weight: 0.85 },
    { phrase: "```tool_result", weight: 0.9 },
    { phrase: "</tool_result>", weight: 0.95 },
    { phrase: "</function_response>", weight: 0.95 },
    { phrase: "end of user", weight: 0.7 },
    { phrase: "end of system", weight: 0.7 },
    { phrase: "begin admin", weight: 0.8 },
    { phrase: "</message>", weight: 0.7 },
    { phrase: "</prompt>", weight: 0.8 },
    { phrase: "</instruction>", weight: 0.8 },
    { phrase: "```assistant", weight: 0.85 },
    { phrase: "```hidden", weight: 0.85 },
    { phrase: "[system]", weight: 0.7 },
    { phrase: "[admin]", weight: 0.65 },
  ],
};

const ALL_CATEGORIES = Object.keys(CATEGORY_KEYWORDS) as AttackCategory[];

/**
 * Tokenize input: split on whitespace and punctuation, lowercase.
 * Preserves meaningful punctuation tokens like XML-like tags.
 */
function tokenize(input: string): string[] {
  return input
    .toLowerCase()
    .split(/(\s+|(?<=[a-z0-9])(?=[^a-z0-9\s])|(?<=[^a-z0-9\s])(?=[a-z0-9]))/)
    .flatMap((segment) => segment.split(/\s+/))
    .filter((token) => token.length > 0);
}

/**
 * Build all bigrams from a token array (consecutive pairs joined by space).
 */
function buildBigrams(tokens: string[]): string[] {
  const bigrams: string[] = [];
  for (let i = 0; i < tokens.length - 1; i++) {
    bigrams.push(`${tokens[i]} ${tokens[i + 1]}`);
  }
  return bigrams;
}

/**
 * Build all trigrams from a token array.
 */
function buildTrigrams(tokens: string[]): string[] {
  const trigrams: string[] = [];
  for (let i = 0; i < tokens.length - 2; i++) {
    trigrams.push(`${tokens[i]} ${tokens[i + 1]} ${tokens[i + 2]}`);
  }
  return trigrams;
}

/**
 * Score a category against the input using keyword matching.
 */
function scoreCategory(
  lowered: string,
  tokens: string[],
  bigrams: string[],
  trigrams: string[],
  keywords: WeightedKeyword[],
): { score: number; matched: string[] } {
  const matched: string[] = [];
  let totalWeight = 0;
  let maxPossibleWeight = 0;

  for (const kw of keywords) {
    maxPossibleWeight += kw.weight;
    const phraseTokens = kw.phrase.split(/\s+/);

    let found = false;

    if (phraseTokens.length === 1) {
      // Single token: check exact token match OR substring match for tags
      if (tokens.includes(kw.phrase) || lowered.includes(kw.phrase)) {
        found = true;
      }
    } else if (phraseTokens.length === 2) {
      // Bigram match
      const bigramPhrase = phraseTokens.join(" ");
      if (bigrams.includes(bigramPhrase) || lowered.includes(kw.phrase)) {
        found = true;
      }
    } else {
      // Trigram or longer: check as substring in lowered input
      if (lowered.includes(kw.phrase)) {
        found = true;
      }
      // Also try trigram match for 3-word phrases
      if (!found && phraseTokens.length === 3) {
        const trigramPhrase = phraseTokens.join(" ");
        if (trigrams.includes(trigramPhrase)) {
          found = true;
        }
      }
    }

    if (found) {
      matched.push(kw.phrase);
      totalWeight += kw.weight;
    }
  }

  // Compute raw score: weighted matches normalized
  const weightScore = maxPossibleWeight > 0 ? totalWeight / maxPossibleWeight : 0;

  // Keyword density: how many matched keywords relative to input length
  const density = tokens.length > 0 ? matched.length / tokens.length : 0;

  // Combined score: heavily weight the keyword match quality,
  // boost with density (capped contribution).
  //
  // Short inputs (few tokens) inflate density when even a single low-weight
  // keyword matches (e.g., "ignore 처리" → density 0.5, score > 0.3).
  // To prevent false positives on short Korean/multilingual text that uses
  // English technical terms (ignore, override, print, output, etc.),
  // dampen the density contribution when there are few matched keywords
  // and the total keyword weight is low.
  const dampedDensity =
    matched.length <= 1 && totalWeight < 0.6
      ? density * 0.3   // single low-weight keyword: heavily dampen density
      : Math.min(density, 0.5);

  const combinedScore = Math.min(
    1.0,
    weightScore * 0.7 + dampedDensity * 0.6,
  );

  return { score: combinedScore, matched };
}

/**
 * Classify the intent of an input string for prompt injection detection.
 *
 * Uses TF-IDF-like keyword scoring against known attack pattern categories.
 * No ML models or external APIs required.
 */
export function classifyIntent(input: string): SemanticResult {
  if (!input || input.trim().length === 0) {
    return {
      score: 0,
      category: "clean",
      confidence: 1.0,
      matchedKeywords: [],
    };
  }

  const lowered = input.toLowerCase();
  const tokens = tokenize(input);
  const bigrams = buildBigrams(tokens);
  const trigrams = buildTrigrams(tokens);

  let bestCategory: string = "clean";
  let bestScore = 0;
  let bestMatched: string[] = [];

  for (const category of ALL_CATEGORIES) {
    const { score, matched } = scoreCategory(
      lowered,
      tokens,
      bigrams,
      trigrams,
      CATEGORY_KEYWORDS[category],
    );

    if (score > bestScore) {
      bestScore = score;
      bestCategory = category;
      bestMatched = matched;
    }
  }

  // Confidence: high when score is clearly above or below thresholds,
  // lower in the ambiguous middle zone (0.2 - 0.5)
  let confidence: number;
  if (bestScore < 0.1) {
    confidence = 0.95;
  } else if (bestScore < 0.2) {
    confidence = 0.7;
  } else if (bestScore < 0.4) {
    confidence = 0.5 + bestScore;
  } else if (bestScore < 0.6) {
    confidence = 0.6 + bestScore * 0.3;
  } else {
    confidence = 0.75 + bestScore * 0.25;
  }
  confidence = Math.min(1.0, confidence);

  // If score below threshold, classify as clean.
  // Threshold 0.45: raised from 0.3 to reduce false positives on short
  // multilingual text that mixes English technical terms (e.g., Korean
  // developer questions using words like "ignore", "print", "override").
  if (bestScore < 0.45) {
    return {
      score: bestScore,
      category: "clean",
      confidence,
      matchedKeywords: bestMatched,
    };
  }

  return {
    score: bestScore,
    category: bestCategory,
    confidence,
    matchedKeywords: bestMatched,
  };
}
