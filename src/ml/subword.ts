/**
 * Subword features for fastText-style embeddings.
 *
 * Korean is the weak spot of plain word2vec here: inflected/rare forms
 * (후킹, 후킹을, 후킹하면) are distinct tokens, most below the frequency floor, so
 * they get no vector. The fix is to represent every word as the sum of its
 * character n-grams — and for Hangul, to first DECOMPOSE each syllable into its
 * jamo so morphologically related words actually share substrings
 * (후 → ㅎㅜ, 킹 → ㅋㅣㅇ). A rare or even unseen Korean word then still gets a
 * composed vector from subwords it shares with common words.
 *
 * Tokenisation is untouched — subwords are an internal representation only — so
 * the embedding vocabulary stays aligned with the search vocabulary.
 */

const S_BASE = 0xac00;
const S_LAST = 0xd7a3;
const L_COUNT = 19, V_COUNT = 21, T_COUNT = 28;
const N_COUNT = V_COUNT * T_COUNT; // 588

const CHO = "ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ";
const JUNG = "ㅏㅐㅑㅒㅓㅔㅕㅖㅗㅘㅙㅚㅛㅜㅝㅞㅟㅠㅡㅢㅣ";
const JONG = ["", "ㄱ", "ㄲ", "ㄳ", "ㄴ", "ㄵ", "ㄶ", "ㄷ", "ㄹ", "ㄺ", "ㄻ", "ㄼ", "ㄽ", "ㄾ", "ㄿ", "ㅀ", "ㅁ", "ㅂ", "ㅄ", "ㅅ", "ㅆ", "ㅇ", "ㅈ", "ㅊ", "ㅋ", "ㅌ", "ㅍ", "ㅎ"];

/** Decompose Hangul syllables to jamo; pass everything else through unchanged. */
export function decomposeHangul(text: string): string {
  let out = "";
  for (const ch of text) {
    const code = ch.codePointAt(0)!;
    if (code >= S_BASE && code <= S_LAST) {
      const idx = code - S_BASE;
      const l = Math.floor(idx / N_COUNT);
      const v = Math.floor((idx % N_COUNT) / T_COUNT);
      const t = idx % T_COUNT;
      out += CHO[l] + JUNG[v] + JONG[t];
    } else {
      out += ch;
    }
  }
  return out;
}

/**
 * The subword set for a token: character n-grams (minN..maxN) over the
 * jamo-decomposed, boundary-marked word, plus the whole word as a distinguished
 * feature. Returns deduped feature strings.
 */
export function wordSubwords(word: string, minN = 3, maxN = 5): string[] {
  const s = "<" + decomposeHangul(word) + ">";
  const set = new Set<string>();
  const len = s.length;
  for (let n = minN; n <= maxN; n++) {
    for (let i = 0; i + n <= len; i++) set.add(s.slice(i, i + n));
  }
  set.add("<" + word + ">"); // whole-word feature (original surface form)
  return [...set];
}

/**
 * Derive a subword vector layer from already-trained word vectors: each subword
 * vector is the centroid of the (semantic) vectors of in-vocab words that
 * contain it. This adds coverage for rare / unseen words — their composed vector
 * is the average of the centroids of the substrings they share with known
 * words — WITHOUT perturbing the trained word vectors. Subwords occurring in
 * fewer than `subwordMinCount` words are dropped.
 */
export function buildSubwordCentroids(
  vocab: string[],
  vectors: Float32Array,
  dim: number,
  minN: number,
  maxN: number,
  subwordMinCount: number,
): { subwordVocab: string[]; subwordVectors: Float32Array; subwordCounts: number[] } {
  const sum = new Map<string, Float64Array>();
  const cnt = new Map<string, number>();
  for (let i = 0; i < vocab.length; i++) {
    const off = i * dim;
    for (const sg of wordSubwords(vocab[i], minN, maxN)) {
      let acc = sum.get(sg);
      if (!acc) { acc = new Float64Array(dim); sum.set(sg, acc); }
      for (let k = 0; k < dim; k++) acc[k] += vectors[off + k];
      cnt.set(sg, (cnt.get(sg) ?? 0) + 1);
    }
  }
  const subwordVocab: string[] = [];
  const subwordCounts: number[] = [];
  for (const [sg, c] of cnt) if (c >= subwordMinCount) { subwordVocab.push(sg); subwordCounts.push(c); }
  const subwordVectors = new Float32Array(subwordVocab.length * dim);
  for (let s = 0; s < subwordVocab.length; s++) {
    const acc = sum.get(subwordVocab[s])!;
    const off = s * dim;
    for (let k = 0; k < dim; k++) subwordVectors[off + k] = acc[k] / subwordCounts[s];
  }
  // subwordCounts[s] = how many in-vocab words back this subword: low = specific
  // (informative), high = generic (near the global mean → noise when composing).
  return { subwordVocab, subwordVectors, subwordCounts };
}
