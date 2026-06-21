/**
 * The promotion gate: does the learned embedding model actually recover the
 * relationships the hand-written synonym graph encodes — and does it do so for
 * the Korean / long-tail terms, which is exactly where pure-TS SGNS is weakest
 * and where the decision to (eventually) add a real multilingual encoder will be
 * made? Reported separately so a flip-to-default is made on a number, not a hope.
 */

import type { EmbeddingModel } from "./embedding-model.js";

const HANGUL = /[가-힣]/;

export type RecallReport = {
  k: number;
  /** Overall recall@k across all in-vocab synonym pairs. */
  recall: number;
  pairsEvaluated: number;
  /** Korean-term subset (a group member containing Hangul). */
  koRecall: number;
  koPairsEvaluated: number;
  /** English/other subset. */
  enRecall: number;
  enPairsEvaluated: number;
  /** Fraction of hand-graph terms that exist in the learned vocab at all. */
  vocabCoverage: number;
  termsTotal: number;
  termsInVocab: number;
};

/**
 * For every hand-authored synonym group, treat each in-vocab member as a query
 * and check how many of its in-vocab group-mates land in the model's top-k
 * neighbours. Recall = hits / possible. A term-mate that is out-of-vocab cannot
 * be recalled and is excluded from the denominator (coverage is reported
 * separately so the two effects are not conflated).
 */
export function evalSynonymRecall(
  model: EmbeddingModel,
  groups: string[][],
  k = 10,
): RecallReport {
  let hits = 0, pairs = 0;
  let koHits = 0, koPairs = 0;
  let enHits = 0, enPairs = 0;

  const allTerms = new Set<string>();
  for (const g of groups) for (const w of g) allTerms.add(w.toLowerCase());
  let inVocab = 0;
  for (const t of allTerms) if (model.has(t)) inVocab++;

  for (const group of groups) {
    const members = group.map((w) => w.toLowerCase()).filter((w) => model.has(w));
    if (members.length < 2) continue;
    const memberSet = new Set(members);

    for (const w of members) {
      const neighbours = new Set(model.mostSimilar(w, k).map((n) => n.word));
      const isKo = HANGUL.test(w);
      for (const mate of members) {
        if (mate === w) continue;
        pairs++;
        if (isKo) koPairs++; else enPairs++;
        if (neighbours.has(mate)) {
          hits++;
          if (isKo) koHits++; else enHits++;
        }
      }
    }
  }

  const safe = (a: number, b: number) => (b === 0 ? 0 : Math.round((a / b) * 1000) / 1000);
  return {
    k,
    recall: safe(hits, pairs),
    pairsEvaluated: pairs,
    koRecall: safe(koHits, koPairs),
    koPairsEvaluated: koPairs,
    enRecall: safe(enHits, enPairs),
    enPairsEvaluated: enPairs,
    vocabCoverage: safe(inVocab, allTerms.size),
    termsTotal: allTerms.size,
    termsInVocab: inVocab,
  };
}
