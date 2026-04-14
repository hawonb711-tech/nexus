/**
 * Zero-Dependency Semantic Similarity Engine
 *
 * Captures meaning without embeddings or external APIs.
 *
 * Three mechanisms:
 *
 * 1. SYNONYM GRAPH
 *    Hard-coded domain knowledge mapping related concepts.
 *    "deploy" ↔ "release" ↔ "publish" ↔ "배포" ↔ "ship"
 *    Bilingual: English ↔ Korean for dev terminology.
 *
 * 2. CO-OCCURRENCE PMI (Pointwise Mutual Information)
 *    Learns from the corpus itself: words that appear together
 *    more than expected by chance are semantically related.
 *    "authentication" frequently near "password" → related.
 *    No training, no model — pure statistics.
 *
 * 3. QUERY EXPANSION
 *    Expands search query with synonyms + co-occurrence neighbors.
 *    "deploy" → ["deploy", "release", "publish", "배포", "ship"]
 *    Then runs BM25 on expanded query → semantic matches found.
 */

// ═══════════════════════════════════════════════════════════════════
// SYNONYM GRAPH — Domain knowledge for dev/security concepts
// ═══════════════════════════════════════════════════════════════════

/** Each group = mutually synonymous concepts. */
const SYNONYM_GROUPS: string[][] = [
  // Actions
  ["deploy", "release", "publish", "ship", "배포", "출시", "docker", "container", "컨테이너", "도커"],
  ["install", "setup", "설치", "설정", "configure", "config"],
  ["fix", "repair", "patch", "고치", "수정", "resolve"],
  ["create", "build", "make", "만들", "생성", "구현", "implement"],
  ["delete", "remove", "drop", "삭제", "제거"],
  ["update", "upgrade", "업데이트", "업그레이드", "갱신"],
  ["test", "verify", "validate", "테스트", "검증", "확인"],
  ["debug", "troubleshoot", "디버그", "디버깅"],
  ["refactor", "restructure", "리팩토", "리팩토링", "정리"],
  ["optimize", "improve", "최적화", "개선", "성능향상"],
  ["analyze", "inspect", "examine", "분석", "조사", "검사"],
  ["review", "audit", "리뷰", "검토", "감사"],
  ["search", "find", "lookup", "query", "검색", "찾기", "조회"],
  ["commit", "push", "submit", "커밋", "푸시", "제출"],
  ["merge", "combine", "병합", "합치"],
  ["migrate", "transfer", "port", "마이그레이션", "이전"],

  // Errors & Issues
  ["error", "bug", "issue", "defect", "fault", "에러", "버그", "오류", "결함"],
  ["crash", "fail", "failure", "down", "크래시", "실패", "다운"],
  ["vulnerability", "exploit", "weakness", "flaw", "취약점", "취약성", "약점"],
  ["warning", "caution", "alert", "경고", "주의"],
  ["exception", "throw", "예외"],

  // Security
  ["security", "safety", "보안", "안전"],
  ["injection", "인젝션", "주입"],
  ["authentication", "auth", "login", "signin", "인증", "로그인"],
  ["authorization", "permission", "access", "권한", "인가", "접근"],
  ["encryption", "encrypt", "cipher", "암호화"],
  ["decryption", "decrypt", "복호화"],
  ["token", "jwt", "session", "cookie", "토큰", "세션", "쿠키"],
  ["hash", "digest", "checksum", "해시"],
  ["firewall", "waf", "방화벽"],
  ["sandbox", "isolation", "격리", "샌드박스"],
  ["password", "credential", "secret", "secrets", "비밀번호", "자격증명", "시크릿"],

  // Infrastructure
  ["server", "backend", "서버", "백엔드"],
  ["client", "frontend", "클라이언트", "프론트엔드"],
  ["database", "db", "store", "데이터베이스"],
  ["api", "endpoint", "route", "엔드포인트", "라우트"],
  ["container", "docker", "컨테이너", "도커", "kubernetes", "k8s", "쿠버네티스", "pod"],
  ["cloud", "aws", "gcp", "azure", "클라우드"],
  ["cache", "redis", "memcache", "캐시"],
  ["queue", "mq", "kafka", "rabbitmq", "큐"],
  ["proxy", "nginx", "loadbalancer", "프록시", "로드밸런서"],
  ["websocket", "실시간", "realtime", "real-time", "socket", "소켓", "양방향", "bidirectional"],
  ["통신", "communication", "네트워크", "network", "연결", "connection"],

  // Code Concepts
  ["function", "method", "handler", "callback", "함수", "메서드"],
  ["variable", "var", "const", "let", "변수"],
  ["class", "object", "instance", "클래스", "객체", "인스턴스"],
  ["module", "package", "library", "모듈", "패키지", "라이브러리"],
  ["interface", "type", "schema", "인터페이스", "타입", "스키마"],
  ["import", "require", "dependency", "의존성"],
  ["export", "expose", "publish", "내보내기"],
  ["async", "await", "promise", "비동기"],
  ["loop", "iterate", "forEach", "map", "반복"],
  ["condition", "if", "switch", "branch", "조건", "분기"],
  ["array", "list", "collection", "배열", "리스트", "컬렉션"],
  ["string", "text", "문자열", "텍스트"],
  ["number", "integer", "float", "숫자", "정수"],
  ["null", "undefined", "nil", "none", "empty"],

  // Tools & Platforms
  ["git", "github", "gitlab", "깃", "깃허브"],
  ["npm", "yarn", "pnpm", "bun"],
  ["typescript", "javascript", "타입스크립트", "자바스크립트"],
  ["python", "파이썬"],
  ["react", "vue", "angular", "svelte", "리액트"],
  ["node", "nodejs", "deno", "노드"],
  ["vscode", "cursor", "neovim", "vim", "에디터"],

  // Testing
  ["unittest", "unit-test", "유닛테스트", "단위테스트"],
  ["integration", "e2e", "통합테스트"],
  ["mock", "stub", "spy", "fake", "모킹"],
  ["assertion", "expect", "assert", "단언"],
  ["coverage", "커버리지"],

  // AI/LLM
  ["prompt", "프롬프트"],
  ["model", "llm", "모델"],
  ["agent", "에이전트"],
  ["embedding", "vector", "임베딩", "벡터"],
  ["context", "window", "컨텍스트", "윈도우"],
  ["token", "토큰"],
  ["inference", "추론"],
  ["training", "finetuning", "학습", "파인튜닝"],

  // Additional cross-domain connections
  ["scale", "확장", "scalability", "스케일"],
  ["latency", "지연", "delay", "딜레이", "레이턴시"],
  ["throughput", "처리량", "bandwidth", "대역폭"],
  ["concurrency", "동시성", "parallel", "병렬"],
  ["deadlock", "데드락", "교착상태"],
  ["memory-leak", "메모리누수", "leak"],
  ["garbage-collection", "gc", "가비지컬렉션"],
  ["ci", "continuous-integration", "지속통합"],
  ["cd", "continuous-deployment", "지속배포"],
  ["monitoring", "모니터링", "관제", "observability"],
  ["logging", "로깅", "로그", "log"],
  ["tracing", "추적", "trace"],
  ["backup", "백업", "복구", "recovery", "restore"],
  ["migration", "마이그레이션", "이관", "이전"],
  ["rollback", "롤백", "되돌리기"],
  ["snapshot", "스냅샷"],
  ["webhook", "웹훅", "callback", "콜백"],
  ["pagination", "페이지네이션", "paging"],
  ["rate-limit", "레이트리밋", "throttle", "쓰로틀"],
  ["cors", "교차출처", "cross-origin"],
  ["csrf", "사이트간위조"],
  ["xss", "크로스사이트스크립팅"],
  ["sql-injection", "sql인젝션", "sqli"],
  ["authentication", "인증", "auth", "로그인", "login", "signin"],
  ["authorization", "인가", "권한", "permission", "access-control"],
];

/** Pre-built lookup: word → all synonyms. */
const synonymMap = new Map<string, Set<string>>();

for (const group of SYNONYM_GROUPS) {
  const lowerGroup = group.map((w) => w.toLowerCase());
  for (const word of lowerGroup) {
    if (!synonymMap.has(word)) synonymMap.set(word, new Set());
    for (const synonym of lowerGroup) {
      if (synonym !== word) synonymMap.get(word)!.add(synonym);
    }
  }
}

/** Get synonyms for a word. */
export function getSynonyms(word: string): string[] {
  return [...(synonymMap.get(word.toLowerCase()) ?? [])];
}

// ═══════════════════════════════════════════════════════════════════
// CO-OCCURRENCE PMI — Learns semantic relationships from corpus
// ═══════════════════════════════════════════════════════════════════

export type CoOccurrenceModel = {
  /** Get top-N semantically related words for a given word. */
  getRelated: (word: string, topN?: number) => { word: string; pmi: number }[];
  /** Rebuild from a new corpus. */
  rebuild: (documents: string[]) => void;
  /** Number of unique terms. */
  vocabSize: () => number;
};

import { STOP_WORDS } from "../shared/stop-words.js";

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z가-힣0-9\s-]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 1 && !STOP_WORDS.has(w));
}

export function createCoOccurrenceModel(): CoOccurrenceModel {
  // word → (word → count)
  let coOccur = new Map<string, Map<string, number>>();
  let wordFreq = new Map<string, number>();
  let totalPairs = 0;

  function rebuild(documents: string[]): void {
    coOccur = new Map();
    wordFreq = new Map();
    totalPairs = 0;

    const WINDOW = 5; // Co-occurrence window size

    for (const doc of documents) {
      const tokens = tokenize(doc);

      // Count word frequencies
      for (const t of tokens) {
        wordFreq.set(t, (wordFreq.get(t) ?? 0) + 1);
      }

      // Count co-occurrences within window
      for (let i = 0; i < tokens.length; i++) {
        const word = tokens[i];
        if (!coOccur.has(word)) coOccur.set(word, new Map());

        for (let j = Math.max(0, i - WINDOW); j < Math.min(tokens.length, i + WINDOW + 1); j++) {
          if (i === j) continue;
          const neighbor = tokens[j];
          const map = coOccur.get(word)!;
          map.set(neighbor, (map.get(neighbor) ?? 0) + 1);
          totalPairs++;
        }
      }
    }
  }

  function getRelated(word: string, topN = 10): { word: string; pmi: number }[] {
    const lower = word.toLowerCase();
    const neighbors = coOccur.get(lower);
    if (!neighbors || totalPairs === 0) return [];

    const pWord = (wordFreq.get(lower) ?? 0) / totalPairs;
    if (pWord === 0) return [];

    const results: { word: string; pmi: number }[] = [];

    for (const [neighbor, count] of neighbors) {
      const pNeighbor = (wordFreq.get(neighbor) ?? 0) / totalPairs;
      if (pNeighbor === 0) continue;

      const pJoint = count / totalPairs;
      // PMI = log2(P(x,y) / (P(x) * P(y)))
      const pmi = Math.log2(pJoint / (pWord * pNeighbor));

      // Only keep positive PMI (co-occur more than expected)
      if (pmi > 0) {
        results.push({ word: neighbor, pmi });
      }
    }

    return results
      .sort((a, b) => b.pmi - a.pmi)
      .slice(0, topN);
  }

  return {
    getRelated,
    rebuild,
    vocabSize: () => wordFreq.size,
  };
}

// ═══════════════════════════════════════════════════════════════════
// QUERY EXPANSION — Combines synonyms + co-occurrence
// ═══════════════════════════════════════════════════════════════════

export type ExpandedQuery = {
  /** Original query tokens. */
  original: string[];
  /** Expanded tokens (includes original + synonyms + co-occurrence). */
  expanded: string[];
  /** Which tokens were added and why. */
  expansions: { token: string; source: "synonym" | "cooccurrence"; relatedTo: string }[];
};

/**
 * Expand a query with semantic neighbors.
 *
 * "deploy error" → ["deploy", "release", "publish", "배포",
 *                    "error", "bug", "issue", "에러",
 *                    + co-occurrence neighbors]
 */
export function expandQuery(
  query: string,
  coModel?: CoOccurrenceModel,
  maxCoOccurrencePerToken = 3,
): ExpandedQuery {
  const original = tokenize(query);
  const expanded = [...original];
  const expansions: ExpandedQuery["expansions"] = [];
  const seen = new Set(original);

  for (const token of original) {
    // 1. Add ALL synonyms (curated groups — no cap needed)
    const synonyms = getSynonyms(token);
    for (const syn of synonyms) {
      if (!seen.has(syn)) {
        expanded.push(syn);
        expansions.push({ token: syn, source: "synonym", relatedTo: token });
        seen.add(syn);
      }
    }

    // 2. Add co-occurrence neighbors (capped — can be noisy)
    if (coModel) {
      const related = coModel.getRelated(token, maxCoOccurrencePerToken);
      for (const { word } of related) {
        if (!seen.has(word)) {
          expanded.push(word);
          expansions.push({ token: word, source: "cooccurrence", relatedTo: token });
          seen.add(word);
        }
      }
    }
  }

  return { original, expanded, expansions };
}

// ═══════════════════════════════════════════════════════════════════
// SEMANTIC SIMILARITY SCORE
// ═══════════════════════════════════════════════════════════════════

/**
 * Compute semantic similarity between two texts.
 * Uses synonym overlap + token overlap + optional co-occurrence.
 *
 * Returns 0-1.
 */
export function semanticSimilarity(
  textA: string,
  textB: string,
  coModel?: CoOccurrenceModel,
): number {
  const tokensA = tokenize(textA);
  const tokensB = tokenize(textB);

  if (tokensA.length === 0 || tokensB.length === 0) return 0;

  // 1. Direct token overlap (Jaccard)
  const setA = new Set(tokensA);
  const setB = new Set(tokensB);
  const intersection = [...setA].filter((t) => setB.has(t)).length;
  const union = new Set([...setA, ...setB]).size;
  const directOverlap = union > 0 ? intersection / union : 0;

  // 2. Synonym-expanded overlap
  const expandedA = new Set(tokensA);
  for (const t of tokensA) {
    for (const syn of getSynonyms(t)) expandedA.add(syn);
  }
  const expandedB = new Set(tokensB);
  for (const t of tokensB) {
    for (const syn of getSynonyms(t)) expandedB.add(syn);
  }
  const synIntersection = [...expandedA].filter((t) => expandedB.has(t)).length;
  const synUnion = new Set([...expandedA, ...expandedB]).size;
  const synonymOverlap = synUnion > 0 ? synIntersection / synUnion : 0;

  // 3. Co-occurrence similarity (if model available)
  let coSimilarity = 0;
  if (coModel) {
    let matches = 0;
    let comparisons = 0;
    for (const a of tokensA.slice(0, 10)) {
      const related = new Set(coModel.getRelated(a, 5).map((r) => r.word));
      for (const b of tokensB.slice(0, 10)) {
        comparisons++;
        if (related.has(b)) matches++;
      }
    }
    coSimilarity = comparisons > 0 ? matches / comparisons : 0;
  }

  // Weighted combination
  return directOverlap * 0.3 + synonymOverlap * 0.5 + coSimilarity * 0.2;
}
