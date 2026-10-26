/**
 * hooks.json's number literals as the user wrote them.
 *
 * Install and uninstall read hooks.json with JSON.parse and write it back with
 * JSON.stringify, which writes a number its own way: `1.0` as `1`, `1e2` as
 * `100`, and an integer beyond 2^53 rounded. Codex hashes an `mcp_tool` hook's
 * input into the trust it keeps for that hook, and tells a float from an
 * integer, so either change would make a hook the user trusted "modified"
 * (Codex then skips it without a word), and a rounded integer is a different
 * value outright. So the literals that would not come back as written are
 * found first (`numberLiterals`, one linear pass over the text), and written
 * back as they were (`stringifyKeeping`).
 */

/**
 * The number literals of a JSON text that JSON.stringify would write some other
 * way, by the object or array that holds each (as JSON.parse made it) and its
 * key there (an index, as a string). A holder is a key here only when it has one.
 */
export type NumberLiterals = Map<object, ReadonlyMap<string, string>>;

/** A JSON number, from its first character (JSON's grammar: no leading zeros, no lone dot). */
const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

/** An object or array being read: where it sits in its parent, and what it holds that matters here. */
type Frame = {
  array: boolean;
  /** Its key (or index) in the parent. */
  at: string;
  /** The key the next value goes under: the last one read, or the next index. */
  slot: string;
  index: number;
  /** In an object: the next string is a key. */
  wantKey: boolean;
  literals: Map<string, string> | null;
  /** Objects and arrays in it that hold such a literal, at any depth. */
  children: Map<string, Frame> | null;
};

/**
 * The literals of `text` that JSON.stringify would not write back as they are
 * (`numberLiterals`'s type), keyed to `doc`, which must be `JSON.parse(text)`.
 * One pass with a stack, so as deep as JSON.parse reads; a key that appears
 * twice counts as JSON.parse counts it, the last time.
 */
export function numberLiterals(text: string, doc: unknown): NumberLiterals {
  const found: NumberLiterals = new Map();
  const stack: Frame[] = [];
  let root: Frame | null = null;
  /** The frame a value starts in: its slot cleared of what an earlier value under the same key left there. */
  const valueIn = (): Frame | undefined => {
    const top = stack.at(-1);
    if (top) {
      top.literals?.delete(top.slot);
      top.children?.delete(top.slot);
    }
    return top;
  };
  for (let i = 0; i < text.length; ) {
    const c = text.charCodeAt(i);
    if (c === 0x22) {
      // a string: to the quote no backslash escapes
      let end = i + 1;
      while (end < text.length && text.charCodeAt(end) !== 0x22) end += text.charCodeAt(end) === 0x5c ? 2 : 1;
      end++;
      const top = stack.at(-1);
      if (top && !top.array && top.wantKey) {
        top.slot = JSON.parse(text.slice(i, end)) as string;
        top.wantKey = false;
      } else valueIn();
      i = end;
    } else if (c === 0x7b || c === 0x5b) {
      const parent = valueIn();
      stack.push({ array: c === 0x5b, at: parent?.slot ?? "", slot: "0", index: 0, wantKey: c === 0x7b, literals: null, children: null });
      i++;
    } else if (c === 0x7d || c === 0x5d) {
      const frame = stack.pop();
      const parent = stack.at(-1);
      if (frame && (frame.literals || frame.children)) {
        if (!parent) root = frame;
        else (parent.children ??= new Map()).set(frame.at, frame);
      }
      i++;
    } else if (c === 0x2c) {
      const top = stack.at(-1);
      if (top?.array) top.slot = String(++top.index);
      else if (top) top.wantKey = true;
      i++;
    } else if (c === 0x2d || (c >= 0x30 && c <= 0x39)) {
      NUMBER.lastIndex = i;
      const literal = NUMBER.exec(text)?.[0] ?? text[i];
      const top = valueIn();
      if (top && JSON.stringify(Number(literal)) !== literal) (top.literals ??= new Map()).set(top.slot, literal);
      i += literal.length;
    } else if (c === 0x74 || c === 0x6e) {
      valueIn(); // true, null
      i += 4;
    } else if (c === 0x66) {
      valueIn(); // false
      i += 5;
    } else i++; // whitespace, a colon, a byte-order mark
  }
  // the frames line up with doc's objects and arrays: each holder found by walking down the same keys
  const work: [Frame, unknown][] = root ? [[root, doc]] : [];
  while (work.length > 0) {
    const [frame, value] = work.pop()!;
    if (value === null || typeof value !== "object") continue;
    if (frame.literals) found.set(value, frame.literals);
    for (const [key, child] of frame.children ?? []) work.push([child, (value as Record<string, unknown>)[key]]);
  }
  return found;
}

/**
 * `value` as `JSON.stringify(value, null, 2)` writes it, but with each number
 * `literals` holds for its place written as it was, while it is still the same
 * number. Without any, JSON.stringify's own text.
 */
export function stringifyKeeping(value: unknown, literals: NumberLiterals): string {
  if (literals.size === 0) return JSON.stringify(value, null, 2);
  const write = (v: unknown, indent: string, literal: string | undefined): string | undefined => {
    if (typeof v === "number") return literal !== undefined && Number(literal) === v ? literal : JSON.stringify(v);
    if (v === null || typeof v !== "object") return JSON.stringify(v);
    const own = literals.get(v);
    const inner = `${indent}  `;
    if (Array.isArray(v)) {
      const items = v.map((x, i) => `${inner}${write(x, inner, own?.get(String(i))) ?? "null"}`);
      return items.length === 0 ? "[]" : `[\n${items.join(",\n")}\n${indent}]`;
    }
    const items: string[] = [];
    for (const [k, x] of Object.entries(v)) {
      const text = write(x, inner, own?.get(k));
      if (text !== undefined) items.push(`${inner}${JSON.stringify(k)}: ${text}`);
    }
    return items.length === 0 ? "{}" : `{\n${items.join(",\n")}\n${indent}}`;
  };
  return write(value, "", undefined) ?? "";
}
