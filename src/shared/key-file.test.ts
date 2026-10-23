import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, chownSync, constants, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { createKeyFile, HEX64_KEY, readKeyFile, replaceKeyFile, type KeyFormat } from "./key-file.js";

const POSIX = process.platform !== "win32";
const ROOT = typeof process.getuid === "function" && process.getuid() === 0;

describe("key files", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "nexus-keyfile-")); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  const keyPath = () => join(dir, ".integrity-key");
  const hex = () => randomBytes(32).toString("hex");
  /** A private key file with exactly `text` in it. */
  const plant = (text: string, mode = 0o600) => {
    writeFileSync(keyPath(), text, { mode });
    chmodSync(keyPath(), mode); // the umask may have narrowed it
  };

  /** Everything about the directory a read could disturb: names, kinds, bytes, modes, links. */
  function snapshot(): string {
    return JSON.stringify(readdirSync(dir).sort().map((name) => {
      const p = join(dir, name);
      const st = lstatSync(p);
      return {
        name,
        mode: st.mode,
        uid: st.uid,
        link: st.isSymbolicLink() ? readlinkSync(p) : null,
        bytes: st.isFile() ? readFileSync(p, "hex") : null,
      };
    }));
  }

  it("reads a private, well-formed key", () => {
    const text = hex();
    plant(text);
    const read = readKeyFile(keyPath());
    assert.equal(read.state, "ok");
    assert.equal(read.state === "ok" && read.key.toString("hex"), text);
  });

  it("accepts one trailing newline and either hex case, and nothing else around the key", () => {
    const text = hex();
    for (const ok of [`${text}\n`, text.toUpperCase()]) {
      plant(ok);
      assert.equal(readKeyFile(keyPath()).state, "ok", JSON.stringify(ok));
    }
    for (const bad of [`${text}\n\n`, ` ${text}`, `${text} `, `${text}\r\n`, text.slice(1), `${text}0`, "not a key", ""]) {
      plant(bad);
      const read = readKeyFile(keyPath());
      assert.deepEqual(read, { state: "untrusted", why: "is malformed" }, JSON.stringify(bad));
    }
  });

  it("checks content with the caller's format instead of the 64-hex default", () => {
    const text = hex();
    const trimmed: KeyFormat = (t) => (/^[0-9a-f]{64}$/i.test(t.trim()) ? Buffer.from(t.trim(), "hex") : null);
    plant(`  ${text}\r\n`);
    assert.equal(readKeyFile(keyPath()).state, "untrusted");
    const read = readKeyFile(keyPath(), trimmed);
    assert.equal(read.state === "ok" && read.key.toString("hex"), text);
    assert.equal(HEX64_KEY(text)?.toString("hex"), text);
  });

  it("reports a missing key without creating one", () => {
    assert.deepEqual(readKeyFile(keyPath()), { state: "missing" });
    assert.equal(existsSync(keyPath()), false);
    assert.deepEqual(readdirSync(dir), []);
  });

  it("does not trust a group/world-accessible key", { skip: !POSIX }, () => {
    for (const mode of [0o644, 0o640, 0o604, 0o660]) {
      plant(hex(), mode);
      const read = readKeyFile(keyPath());
      assert.equal(read.state, "untrusted", mode.toString(8));
      assert.match(read.state === "untrusted" ? read.why : "", /group\/world-accessible/);
    }
  });

  it("does not trust a key owned by another user", { skip: !POSIX || !ROOT }, () => {
    plant(hex());
    chownSync(keyPath(), 12345, 12345);
    const read = readKeyFile(keyPath());
    assert.deepEqual(read, { state: "untrusted", why: "is owned by another user" });
  });

  it("refuses a symlink at the key path rather than following it", { skip: !POSIX || constants.O_NOFOLLOW === undefined }, () => {
    const target = join(dir, "real-key");
    writeFileSync(target, hex(), { mode: 0o600 });
    chmodSync(target, 0o600);
    symlinkSync(target, keyPath());
    assert.deepEqual(readKeyFile(keyPath()), { state: "untrusted", why: "is a symlink" });
  });

  it("does not trust a key path that is not a regular file", () => {
    mkdirSync(keyPath());
    const read = readKeyFile(keyPath());
    assert.equal(read.state, "untrusted");
    // win32 refuses to open a directory at all; POSIX opens it and fstat says what it is.
    if (POSIX) assert.equal(read.state === "untrusted" && read.why, "is not a regular file");
  });

  it("never creates, replaces, chmods or re-points anything on the read path", () => {
    const states: [string, () => void][] = [
      ["missing", () => {}],
      ["ok", () => plant(hex())],
      ["malformed", () => plant("zz")],
      ["directory", () => mkdirSync(keyPath())],
    ];
    if (POSIX) {
      states.push(["loose", () => plant(hex(), 0o644)]);
      states.push(["symlink", () => {
        writeFileSync(join(dir, "real-key"), hex(), { mode: 0o600 });
        symlinkSync(join(dir, "real-key"), keyPath());
      }]);
      states.push(["dangling symlink", () => symlinkSync(join(dir, "nowhere"), keyPath())]);
    }
    for (const [name, setup] of states) {
      rmSync(dir, { recursive: true, force: true });
      mkdirSync(dir);
      setup();
      const before = snapshot();
      readKeyFile(keyPath());
      readKeyFile(keyPath());
      assert.equal(snapshot(), before, name);
    }
  });

  it("creates a fresh 0600 key exclusively", () => {
    const created = createKeyFile(keyPath());
    assert.equal(created.state, "ok");
    const text = readFileSync(keyPath(), "utf-8");
    assert.match(text, /^[0-9a-f]{64}$/);
    assert.equal(created.state === "ok" && created.key.toString("hex"), text);
    if (POSIX) assert.equal(statSync(keyPath()).mode & 0o777, 0o600);
    const again = readKeyFile(keyPath());
    assert.equal(again.state === "ok" && again.key.toString("hex"), text);
  });

  it("falls back to reading an existing key, never overwriting it", () => {
    const text = hex();
    plant(text);
    const created = createKeyFile(keyPath());
    assert.equal(created.state === "ok" && created.key.toString("hex"), text);
    assert.equal(readFileSync(keyPath(), "utf-8"), text);

    // An existing key that is not trusted is reported, not replaced: the caller decides.
    plant("zz");
    assert.deepEqual(createKeyFile(keyPath()), { state: "untrusted", why: "is malformed" });
    assert.equal(readFileSync(keyPath(), "utf-8"), "zz");
  });

  it("throws when the key cannot be created at all", () => {
    assert.throws(() => createKeyFile(join(dir, "no-such-dir", ".integrity-key")), { code: "ENOENT" });
  });

  it("replaces an untrusted key with a fresh private one, leaving no temp file", { skip: !POSIX }, () => {
    const old = hex();
    plant(old, 0o644);
    const key = replaceKeyFile(keyPath());
    assert.notEqual(key.toString("hex"), old);
    assert.equal(statSync(keyPath()).mode & 0o777, 0o600);
    const read = readKeyFile(keyPath());
    assert.equal(read.state === "ok" && read.key.toString("hex"), key.toString("hex"));
    assert.deepEqual(readdirSync(dir), [".integrity-key"]);
  });

  it("replaces a symlink at the key path itself, never its target", { skip: !POSIX }, () => {
    const target = join(dir, "real-key");
    const original = hex();
    writeFileSync(target, original, { mode: 0o600 });
    symlinkSync(target, keyPath());
    replaceKeyFile(keyPath());
    assert.ok(lstatSync(keyPath()).isFile());
    assert.equal(readFileSync(target, "utf-8"), original);
    assert.equal(readKeyFile(keyPath()).state, "ok");
  });

  it("throws when the key path cannot be replaced, and leaves no temp file", () => {
    mkdirSync(keyPath());
    writeFileSync(join(keyPath(), "inside"), "x"); // a non-empty directory cannot be renamed over
    assert.throws(() => replaceKeyFile(keyPath()));
    assert.deepEqual(readdirSync(dir), [".integrity-key"]);
    assert.ok(statSync(keyPath()).isDirectory());
  });
});
