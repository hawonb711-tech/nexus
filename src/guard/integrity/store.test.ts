import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync, chownSync, closeSync, constants, copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync,
  readSync, readdirSync, readlinkSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHmac, randomBytes } from "node:crypto";
import { canonicalJson } from "../../shared/sign.js";
import {
  appendLog, collectGarbage, commitStores, emptyRegistry, initIntegrity, integrityPaths, isCurrentVersion, isIntegrityDisabled,
  loadIntegrity, newStoreDoc, readConfig, readLog, readRegistry, readStore, readWatchPrefixes, RegistryTamperError, removeDisabled,
  signerFor, TAMPER_FRAGMENTS, upgradeStore, withStoreLock, writeConfig, writeDisabled, writeWatchPrefixes,
  type IntegrityPaths, type Signer, type UnsignedStoreDoc,
} from "./store.js";
import { LOCK_WAIT_SESSION_START_MS, LOG_KEEP_LINES, LOG_MAX_LINES, type LogEntry, type StoreEntry, type StoreId } from "./types.js";

const POSIX = process.platform !== "win32";
const ROOT = typeof process.getuid === "function" && process.getuid() === 0;
const NOW = new Date("2026-10-23T09:00:00.000Z");
const DAY = 24 * 60 * 60 * 1000;
const DEAD_PID = 99_999_999;
const TSX = pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;
const MODULE_URL = pathToFileURL(fileURLToPath(new URL("./store.ts", import.meta.url))).href;

const PROJECT: StoreId = "project-0123456789abcdef";
const MEMORY: StoreId = "memory-fedcba9876543210";
const IDS = ["global", PROJECT, MEMORY];

/** The MAC an attacker holding `key` could compute — written out independently of store.ts. */
function forgeMac(key: Buffer, label: string, doc: Record<string, unknown>): string {
  const sub = createHmac("sha256", key).update(`nexus/integrity/v1/${label}`).digest();
  const { mac: _ignored, ...rest } = doc;
  return `v1:${createHmac("sha256", sub).update(canonicalJson(rest)).digest("hex")}`;
}

function entry(path: string, over: Partial<StoreEntry> = {}): StoreEntry {
  return {
    path,
    role: "ancestor-claude-md",
    state: "file",
    sha256: "a".repeat(64),
    size: 10,
    stat: [10, 1761200000000.5, 1761200000000.5, 123, 2049],
    link: null,
    units: ["a1b2c3d4e5f60718#1"],
    cat: {},
    tok: [],
    nexusHooks: [],
    history: [],
    acceptedAt: NOW.toISOString(),
    acceptedBy: "first-run",
    held: null,
    ...over,
  };
}

/** Every path under `root` with its kind, mode and bytes: anything a read could disturb. */
function snapshot(root: string): string {
  const out: unknown[] = [];
  const walk = (dir: string) => {
    if (!existsSync(dir)) return;
    for (const name of readdirSync(dir).sort()) {
      const p = join(dir, name);
      const st = lstatSync(p);
      out.push({ p, mode: st.mode, link: st.isSymbolicLink() ? readlinkSync(p) : null, bytes: st.isFile() ? readFileSync(p, "hex") : null });
      if (st.isDirectory()) walk(p);
    }
  };
  walk(root);
  return JSON.stringify(out);
}

/** Every file under `dir`, recursively. */
function filesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (lstatSync(p).isDirectory()) out.push(...filesUnder(p));
    else out.push(p);
  }
  return out;
}

describe("integrity store", () => {
  let base: string;
  let home: string;
  let data: string;
  let paths: IntegrityPaths;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), "nexus-integrity-store-"));
    home = join(base, "home");
    mkdirSync(home);
    data = join(home, ".nexus");
    paths = integrityPaths(data);
  });
  afterEach(() => { rmSync(base, { recursive: true, force: true }); });

  const load = (dataDir = data) => loadIntegrity({ dataDir, homedir: home, platform: process.platform }, IDS);
  const tamperOf = (state = load()) => Object.fromEntries(IDS.map((id) => [id, state.stores[id].tamper]));

  function init(): Signer {
    const result = initIntegrity(paths, NOW);
    assert.equal(result.ok, true);
    return result.ok ? result.signer : (undefined as never);
  }

  function storeDoc(kind: "global" | "project" | "memory", id: StoreId, keys: string[]): UnsignedStoreDoc {
    const doc = newStoreDoc(kind, id, kind === "global" ? null : `/home/u/${id}`, NOW);
    for (const k of keys) doc.entries[k] = entry(k);
    return doc;
  }

  /** init, then one commit of all three stores. */
  function setup(): Signer {
    const signer = init();
    const reg = readRegistry(paths, signer);
    assert.equal(reg.state, "ok");
    commitStores(paths, signer, reg.state === "ok" ? reg.doc : null, {
      write: [
        storeDoc("global", "global", ["/home/u/.claude/CLAUDE.md"]),
        storeDoc("project", PROJECT, ["/home/u/app/CLAUDE.md", "/home/u/app/AGENTS.md"]),
        storeDoc("memory", MEMORY, ["/home/u/.claude/projects/-home-u-app/memory/MEMORY.md"]),
      ],
    }, NOW);
    return signer;
  }

  const flipByte = (file: string, find: string) => {
    const text = readFileSync(file, "utf-8");
    const at = text.indexOf(find);
    assert.ok(at >= 0, `${find} in ${file}`);
    writeFileSync(file, text.slice(0, at) + find.toUpperCase() + text.slice(at + find.length));
  };

  describe("signing", () => {
    it("signs documents so they verify, and rejects a flipped field, another label or another key", () => {
      const key = randomBytes(32);
      const signer = signerFor(key);
      const doc = signer.sign<{ v: number; b: string[]; a: { z: number; y: null }; mac: string }>("store", { v: 1, b: ["x", "y"], a: { z: 1, y: null } });
      assert.match(doc.mac, /^v1:[0-9a-f]{64}$/);
      assert.equal(doc.mac, forgeMac(key, "store", doc));
      assert.equal(signer.verify("store", doc), true);
      // key order does not matter; a JSON round trip still verifies
      assert.equal(signer.verify("store", JSON.parse(JSON.stringify({ mac: doc.mac, a: { y: null, z: 1 }, b: ["x", "y"], v: 1 }))), true);
      assert.equal(signer.verify("store", { ...doc, b: ["y", "x"] }), false, "array order is signed");
      assert.equal(signer.verify("store", { ...doc, v: 2 }), false);
      assert.equal(signer.verify("registry", doc), false, "a MAC is bound to its label");
      assert.equal(signerFor(randomBytes(32)).verify("store", doc), false);
      for (const junk of [null, "x", [doc], { ...doc, mac: 42 }, { ...doc, mac: doc.mac.slice(0, -1) }, { ...doc, mac: undefined }]) {
        assert.equal(signer.verify("store", junk), false, JSON.stringify(junk));
      }
    });

    it("derives keyed ids per label, and a keyId that names the key", () => {
      const key = randomBytes(32);
      const signer = signerFor(key);
      const sub = createHmac("sha256", key).update("nexus/integrity/v1/unit").digest();
      assert.equal(signer.hmac16("unit", "m\0line"), createHmac("sha256", sub).update("m\0line").digest("hex").slice(0, 16));
      assert.notEqual(signer.hmac16("nonce", "m\0line"), signer.hmac16("unit", "m\0line"));
      assert.match(signer.keyId, /^[0-9a-f]{16}$/);
      assert.equal(signerFor(Buffer.from(key)).keyId, signer.keyId);
      assert.notEqual(signerFor(randomBytes(32)).keyId, signer.keyId);
    });
  });

  describe("first run and initialisation", () => {
    it("reports a machine first run without creating anything", () => {
      const before = snapshot(base);
      const state = load();
      assert.equal(state.machineFirstRun, true);
      assert.deepEqual(state.tamper, []);
      assert.equal(state.key.state, "missing");
      for (const id of IDS) assert.deepEqual(state.stores[id], { id, doc: null, verified: false, registered: false, orphan: false, tamper: null });
      assert.equal(snapshot(base), before);
      assert.equal(existsSync(data), false);
    });

    it("creates the private directories, key, signed empty registry and anchor", () => {
      const result = initIntegrity(paths, NOW);
      assert.ok(result.ok);
      assert.deepEqual({ ...result, signer: undefined }, { ok: true, signer: undefined, createdKey: true, wroteRegistry: true, wroteAnchor: true, replacedConfig: false });
      if (POSIX) {
        for (const dir of [data, paths.dir]) assert.equal(statSync(dir).mode & 0o777, 0o700, dir);
        for (const file of [paths.key, paths.registry, paths.anchor]) assert.equal(statSync(file).mode & 0o777, 0o600, file);
      }
      assert.match(readFileSync(paths.key, "utf-8"), /^[0-9a-f]{64}$/);
      const anchor = JSON.parse(readFileSync(paths.anchor, "utf-8"));
      assert.deepEqual(anchor, { v: 1, createdAt: NOW.toISOString(), keyId: result.signer.keyId });
      assert.deepEqual(readRegistry(paths, result.signer), { state: "ok", doc: { ...emptyRegistry(), mac: JSON.parse(readFileSync(paths.registry, "utf-8")).mac } });

      const state = load();
      assert.equal(state.machineFirstRun, false);
      assert.deepEqual(state.tamper, []);
      assert.equal(state.registryVerified, true);
      for (const id of IDS) assert.equal(state.stores[id].doc, null);
      assert.deepEqual(state.config, { instructionGate: "always", memoryGate: "novel-tokens", agentWindowEscalation: true, withholdMcp: "suspect", quoteFlaggedLines: true, enabled: true });
    });

    it("keeps a trusted key and an existing anchor on a second init (install)", () => {
      const first = init();
      const keyBefore = readFileSync(paths.key, "utf-8");
      const anchorBefore = readFileSync(paths.anchor, "utf-8");
      const again = initIntegrity(paths, new Date(NOW.getTime() + DAY));
      assert.ok(again.ok);
      assert.equal(again.signer.keyId, first.keyId);
      assert.deepEqual([again.createdKey, again.wroteRegistry, again.wroteAnchor], [false, false, false]);
      assert.equal(readFileSync(paths.key, "utf-8"), keyBefore);
      assert.equal(readFileSync(paths.anchor, "utf-8"), anchorBefore);
    });

    it("replaces an untrusted key only on reset", { skip: !POSIX }, () => {
      setup();
      chmodSync(paths.key, 0o644);
      const before = snapshot(base);
      const refused = initIntegrity(paths, NOW);
      assert.equal(refused.ok, false);
      assert.match(refused.ok ? "" : refused.why, /group\/world-accessible/);
      assert.equal(snapshot(base), before, "nothing replaced without reset");

      const reset = initIntegrity(paths, NOW, { reset: true });
      assert.ok(reset.ok);
      assert.equal(reset.createdKey, true);
      assert.equal(statSync(paths.key).mode & 0o777, 0o600);
      const state = load();
      assert.deepEqual(state.tamper, [], "new key, new anchor, new registry");
      // the old stores no longer verify and are not registered: leftovers, loaded as absent
      for (const id of IDS) assert.deepEqual([state.stores[id].orphan, state.stores[id].tamper], [true, null], id);
    });

    it("on reset with a trusted key, replaces a registry that does not verify and keeps the stores that do", () => {
      setup();
      flipByte(paths.registry, "nexus-integrity-registry");
      assert.deepEqual(load().tamper, ["mac"]);
      const plain = initIntegrity(paths, NOW);
      assert.ok(plain.ok);
      assert.equal(plain.wroteRegistry, false, "install never launders a tampered registry");
      assert.deepEqual(load().tamper, ["mac"]);

      const reset = initIntegrity(paths, NOW, { reset: true });
      assert.ok(reset.ok);
      assert.deepEqual([reset.createdKey, reset.wroteRegistry, reset.wroteAnchor], [false, true, true]);
      const state = load();
      assert.deepEqual(state.tamper, []);
      for (const id of IDS) assert.deepEqual([state.stores[id].verified, state.stores[id].registered, state.stores[id].tamper], [true, false, null], id);
    });

    it("on reset, replaces a config.json that does not verify with signed defaults and reports it; a plain install does not", () => {
      const signer = setup();
      const set = { instructionGate: "risky", memoryGate: "exposed", agentWindowEscalation: false, withholdMcp: "unreviewed", quoteFlaggedLines: false } as const;
      writeConfig(paths, signer, set);
      flipByte(paths.config, "unreviewed");
      assert.deepEqual(load().tamper, ["mac"]);

      const plain = initIntegrity(paths, NOW);
      assert.ok(plain.ok);
      assert.equal(plain.replacedConfig, false);
      assert.deepEqual(load().tamper, ["mac"], "install never launders a tampered config");

      const reset = initIntegrity(paths, NOW, { reset: true });
      assert.ok(reset.ok);
      assert.deepEqual([reset.createdKey, reset.wroteRegistry, reset.replacedConfig], [false, false, true]);
      const state = load();
      assert.deepEqual(state.tamper, []);
      assert.deepEqual(readConfig(paths, signer), {
        state: "ok", config: { instructionGate: "always", memoryGate: "novel-tokens", agentWindowEscalation: true, withholdMcp: "suspect", quoteFlaggedLines: true },
      });
      // a config that verifies is kept as it is
      writeConfig(paths, signer, set);
      const again = initIntegrity(paths, NOW, { reset: true });
      assert.ok(again.ok);
      assert.equal(again.replacedConfig, false);
      assert.deepEqual(readConfig(paths, signer), { state: "ok", config: set });
    });

    it("never clears `store-deleted` on a plain install when only the registry was deleted", () => {
      setup();
      rmSync(paths.registry);
      assert.deepEqual(load().tamper, ["store-deleted"]);
      const before = snapshot(base);
      const plain = initIntegrity(paths, NOW);
      assert.ok(plain.ok);
      assert.deepEqual([plain.createdKey, plain.wroteRegistry, plain.wroteAnchor], [false, false, false]);
      assert.equal(snapshot(base), before);
      assert.deepEqual(load().tamper, ["store-deleted"]);

      const reset = initIntegrity(paths, NOW, { reset: true });
      assert.ok(reset.ok);
      assert.deepEqual([reset.createdKey, reset.wroteRegistry, reset.wroteAnchor], [false, true, true]);
      assert.deepEqual(load().tamper, []);
    });

    it("does not launder a rollback by deleting the registry and reinstalling", () => {
      const signer = setup();
      const file = join(paths.storesDir, `${PROJECT}.json`);
      const old = readFileSync(file);
      const state = load();
      commitStores(paths, signer, state.registry, { write: [state.stores[PROJECT].doc!] }, NOW);
      writeFileSync(file, old); // gen 1 again, while the registry says 2
      rmSync(paths.registry);
      assert.ok(initIntegrity(paths, NOW).ok);
      const after = load();
      assert.deepEqual(after.tamper, ["store-deleted"]);
      assert.equal(after.stores[PROJECT].tamper, "store-deleted");
    });

    it("does not launder a rollback by deleting the registry and the anchor, then reinstalling", () => {
      const signer = setup();
      const file = join(paths.storesDir, `${PROJECT}.json`);
      const old = readFileSync(file);
      const state = load();
      commitStores(paths, signer, state.registry, { write: [state.stores[PROJECT].doc!] }, NOW);
      writeFileSync(file, old); // gen 1 again, while the registry says 2
      rmSync(paths.registry);
      rmSync(paths.anchor);
      const attacked = load();
      assert.equal(attacked.machineFirstRun, false, "stores exist: the anchor was deleted, not never written");
      assert.deepEqual(attacked.tamper, ["store-deleted"]);
      assert.deepEqual(tamperOf(attacked), { global: "store-deleted", [PROJECT]: "store-deleted", [MEMORY]: "store-deleted" });

      const before = snapshot(base);
      const plain = initIntegrity(paths, NOW);
      assert.ok(plain.ok);
      assert.deepEqual([plain.createdKey, plain.wroteRegistry, plain.wroteAnchor], [false, false, false]);
      assert.equal(snapshot(base), before, "install writes no registry and no anchor over it");
      assert.deepEqual(load().tamper, ["store-deleted"]);

      const reset = initIntegrity(paths, NOW, { reset: true });
      assert.ok(reset.ok);
      assert.deepEqual([reset.wroteRegistry, reset.wroteAnchor], [true, true]);
      assert.deepEqual(load().tamper, []);
    });

    it("reports `store-deleted` when the anchor and registry go while any store file remains, this context's or not", () => {
      const signer = setup();
      const other: StoreId = "project-aaaaaaaaaaaaaaaa";
      const state = load();
      commitStores(paths, signer, state.registry, { write: [storeDoc("project", other, ["/x/CLAUDE.md"])] }, NOW);
      for (const id of IDS) rmSync(join(paths.storesDir, `${id}.json`));
      rmSync(paths.registry);
      rmSync(paths.anchor);
      const after = load();
      assert.equal(after.machineFirstRun, false);
      assert.deepEqual(after.tamper, ["store-deleted"]);

      // The registry alone still lists the stores.
      rmSync(data, { recursive: true });
      setup();
      rmSync(paths.storesDir, { recursive: true });
      rmSync(paths.anchor);
      assert.deepEqual(load().tamper, ["store-deleted"]);
    });

    it("finishes an interrupted first run: no anchor and no registry yet, or an empty registry", () => {
      for (const keep of [false, true]) {
        rmSync(data, { recursive: true, force: true });
        init();
        if (!keep) rmSync(paths.registry);
        rmSync(paths.anchor);
        const state = load();
        assert.deepEqual([state.machineFirstRun, state.tamper], [true, []], `registry kept: ${keep}`);
        const again = initIntegrity(paths, NOW);
        assert.ok(again.ok);
        assert.deepEqual([again.createdKey, again.wroteRegistry, again.wroteAnchor], [false, !keep, true]);
        const after = load();
        assert.deepEqual([after.machineFirstRun, after.tamper, after.registryVerified], [false, [], true]);
      }
    });
  });

  describe("the read path", () => {
    it("never creates, replaces or repairs anything, whatever state the store is in", () => {
      const states: [string, () => void][] = [
        ["no data dir", () => {}],
        ["anchor only", () => { setup(); rmSync(paths.dir, { recursive: true }); }],
        ["no key", () => { setup(); rmSync(paths.key); }],
        ["no anchor", () => { setup(); rmSync(paths.anchor); }],
        ["healthy", () => { setup(); }],
      ];
      for (const [name, arrange] of states) {
        rmSync(data, { recursive: true, force: true });
        arrange();
        const before = snapshot(base);
        const state = load();
        readConfig(paths, state.signer);
        isIntegrityDisabled(paths);
        readWatchPrefixes(paths);
        readLog(paths);
        readRegistry(paths, state.signer);
        assert.equal(snapshot(base), before, name);
      }
    });
  });

  describe("stores and the registry", () => {
    it("commits signed stores with generation counters mirrored in the registry", () => {
      const signer = setup();
      let state = load();
      assert.deepEqual(state.tamper, []);
      for (const id of IDS) {
        const s = state.stores[id];
        assert.deepEqual([s.verified, s.registered, s.tamper, s.doc?.gen], [true, true, null, 1], id);
      }
      assert.deepEqual(state.registry?.stores.global, { gen: 1, updatedAt: NOW.toISOString() });
      assert.deepEqual(state.registry?.stores[PROJECT], { gen: 1, updatedAt: NOW.toISOString(), root: `/home/u/${PROJECT}` });
      assert.deepEqual(state.stores[PROJECT].doc?.entries["/home/u/app/AGENTS.md"], entry("/home/u/app/AGENTS.md"));
      assert.equal(state.stores.global.doc?.memoryWritesObserved, false);
      assert.equal(state.stores[PROJECT].doc?.autoMemoryDir, null);

      const later = new Date(NOW.getTime() + 60_000);
      const out = commitStores(paths, signer, state.registry, { write: [state.stores[PROJECT].doc!] }, later);
      assert.equal(out.stores[0].gen, 2);
      assert.equal(out.registry.stores[PROJECT].gen, 2);
      state = load();
      assert.deepEqual([state.stores[PROJECT].doc?.gen, state.stores[PROJECT].doc?.updatedAt, state.stores.global.doc?.gen], [2, later.toISOString(), 1]);
      assert.deepEqual(state.tamper, []);
    });

    it("round-trips a held item's rule; a rule that does not hold a version is dropped on read", () => {
      const signer = setup();
      const state = load();
      const doc = state.stores[PROJECT].doc!;
      const held = (rule: string) => ({ id: "h_0123456789ab", tier: "HOLD", since: NOW.toISOString(), reasons: ["r"], flaggedUnits: [], rule });
      const written = { ...doc, entries: { "/a": { ...entry("/a"), held: held("H1") }, "/b": { ...entry("/b"), held: held("N1") } } } as unknown as UnsignedStoreDoc;
      commitStores(paths, signer, state.registry, { write: [written] }, NOW);
      const back = load().stores[PROJECT].doc!;
      assert.equal(back.entries["/a"].held?.rule, "H1");
      assert.equal(back.entries["/b"].held?.rule, undefined);
    });

    it("writes every file atomically 0600 in 0700 directories, leaving no temp file", () => {
      const signer = setup();
      writeConfig(paths, signer, { instructionGate: "risky", memoryGate: "exposed", agentWindowEscalation: false, withholdMcp: "unreviewed", quoteFlaggedLines: false });
      writeDisabled(paths, signer, "cli", NOW);
      writeWatchPrefixes(paths, { memoryDirs: ["/m"], configDirs: [], importTargets: [], hookScripts: [] }, NOW);
      withStoreLock(paths, () => appendLog(paths, [{ at: NOW.toISOString(), event: "first-run" }]), 0);
      const files = filesUnder(data);
      assert.deepEqual(files.filter((f) => f.endsWith(".tmp")), []);
      assert.equal(existsSync(paths.lock), false, "the lock is released");
      if (POSIX) {
        for (const f of files) assert.equal(statSync(f).mode & 0o777, 0o600, f);
        for (const d of [data, paths.dir, paths.storesDir]) assert.equal(statSync(d).mode & 0o777, 0o700, d);
      }
    });

    it("reports `mac` for a flipped byte, and still parses the old entries unverified", () => {
      setup();
      flipByte(join(paths.storesDir, `${PROJECT}.json`), "first-run");
      const state = load();
      assert.deepEqual(state.tamper, []);
      assert.deepEqual(tamperOf(state), { global: null, [PROJECT]: "mac", [MEMORY]: null });
      const project = state.stores[PROJECT];
      assert.equal(project.verified, false);
      assert.deepEqual(Object.keys(project.doc?.entries ?? {}).sort(), ["/home/u/app/AGENTS.md", "/home/u/app/CLAUDE.md"]);
      assert.equal(TAMPER_FRAGMENTS.mac, "signature mismatch");
    });

    it("rejects a forgery signed with a different key", () => {
      setup();
      const file = join(paths.storesDir, `${PROJECT}.json`);
      const doc = JSON.parse(readFileSync(file, "utf-8"));
      doc.entries["/home/u/app/CLAUDE.md"].sha256 = "b".repeat(64);
      doc.mac = forgeMac(randomBytes(32), "store", doc);
      writeFileSync(file, JSON.stringify(doc));
      assert.equal(tamperOf()[PROJECT], "mac");
    });

    it("does not accept one store's signed document in place of another's", () => {
      setup();
      copyFileSync(join(paths.storesDir, `${PROJECT}.json`), join(paths.storesDir, `${MEMORY}.json`));
      assert.deepEqual(tamperOf(), { global: null, [PROJECT]: null, [MEMORY]: "mac" });
    });

    it("reports `missing-store` when a registered store file is gone", () => {
      setup();
      rmSync(join(paths.storesDir, "global.json"));
      const state = load();
      assert.deepEqual(tamperOf(state), { global: "missing-store", [PROJECT]: null, [MEMORY]: null });
      assert.equal(state.stores.global.doc, null);
    });

    it("reports `rollback` when an older signed store is restored", () => {
      const signer = setup();
      const file = join(paths.storesDir, `${PROJECT}.json`);
      const old = readFileSync(file);
      const state = load();
      commitStores(paths, signer, state.registry, { write: [state.stores[PROJECT].doc!] }, NOW);
      writeFileSync(file, old);
      const after = load();
      assert.equal(after.stores[PROJECT].verified, true, "the old document is validly signed");
      assert.deepEqual(tamperOf(after), { global: null, [PROJECT]: "rollback", [MEMORY]: null });
    });

    it("reports a store-wide `mac` for a tampered registry or config", () => {
      const signer = setup();
      flipByte(paths.registry, "nexus-integrity-registry");
      assert.deepEqual(load().tamper, ["mac"]);
      assert.deepEqual(tamperOf(), { global: "mac", [PROJECT]: "mac", [MEMORY]: "mac" });

      rmSync(data, { recursive: true });
      setup();
      writeConfig(paths, signer, { instructionGate: "always", memoryGate: "exposed", agentWindowEscalation: true, withholdMcp: "suspect", quoteFlaggedLines: true });
      const forged = JSON.parse(readFileSync(paths.config, "utf-8"));
      Object.assign(forged, { agentWindowEscalation: false });
      writeFileSync(paths.config, JSON.stringify(forged));
      const state = load();
      assert.deepEqual(state.tamper, ["mac"]);
      assert.equal(state.config.agentWindowEscalation, true, "an unverified config gives the defaults");
    });

    it("loads an unregistered store left by a crash before the registry write", () => {
      const signer = setup();
      const reg = readFileSync(paths.registry);
      const state = load();
      const extra: StoreId = "project-aaaaaaaaaaaaaaaa";
      commitStores(paths, signer, state.registry, { write: [storeDoc("project", extra, ["/x/CLAUDE.md"])] }, NOW);
      writeFileSync(paths.registry, reg); // the registry write never happened
      const after = loadIntegrity({ dataDir: data, homedir: home, platform: process.platform }, [...IDS, extra]);
      assert.deepEqual(after.tamper, []);
      assert.deepEqual([after.stores[extra].verified, after.stores[extra].registered, after.stores[extra].tamper], [true, false, null]);
    });

    it("treats an unregistered store that does not verify as a leftover, not as tampering", () => {
      init();
      mkdirSync(paths.storesDir, { recursive: true });
      writeFileSync(join(paths.storesDir, `${PROJECT}.json`), JSON.stringify({ schema: "nexus-integrity-store", junk: true, mac: "v1:00" }));
      const state = load();
      assert.deepEqual(state.tamper, []);
      assert.deepEqual(state.stores[PROJECT], { id: PROJECT, doc: null, verified: false, registered: false, orphan: true, tamper: null });
    });

    it("drops stores and their registry entries on request", () => {
      const signer = setup();
      const state = load();
      const out = commitStores(paths, signer, state.registry, { drop: [MEMORY] }, NOW);
      assert.equal(out.registry.stores[MEMORY], undefined);
      assert.equal(existsSync(join(paths.storesDir, `${MEMORY}.json`)), false);
      const after = load();
      assert.deepEqual(after.tamper, []);
      assert.deepEqual([after.stores[MEMORY].doc, after.stores[MEMORY].tamper], [null, null]);
    });

    it("reports `store-deleted` when only the anchor was lost, and never re-anchors on commit", () => {
      const signer = setup();
      rmSync(paths.anchor);
      const state = load();
      assert.equal(state.machineFirstRun, false);
      assert.deepEqual(state.tamper, ["store-deleted"], "a lost anchor is not a first run while stores exist");
      commitStores(paths, signer, state.registry, { write: [state.stores.global.doc!] }, NOW);
      assert.equal(existsSync(paths.anchor), false, "only initIntegrity writes the anchor");
      assert.deepEqual(load().tamper, ["store-deleted"]);
    });

    it("merges the registry on disk: a stale copy neither drops a store registered since nor rolls a generation back", () => {
      const signer = setup();
      const projectFile = join(paths.storesDir, `${PROJECT}.json`);
      const projectAtGen1 = readFileSync(projectFile);
      const extra: StoreId = "project-aaaaaaaaaaaaaaaa";
      const ids = [...IDS, extra];
      const loadAll = () => loadIntegrity({ dataDir: data, homedir: home, platform: process.platform }, ids);
      // two sessions load the same registry (every store at gen 1)
      const a = load();
      const b = load();
      // A commits its project store and a newly seen project's store
      commitStores(paths, signer, a.registry, { write: [a.stores[PROJECT].doc!, storeDoc("project", extra, ["/x/CLAUDE.md"])] }, NOW);
      // B, holding its stale copy, commits the global store
      const out = commitStores(paths, signer, b.registry, { write: [b.stores.global.doc!] }, NOW);
      assert.deepEqual([out.registry.stores.global.gen, out.registry.stores[PROJECT].gen, out.registry.stores[extra]?.gen], [2, 2, 1]);
      let state = loadAll();
      assert.deepEqual(state.tamper, []);
      assert.deepEqual([state.stores[extra].registered, state.stores[extra].verified, state.stores[PROJECT].tamper], [true, true, null]);
      // the old project store restored is still caught as a rollback
      const projectNow = readFileSync(projectFile);
      writeFileSync(projectFile, projectAtGen1);
      assert.equal(loadAll().stores[PROJECT].tamper, "rollback");
      writeFileSync(projectFile, projectNow);
      // a store written from a stale copy gets a generation above both copies
      const c = commitStores(paths, signer, b.registry, { write: [b.stores[PROJECT].doc!] }, NOW);
      assert.equal(c.stores[0].gen, 3);
      assert.equal(c.registry.stores[PROJECT].gen, 3);
      // a store dropped in the meantime stays dropped (no `missing-store` from a stale copy)
      commitStores(paths, signer, loadAll().registry, { drop: [MEMORY] }, NOW);
      commitStores(paths, signer, b.registry, { write: [b.stores.global.doc!] }, NOW);
      state = loadAll();
      assert.equal(state.registry?.stores[MEMORY], undefined);
      assert.deepEqual([state.stores[MEMORY].tamper, state.stores[MEMORY].doc], [null, null]);
      // a registry that does not verify is left as it is: nothing is written
      flipByte(paths.registry, "nexus-integrity-registry");
      const tampered = snapshot(base);
      assert.throws(() => commitStores(paths, signer, b.registry, { write: [b.stores.global.doc!] }, NOW), RegistryTamperError);
      assert.equal(snapshot(base), tampered);
      assert.deepEqual(loadAll().tamper, ["mac"]);
    });

    it("refuses store ids that are not store ids", () => {
      init();
      assert.throws(() => readStore(paths, "../registry", null), TypeError);
      assert.throws(() => loadIntegrity({ dataDir: data, homedir: home, platform: process.platform }, ["project-x/../../y"]), TypeError);
    });
  });

  describe("TAMPER: deleted store, key, redirect", () => {
    it("reports `store-deleted` when the anchor remains but the directory, registry or key is gone", () => {
      for (const victim of [() => paths.dir, () => paths.registry, () => paths.key]) {
        rmSync(data, { recursive: true, force: true });
        setup();
        rmSync(victim(), { recursive: true });
        const state = load();
        assert.equal(state.machineFirstRun, false);
        assert.equal(state.tamper[0], "store-deleted", victim());
        assert.deepEqual(tamperOf(state), { global: "store-deleted", [PROJECT]: "store-deleted", [MEMORY]: "store-deleted" });
      }
    });

    it("reports `key` for a group/world-readable key", { skip: !POSIX }, () => {
      setup();
      chmodSync(paths.key, 0o644);
      const state = load();
      assert.equal(state.key.state, "untrusted");
      assert.deepEqual(state.tamper, ["key"]);
      // unverifiable, but the old entries are still readable for the frame
      assert.equal(state.stores[PROJECT].tamper, "key");
      assert.equal(Object.keys(state.stores[PROJECT].doc?.entries ?? {}).length, 2);
    });

    it("reports `key` for a key owned by another user", { skip: !POSIX || !ROOT }, () => {
      setup();
      chownSync(paths.key, 12345, 12345);
      assert.deepEqual(load().tamper, ["key"]);
    });

    it("reports `key` for a malformed key", () => {
      setup();
      writeFileSync(paths.key, "not a key", { mode: 0o600 });
      if (POSIX) chmodSync(paths.key, 0o600);
      assert.deepEqual(load().tamper, ["key"]);
    });

    it("reports `key` when the key no longer matches the anchor's keyId, or the anchor is malformed", () => {
      setup();
      writeFileSync(paths.key, randomBytes(32).toString("hex"), { mode: 0o600 });
      if (POSIX) chmodSync(paths.key, 0o600);
      const state = load();
      assert.equal(state.tamper[0], "key");
      assert.ok(state.tamper.includes("mac"), "nothing else verifies under the new key either");

      rmSync(data, { recursive: true });
      setup();
      writeFileSync(paths.anchor, "{");
      assert.deepEqual(load().tamper, ["key"]);
      assert.equal(TAMPER_FRAGMENTS.key, "the integrity key is unreadable or was replaced");
    });

    it("reports `redirect` when NEXUS_DATA points at an empty store while ~/.nexus has one", () => {
      setup(); // ~/.nexus is the real store
      const elsewhere = join(base, "elsewhere");
      const state = load(elsewhere);
      assert.equal(state.machineFirstRun, false, "never a quiet first run");
      assert.deepEqual(state.tamper, ["redirect"]);
      assert.deepEqual(tamperOf(state), { global: "redirect", [PROJECT]: "redirect", [MEMORY]: "redirect" });
      assert.equal(existsSync(elsewhere), false);
      assert.match(TAMPER_FRAGMENTS.redirect, /^NEXUS_DATA points to an empty store/);

      // the same directory spelled differently is not a redirect
      assert.deepEqual(load(join(home, "x", "..", ".nexus")).tamper, []);
      // a redirected store that has its own anchor is just another store
      const own = integrityPaths(elsewhere);
      assert.ok(initIntegrity(own, NOW).ok);
      assert.deepEqual(load(elsewhere).tamper, []);
    });

    it("is a plain first run in another data dir when ~/.nexus has no store", () => {
      const state = load(join(base, "elsewhere"));
      assert.deepEqual([state.machineFirstRun, state.tamper], [true, []]);
    });
  });

  describe("config and the disabled marker", () => {
    it("reads defaults for a missing config and round-trips a written one", () => {
      const signer = init();
      assert.deepEqual(readConfig(paths, signer), {
        state: "missing",
        config: { instructionGate: "always", memoryGate: "novel-tokens", agentWindowEscalation: true, withholdMcp: "suspect", quoteFlaggedLines: true },
      });
      const set = { instructionGate: "risky", memoryGate: "tainted-only", agentWindowEscalation: false, withholdMcp: "off", quoteFlaggedLines: false } as const;
      writeConfig(paths, signer, set);
      assert.deepEqual(readConfig(paths, signer), { state: "ok", config: set });
      assert.deepEqual(load().config, { ...set, enabled: true });
      // values outside the vocabulary are never written
      writeConfig(paths, signer, { ...set, memoryGate: "never" as never, quoteFlaggedLines: "yes" as never });
      assert.deepEqual(readConfig(paths, signer).config, { ...set, memoryGate: "novel-tokens", quoteFlaggedLines: true });
    });

    it("turns integrity off only while a signed marker is present", () => {
      const signer = setup();
      assert.equal(isIntegrityDisabled(paths), false);
      writeDisabled(paths, signer, "cli", NOW);
      assert.equal(isIntegrityDisabled(paths), true);
      let state = load();
      assert.deepEqual([state.disabled, state.config.enabled], [true, false]);

      const marker = JSON.parse(readFileSync(paths.disabled, "utf-8"));
      for (const forged of [
        { ...marker, at: "2027-01-01T00:00:00.000Z" },
        { ...marker, mac: forgeMac(randomBytes(32), "config", marker) },
        { ...marker, by: "agent", mac: forgeMac(randomBytes(32), "config", { ...marker, by: "agent" }) },
      ]) {
        writeFileSync(paths.disabled, JSON.stringify(forged));
        assert.equal(isIntegrityDisabled(paths), false, JSON.stringify(forged));
      }
      writeFileSync(paths.disabled, "garbage");
      assert.equal(isIntegrityDisabled(paths), false);
      // a validly signed config document is not a marker
      writeConfig(paths, signer, readConfig(paths, signer).config);
      copyFileSync(paths.config, paths.disabled);
      assert.equal(isIntegrityDisabled(paths), false);

      writeDisabled(paths, signer, "install", NOW);
      removeDisabled(paths);
      removeDisabled(paths); // idempotent
      state = load();
      assert.deepEqual([state.disabled, state.config.enabled], [false, true]);
    });
  });

  describe("config and the disabled marker: one cannot pass for the other", () => {
    it("signs a kind into each, checked on read: a marker copied over config.json is a `mac` TAMPER, a config over .disabled is no marker", () => {
      const signer = setup();
      const set = { instructionGate: "risky", memoryGate: "exposed", agentWindowEscalation: false, withholdMcp: "unreviewed", quoteFlaggedLines: false } as const;
      writeConfig(paths, signer, set);
      writeDisabled(paths, signer, "cli", NOW);
      const config = readFileSync(paths.config);
      const marker = readFileSync(paths.disabled);
      assert.equal(JSON.parse(config.toString()).kind, "config");
      assert.equal(JSON.parse(marker.toString()).kind, "disabled");

      // the marker in config.json's place would reset every setting to its default without a trace
      writeFileSync(paths.config, marker);
      assert.equal(readConfig(paths, signer).state, "unverified");
      assert.deepEqual(load().tamper, ["mac"]);
      // the config in .disabled's place would turn integrity off
      writeFileSync(paths.config, config);
      writeFileSync(paths.disabled, config);
      assert.equal(isIntegrityDisabled(paths), false);
      assert.deepEqual(load().tamper, []);
      // relabelling the kind breaks the signature
      writeFileSync(paths.config, JSON.stringify({ ...JSON.parse(marker.toString()), kind: "config" }));
      assert.equal(readConfig(paths, signer).state, "unverified");
      // each verifies in its own place
      writeFileSync(paths.config, config);
      writeFileSync(paths.disabled, marker);
      assert.deepEqual([readConfig(paths, signer).state, isIntegrityDisabled(paths)], ["ok", true]);
    });
  });

  describe("watch-prefixes.json", () => {
    it("round-trips the lists and ignores a malformed file", () => {
      init();
      assert.equal(readWatchPrefixes(paths), null);
      const lists = { memoryDirs: ["/m"], configDirs: ["/c"], importTargets: ["/i.md"], hookScripts: ["/h.sh"] };
      writeWatchPrefixes(paths, lists, NOW);
      assert.deepEqual(readWatchPrefixes(paths), { v: 1, ...lists, updatedAt: NOW.toISOString() });
      writeFileSync(paths.watchPrefixes, JSON.stringify({ v: 1, memoryDirs: ["/m", 7, ""], configDirs: "nope" }));
      assert.deepEqual(readWatchPrefixes(paths), { v: 1, memoryDirs: ["/m"], configDirs: [], importTargets: [], hookScripts: [], updatedAt: new Date(0).toISOString() });
      writeFileSync(paths.watchPrefixes, "{");
      assert.equal(readWatchPrefixes(paths), null);
    });
  });

  describe("log.jsonl", () => {
    const line = (i: number): LogEntry => ({ at: new Date(NOW.getTime() + i).toISOString(), event: "advance", store: "global", added: i });

    it("appends entries and reads the last ones back, skipping malformed lines", () => {
      init();
      withStoreLock(paths, () => appendLog(paths, [line(1), line(2)]), 0);
      writeFileSync(paths.log, readFileSync(paths.log, "utf-8") + "not json\n{\"at\":1}\n");
      withStoreLock(paths, () => appendLog(paths, [line(3)]), 0);
      assert.deepEqual(readLog(paths).map((e) => e.added), [1, 2, 3]);
      assert.deepEqual(readLog(paths, 2).map((e) => e.added), [2, 3]);
      if (POSIX) assert.equal(statSync(paths.log).mode & 0o777, 0o600);
    });

    it("never appends through a symlink planted at the log path", { skip: !POSIX }, () => {
      init();
      const victim = join(base, "victim.txt");
      writeFileSync(victim, "keep\n");
      try {
        symlinkSync(victim, paths.log);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EPERM") return;
        throw error;
      }
      assert.throws(() => withStoreLock(paths, () => appendLog(paths, [line(1)]), 0), { code: "ELOOP" });
      assert.equal(readFileSync(victim, "utf-8"), "keep\n");
      assert.deepEqual(readLog(paths), []);
    });

    it("never blocks on, or appends to, a FIFO planted at the log path", { skip: !POSIX }, (t) => {
      init();
      if (spawnSync("mkfifo", [paths.log]).status !== 0) return t.skip("mkfifo is unavailable");
      // No reader: a blocking open() would wait forever, so the append runs in a child with a timeout.
      const child = spawnSync(process.execPath, [
        "--import", TSX, "--input-type=module", "-e",
        `const { appendLog, integrityPaths } = await import(${JSON.stringify(MODULE_URL)});
         try {
           appendLog(integrityPaths(${JSON.stringify(data)}), [${JSON.stringify(line(1))}]);
           process.stdout.write("appended");
         } catch (error) {
           process.stdout.write(String(error.code));
         }`,
      ], { encoding: "utf-8", timeout: 15_000, env: { ...process.env, HOME: home, USERPROFILE: home, NEXUS_DATA: data, CLAUDE_CONFIG_DIR: join(home, ".claude") } });
      assert.equal(child.signal, null, "the append hung on the FIFO");
      assert.equal(child.stdout, "ENXIO");
      // A reader present: the open succeeds, but a FIFO is still not a log.
      const reader = openSync(paths.log, constants.O_RDONLY | constants.O_NONBLOCK);
      try {
        assert.throws(() => withStoreLock(paths, () => appendLog(paths, [line(1)]), 0), /not a regular file/);
        assert.equal(readSync(reader, Buffer.alloc(64), 0, 64, null), 0, "nothing was written into the FIFO");
      } finally {
        closeSync(reader);
      }
    });

    it("is rewritten to the last 1,000 lines once it reaches 1,200", () => {
      init();
      const lines = () => readFileSync(paths.log, "utf-8").split("\n").filter((l) => l !== "");
      withStoreLock(paths, () => appendLog(paths, Array.from({ length: LOG_MAX_LINES - 2 }, (_, i) => line(i))), 0);
      assert.equal(lines().length, LOG_MAX_LINES - 2);
      withStoreLock(paths, () => appendLog(paths, [line(LOG_MAX_LINES - 2)]), 0);
      assert.equal(lines().length, LOG_MAX_LINES - 1, "below the cap nothing is dropped");
      withStoreLock(paths, () => appendLog(paths, [line(LOG_MAX_LINES - 1)]), 0);
      const kept = lines();
      assert.equal(kept.length, LOG_KEEP_LINES);
      assert.equal(JSON.parse(kept[0]).added, LOG_MAX_LINES - LOG_KEEP_LINES);
      assert.equal(JSON.parse(kept[kept.length - 1]).added, LOG_MAX_LINES - 1);
      assert.deepEqual(readdirSync(paths.dir).filter((f) => f.endsWith(".tmp")), []);
    });
  });

  describe("the store lock", () => {
    const plantLock = (pid: number, ageMs: number) => {
      writeFileSync(paths.lock, JSON.stringify({ pid, token: "planted", createdAt: new Date(0).toISOString() }));
      const at = new Date(Date.now() - ageMs);
      utimesSync(paths.lock, at, at);
    };

    it("runs fn under the lock and returns its value", () => {
      init();
      const result = withStoreLock(paths, () => {
        assert.equal(JSON.parse(readFileSync(paths.lock, "utf-8")).pid, process.pid);
        return 7;
      }, 0);
      assert.deepEqual(result, { ok: true, value: 7 });
      assert.equal(existsSync(paths.lock), false);
    });

    it("gives a typed `busy` result on contention instead of throwing, after waiting", () => {
      init();
      plantLock(process.pid, 0);
      let ran = false;
      const started = Date.now();
      const result = withStoreLock(paths, () => { ran = true; }, 100);
      assert.equal(result.ok, false);
      assert.equal(result.ok ? null : result.reason, "busy");
      assert.ok(Date.now() - started >= 100);
      assert.equal(ran, false);
      assert.equal(JSON.parse(readFileSync(paths.lock, "utf-8")).token, "planted");
    });

    it("takes over a stale lock whose owner is dead (30 s)", () => {
      init();
      plantLock(DEAD_PID, 10_000);
      assert.equal(withStoreLock(paths, () => "x", 0).ok, false, "too young to take over");
      plantLock(DEAD_PID, 31_000);
      assert.deepEqual(withStoreLock(paths, () => "taken", 0), { ok: true, value: "taken" });
      assert.equal(existsSync(paths.lock), false);
    });

    it("gives `busy` within the SessionStart wait for a FIFO planted at the lock or the recovery lock", { skip: !POSIX }, (t) => {
      init();
      if (spawnSync("mkfifo", [paths.lock]).status !== 0) return t.skip("mkfifo is unavailable");
      // A blocking read of a FIFO with no writer waits forever, so each attempt runs in a child with a timeout.
      const attempt = () => spawnSync(process.execPath, [
        "--import", TSX, "--input-type=module", "-e",
        `const { integrityPaths, withStoreLock } = await import(${JSON.stringify(MODULE_URL)});
         const started = Date.now();
         const result = withStoreLock(integrityPaths(${JSON.stringify(data)}), () => "persisted", ${LOCK_WAIT_SESSION_START_MS});
         process.stdout.write(JSON.stringify({ reason: result.ok ? result.value : result.reason, ms: Date.now() - started }));`,
      ], { encoding: "utf-8", timeout: 15_000, env: { ...process.env, HOME: home, USERPROFILE: home, NEXUS_DATA: data, CLAUDE_CONFIG_DIR: join(home, ".claude") } });

      let child = attempt();
      assert.equal(child.signal, null, "withStoreLock hung on a FIFO at integrity/.lock");
      let out = JSON.parse(child.stdout) as { reason: string; ms: number };
      assert.equal(out.reason, "busy");
      assert.ok(out.ms >= LOCK_WAIT_SESSION_START_MS && out.ms < 5_000, `${out.ms} ms`);

      rmSync(paths.lock);
      plantLock(DEAD_PID, 31_000); // stale: recovery runs, and meets the FIFO
      if (spawnSync("mkfifo", [`${paths.lock}.recovery`]).status !== 0) return;
      child = attempt();
      assert.equal(child.signal, null, "withStoreLock hung on a FIFO at integrity/.lock.recovery");
      out = JSON.parse(child.stdout) as { reason: string; ms: number };
      assert.equal(out.reason, "busy");
      assert.equal(JSON.parse(readFileSync(paths.lock, "utf-8")).token, "planted");
    });

    it("reports `unavailable` when the lock cannot be created, and lets fn's own errors through", () => {
      const result = withStoreLock(paths, () => "never", 0); // no integrity/ yet
      assert.equal(result.ok ? null : result.reason, "unavailable");
      init();
      assert.throws(() => withStoreLock(paths, () => { throw new Error("inside"); }, 0), /inside/);
      assert.equal(existsSync(paths.lock), false);
    });
  });

  describe("retention", () => {
    const now = Date.UTC(2026, 9, 23, 12);
    const dayDir = (daysAgo: number) => new Date(now - daysAgo * DAY).toISOString().slice(0, 10).replace(/-/g, "");

    function plant(): void {
      init();
      for (const [daysAgo, n] of [[40, 3], [32, 1], [29, 1], [0, 1]] as const) {
        const dir = join(paths.ledgerDir, dayDir(daysAgo));
        mkdirSync(dir, { recursive: true });
        for (let i = 0; i < n; i++) writeFileSync(join(dir, `${now - daysAgo * DAY}-abcdef01-00000${i}.json`), "{}");
      }
      mkdirSync(join(paths.ledgerDir, "notes"));
      mkdirSync(paths.sessionsDir, { recursive: true });
      const old = new Date(now - 31 * DAY);
      for (const name of ["0123456789abcdef.log", "0123456789abcdef.json", "fedcba9876543210.log", "readme.txt"]) {
        const p = join(paths.sessionsDir, name);
        writeFileSync(p, "x");
        if (name !== "fedcba9876543210.log") utimesSync(p, old, old);
      }
    }

    it("removes ledger days and session files older than 30 days, and nothing else", () => {
      plant();
      const result = collectGarbage(paths, { now });
      assert.deepEqual(result, { deleted: 3 + 1 + 1 + 1 + 2, complete: true });
      assert.deepEqual(readdirSync(paths.ledgerDir).sort(), [dayDir(29), dayDir(0), "notes"].sort());
      assert.deepEqual(readdirSync(paths.sessionsDir).sort(), ["fedcba9876543210.log", "readme.txt"]);
      assert.deepEqual(collectGarbage(paths, { now }), { deleted: 0, complete: true });
    });

    it("stops at the deletion cap and at the deadline, finishing on a later call", () => {
      plant();
      assert.deepEqual(collectGarbage(paths, { now, maxDeletions: 2 }), { deleted: 2, complete: false });
      assert.deepEqual(collectGarbage(paths, { now, deadline: now, clock: () => now + 1 }), { deleted: 0, complete: false });
      let t = now;
      const partial = collectGarbage(paths, { now, deadline: now + 3, clock: () => t++ });
      assert.equal(partial.complete, false);
      assert.ok(partial.deleted > 0 && partial.deleted < 6);
      assert.equal(collectGarbage(paths, { now }).complete, true);
      assert.deepEqual(readdirSync(paths.sessionsDir).sort(), ["fedcba9876543210.log", "readme.txt"]);
    });

    it("never follows a symlinked ledger, day or sessions directory, and removes only ledger records", { skip: !POSIX }, () => {
      init();
      const record = (daysAgo: number) => `${now - daysAgo * DAY}-abcdef01-000000.json`;
      const old = new Date(now - 31 * DAY);
      const victim = join(base, "victim");
      mkdirSync(victim);
      const kept = ["CLAUDE.md", "package.json", "src.ts", record(40), "0123456789abcdef.log"];
      for (const name of kept) {
        writeFileSync(join(victim, name), "keep");
        utimesSync(join(victim, name), old, old);
      }
      mkdirSync(paths.ledgerDir, { recursive: true });
      try {
        symlinkSync(victim, join(paths.ledgerDir, dayDir(40)));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EPERM") return;
        throw error;
      }
      // a real old day directory: its records go, a stray file (and so the directory) stays
      const real = join(paths.ledgerDir, dayDir(41));
      mkdirSync(real);
      writeFileSync(join(real, record(41)), "{}");
      writeFileSync(join(real, "notes.txt"), "keep");
      symlinkSync(victim, paths.sessionsDir);

      assert.deepEqual(collectGarbage(paths, { now }), { deleted: 1, complete: true });
      assert.deepEqual(readdirSync(victim).sort(), [...kept].sort());
      assert.deepEqual(readdirSync(real), ["notes.txt"]);

      // a symlinked ledger directory is not followed either
      rmSync(paths.ledgerDir, { recursive: true });
      mkdirSync(join(victim, dayDir(40)));
      writeFileSync(join(victim, dayDir(40), record(40)), "{}");
      symlinkSync(victim, paths.ledgerDir);
      assert.deepEqual(collectGarbage(paths, { now }), { deleted: 0, complete: true });
      assert.deepEqual(readdirSync(join(victim, dayDir(40))), [record(40)]);
    });
  });

  describe("version bumps", () => {
    it("recomputes derived fields for unchanged entries only, keeping their provenance", () => {
      const held = { id: "h_0123456789ab", tier: "HOLD" as const, since: NOW.toISOString(), reasons: ["r"], flaggedUnits: [] };
      const doc: UnsignedStoreDoc = {
        ...newStoreDoc("project", PROJECT, "/home/u/app", NOW),
        v: 0,
        watchedSetVersion: 0,
        entries: {
          "/a": entry("/a", { acceptedBy: "user", history: [{ sha256: "c".repeat(64), at: NOW.toISOString() }], held }),
          "/b": entry("/b", { sha256: "b".repeat(64) }),
          "/c": entry("/c", { state: "missing", sha256: null, units: [] }),
        },
      };
      assert.equal(isCurrentVersion(doc), false);
      const current: Record<string, string | null> = { "/a": "a".repeat(64), "/b": "d".repeat(64), "/c": null };
      const seen: string[] = [];
      const { doc: up, recomputed } = upgradeStore(doc, (key) => current[key], (key) => {
        seen.push(key);
        return { units: ["ffffffffffffffff#1"], cat: { "ffffffffffffffff#1": "e" }, tok: ["t"], nexusHooks: ["SessionStart"] };
      });
      assert.deepEqual(recomputed, ["/a"]);
      assert.deepEqual(seen, ["/a"]);
      assert.equal(isCurrentVersion(up), true);
      assert.deepEqual(up.entries["/a"], {
        ...doc.entries["/a"], units: ["ffffffffffffffff#1"], cat: { "ffffffffffffffff#1": "e" }, tok: ["t"], nexusHooks: ["SessionStart"],
      });
      assert.deepEqual(up.entries["/b"], doc.entries["/b"]);
      assert.deepEqual(up.entries["/c"], doc.entries["/c"]);
      assert.equal(doc.v, 0, "the input is not modified");
    });
  });
});
