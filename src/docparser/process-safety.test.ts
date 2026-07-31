import { test } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { extractDocxText } from "./docx.js";
import { convertWithMarkItDown } from "./markitdown.js";
import { extractPdfText } from "./pdf.js";

interface FakeCommandContext {
  capturePath: string;
  hostilePath: string;
  markerPath: string;
  probeCapturePath: string;
  leadingDashName: string;
}

function withFakeCommand(
  command: string,
  extension: string,
  stdout: string,
  run: (context: FakeCommandContext) => void,
): void {
  const root = mkdtempSync(join(tmpdir(), "nexus-docparser-"));
  const binDir = join(root, "bin");
  const executable = join(binDir, command);
  const capturePath = join(root, "args.bin");
  const probeCapturePath = join(root, "probe-args.bin");
  const markerPath = join(root, "pwned");
  const hostilePath = join(root, `report$(touch\${IFS}pwned)${extension}`);
  const leadingDashName = `--output=victim${extension}`;
  const originalCwd = process.cwd();
  const originalPath = process.env.PATH;
  const originalCapture = process.env.NEXUS_CAPTURE;
  const originalProbeCapture = process.env.NEXUS_PROBE_CAPTURE;

  mkdirSync(binDir);
  writeFileSync(hostilePath, "fixture");
  writeFileSync(join(root, leadingDashName), "fixture");
  writeFileSync(
    executable,
    [
      "#!/bin/sh",
      'printf \'%s\\0\' "$@" > "$NEXUS_CAPTURE"',
      'if [ "$1" = "--help" ] || [ "$2" = "import fitz" ]; then',
      '  printf \'%s\\0\' "$@" > "$NEXUS_PROBE_CAPTURE"',
      "fi",
      `printf '%s' '${stdout}'`,
      "",
    ].join("\n"),
  );
  chmodSync(executable, 0o755);

  process.env.PATH = `${binDir}${delimiter}${originalPath ?? ""}`;
  process.env.NEXUS_CAPTURE = capturePath;
  process.env.NEXUS_PROBE_CAPTURE = probeCapturePath;
  process.chdir(root);

  try {
    run({ capturePath, hostilePath, markerPath, probeCapturePath, leadingDashName });
  } finally {
    process.chdir(originalCwd);
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
    if (originalCapture === undefined) delete process.env.NEXUS_CAPTURE;
    else process.env.NEXUS_CAPTURE = originalCapture;
    if (originalProbeCapture === undefined) delete process.env.NEXUS_PROBE_CAPTURE;
    else process.env.NEXUS_PROBE_CAPTURE = originalProbeCapture;
    rmSync(root, { recursive: true, force: true });
  }
}

function capturedArgs(path: string): string[] {
  return readFileSync(path, "utf8").split("\0").filter(Boolean);
}

test("DOCX extraction passes a hostile filename to unzip as one literal argument", {
  skip: process.platform === "win32",
}, () => {
  withFakeCommand("unzip", ".docx", "<w:p><w:t>safe</w:t></w:p>", (context) => {
    assert.equal(extractDocxText(context.hostilePath), "safe");
    assert.deepEqual(capturedArgs(context.capturePath), [
      "-p",
      context.hostilePath,
      "word/document.xml",
    ]);
    assert.equal(existsSync(context.markerPath), false);

    assert.equal(extractDocxText(context.leadingDashName), "safe");
    assert.deepEqual(capturedArgs(context.capturePath), [
      "-p",
      resolve(context.leadingDashName),
      "word/document.xml",
    ]);
  });
});

test("MarkItDown probe and conversion never interpret a hostile filename as shell code", {
  skip: process.platform === "win32",
}, () => {
  withFakeCommand("markitdown", ".html", "converted", (context) => {
    assert.equal(convertWithMarkItDown(context.hostilePath), "converted");
    assert.deepEqual(capturedArgs(context.probeCapturePath), ["--help"]);
    assert.deepEqual(capturedArgs(context.capturePath), [context.hostilePath]);
    assert.equal(existsSync(context.markerPath), false);

    assert.equal(convertWithMarkItDown(context.leadingDashName), "converted");
    assert.deepEqual(capturedArgs(context.capturePath), [resolve(context.leadingDashName)]);
  });
});

test("PDF probe and extraction pass Python code and a hostile filename as separate arguments", {
  skip: process.platform === "win32",
}, () => {
  withFakeCommand("python3", ".pdf", '{"text":"safe","pageCount":1}', (context) => {
    assert.deepEqual(extractPdfText(context.hostilePath), { text: "safe", pageCount: 1 });
    assert.deepEqual(capturedArgs(context.probeCapturePath), ["-c", "import fitz"]);
    const args = capturedArgs(context.capturePath);
    assert.equal(args[0], "-c");
    assert.match(args[1], /fitz\.open\(sys\.argv\[1\]\)/);
    assert.equal(args[2], context.hostilePath);
    assert.equal(args.length, 3);
    assert.equal(existsSync(context.markerPath), false);

    assert.deepEqual(extractPdfText(context.leadingDashName), { text: "safe", pageCount: 1 });
    assert.equal(capturedArgs(context.capturePath)[2], resolve(context.leadingDashName));
  });
});
