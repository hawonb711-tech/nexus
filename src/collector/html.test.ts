import { test } from "node:test";
import assert from "node:assert/strict";

import { extractTitle, extractText } from "./html.js";

test("extractTitle pulls and trims text from <title>", () => {
  const html = "<html><head><title>  Hello World  </title></head><body></body></html>";
  assert.equal(extractTitle(html), "Hello World");
});

test("extractTitle decodes HTML entities and is case-insensitive on the tag", () => {
  const html = "<TITLE>Tom &amp; Jerry &lt;3</TITLE>";
  assert.equal(extractTitle(html), "Tom & Jerry <3");
});

test("extractTitle returns empty string when there is no title", () => {
  assert.equal(extractTitle("<html><body><p>no title here</p></body></html>"), "");
});

test("extractText strips tags and decodes entities from body content", () => {
  const html = "<html><body><p>Fish &amp; chips</p><p>Second line</p></body></html>";
  const out = extractText(html);
  assert.equal(out.includes("<"), false, "tags should be stripped");
  assert.equal(out.includes("Fish & chips"), true, "entities should be decoded");
  assert.equal(out.includes("Second line"), true);
});

test("extractText removes <script> and <style> blocks entirely", () => {
  const html = [
    "<html><body>",
    "<style>.x{color:red}</style>",
    "<script>var leak = 'SECRET_SCRIPT';</script>",
    "<p>Visible content</p>",
    "</body></html>",
  ].join("");
  const out = extractText(html);
  assert.equal(out.includes("Visible content"), true);
  assert.equal(out.includes("SECRET_SCRIPT"), false, "script body must not appear");
  assert.equal(out.includes("color:red"), false, "style body must not appear");
});

test("extractText converts <br> and block boundaries into newlines", () => {
  const html = "<body><p>Alpha<br>Beta</p><p>Gamma</p></body>";
  const out = extractText(html);
  assert.match(out, /Alpha\nBeta/);
  assert.match(out, /Beta\n\nGamma/);
});

test("extractText handles empty and garbage input without throwing", () => {
  assert.equal(extractText(""), "");
  assert.equal(typeof extractText("just plain text, no tags at all"), "string");
  assert.equal(typeof extractText("<<<>>> &broken; <div"), "string");
});
