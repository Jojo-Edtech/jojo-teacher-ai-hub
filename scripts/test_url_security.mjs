import assert from "node:assert/strict";
import test from "node:test";

import { isGovernmentSource, safeExternalUrl } from "../docs/url-security.mjs";

test("safeExternalUrl permits ordinary HTTP and HTTPS links", () => {
  assert.equal(safeExternalUrl("https://example.org/path?q=1"), "https://example.org/path?q=1");
  assert.equal(safeExternalUrl("http://example.org/"), "http://example.org/");
});

test("safeExternalUrl rejects executable, local, credential, and ambiguous links", () => {
  for (const unsafe of [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "//example.org/path",
    "https://user:password@example.org/",
    "https://example.org\\@evil.example/",
    "https://example.org/\nnext",
  ]) {
    assert.equal(safeExternalUrl(unsafe), "", unsafe);
  }
});

test("isGovernmentSource accepts exact government labels and bounded EDB tokens", () => {
  assert.equal(isGovernmentSource({ source: " News.gov.hk " }), true);
  assert.equal(isGovernmentSource({ source: "香港教育局 EDB" }), true);
  assert.equal(isGovernmentSource({ category: "EDB update" }), true);
});

test("isGovernmentSource rejects attacker-controlled substring lookalikes", () => {
  for (const item of [
    { source: "https://evil.example/?next=news.gov.hk" },
    { source: "evil-news.gov.hk" },
    { source: "news.gov.hk.evil.example" },
    { source: "notedb" },
  ]) {
    assert.equal(isGovernmentSource(item), false, JSON.stringify(item));
  }
});
