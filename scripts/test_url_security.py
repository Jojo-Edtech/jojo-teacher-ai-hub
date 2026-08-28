from __future__ import annotations

import unittest

import update_data


class UrlSecurityTests(unittest.TestCase):
    def test_only_plain_http_urls_are_retained(self) -> None:
        self.assertEqual(
            update_data.normalize_http_url("https://example.org/path?q=1#section"),
            "https://example.org/path?q=1#section",
        )
        self.assertEqual(update_data.normalize_http_url("http://example.org/"), "http://example.org/")
        for unsafe in [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "//example.org/path",
            "https://user:password@example.org/",
            "https://example.org\\@evil.example/",
            "https://example.org/\nnext",
        ]:
            with self.subTest(url=unsafe):
                self.assertEqual(update_data.normalize_http_url(unsafe), "")

    def test_item_sanitizer_drops_unsafe_links_and_caps_text(self) -> None:
        item = {
            "title": "T" * 900,
            "source": "Test source",
            "summary": "AI education for teachers",
            "url": "javascript:alert(1)",
            "registerUrl": "data:text/html,boom",
            "image": "file:///etc/passwd",
        }
        update_data.sanitize_item(item)
        self.assertEqual(len(item["title"]), update_data.TEXT_FIELD_LIMITS["title"])
        self.assertEqual(item["url"], "")
        self.assertNotIn("registerUrl", item)
        self.assertNotIn("image", item)
        self.assertEqual(update_data.enrich(item)["url"], "")

    def test_domain_matching_rejects_substring_spoofs(self) -> None:
        self.assertTrue(update_data.url_has_domain("https://www.linkedin.com/posts/1", "linkedin.com"))
        self.assertFalse(update_data.url_has_domain("https://linkedin.com.evil.example/", "linkedin.com"))
        self.assertFalse(update_data.url_has_domain("https://evil.example/?next=linkedin.com", "linkedin.com"))

    def test_page_detail_fetch_uses_hostname_allowlist(self) -> None:
        self.assertTrue(
            update_data.should_fetch_page_details(
                {"url": "https://web.edu.hku.hk/news/example", "source": "HKU Education"}
            )
        )
        self.assertFalse(
            update_data.should_fetch_page_details(
                {"url": "https://evil.example/?source=edb.gov.hk", "source": "EdCity"}
            )
        )

    def test_fetch_targets_and_redirects_stay_on_trusted_public_domains(self) -> None:
        self.assertTrue(update_data.is_safe_fetch_target("https://www.edb.gov.hk/tc/news"))
        self.assertTrue(
            update_data.redirect_is_allowed(
                "https://www.edb.gov.hk/tc/news",
                "https://edb.gov.hk/tc/other",
            )
        )
        for unsafe in [
            "http://www.edb.gov.hk/tc/news",
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "https://edb.gov.hk.evil.example/",
            "https://example.org/",
        ]:
            with self.subTest(url=unsafe):
                self.assertFalse(update_data.is_safe_fetch_target(unsafe))
                self.assertFalse(
                    update_data.redirect_is_allowed("https://www.edb.gov.hk/tc/news", unsafe)
                )

    def test_response_reader_enforces_content_and_stream_limits(self) -> None:
        class FakeResponse:
            def __init__(self, body: bytes, content_length: str | None = None) -> None:
                self.body = body
                self.headers = {} if content_length is None else {"Content-Length": content_length}

            def read(self, limit: int) -> bytes:
                return self.body[:limit]

        self.assertEqual(update_data.read_limited_response(FakeResponse(b"ok", "2")), b"ok")
        with self.assertRaises(ValueError):
            update_data.read_limited_response(
                FakeResponse(b"", str(update_data.MAX_RESPONSE_BYTES + 1))
            )
        with self.assertRaises(ValueError):
            update_data.read_limited_response(
                FakeResponse(b"x" * (update_data.MAX_RESPONSE_BYTES + 1))
            )


if __name__ == "__main__":
    unittest.main()
