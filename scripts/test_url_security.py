from __future__ import annotations

import unittest

import update_data


class UrlSecurityTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
