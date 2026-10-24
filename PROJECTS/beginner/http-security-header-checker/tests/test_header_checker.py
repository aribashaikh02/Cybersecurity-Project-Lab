import unittest
from header_checker import normalize_url


class NormalizeUrlTests(unittest.TestCase):
    def test_adds_https_when_scheme_is_missing(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")

    def test_accepts_http(self):
        self.assertEqual(normalize_url("http://example.com"), "http://example.com")

    def test_rejects_other_schemes(self):
        with self.assertRaises(ValueError):
            normalize_url("ftp://example.com")

    def test_rejects_missing_host(self):
        with self.assertRaises(ValueError):
            normalize_url("https://")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            normalize_url("https://user:password@example.com")


if __name__ == "__main__":
    unittest.main()
