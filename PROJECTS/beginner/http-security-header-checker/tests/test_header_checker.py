import unittest
from unittest.mock import Mock, patch

from header_checker import normalize_url, inspect_headers, HEADER_RULES


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


class HeaderScoringTests(unittest.TestCase):
    @patch("header_checker.requests.get")
    def test_all_seven_headers_are_counted(self, mock_get):
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")

        self.assertEqual(len(report["headers"]), 7)
        self.assertEqual(report["checklist_possible"], 7)
        self.assertEqual(report["checklist_score"], 0)

    @patch("header_checker.requests.get")
    def test_present_x_content_type_options_scores_a_point(self, mock_get):
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"X-Content-Type-Options": "nosniff"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")

        self.assertEqual(report["checklist_score"], 1)
        self.assertEqual(report["checklist_possible"], 7)

    def test_all_seven_rules_are_included_in_score(self):
        self.assertEqual(len(HEADER_RULES), 7)
        self.assertTrue(all(rule[3] for rule in HEADER_RULES))


if __name__ == "__main__":
    unittest.main()
