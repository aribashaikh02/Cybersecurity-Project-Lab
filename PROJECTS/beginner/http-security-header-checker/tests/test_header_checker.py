# unittest is used to check that the functions behave as expected.
# Mock and patch let us test responses without sending real requests to websites.
import unittest
from unittest.mock import Mock, patch

from header_checker import normalize_url, inspect_headers, HEADER_RULES


class NormalizeUrlTests(unittest.TestCase):
    # These tests make sure the URL is cleaned up before the request is sent.
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
    # Each test uses a fake server response so the result stays predictable.
    # The checker still runs normally; only the network request is mocked.

    # A valid SAMEORIGIN value should be accepted and earn a point.
    @patch("header_checker.requests.get")
    def test_valid_x_frame_options_is_present(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"X-Frame-Options": "SAMEORIGIN"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item for item in report["headers"] if item["header"] == "X-Frame-Options"
        )

        self.assertEqual(result["status"], "PRESENT")
        self.assertEqual(report["checklist_score"], 1)

    # Having the header is not enough if its value is not recognized.
    @patch("header_checker.requests.get")
    def test_invalid_x_frame_options_needs_review(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"X-Frame-Options": "INVALID"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item for item in report["headers"] if item["header"] == "X-Frame-Options"
        )

        self.assertEqual(result["status"], "REVIEW")
        self.assertEqual(report["checklist_score"], 0)

    # This checks presence only; the checker does not audit CSP directives yet.
    @patch("header_checker.requests.get")
    def test_present_csp_is_not_automatically_flagged(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Content-Security-Policy": "default-src 'self'"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item
            for item in report["headers"]
            if item["header"] == "Content-Security-Policy"
        )
        self.assertIn("not automatically validated", result["purpose"])
        self.assertEqual(result["status"], "PRESENT")
        self.assertEqual(report["checklist_score"], 1)

    # X-Content-Type-Options should use the exact value "nosniff".
    @patch("header_checker.requests.get")
    def test_invalid_content_type_options_does_not_score(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"X-Content-Type-Options": "invalid"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item
            for item in report["headers"]
            if item["header"] == "X-Content-Type-Options"
        )

        self.assertEqual(result["status"], "REVIEW")
        self.assertEqual(report["checklist_score"], 0)

    # Even when none of the headers are returned, all seven rules are checked.
    @patch("header_checker.requests.get")
    def test_all_seven_headers_are_counted(self, mock_get):
        # Build the response that requests.get would normally return.
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

    # A correct nosniff value should count as one successful check.
    @patch("header_checker.requests.get")
    def test_present_x_content_type_options_scores_a_point(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"X-Content-Type-Options": "nosniff"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")

        self.assertEqual(report["checklist_score"], 1)
        self.assertEqual(report["checklist_possible"], 7)

    # HSTS is checked on HTTPS, and max-age must contain a number.
    @patch("header_checker.requests.get")
    def test_valid_hsts_max_age_is_present(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Strict-Transport-Security": "max-age=31536000"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item
            for item in report["headers"]
            if item["header"] == "Strict-Transport-Security"
        )

        self.assertEqual(result["status"], "PRESENT")
        self.assertEqual(report["checklist_score"], 1)

    # A non-numeric max-age should be flagged instead of counted.
    @patch("header_checker.requests.get")
    def test_invalid_hsts_max_age_needs_review(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Strict-Transport-Security": "max-age=abc"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item
            for item in report["headers"]
            if item["header"] == "Strict-Transport-Security"
        )

        self.assertEqual(result["status"], "REVIEW")
        self.assertEqual(report["checklist_score"], 0)

    # Check that a standard Referrer-Policy value is recognized.
    @patch("header_checker.requests.get")
    def test_valid_referrer_policy_is_present(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Referrer-Policy": "strict-origin-when-cross-origin"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item for item in report["headers"] if item["header"] == "Referrer-Policy"
        )

        self.assertEqual(result["status"], "PRESENT")
        self.assertEqual(report["checklist_score"], 1)

    # Unknown policy names should not receive a checklist point.
    @patch("header_checker.requests.get")
    def test_invalid_referrer_policy_needs_review(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Referrer-Policy": "not-a-policy"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item for item in report["headers"] if item["header"] == "Referrer-Policy"
        )

        self.assertEqual(result["status"], "REVIEW")
        self.assertEqual(report["checklist_score"], 0)

    # same-origin is one of the recognized COOP policy values.
    @patch("header_checker.requests.get")
    def test_valid_coop_policy_is_present(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Cross-Origin-Opener-Policy": "same-origin"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item
            for item in report["headers"]
            if item["header"] == "Cross-Origin-Opener-Policy"
        )

        self.assertEqual(result["status"], "PRESENT")
        self.assertEqual(report["checklist_score"], 1)

    # An unrecognized COOP value should be marked for review.
    @patch("header_checker.requests.get")
    def test_invalid_coop_policy_needs_review(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Cross-Origin-Opener-Policy": "invalid"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item
            for item in report["headers"]
            if item["header"] == "Cross-Origin-Opener-Policy"
        )

        self.assertEqual(result["status"], "REVIEW")
        self.assertEqual(report["checklist_score"], 0)

    # Keep the score in sync with the seven headers listed in HEADER_RULES.
    def test_all_seven_rules_are_included_in_score(self):
        self.assertEqual(len(HEADER_RULES), 7)
        self.assertTrue(all(rule[3] for rule in HEADER_RULES))

    # max-age is required for an HSTS policy to be useful.
    @patch("header_checker.requests.get")
    def test_hsts_missing_max_age_is_review(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Strict-Transport-Security": "includeSubDomains"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item
            for item in report["headers"]
            if item["header"] == "Strict-Transport-Security"
        )

        self.assertEqual(result["status"], "REVIEW")

    # Letters or other non-numeric values are not valid max-age values.
    @patch("header_checker.requests.get")
    def test_hsts_invalid_max_age_is_review(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Strict-Transport-Security": "max-age=abc"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item
            for item in report["headers"]
            if item["header"] == "Strict-Transport-Security"
        )

        self.assertEqual(result["status"], "REVIEW")

    # Two max-age directives can conflict, so this case should be reviewed.
    @patch("header_checker.requests.get")
    def test_hsts_duplicate_max_age_is_review(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Strict-Transport-Security": "max-age=31536000; max-age=0"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item
            for item in report["headers"]
            if item["header"] == "Strict-Transport-Security"
        )

        self.assertEqual(result["status"], "REVIEW")

    # Browsers can receive a list of policies; a recognized value should be found.
    @patch("header_checker.requests.get")
    def test_referrer_policy_multiple_values(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {
            "Referrer-Policy": "invalid-policy, strict-origin-when-cross-origin"
        }
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item for item in report["headers"] if item["header"] == "Referrer-Policy"
        )

        self.assertEqual(result["status"], "PRESENT")

    # HSTS should be assessed using the final URL after redirects are followed.
    @patch("header_checker.requests.get")
    def test_hsts_is_checked_after_http_to_https_redirect(self, mock_get):
        # Build the response that requests.get would normally return.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = [Mock()]
        response.headers = {"Strict-Transport-Security": "max-age=31536000"}
        mock_get.return_value = response

        report = inspect_headers("http://example.com")
        result = next(
            item
            for item in report["headers"]
            if item["header"] == "Strict-Transport-Security"
        )

        self.assertEqual(result["status"], "PRESENT")
        self.assertTrue(report["https"])
        self.assertEqual(report["redirect_count"], 1)

    # HSTS should not count when the final response is still HTTP.
    @patch("header_checker.requests.get")
    def test_hsts_is_info_when_final_response_is_http(self, mock_get):
        response = Mock()
        response.url = "http://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Strict-Transport-Security": "max-age=31536000"}
        mock_get.return_value = response

        report = inspect_headers("http://example.com")
        result = next(
            item
            for item in report["headers"]
            if item["header"] == "Strict-Transport-Security"
        )

        self.assertEqual(result["status"], "INFO")
        self.assertFalse(result["included_in_checklist_score"])
        self.assertFalse(report["https"])

    # A valid policy should still be accepted when an unknown value follows it.
    @patch("header_checker.requests.get")
    def test_referrer_policy_ignores_unrecognized_values(self, mock_get):
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Referrer-Policy": "strict-origin, unknown-policy"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item for item in report["headers"] if item["header"] == "Referrer-Policy"
        )

        self.assertEqual(result["status"], "PRESENT")

    # Unknown values should not make a valid policy fail.
    @patch("header_checker.requests.get")
    def test_referrer_policy_all_unrecognized_values_are_review(self, mock_get):
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Referrer-Policy": "unknown-policy, invalid-policy"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item for item in report["headers"] if item["header"] == "Referrer-Policy"
        )

        self.assertEqual(result["status"], "REVIEW")

        # A CSP header is marked present, but its directives aren't fully checked.

        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self'"
        }
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item
            for item in report["headers"]
            if item["header"] == "Content-Security-Policy"
        )

        self.assertEqual(result["status"], "PRESENT")
        self.assertIn("not automatically validated", result["purpose"])

        # An unrecognized X-Frame-Options value should be flagged for review.
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"X-Frame-Options": "ALLOW-FROM example.com"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item for item in report["headers"] if item["header"] == "X-Frame-Options"
        )

        self.assertEqual(result["status"], "REVIEW")

        # The header should be reviewed if its value isn't nosniff.
    @patch("header_checker.requests.get")
    def test_permissions_policy_is_present_without_directive_validation(self, mock_get):
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Permissions-Policy": "camera=(), microphone=()"}
        mock_get.return_value = response

        report = inspect_headers("https://example.com")
        result = next(
            item for item in report["headers"] if item["header"] == "Permissions-Policy"
        )

        self.assertEqual(result["status"], "PRESENT")

        # Only headers marked PRESENT should earn points.

    @patch("header_checker.requests.get")
    def test_review_headers_do_not_increase_score(self, mock_get):
        response = Mock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {
            "X-Content-Type-Options": "invalid-value",
            "X-Frame-Options": "invalid-value",
        }
        mock_get.return_value = response

        report = inspect_headers("https://example.com")

        self.assertEqual(report["checklist_score"], 0)
        self.assertEqual(report["checklist_possible"], len(HEADER_RULES))

        # HSTS should be excluded from both the score and possible points over HTTP.

    @patch("header_checker.requests.get")
    def test_hsts_http_response_is_excluded_from_score(self, mock_get):
        response = Mock()
        response.url = "http://example.com/"
        response.status_code = 200
        response.history = []
        response.headers = {"Strict-Transport-Security": "max-age=31536000"}
        mock_get.return_value = response

        report = inspect_headers("http://example.com")

        self.assertEqual(report["checklist_possible"], len(HEADER_RULES) - 1)
        self.assertFalse(report["https"])


if __name__ == "__main__":
    unittest.main()
