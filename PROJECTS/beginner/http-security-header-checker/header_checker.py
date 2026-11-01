"""Check common HTTP security response headers for an authorized target."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

# These values are sent with each request so the checker identifies itself
# and doesn't wait forever if the target takes too long to respond.
USER_AGENT = "Cybersecurity-Project-Lab-HeaderChecker/1.0"
TIMEOUT_SECONDS = 10

# Each entry contains the header name, what it does, a basic recommendation,
# and whether it should count towards the checklist score.
HEADER_RULES = [
    (
        "Content-Security-Policy",
        "Helps limit sources from which browsers may load content.",
        "Define a policy appropriate to the application. Consider report-only mode when introducing a policy.",
        True,
    ),
    (
        "Strict-Transport-Security",
        "Tells browsers to use HTTPS for future visits after a valid HTTPS response.",
        "Configure HSTS after HTTPS is working correctly for the intended hostnames. Never send HSTS over plain HTTP.",
        True,
    ),
    (
        "X-Content-Type-Options",
        "Helps prevent browser MIME-type sniffing.",
        "The usual value is `nosniff`.",
        True,
    ),
    (
        "X-Frame-Options",
        "Provides older-browser protection against unwanted framing.",
        "Consider `DENY` or `SAMEORIGIN` as appropriate. CSP `frame-ancestors` is more flexible.",
        True,
    ),
    (
        "Referrer-Policy",
        "Controls how much referrer information browsers send.",
        "Choose a policy that fits privacy and application requirements; `strict-origin-when-cross-origin` is a common starting point.",
        True,
    ),
    (
        "Permissions-Policy",
        "Controls access to selected browser features, depending on browser support.",
        "Restrict features the application does not need. The correct policy depends on the app.",
        True,
    ),
    (
        "Cross-Origin-Opener-Policy",
        "Can isolate a browsing context group and reduce some cross-origin interactions.",
        "Review whether `same-origin` or another value fits authentication, popup, and integration flows.",
        True,
    ),
]


def normalize_url(raw_url: str) -> str:
    # Remove extra spaces before checking the URL.
    candidate = raw_url.strip()
    if not candidate:
        raise ValueError("Please enter a URL.")

    # If the user leaves out the scheme, try HTTPS by default.
    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")

    # Only web URLs are accepted by this checker.
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("That URL does not contain a valid hostname.")

    # Avoid URLs that include login details.
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not accepted.")

    return parsed.geturl()


def inspect_headers(url: str) -> dict:
    # Normalize the input first, then make the request and follow redirects.
    normalized = normalize_url(url)
    response = requests.get(
        normalized,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
        timeout=TIMEOUT_SECONDS,
        allow_redirects=True,
    )

    # Use the final URL after redirects to decide whether the response is HTTPS.
    final_url = response.url
    is_https = urlparse(final_url).scheme.lower() == "https"

    # HTTP header names are case-insensitive, so lowercase them for easy lookup.
    response_headers = {k.lower(): v.strip() for k, v in response.headers.items()}
    results, score, possible = [], 0, 0

    # Check each header listed in HEADER_RULES.
    for name, purpose, recommendation, counted in HEADER_RULES:
        value = response_headers.get(name.lower())
        status = "PRESENT" if value else "MISSING"
        note = purpose
        tip = recommendation

        # HSTS only counts when it comes from an HTTPS response.
        if name == "Strict-Transport-Security" and not is_https:
            status, counted = "INFO", False
            note = "HSTS is meaningful only when delivered over HTTPS."
            tip = "The final response was not HTTPS. Check HTTPS configuration before assessing HSTS."

        # Check that this header uses the expected value.
        elif value and name == "X-Content-Type-Options":
            if value.lower() != "nosniff":
                status = "REVIEW"
                note = "The header is present, but its value is not the expected nosniff value."

        # X-Frame-Options should use one of these recognized values.
        elif value and name == "X-Frame-Options":
            if value.strip().lower() not in {"deny", "sameorigin"}:
                status = "REVIEW"
                note = "The X-Frame-Options value is not a recognized standard value."

        # We check that CSP exists, but don't try to fully validate its directives here.
        elif value and name == "Content-Security-Policy":
            note = "The CSP header is present, but its directives are not automatically validated."
            tip = "Review the directives to ensure they suit the application and avoid unnecessarily broad sources."

        # HSTS should contain exactly one max-age value, and it should be numeric.
        elif value and name == "Strict-Transport-Security":
            directives = [part.strip().lower() for part in value.split(";")]
            max_age_values = [
                part.split("=", 1)[1].strip()
                for part in directives
                if part.startswith("max-age=")
            ]

            if len(max_age_values) != 1 or not max_age_values[0].isdigit():
                status = "REVIEW"
                note = "The HSTS header is present, but its max-age directive is missing or invalid."

        # Referrer-Policy can contain more than one comma-separated value.
        elif value and name == "Referrer-Policy":
            valid_policies = {
                "no-referrer",
                "no-referrer-when-downgrade",
                "origin",
                "origin-when-cross-origin",
                "same-origin",
                "strict-origin",
                "strict-origin-when-cross-origin",
                "unsafe-url",
            }
            # collect recognized values first, then check whether the list is empty.
            policies = [part.strip().lower() for part in value.split(",")]
            recognized_policies = [
                policy for policy in policies
                if policy in valid_policies
            ]

            if not recognized_policies:
                status = "REVIEW"
                note = "No recognized Referrer-Policy value was found."

        # Make sure COOP uses a value the checker recognizes.
        elif value and name == "Cross-Origin-Opener-Policy":
            valid_policies = {
                "unsafe-none",
                "same-origin-allow-popups",
                "same-origin",
                "noopener-allow-popups",
            }
            policy = value.strip().lower()

            if policy not in valid_policies:
                status = "REVIEW"
                note = "The Cross-Origin-Opener-Policy value is not recognized."

        # Only headers marked as countable contribute to the checklist score.
        if counted:
            possible += 1
            if status == "PRESENT":
                score += 1
        # Count only headers that are eligible for the checklist score.
        # score increases only when an eligible header has status PRESENT. REVIEW, MISSING, and INFO don't earn a point.

        # Keep the result for this header so it can be printed or saved as JSON.
        results.append(
            {
                "header": name,
                "status": status,
                "value": value,
                "purpose": note,
                "recommendation": tip,
                "included_in_checklist_score": counted,
            }
        )

    # Return the scan details and all header results in one report.
    return {
        "tool": "HTTP Security Header Checker",
        "tool_version": "1.0.0",
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "requested_url": normalized,
        "final_url": final_url,
        "http_status": response.status_code,
        "https": is_https,
        "redirect_count": len(response.history),
        "checklist_score": score,
        "checklist_possible": possible,
        "score_note": "Educational checklist only, not a formal security rating. Header presence does not validate the policy.",
        "headers": results,
    }


def print_report(report: dict) -> None:
    # Display the main details first, followed by each header's result.
    print("\nHTTP Security Header Checker")
    print("=" * 29)
    print(f"Target:      {report['requested_url']}")
    print(f"Final URL:   {report['final_url']}")
    print(f"HTTP status: {report['http_status']}")
    print(f"Redirects:   {report['redirect_count']}\n")
    for item in report["headers"]:
        print(f"[{item['status']:<7}] {item['header']}")
        if item["value"]:
            print(f"          Value: {item['value']}")
        print(f"          Why:   {item['purpose']}")
        if item["status"] in {"MISSING", "REVIEW"}:
            print(f"          Tip:   {item['recommendation']}")
    print(
        f"\nChecklist score: {report['checklist_score']}/{report['checklist_possible']} (educational only)"
    )
    print(report["score_note"])


def main() -> int:
    # argparse handles the target URL and optional output-file argument.
    parser = argparse.ArgumentParser(
        description="Check common HTTP security response headers on a site you own or are authorized to assess."
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument(
        "--output", "-o", type=Path, help="Optional JSON report path, e.g. report.json"
    )
    args = parser.parse_args()

    # Handle common request and input errors without showing a full traceback.
    try:
        report = inspect_headers(args.url)
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    except requests.exceptions.Timeout:
        print(f"Request timed out after {TIMEOUT_SECONDS} seconds.", file=sys.stderr)
        return 1
    except requests.exceptions.SSLError as exc:
        print(f"TLS/SSL error: {exc}", file=sys.stderr)
        print(
            "Check the URL and certificate. Do not disable certificate verification to bypass this error.",
            file=sys.stderr,
        )
        return 1
    except requests.exceptions.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    print_report(report)

    # Save the same report as a JSON file if the user asked for one.
    if args.output:
        try:
            args.output.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            print(f"Could not write report: {exc}", file=sys.stderr)
            return 1
        print(f"\nJSON report saved to: {args.output}")
    return 0


# Run the command-line tool only when this file is executed directly.
if __name__ == "__main__":
    raise SystemExit(main())
