"""Check common HTTP security response headers for an authorized target."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

USER_AGENT = "Cybersecurity-Project-Lab-HeaderChecker/1.0"
TIMEOUT_SECONDS = 10

HEADER_RULES = [
    ("Content-Security-Policy", "Helps limit sources from which browsers may load content.",
     "Define a policy appropriate to the application. Consider report-only mode when introducing a policy.", True),
    ("Strict-Transport-Security", "Tells browsers to use HTTPS for future visits after a valid HTTPS response.",
     "Configure HSTS after HTTPS is working correctly for the intended hostnames. Never send HSTS over plain HTTP.", True),
    ("X-Content-Type-Options", "Helps prevent browser MIME-type sniffing.",
     "The usual value is `nosniff`.", True),
    ("X-Frame-Options", "Provides older-browser protection against unwanted framing.",
     "Consider `DENY` or `SAMEORIGIN` as appropriate. CSP `frame-ancestors` is more flexible.", True),
    ("Referrer-Policy", "Controls how much referrer information browsers send.",
     "Choose a policy that fits privacy and application requirements; `strict-origin-when-cross-origin` is a common starting point.", True),
    ("Permissions-Policy", "Controls access to selected browser features, depending on browser support.",
     "Restrict features the application does not need. The correct policy depends on the app.", True),
    ("Cross-Origin-Opener-Policy", "Can isolate a browsing context group and reduce some cross-origin interactions.",
     "Review whether `same-origin` or another value fits authentication, popup, and integration flows.", True),
]


def normalize_url(raw_url: str) -> str:
    candidate = raw_url.strip()
    if not candidate:
        raise ValueError("Please enter a URL.")
    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("That URL does not contain a valid hostname.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not accepted.")
    return parsed.geturl()


def inspect_headers(url: str) -> dict:
    normalized = normalize_url(url)
    response = requests.get(
        normalized,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
        timeout=TIMEOUT_SECONDS,
        allow_redirects=True,
    )
    final_url = response.url
    is_https = urlparse(final_url).scheme.lower() == "https"
    response_headers = {k.lower(): v.strip() for k, v in response.headers.items()}
    results, score, possible = [], 0, 0

    for name, purpose, recommendation, counted in HEADER_RULES:
        value = response_headers.get(name.lower())
        status = "PRESENT" if value else "MISSING"
        note = purpose
        tip = recommendation

        if name == "Strict-Transport-Security" and not is_https:
            status, counted = "INFO", False
            note = "HSTS is meaningful only when delivered over HTTPS."
            tip = "The final response was not HTTPS. Check HTTPS configuration before assessing HSTS."
        elif value and name == "X-Content-Type-Options" and value.lower() != "nosniff":
            status = "REVIEW"
        elif value and name in {"Content-Security-Policy", "X-Frame-Options"}:
            status = "REVIEW"
            if name == "Content-Security-Policy":
                note = "A CSP header exists, but its directives need review to judge how restrictive it is."

        if counted:
            possible += 1
            if status in {"PRESENT", "REVIEW"}:
                score += 1

        results.append({
            "header": name, "status": status, "value": value,
            "purpose": note, "recommendation": tip,
            "included_in_checklist_score": counted,
        })

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
    print(f"\nChecklist score: {report['checklist_score']}/{report['checklist_possible']} (educational only)")
    print(report["score_note"])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check common HTTP security response headers on a site you own or are authorized to assess."
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--output", "-o", type=Path, help="Optional JSON report path, e.g. report.json")
    args = parser.parse_args()

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
        print("Check the URL and certificate. Do not disable certificate verification to bypass this error.", file=sys.stderr)
        return 1
    except requests.exceptions.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    print_report(report)
    if args.output:
        try:
            args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Could not write report: {exc}", file=sys.stderr)
            return 1
        print(f"\nJSON report saved to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
