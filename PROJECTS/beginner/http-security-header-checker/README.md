# HTTP Security Header Checker

A beginner-friendly Python CLI that reviews common HTTP security response headers for a website you own or are authorized to assess.

## Features
- Checks common browser security headers
- Follows redirects and reports the final URL
- Explains each header and offers practical remediation hints
- Writes a JSON report
- Handles invalid URLs, timeouts, and connection errors

## Requirements
- Python 3.10+
- `requests`

## Setup (Windows / VS Code)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, use the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run

```powershell
python header_checker.py https://example.com
python header_checker.py https://example.com --output report.json
```

Only check websites you own or are authorized to assess.

## Results
- **PRESENT** — header exists; its policy may still be weak.
- **MISSING** — header was absent from the final response inspected.
- **REVIEW** — header exists but needs human review.
- **INFO** — contextual observation, not a security verdict.

The score is an educational checklist, not a formal security rating. Header presence does not prove that the policy is effective.

## Headers checked
`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cross-Origin-Opener-Policy`.

## Limitations
This checks response headers only. It does not crawl pages, test exploitability, inspect application code, or replace a professional security assessment. HSTS is assessed only when the final response is HTTPS.

## Responsible use
This tool sends one normal GET request (following redirects) with a timeout. Use only on systems you own or have explicit permission to assess. Review generated reports before publishing because they contain the target URL and response details.

## License
MIT — see `LICENSE`.
