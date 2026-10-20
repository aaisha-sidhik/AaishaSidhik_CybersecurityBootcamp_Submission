# Automated Web Security Header Scanner

**IBM SkillsBuild National Cybersecurity Bootcamp 2026 — BharatCares**

## Overview
A lightweight Python command-line tool that sends one HTTP GET request to an authorized website and reviews selected security-related response settings. It checks common HTTP security headers, the `Access-Control-Allow-Origin` CORS header, cookie flags, HTTPS use, and potentially revealing `Server` / `X-Powered-By` headers. It writes a JSON report and can optionally write an HTML report.

This is a basic configuration review tool, not a full vulnerability scanner or penetration test. A `PASS` result does not guarantee that a website is secure; findings should be interpreted in context and verified manually.

## Features
- Checks Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy.
- Reviews a wildcard CORS origin and the credentials header.
- Reviews `Secure`, `HttpOnly`, and `SameSite` cookie attributes where `Set-Cookie` is returned.
- Checks whether the final response URL uses HTTPS.
- Flags `Server` and `X-Powered-By` headers for review.
- Saves findings to JSON and optional HTML output.
- Uses a request timeout and follows redirects.

## Technologies
- Python 3.10 or later recommended
- `requests`
- Python standard library: `argparse`, `dataclasses`, `datetime`, `html`, `json`, `pathlib`, `sys`, and `urllib.parse`

## Requirements
Install Python, then install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Run
Run against a site you own or have explicit permission to test:

```bash
python AaishaSidhik_AutomatedWebSecurityHeaderScanner.py https://example.com
```

Generate both JSON and HTML reports:

```bash
python AaishaSidhik_AutomatedWebSecurityHeaderScanner.py https://example.com --output scan_report.json --html scan_report.html
```

If you omit the URL, the script prompts you to enter one:

```bash
python AaishaSidhik_AutomatedWebSecurityHeaderScanner.py
```

Optional timeout (seconds, allowed range 1–120):

```bash
python AaishaSidhik_AutomatedWebSecurityHeaderScanner.py https://example.com --timeout 15
```

## Output
- `scan_report.json`: scan metadata, counts of PASS / REVIEW / WARN findings, evidence, and recommendations.
- `scan_report.html`: readable table of findings (created only when `--html` is provided).

Reports are saved to the current working directory unless an output path is specified.

## Dataset
No machine-learning dataset is required. This project inspects live HTTP response headers. For a reproducible assessment, use a local test web server or a website for which you have authorization, and record the tested URL and date in your report. Do not scan third-party systems without permission.

## Checks and limitations
- A single GET request is made; the tool does not crawl pages or submit forms.
- It does not exploit vulnerabilities or test authenticated application behavior.
- It checks header presence and a few simple conditions; it does not validate whether every policy is well designed.
- CORS behavior can depend on the request's `Origin` header and browser enforcement; this script's basic response-header check is not a complete CORS test.
- Cookie flags are reviewed only for cookies visible in the response. Cookies set on other routes or through other mechanisms may not be covered.
- `PASS`, `REVIEW`, and `WARN` are scanner labels, not a formal security certification.

## Ethical use
Only test websites you own or are authorized to assess. Keep request rates low, follow organizational rules, and do not use this tool to bypass access controls.

## Author
Aaisha Sidhik
