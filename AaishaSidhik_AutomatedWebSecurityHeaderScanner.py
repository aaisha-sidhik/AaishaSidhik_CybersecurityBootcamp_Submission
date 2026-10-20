#!/usr/bin/env python3
"""Automated Web Security Header Scanner.

A defensive, low-impact scanner for websites you own or are authorized to test.
It sends one HTTP GET request and reviews common security headers, CORS,
cookie flags, HTTPS usage, and information-disclosure headers.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests
from requests import Response


@dataclass
class Finding:
    category: str
    check: str
    severity: str
    status: str
    evidence: str
    recommendation: str


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "High",
        "Define a restrictive Content-Security-Policy to reduce the impact of XSS and injection.",
    ),
    "Strict-Transport-Security": (
        "Medium",
        "Enable HSTS after confirming the entire site works correctly over HTTPS.",
    ),
    "X-Content-Type-Options": (
        "Low",
        "Set X-Content-Type-Options: nosniff.",
    ),
    "X-Frame-Options": (
        "Medium",
        "Set X-Frame-Options: DENY/SAMEORIGIN or use CSP frame-ancestors.",
    ),
    "Referrer-Policy": (
        "Low",
        "Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin.",
    ),
    "Permissions-Policy": (
        "Low",
        "Restrict browser features that the application does not need.",
    ),
}


def normalize_url(value: str) -> str:
    """Add HTTPS when no scheme is supplied and validate the URL structure."""
    value = value.strip()
    if not value:
        raise ValueError("Please provide a target URL or hostname.")
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL, such as https://example.com.")
    if any(char.isspace() for char in value):
        raise ValueError("The URL must not contain spaces.")
    return value


def add_header_findings(response: Response) -> list[Finding]:
    findings: list[Finding] = []
    headers = {key.lower(): value for key, value in response.headers.items()}

    for header, (severity, recommendation) in SECURITY_HEADERS.items():
        value = headers.get(header.lower())
        findings.append(
            Finding(
                category="Security headers",
                check=header,
                severity=severity,
                status="PASS" if value else "WARN",
                evidence=value or "Header not present",
                recommendation="No action required." if value else recommendation,
            )
        )

    cors = headers.get("access-control-allow-origin")
    credentials = headers.get("access-control-allow-credentials", "").lower()

    if cors == "*" and credentials == "true":
        status, severity = "WARN", "High"
        evidence = "Wildcard origin combined with credentials=true"
        recommendation = (
            "Do not combine Access-Control-Allow-Origin: * with credentials; "
            "allow only trusted origins."
        )
    elif cors == "*":
        status, severity = "REVIEW", "Medium"
        evidence = "Access-Control-Allow-Origin: *"
        recommendation = (
            "Review whether every origin needs access. Use an explicit allowlist "
            "when the endpoint returns sensitive data."
        )
    else:
        status, severity = "PASS", "Medium"
        evidence = cors or "No wildcard CORS origin observed"
        recommendation = (
            "Review the allowed origin against the application's intended policy."
            if cors
            else "No wildcard CORS origin observed; this does not prove the CORS policy is safe."
        )

    findings.append(
        Finding(
            "CORS",
            "Access-Control-Allow-Origin",
            severity,
            status,
            evidence,
            recommendation,
        )
    )

    for key in ("Server", "X-Powered-By"):
        value = headers.get(key.lower())
        findings.append(
            Finding(
                category="Information disclosure",
                check=key,
                severity="Low",
                status="REVIEW" if value else "PASS",
                evidence=value or "Not disclosed",
                recommendation=(
                    "Minimize unnecessary version and framework details."
                    if value
                    else "No action required."
                ),
            )
        )
    return findings


def add_cookie_findings(response: Response) -> list[Finding]:
    findings: list[Finding] = []
    raw = response.headers.get("Set-Cookie")
    if not raw:
        return [
            Finding(
                "Cookies",
                "Set-Cookie flags",
                "Medium",
                "PASS",
                "No Set-Cookie header returned",
                "No action required.",
            )
        ]

    try:
        cookie_lines = response.raw.headers.getlist("Set-Cookie")
    except (AttributeError, TypeError):
        cookie_lines = [raw]

    for cookie in cookie_lines:
        name = cookie.split("=", 1)[0].strip()
        lower = cookie.lower()
        missing = [
            flag
            for flag, present in (
                ("Secure", "; secure" in lower),
                ("HttpOnly", "; httponly" in lower),
                ("SameSite", "samesite=" in lower),
            )
            if not present
        ]
        findings.append(
            Finding(
                category="Cookies",
                check=f"{name} cookie flags",
                severity="Medium",
                status="WARN" if missing else "PASS",
                evidence=(
                    "Missing: " + ", ".join(missing)
                    if missing
                    else "Secure, HttpOnly, and SameSite present"
                ),
                recommendation=(
                    "Set Secure, HttpOnly, and an appropriate SameSite attribute."
                    if missing
                    else "No action required."
                ),
            )
        )
    return findings


def scan(url: str, timeout: int = 10) -> dict:
    """Scan a single URL with one GET request and return structured findings."""
    url = normalize_url(url)
    if timeout < 1 or timeout > 120:
        raise ValueError("Timeout must be between 1 and 120 seconds.")

    started = datetime.now(timezone.utc).isoformat()
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "Bootcamp-WebSecurityScanner/1.0"},
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Request failed: {exc}") from exc

    findings: list[Finding] = []
    final_scheme = urlparse(response.url).scheme.lower()
    if final_scheme == "https":
        findings.append(
            Finding(
                "Transport security",
                "HTTPS",
                "High",
                "PASS",
                "Final response URL uses HTTPS",
                "No action required.",
            )
        )
    else:
        findings.append(
            Finding(
                "Transport security",
                "HTTPS",
                "High",
                "WARN",
                "Final response URL uses HTTP",
                "Serve the application exclusively over HTTPS.",
            )
        )

    findings.extend(add_header_findings(response))
    findings.extend(add_cookie_findings(response))

    counts = {
        status: sum(1 for finding in findings if finding.status == status)
        for status in ("PASS", "REVIEW", "WARN")
    }
    return {
        "scan_metadata": {
            "target": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "scanned_at_utc": started,
            "scanner": "Automated Web Security Header Scanner 1.1",
            "authorization_note": "Run only against systems you own or are authorized to test.",
        },
        "summary": counts,
        "findings": [asdict(finding) for finding in findings],
    }


def save_json(result: dict, path: Path) -> None:
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")


def save_html(result: dict, path: Path) -> None:
    meta = result["scan_metadata"]
    rows = []
    for finding in result["findings"]:
        rows.append(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(finding[key]))}</td>"
                for key in (
                    "category",
                    "check",
                    "severity",
                    "status",
                    "evidence",
                    "recommendation",
                )
            )
            + "</tr>"
        )

    summary = html.escape(json.dumps(result["summary"]))
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web Security Scan</title>
<style>
body{{font-family:Arial,sans-serif;margin:2rem;color:#17202a}}
table{{border-collapse:collapse;width:100%;overflow-wrap:anywhere}}
th,td{{border:1px solid #ccd;padding:8px;text-align:left;vertical-align:top}}
th{{background:#17202a;color:white}}
.WARN{{background:#ffe5e5}}.REVIEW{{background:#fff3cd}}.PASS{{background:#e5f6e9}}
</style>
</head>
<body>
<h1>Automated Web Security Header Scanner Report</h1>
<p><b>Target:</b> {html.escape(meta['target'])}<br>
<b>Final URL:</b> {html.escape(meta['final_url'])}<br>
<b>HTTP status:</b> {meta['status_code']}<br>
<b>Scan time (UTC):</b> {html.escape(meta['scanned_at_utc'])}</p>
<p><b>Summary:</b> {summary}</p>
<table>
<tr><th>Category</th><th>Check</th><th>Severity</th><th>Status</th>
<th>Evidence</th><th>Recommendation</th></tr>
{''.join(rows)}
</table>
<p><small>Defensive tool. Test only systems for which you have authorization.
Results are indicative and do not replace a full security assessment.</small></p>
</body>
</html>"""
    path.write_text(document, encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit common web security headers with one low-impact GET request."
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="Authorized target URL, for example https://example.com",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10; allowed: 1-120)",
    )
    parser.add_argument(
        "--output",
        default="scan_report.json",
        help="JSON output path (default: scan_report.json)",
    )
    parser.add_argument("--html", help="Optional HTML report path")

    args = parser.parse_args(argv)
    target = args.url
    if not target:
        try:
            target = input("Enter an authorized target URL: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nNo target URL provided.", file=sys.stderr)
            return 2
        if not target:
            print("Error: no target URL provided.", file=sys.stderr)
            return 2

    try:
        result = scan(target, args.timeout)
        save_json(result, Path(args.output))
        if args.html:
            save_html(result, Path(args.html))
        print(json.dumps(result["summary"], indent=2))
        print(f"JSON report saved to {args.output}")
        if args.html:
            print(f"HTML report saved to {args.html}")
        return 0
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
