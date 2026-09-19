"""HTTP method testing with improved coverage."""

from __future__ import annotations

from typing import List, Dict, Any
from ..baseline import Baseline
from ..http_client import CurlClient

METHODS_TO_TEST = [
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "OPTIONS", "TRACE", "HEAD", "CONNECT",
    "PROPFIND", "MKCOL",  # WebDAV basics
]

RISKY_IF_ALLOWED = {"PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "MKCOL"}


def run(client: CurlClient, url: str, baseline: Baseline) -> List[Dict[str, Any]]:
    findings = []

    for method in METHODS_TO_TEST:
        resp = client.request(url, method=method)
        if not resp or resp.error:
            continue
        if baseline.is_default_page(resp):
            continue

        allow_header = resp.header("allow")

        if method in RISKY_IF_ALLOWED and resp.status_code < 400:
            findings.append({
                "method": method,
                "status": resp.status_code,
                "issue": f"{method} appears to be allowed — verify this is intentional",
                "allow_header": allow_header,
                "confidence": "medium" if method != "TRACE" else "high",
                "evidence": baseline.evidence(resp),
            })
        elif method == "OPTIONS" and allow_header:
            findings.append({
                "method": "OPTIONS",
                "status": resp.status_code,
                "allow_header": allow_header,
                "confidence": "low",
                "issue": "OPTIONS returned Allow header",
                "evidence": baseline.evidence(resp),
            })
        elif method == "TRACE" and resp.status_code == 200 and "TRACE" in resp.body.upper():
            findings.append({
                "method": "TRACE",
                "status": resp.status_code,
                "issue": "TRACE reflects request — possible Cross-Site Tracing (XST) exposure",
                "confidence": "high",
                "evidence": baseline.evidence(resp),
            })

    # Method override check (common bypass)
    for override_header, override_value in [
        ("X-HTTP-Method-Override", "DELETE"),
        ("X-Method-Override", "PUT"),
        ("X-HTTP-Method", "DELETE"),
    ]:
        resp = client.request(
            url,
            method="POST",
            headers={override_header: override_value},
        )
        if resp and not resp.error and not baseline.is_default_page(resp) and resp.status_code < 400:
            findings.append({
                "method": f"POST + {override_header}",
                "status": resp.status_code,
                "issue": f"Method override via {override_header} appears accepted",
                "confidence": "medium",
                "evidence": baseline.evidence(resp),
            })

    return findings
