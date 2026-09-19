"""WAF / CDN fingerprinting with expanded signatures and better blocking heuristics."""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from ..waf_signatures import WAF_SIGNATURES
from ..baseline import Baseline
from ..http_client import CurlClient, HttpResponse

TEST_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "; ls -la",
    "| cat /etc/passwd",
    "UNION SELECT NULL,NULL--",
    "{{7*7}}",
    "${7*7}",
    "(); DECLARE @x VARCHAR(100)",
]


def fingerprint_from_response(resp: Optional[HttpResponse]) -> List[Dict[str, Any]]:
    if not resp or resp.error:
        return []
    headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
    body_lower = (resp.body or "").lower()
    server = headers_lower.get("server", "")
    set_cookie = headers_lower.get("set-cookie", "")

    matches = []
    for waf_name, sig in WAF_SIGNATURES.items():
        score = 0
        reasons = []
        for h in sig["headers"]:
            if h in headers_lower:
                score += 2
                reasons.append(f"header:{h}")
        for c in sig["cookies"]:
            if c in set_cookie:
                score += 2
                reasons.append(f"cookie:{c}")
        for s in sig["server"]:
            if s in server:
                score += 2
                reasons.append(f"server:{s}")
        for marker in sig["block_page_markers"]:
            if marker in body_lower:
                score += 1
                reasons.append(f"body:{marker}")
        if score > 0:
            matches.append({"waf": waf_name, "score": score, "reasons": reasons})

    matches.sort(key=lambda m: -m["score"])
    return matches


def run(
    client: CurlClient,
    base_url: str,
    baseline: Baseline,
    param: str = "q",
) -> List[Dict[str, Any]]:
    clean_resp = client.request(f"{base_url}?{param}=test")

    triggered = 0
    all_fps: Dict[str, int] = {}
    block_examples = []

    for payload in TEST_PAYLOADS:
        # Simple URL encoding of spaces / special chars is left to curl
        resp = client.request(f"{base_url}?{param}={payload}")
        if not resp or resp.error:
            continue

        looks_blocked = (
            resp.status_code in (403, 406, 429, 501, 503, 999)
            or (clean_resp and not clean_resp.error and resp.status_code != clean_resp.status_code)
        ) and baseline.deviates(resp)

        if looks_blocked:
            triggered += 1
            if len(block_examples) < 3:
                block_examples.append({
                    "payload": payload[:60],
                    "status": resp.status_code,
                    "size": resp.size,
                })

        for fp in fingerprint_from_response(resp):
            all_fps[fp["waf"]] = all_fps.get(fp["waf"], 0) + fp["score"]

    # Also fingerprint clean response (many CDNs add headers always)
    for fp in fingerprint_from_response(clean_resp):
        all_fps[fp["waf"]] = all_fps.get(fp["waf"], 0) + fp["score"]

    confidence = "low"
    if triggered >= 4 or (all_fps and max(all_fps.values()) >= 5):
        confidence = "high"
    elif triggered >= 1 or all_fps:
        confidence = "medium"

    detected = sorted(all_fps.items(), key=lambda kv: -kv[1])

    return [{
        "test": "waf_fingerprint",
        "payloads_tested": len(TEST_PAYLOADS),
        "payloads_that_looked_blocked": triggered,
        "confidence": confidence,
        "serverity" : "info",
        "waf_candidates": [{"name": n, "score": s} for n, s in detected],
        "block_examples": block_examples,
        "issue": "WAF/CDN fingerprinting results",
    }]
