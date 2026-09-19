"""Authentication / session checks — cookies, JWT, access-control diffing."""

from __future__ import annotations

import base64
import json
from typing import List, Dict, Any, Optional
from ..http_client import CurlClient, HttpResponse


def check_cookie_flags(resp: HttpResponse) -> List[Dict[str, Any]]:
    issues = []
    for line in (resp.raw or "").split("\n"):
        if line.lower().startswith("set-cookie:"):
            cookie = line.split(":", 1)[1].strip()
            lower = cookie.lower()
            name = cookie.split("=")[0].strip()
            missing = []
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "secure" not in lower:
                missing.append("Secure")
            if "samesite" not in lower:
                missing.append("SameSite")
            if missing:
                issues.append({
                    "cookie": name,
                    "missing_flags": missing,
                    "confidence": "medium",
                    "issue": f"Cookie '{name}' missing flags: {', '.join(missing)}",
                })
    return issues


def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        def pad(s: str) -> str:
            return s + "=" * (-len(s) % 4)

        header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
        return {"header": header, "payload": payload}
    except Exception:
        return None


def check_jwt(token: str) -> Dict[str, Any]:
    decoded = decode_jwt(token)
    if not decoded:
        return {"error": "Could not decode token as a JWT", "confidence": "info"}

    issues = []
    header = decoded["header"]
    payload = decoded["payload"]
    alg = str(header.get("alg", ""))

    if alg.lower() == "none":
        issues.append({
            "issue": "alg=none — confirm the server rejects this",
            "confidence": "high",
        })
    if alg.upper().startswith("HS"):
        issues.append({
            "issue": "HMAC-signed (HS*) — check for algorithm confusion (RS→HS)",
            "confidence": "medium",
        })
    if "kid" in header:
        issues.append({
            "issue": "JWT contains 'kid' header — potential key injection / path traversal vector",
            "confidence": "low",
        })
    if not payload.get("exp"):
        issues.append({
            "issue": "No 'exp' claim — token may never expire",
            "confidence": "medium",
        })
    if not payload.get("iat") and not payload.get("nbf"):
        issues.append({
            "issue": "Missing both 'iat' and 'nbf' — weaker temporal controls",
            "confidence": "low",
        })

    return {
        "decoded": decoded,
        "issues": issues,
        "confidence": "high" if any(i["confidence"] == "high" for i in issues) else "medium",
    }


def check_access_control(
    client: CurlClient,
    base_url: str,
    protected_paths: List[str],
    auth_headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    findings = []
    for path in protected_paths:
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        auth_resp = client.request(url, headers=auth_headers, cookies=cookies) if (auth_headers or cookies) else None
        unauth_resp = client.request(url)

        if unauth_resp and not unauth_resp.error and unauth_resp.status_code == 200:
            findings.append({
                "path": path,
                "issue": "Accessible without authentication",
                "status": unauth_resp.status_code,
                "confidence": "high",
                "size": unauth_resp.size,
            })
        elif (
            auth_resp and unauth_resp
            and not auth_resp.error and not unauth_resp.error
            and auth_resp.status_code == unauth_resp.status_code
            and abs(auth_resp.size - unauth_resp.size) < 50
        ):
            findings.append({
                "path": path,
                "issue": "Authenticated and unauthenticated responses look identical",
                "status": unauth_resp.status_code,
                "confidence": "medium",
            })
    return findings
