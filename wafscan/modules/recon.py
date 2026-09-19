"""Reconnaissance module — security headers, sensitive path discovery, server banner, basic tech hints."""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from ..baseline import Baseline
from ..http_client import CurlClient, HttpResponse

SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
]

# Significantly expanded list of interesting paths
SENSITIVE_PATHS = [
    # VCS / secrets
    ".git/HEAD", ".git/config", ".svn/entries", ".hg/hgrc",
    ".env", ".env.local", ".env.production", ".env.backup",
    "id_rsa", "id_rsa.pub", ".aws/credentials", ".aws/config",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
    "config.php.bak", "config.inc.php.bak", "settings.py.bak",
    "web.config", "web.config.bak", "appsettings.json",
    # Backups & dumps
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
    "db.sql", "database.sql", "site.zip", "www.zip",
    "backup/", "backups/", "old/", "temp/", "tmp/",
    # Debug / info
    "phpinfo.php", "info.php", "test.php", "debug/", "debug.log",
    "server-status", "server-info", ".well-known/security.txt",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    # Admin / panels
    "admin/", "admin/login", "administrator/", "wp-admin/", "wp-login.php",
    "manager/", "management/", "console/", "dashboard/",
    "phpmyadmin/", "pma/", "adminer.php", "adminer/",
    # API / docs
    "swagger.json", "swagger-ui.html", "api-docs", "openapi.json",
    "graphql", "graphiql", "v1/api-docs", "actuator", "actuator/health",
    "actuator/env", "actuator/info", ".json",
    # Cloud / infra
    "metadata", "latest/meta-data/", "computeMetadata/v1/",
    # Common CMS / framework
    "elmah.axd", "trace.axd", "web-inf/web.xml",
    "package.json", "composer.json", "yarn.lock", "Gemfile",
    ".DS_Store", "Thumbs.db",
]


def check_security_headers(resp: HttpResponse) -> Dict[str, Any]:
    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    present = {h: resp.headers[h] for h in SECURITY_HEADERS if h in resp.headers}
    return {
        "test": "security_headers",
        "missing": missing,
        "present": present,
        "confidence": "medium" if missing else "info",
    }


def check_sensitive_paths(
    client: CurlClient,
    base_url: str,
    baseline: Baseline,
    max_workers: int = 6,
) -> List[Dict[str, Any]]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    findings = []
    base = base_url.rstrip("/")

    def probe(path: str) -> Optional[Dict[str, Any]]:
        resp = client.request(f"{base}/{path}")
        if not resp or resp.error:
            return None
        if baseline.is_default_page(resp):
            return None
        if resp.status_code in (200, 206) and resp.size > 0:
            conf = "high" if resp.size > 40 else "medium"
            return {
                "path": path,
                "status": resp.status_code,
                "size": resp.size,
                "confidence": conf,
                "evidence": baseline.evidence(resp),
                "issue": "Sensitive or interesting path appears accessible",
            }
        if resp.status_code in (301, 302, 401, 403):
            return {
                "path": path,
                "status": resp.status_code,
                "size": resp.size,
                "confidence": "low",
                "evidence": baseline.evidence(resp),
                "issue": "Path exists but redirected or access-controlled",
            }
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(probe, p): p for p in SENSITIVE_PATHS}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                findings.append(result)

    findings.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x["confidence"], 3))
    return findings


def tech_hints(resp: HttpResponse) -> List[str]:
    """Very lightweight technology hints from headers/body."""
    hints = []
    server = (resp.header("server") or "").lower()
    powered = (resp.header("x-powered-by") or "").lower()
    body = resp.body[:3000].lower() if not resp.is_binary else ""

    if "cloudflare" in server or resp.header("cf-ray"):
        hints.append("Cloudflare")
    if "nginx" in server:
        hints.append("nginx")
    if "apache" in server:
        hints.append("Apache")
    if "iis" in server or "microsoft-iis" in server:
        hints.append("IIS")
    if "php" in powered or "php" in server:
        hints.append("PHP")
    if "asp.net" in powered or "x-aspnet-version" in resp.headers:
        hints.append("ASP.NET")
    if "express" in powered:
        hints.append("Express/Node")
    if "wordpress" in body or "wp-content" in body:
        hints.append("WordPress")
    if "laravel" in body or "laravel_session" in (resp.header("set-cookie") or ""):
        hints.append("Laravel")
    if "drupal" in body:
        hints.append("Drupal")
    if "joomla" in body:
        hints.append("Joomla")
    if "shopify" in body or "cdn.shopify" in body:
        hints.append("Shopify")
    return hints


def run(client: CurlClient, base_url: str, baseline: Baseline, threads: int = 6) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    root = client.request(base_url)
    if root and not root.error:
        results["headers"] = check_security_headers(root)
        results["server_banner"] = root.header("server")
        results["powered_by"] = root.header("x-powered-by")
        results["tech_hints"] = tech_hints(root)
        if root.hops and len(root.hops) > 1:
            results["redirect_chain"] = [{"status": h["status"]} for h in root.hops]
    results["sensitive_paths"] = check_sensitive_paths(client, base_url, baseline, max_workers=threads)
    return results
