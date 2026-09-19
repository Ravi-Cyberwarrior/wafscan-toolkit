#!/usr/bin/env python3
"""
wafscan v2 — modular, curl-driven security testing scanner.

Improvements over v1:
- Concurrent path probing
- Richer baseline (hash + consistency checks)
- Expanded sensitive paths & WAF signatures
- Better error handling & evidence in findings
- Cookie support, improved JWT checks, method overrides
- Progress-friendly UI, delay/rate control, more CLI options
"""

from __future__ import annotations

import argparse
import sys
from typing import Dict, Any

from wafscan.http_client import CurlClient
from wafscan.baseline import Baseline
from wafscan.modules import recon, auth, methods, waf_detect, ssrf
from wafscan import scoring, report, ui


def parse_args():
    parser = argparse.ArgumentParser(
        prog="wafscan",
        description="Modular curl-based scanner: recon, auth/session checks, "
                    "HTTP method testing, WAF fingerprinting, and blind-SSRF probing."
    )
    parser.add_argument("url", help="Base target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds (default 10)")
    parser.add_argument("--insecure", action="store_true", help="Ignore TLS certificate errors")
    parser.add_argument("--proxy", help="Route through a proxy, e.g. 127.0.0.1:8080 for Burp")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects (-L) and record hops")
    parser.add_argument("--delay", type=float, default=0.0, help="Minimum delay between requests in seconds")
    parser.add_argument("--threads", type=int, default=6, help="Concurrency for path probing (default 6)")
    parser.add_argument("--baseline-samples", type=int, default=3, help="Number of baseline samples (default 3)")
    parser.add_argument("--baseline-path", help="Known non-existent path to use for baselining")
    parser.add_argument("--auth-header", help='Header for access-control tests, e.g. "Authorization: Bearer xxx"')
    parser.add_argument("--cookie", help='Cookie string for authenticated requests, e.g. "session=abc; token=xyz"')
    parser.add_argument("--jwt", help="JWT to decode and sanity-check")
    parser.add_argument("--protected-paths", nargs="*", default=[],
                        help="Paths that should require auth, to test for broken access control")
    parser.add_argument("--ssrf-callback", help="Out-of-band domain you control (Collaborator/interact.sh)")
    parser.add_argument("--ssrf-params", nargs="*", default=[],
                        help='param=endpoint pairs to probe, e.g. url=/api/fetch-image')
    parser.add_argument("--waf-param", default="q", help="Query param name for WAF payloads (default: q)")
    parser.add_argument("--skip", nargs="*", default=[],
                        choices=["recon", "auth", "methods", "waf", "ssrf"],
                        help="Module(s) to skip")
    parser.add_argument("--output", help="Write full JSON report to this file")
    parser.add_argument("--no-banner", action="store_true", help="Suppress ASCII banner")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colours")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Skip interactive authorization prompt (still bound by acceptable-use terms)")
    parser.add_argument("-v", "--verbose", action="store_true", help="More verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output (findings + summary only)")
    return parser.parse_args()


def confirm_authorization(url: str, skip_prompt: bool = False) -> None:
    import datetime
    from pathlib import Path

    if not skip_prompt:
        ui.warn(f"You are about to scan: {url}")
        ui.warn("This tool must ONLY be used against systems you own or are explicitly authorized to test.")
        answer = input("Type 'yes' to confirm you have authorization: ").strip().lower()
        if answer != "yes":
            ui.err("Authorization not confirmed. Exiting.")
            sys.exit(1)

    try:
        log_path = Path.home() / ".wafscan_audit.log"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(
                f"{datetime.datetime.now().isoformat()}  target={url}  "
                f"confirmed={'flag(-y)' if skip_prompt else 'interactive'}\n"
            )
    except OSError:
        pass


def parse_cookie_string(cookie_str: str) -> Dict[str, str]:
    cookies = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def print_findings_summary(results: Dict[str, Any]) -> None:
    def walk(section_name: str, items):
        if isinstance(items, list):
            for i in items:
                if not isinstance(i, dict):
                    continue
                conf = i.get("confidence", "medium")
                label = (
                    i.get("issue")
                    or i.get("path")
                    or i.get("test")
                    or i.get("method")
                    or i.get("param")
                )
                if label:
                    ui.finding(conf, f"{section_name}: {label}")
        elif isinstance(items, dict):
            for k, v in items.items():
                walk(f"{section_name}.{k}", v)

    for section_name, data in results.items():
        if section_name == "summary":
            continue
        walk(section_name, data)


def main() -> None:
    args = parse_args()

    if args.no_color:
        for attr in dir(ui.C):
            if not attr.startswith("_"):
                setattr(ui.C, attr, "")

    if not args.no_banner and not args.quiet:
        ui.print_banner()

    confirm_authorization(args.url, skip_prompt=args.yes)

    if not args.quiet:
        ui.info(f"Target: {args.url}")
        if args.proxy:
            ui.info(f"Proxy: {args.proxy}")
        if args.delay:
            ui.info(f"Delay between requests: {args.delay}s")

    client = CurlClient(
        timeout=args.timeout,
        insecure=args.insecure,
        follow_redirects=args.follow_redirects,
        proxy=args.proxy,
        delay=args.delay,
    )

    if not args.quiet:
        ui.section("BASELINE")
    baseline = Baseline(
        client,
        args.url,
        samples=args.baseline_samples,
        known_path=args.baseline_path,
    ).build()

    if not args.quiet:
        ui.info(f"default status: {baseline.default_status}   avg size: {baseline.default_size:.0f} bytes")
        if not baseline.consistent:
            for w in baseline.warnings:
                ui.warn(w)
        elif baseline.warnings:
            for w in baseline.warnings:
                ui.warn(w)

    results: Dict[str, Any] = {}
    errors: list = []

    if "recon" not in args.skip:
        if not args.quiet:
            ui.section("RECON")
        results["recon"] = recon.run(client, args.url, baseline, threads=args.threads)

    if "methods" not in args.skip:
        if not args.quiet:
            ui.section("HTTP METHODS")
        results["methods"] = methods.run(client, args.url, baseline)

    if "waf" not in args.skip:
        if not args.quiet:
            ui.section("WAF FINGERPRINT")
        results["waf"] = waf_detect.run(client, args.url, baseline, param=args.waf_param)

    if "auth" not in args.skip:
        if not args.quiet:
            ui.section("AUTH / SESSION")
        auth_headers = {}
        if args.auth_header and ":" in args.auth_header:
            k, v = args.auth_header.split(":", 1)
            auth_headers[k.strip()] = v.strip()

        cookies = parse_cookie_string(args.cookie) if args.cookie else None

        auth_findings: Dict[str, Any] = {}
        if args.protected_paths:
            auth_findings["access_control"] = auth.check_access_control(
                client, args.url, args.protected_paths,
                auth_headers=auth_headers or None,
                cookies=cookies,
            )
        if args.jwt:
            auth_findings["jwt"] = auth.check_jwt(args.jwt)
        root_resp = client.request(args.url)
        if root_resp and not root_resp.error:
            cookie_issues = auth.check_cookie_flags(root_resp)
            if cookie_issues:
                auth_findings["cookie_flags"] = cookie_issues
        results["auth"] = auth_findings

    if "ssrf" not in args.skip and args.ssrf_callback and args.ssrf_params:
        if not args.quiet:
            ui.section("SSRF PROBES")
        pairs = []
        for p in args.ssrf_params:
            if "=" in p:
                name, endpoint = p.split("=", 1)
                pairs.append((name, endpoint))
        results["ssrf"] = ssrf.run(client, args.url, pairs, args.ssrf_callback)

    results["summary"] = scoring.summarize(results)
    results["meta"] = {
        "target": args.url,
        "baseline_status": baseline.default_status,
        "baseline_avg_size": baseline.default_size,
        "baseline_consistent": baseline.consistent,
        "tool_version": ui.VERSION,
    }

    if not args.quiet:
        ui.section("FINDINGS")
    print_findings_summary(results)

    s = results["summary"]
    print()
    ui.ok(
        f"Total: {s['total_findings']}  |  High: {s['high']}  "
        f"Medium: {s['medium']}  Low: {s['low']}  Info: {s.get('info', 0)}"
    )

    if args.output:
        report.to_json(results, args.output)
        ui.info(f"Full JSON report written to {args.output}")
    elif not args.quiet:
        ui.info("Pass --output report.json to save full JSON details.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupted.")
