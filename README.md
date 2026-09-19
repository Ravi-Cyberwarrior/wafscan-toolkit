# wafscan v2

A modular, curl-driven security testing scanner: recon, auth/session checks,
HTTP method testing, WAF/firewall fingerprinting, and blind-SSRF probing —
built to cut down false positives via baselining rather than trusting raw
status codes in isolation.

**Only run this against systems you are authorized to test.**

## What's new in v2

- Concurrent path probing (`--threads`)
- Stronger baselining (content-hash + consistency warnings + optional known path)
- Expanded sensitive-path list and WAF/CDN signatures
- Better error handling (failed requests are no longer silent)
- Evidence attached to findings (status, size delta, similarity, hash match)
- Cookie support + improved JWT checks (kid, iat/nbf, algorithm confusion notes)
- Method-override detection and extra WebDAV/CONNECT methods
- Request delay / rate control (`--delay`)
- Redirect hop recording (`--follow-redirects`)
- Richer JSON report with meta section
- Quiet / verbose modes

## Why baselining matters

Most naïve scanners flag "found a path" purely off status code 200. That
breaks on any site that returns 200 (or a generic branded page) for
*everything*, or a WAF that returns fake 404s for blocked content. Before
running any test, `wafscan` requests a few random (or user-supplied)
guaranteed-nonexistent paths and records the typical status code, response
size, body hash and content sample. Every later test result is compared
against that baseline using multiple signals:

1. Status code + size within tolerance, **or**
2. Exact content-hash match, **or**
3. Status code matches baseline **and** body similarity (difflib) is high

Only if a result diverges from baseline is it reported.

## Legal & Ethical Use

This tool sends real requests to whatever URL you give it. **Only scan
systems you own, or have explicit written authorization to test**.

- Every run requires the target URL as an explicit argument.
- Every run requires interactive confirmation (`type 'yes'`) unless you
  pass `-y/--yes` (you remain bound by the acceptable-use terms).
- Each run appends a line to `~/.wafscan_audit.log`.
- Full terms are in [LICENSE](LICENSE).

## Install (Kali Linux)

```bash
unzip wafscan-improved.zip && cd wafscan-improved
sudo ./install.sh
```

Or run directly without installing:

```bash
python3 main.py https://target.example
```

## Usage examples

```bash
# Basic scan
python3 main.py https://target.example

# Through Burp, ignore TLS errors, polite delay
python3 main.py https://target.example \
  --proxy 127.0.0.1:8080 --insecure --delay 0.3

# Auth / access-control testing with header + cookie
python3 main.py https://target.example \
  --auth-header "Authorization: Bearer <token>" \
  --cookie "session=abc123" \
  --protected-paths admin/dashboard api/users/me

# JWT sanity check
python3 main.py https://target.example --jwt eyJhbGciOi...

# Blind SSRF (confirmation on YOUR listener)
python3 main.py https://target.example \
  --ssrf-callback yourid.oast.fun \
  --ssrf-params url=/api/fetch-image webhook=/api/notify

# Faster recon, custom baseline, JSON output
python3 main.py https://target.example \
  --threads 10 --baseline-samples 5 \
  --baseline-path /definitely-not-a-real-page-xyz \
  --output report.json --skip ssrf
```

## Command reference

```
usage: wafscan [-h] [--timeout TIMEOUT] [--insecure] [--proxy PROXY]
               [--follow-redirects] [--delay DELAY] [--threads THREADS]
               [--baseline-samples N] [--baseline-path PATH]
               [--auth-header AUTH_HEADER] [--cookie COOKIE] [--jwt JWT]
               [--protected-paths [PROTECTED_PATHS ...]]
               [--ssrf-callback SSRF_CALLBACK]
               [--ssrf-params [SSRF_PARAMS ...]] [--waf-param WAF_PARAM]
               [--skip [{recon,auth,methods,waf,ssrf} ...]] [--output OUTPUT]
               [--no-banner] [--no-color] [-y] [-v] [-q]
               url
```

## Modules

| Module    | What it does |
|-----------|--------------|
| `recon`   | Security headers, expanded sensitive path discovery, server banner, light tech hints, redirect chain |
| `methods` | GET/POST/PUT/DELETE/PATCH/OPTIONS/TRACE/HEAD/CONNECT + WebDAV basics + method-override checks |
| `waf`     | Generic attack patterns + expanded WAF/CDN fingerprinting (Cloudflare, Akamai, Imperva, AWS, Sucuri, F5, ModSecurity, Barracuda, FortiWeb, Fastly, Azure, Wordfence, etc.) |
| `auth`    | Cookie flags, improved JWT analysis, authenticated vs unauthenticated response diffing |
| `ssrf`    | Blind SSRF probes with multiple bypass patterns — confirmation on your OOB listener |

## Extending

- Add WAF vendors in `wafscan/waf_signatures.py`.
- Add paths in `wafscan/modules/recon.py::SENSITIVE_PATHS`.
- Baseline similarity can be swapped for stronger algorithms if needed.

## Known limitations

- Apps whose routing genuinely differs by path shape can still surface as findings; the tool flags *divergence from baseline*, not confirmed vulnerabilities. Human review is required.
- SSRF module only sends probes — it cannot confirm a hit by itself.
- Concurrency is best-effort; very aggressive thread counts + low delays may still trigger rate limits or WAF challenges.

## License

MIT + additional acceptable-use terms. See [LICENSE](LICENSE).
