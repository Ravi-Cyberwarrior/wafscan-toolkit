"""Thin, reliable wrapper around curl.
Improvements over original:
- Explicit error objects instead of silent None
- Optional redirect following with hop visibility
- Binary detection
- Content-Length preferred for size
- Better parsing of multi-hop responses
"""

from __future__ import annotations

import subprocess
import time
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any


@dataclass
class HttpResponse:
    status_code: int
    headers: Dict[str, str]          # lower-cased name -> value
    body: str
    elapsed: float
    size: int                        # preferred: Content-Length, else len(body)
    raw: str = ""
    is_binary: bool = False
    error: Optional[str] = None
    hops: List[Dict[str, Any]] = field(default_factory=list)  # intermediate redirects

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

    def __repr__(self) -> str:
        if self.error:
            return f"<HttpResponse ERROR: {self.error}>"
        return f"<HttpResponse {self.status_code} size={self.size} t={self.elapsed:.2f}s binary={self.is_binary}>"


class CurlClient:
    def __init__(
        self,
        timeout: int = 10,
        insecure: bool = False,
        follow_redirects: bool = False,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        delay: float = 0.0,
    ):
        self.timeout = timeout
        self.insecure = insecure
        self.follow_redirects = follow_redirects
        self.user_agent = user_agent or "wafscan/2.0 (+authorized-testing)"
        self.proxy = proxy
        self.delay = delay
        self._last_request_time = 0.0

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        extra_args: Optional[List[str]] = None,
    ) -> HttpResponse:
        if self.delay > 0:
            elapsed_since = time.time() - self._last_request_time
            if elapsed_since < self.delay:
                time.sleep(self.delay - elapsed_since)

        cmd = [
            "curl", "-s", "-i", "-X", method,
            "--max-time", str(self.timeout),
            "-A", self.user_agent,
        ]
        if self.insecure:
            cmd.append("-k")
        if self.follow_redirects:
            cmd.append("-L")
        if self.proxy:
            cmd += ["-x", self.proxy]
        if headers:
            for k, v in headers.items():
                cmd += ["-H", f"{k}: {v}"]
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            cmd += ["-b", cookie_str]
        if data is not None:
            cmd += ["--data", data]
        if extra_args:
            cmd += extra_args
        cmd.append(url)

        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 5,
            )
        except subprocess.TimeoutExpired:
            self._last_request_time = time.time()
            return HttpResponse(0, {}, "", 0.0, 0, error="timeout")
        except FileNotFoundError:
            raise RuntimeError("curl not found on this system — install curl first.")
        except Exception as e:
            self._last_request_time = time.time()
            return HttpResponse(0, {}, "", 0.0, 0, error=str(e))

        elapsed = time.time() - start
        self._last_request_time = time.time()

        if proc.returncode != 0 and not proc.stdout:
            err = (proc.stderr or "").strip() or f"curl exit {proc.returncode}"
            return HttpResponse(0, {}, "", elapsed, 0, error=err)

        return self._parse(proc.stdout, elapsed)

    @staticmethod
    def _parse(raw: str, elapsed: float) -> HttpResponse:
        remaining = raw
        header_blocks: List[str] = []
        hops: List[Dict[str, Any]] = []

        while True:
            sep = "\r\n\r\n" if "\r\n\r\n" in remaining else "\n\n"
            if sep not in remaining:
                break
            block, rest = remaining.split(sep, 1)
            if re.match(r"^HTTP/\S+\s+\d+", block.strip()):
                header_blocks.append(block)
                remaining = rest
            else:
                break

        body = remaining
        if not header_blocks:
            return HttpResponse(0, {}, raw, elapsed, len(raw), raw=raw)

        # Parse all hops; final one is the response we care about most
        for block in header_blocks:
            lines = block.strip().split("\n")
            status_line = lines[0].strip()
            m = re.search(r"HTTP/\S+\s+(\d+)", status_line)
            code = int(m.group(1)) if m else 0
            hdrs = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()
            hops.append({"status": code, "headers": hdrs})

        final = hops[-1]
        status_code = final["status"]
        headers = final["headers"]

        # Prefer Content-Length when available
        cl = headers.get("content-length")
        try:
            size = int(cl) if cl is not None else len(body)
        except ValueError:
            size = len(body)

        # Simple binary detection
        is_binary = False
        ctype = headers.get("content-type", "").lower()
        if "octet-stream" in ctype or "image/" in ctype or "application/pdf" in ctype:
            is_binary = True
        elif "\x00" in body[:2048]:
            is_binary = True

        return HttpResponse(
            status_code=status_code,
            headers=headers,
            body=body,
            elapsed=elapsed,
            size=size,
            raw=raw,
            is_binary=is_binary,
            hops=hops,
        )
