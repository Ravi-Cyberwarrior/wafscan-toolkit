"""Improved baselining engine.

Improvements:
- Configurable sample count
- Content-hash comparison in addition to difflib
- Consistency warning when baseline samples disagree
- Optional user-supplied known-not-found path
- Binary-aware similarity
"""

from __future__ import annotations

import random
import string
import hashlib
import difflib
from typing import Optional, List
from .http_client import CurlClient, HttpResponse


def _random_path(length: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


class Baseline:
    def __init__(
        self,
        client: CurlClient,
        base_url: str,
        samples: int = 3,
        known_path: Optional[str] = None,
    ):
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.samples = max(1, samples)
        self.known_path = known_path
        self.status_codes: List[int] = []
        self.sizes: List[int] = []
        self.hashes: List[str] = []
        self.bodies: List[str] = []
        self.avg_time: float = 0.0
        self.consistent: bool = True
        self.warnings: List[str] = []

    def build(self) -> "Baseline":
        times = []
        paths = []
        if self.known_path:
            paths.append(self.known_path.lstrip("/"))
        while len(paths) < self.samples:
            paths.append(_random_path())

        for path in paths:
            resp = self.client.request(f"{self.base_url}/{path}")
            if resp is None or resp.error:
                self.warnings.append(f"Baseline sample failed for /{path}: {getattr(resp, 'error', 'unknown')}")
                continue
            self.status_codes.append(resp.status_code)
            self.sizes.append(resp.size)
            body_for_hash = resp.body if not resp.is_binary else ""
            self.hashes.append(hashlib.sha256(body_for_hash.encode(errors="ignore")).hexdigest())
            self.bodies.append(resp.body[:4000] if not resp.is_binary else "")
            times.append(resp.elapsed)

        self.avg_time = sum(times) / len(times) if times else 0.0

        # Consistency check
        if len(set(self.status_codes)) > 1:
            self.consistent = False
            self.warnings.append(
                f"Baseline status codes are inconsistent: {self.status_codes}. "
                "False-positive rate may be higher."
            )
        if self.sizes and (max(self.sizes) - min(self.sizes)) / max(max(self.sizes), 1) > 0.4:
            self.consistent = False
            self.warnings.append("Baseline response sizes vary significantly.")

        return self

    @property
    def default_status(self) -> Optional[int]:
        if not self.status_codes:
            return None
        return max(set(self.status_codes), key=self.status_codes.count)

    @property
    def default_size(self) -> float:
        if not self.sizes:
            return 0.0
        return sum(self.sizes) / len(self.sizes)

    def similarity(self, resp: HttpResponse) -> float:
        if resp is None or resp.error or resp.is_binary or not self.bodies:
            return 0.0
        candidate = resp.body[:4000]
        best = 0.0
        for b in self.bodies:
            if not b:
                continue
            ratio = difflib.SequenceMatcher(None, candidate, b).quick_ratio()
            best = max(best, ratio)
        return best

    def content_hash_match(self, resp: HttpResponse) -> bool:
        if resp is None or resp.error or resp.is_binary or not self.hashes:
            return False
        h = hashlib.sha256(resp.body.encode(errors="ignore")).hexdigest()
        return h in self.hashes

    def is_default_page(
        self,
        resp: Optional[HttpResponse],
        size_tolerance: float = 0.15,
        similarity_threshold: float = 0.85,
    ) -> bool:
        if resp is None or resp.error:
            return False

        same_status = resp.status_code == self.default_status
        size_close = False
        if self.default_size:
            diff = abs(resp.size - self.default_size) / max(self.default_size, 1)
            size_close = diff <= size_tolerance
        elif resp.size == 0:
            size_close = True

        if same_status and size_close:
            return True
        if same_status and self.content_hash_match(resp):
            return True
        if same_status and self.similarity(resp) >= similarity_threshold:
            return True
        return False

    def deviates(self, resp: Optional[HttpResponse], size_tolerance: float = 0.15) -> bool:
        return not self.is_default_page(resp, size_tolerance)

    def evidence(self, resp: Optional[HttpResponse]) -> dict:
        """Return diagnostic info useful for reports."""
        if resp is None or resp.error:
            return {"error": getattr(resp, "error", "no response")}
        return {
            "status": resp.status_code,
            "size": resp.size,
            "baseline_status": self.default_status,
            "baseline_avg_size": round(self.default_size, 1),
            "size_delta_pct": round(
                abs(resp.size - self.default_size) / max(self.default_size, 1) * 100, 1
            ) if self.default_size else None,
            "similarity": round(self.similarity(resp), 3),
            "hash_match": self.content_hash_match(resp),
            "is_binary": resp.is_binary,
        }
