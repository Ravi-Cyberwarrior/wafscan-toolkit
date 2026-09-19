"""Summarise findings with severity counts and optional filtering."""

from __future__ import annotations

from typing import Dict, Any


def summarize(all_findings: Dict[str, Any]) -> Dict[str, Any]:
    total = high = medium = low = info = 0

    def walk(items):
        nonlocal total, high, medium, low, info
        if isinstance(items, list):
            for i in items:
                if isinstance(i, dict) and any(
                    k in i for k in ("issue", "test", "path", "param", "method")
                ):
                    total += 1
                    conf = i.get("confidence", "medium")
                    if conf == "high":
                        high += 1
                    elif conf == "low":
                        low += 1
                    elif conf == "info":
                        info += 1
                    else:
                        medium += 1
        elif isinstance(items, dict):
            for v in items.values():
                walk(v)

    for section, data in all_findings.items():
        if section == "summary":
            continue
        walk(data)

    return {
        "total_findings": total,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
    }
