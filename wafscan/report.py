"""Reporting helpers — JSON + richer console summary."""

from __future__ import annotations

import json
from typing import Dict, Any, Optional


def to_json(results: Dict[str, Any], path: Optional[str] = None) -> str:
    text = json.dumps(results, indent=2, default=str)
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    return text


def print_console(results: Dict[str, Any]) -> None:
    print("\n================ SCAN RESULTS ================")
    for section, data in results.items():
        print(f"\n--- {section} ---")
        print(json.dumps(data, indent=2, default=str))
    print("\n================================================")
