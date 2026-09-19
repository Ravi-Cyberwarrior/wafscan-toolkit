"""Terminal presentation — banner, colours, progress-friendly helpers."""

from __future__ import annotations

import shutil
import sys

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

VERSION = "2.0.0"

_ART = r"""
 __      __        __ _____                 
/  \    /  \_____ |  |   __\______ _____    
\   \/\/   /\__  \|  |  |  \/  ___/\__  \   
 \        /  / __ \|  |  |__ \___ \  / __ \_
  \__/\__/  (____  /__|____/____  >(____  /
                  \/             \/      \/  
"""


def print_banner() -> None:
    print(f"{C.CYAN}{C.BOLD}{_ART}{C.RESET}")
    print(f"{C.DIM}    curl-driven recon / auth / methods / WAF-fingerprint / SSRF scanner{C.RESET}")
    print(f"{C.DIM}    v{VERSION}  ·  for authorized security testing only{C.RESET}\n")


def section(title: str) -> None:
    width = min(shutil.get_terminal_size((80, 20)).columns, 70)
    line = "─" * width
    print(f"\n{C.BLUE}{line}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}[{title}]{C.RESET}")
    print(f"{C.BLUE}{line}{C.RESET}")


def info(msg: str) -> None:
    print(f"{C.CYAN}[*]{C.RESET} {msg}")


def ok(msg: str) -> None:
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def err(msg: str) -> None:
    print(f"{C.RED}[x]{C.RESET} {msg}")


def finding(conf: str, text: str) -> None:
    color = {"high": C.RED, "medium": C.YELLOW, "low": C.DIM, "info": C.CYAN}.get(conf, C.WHITE)
    tag = {"high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}.get(conf, "????")
    print(f"    {color}[{tag}]{C.RESET} {text}")


def progress(current: int, total: int, prefix: str = "") -> None:
    """Simple single-line progress (overwrites)."""
    if total <= 0:
        return
    pct = int(current / total * 100)
    bar_len = 24
    filled = int(bar_len * current / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    sys.stdout.write(f"\r{C.DIM}{prefix}[{bar}] {pct}% ({current}/{total}){C.RESET}")
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")
