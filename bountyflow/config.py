"""Shared config, constants, wordlists."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

__version__ = "2.7.0"

BASE = Path(__file__).resolve().parent.parent
FINDINGS = BASE / "finding"
RUNS = BASE / "runs"  # legacy, still supported via --output-dir


@dataclass
class RunConfig:
    domain: str
    phases: set[int]
    single_url: str
    api_url: str
    aggressive: bool = False
    dry_run: bool = False
    excludes: set[str] = field(default_factory=set)
    timeout: int = 3600
    threads: int = 100
    out_base: Path = FINDINGS
    headers: tuple[str, ...] = ()
    proxy: str = ""


def find_wordlist(*candidates: str) -> str:
    for c in candidates:
        if Path(c).exists():
            return c
    return candidates[0]


DIR_MEDIUM = find_wordlist(
    "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
)
PARAM_WORDS = find_wordlist(
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "/usr/share/wordlists/wfuzz/general/common.txt",
)
API_WORDS = find_wordlist(
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
)
