"""External tool detection."""
from __future__ import annotations

import shutil
import subprocess

from .config import API_WORDS, DIR_MEDIUM, PARAM_WORDS
from pathlib import Path


def which(t: str) -> str | None:
    return shutil.which(t)


def httpx_bin() -> str:
    """Prefer ProjectDiscovery httpx. Kali ships python-httpx as /usr/bin/httpx."""
    for cand in ("httpx-toolkit", "httpx"):
        p = which(cand)
        if not p:
            continue
        if cand == "httpx":
            try:
                r = subprocess.run(
                    "httpx --help 2>&1 | head -n 20", shell=True,
                    capture_output=True, text=True, timeout=5,
                )
                blob = r.stdout + r.stderr
                if "No such option" in blob or "next generation HTTP client" in blob:
                    continue
            except Exception:
                continue
        return cand
    return "httpx-toolkit"


def tool_version(cmd: str) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        out = (r.stdout + r.stderr).strip().splitlines()
        return out[0][:120] if out else "unknown"
    except Exception:
        return "unknown"


def tools_check() -> int:
    from .config import __version__

    print(f"bountyflow {__version__} — tool check")
    rows = [
        ("amass", "amass version"),
        ("subfinder", "subfinder -version"),
        ("httpx-toolkit", "httpx-toolkit -version"),
        ("naabu", "naabu -version"),
        ("nmap", "nmap --version"),
        ("katana", "katana -version"),
        ("gau", "gau --version"),
        ("waybackurls", "waybackurls -version"),
        ("nuclei", "nuclei -version"),
        ("ffuf", "ffuf -V"),
        ("feroxbuster", "feroxbuster --version"),
        ("arjun", "arjun --help"),
        ("dalfox", "dalfox --help"),
    ]
    missing = 0
    for name, ver_cmd in rows:
        path = which(name)
        if name == "httpx-toolkit" and not path:
            alt = which("httpx")
            print(f"  MISS {name} (found python httpx at {alt} — apt install httpx-toolkit)")
            missing += 1
            continue
        status = "OK  " if path else "MISS"
        if not path:
            missing += 1
        ver = tool_version(ver_cmd) if path else "—"
        print(f"  {status} {name:14} {path or '—':40} {ver}")
    print(f"wordlists: dir={DIR_MEDIUM} params={PARAM_WORDS} api={API_WORDS}")
    for p in (DIR_MEDIUM, PARAM_WORDS, API_WORDS):
        if not Path(p).exists():
            print(f"  WARN missing wordlist: {p}")
    return 1 if missing else 0
