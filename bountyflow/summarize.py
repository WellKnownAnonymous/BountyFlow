"""Parsers and clean-list builders."""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .logging_setup import LOG
from .utils import atomic_write, parse_lines


def summarize_nuclei(nfile: Path) -> list[dict]:
    p = Path(nfile)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
            out.append({
                "template": j.get("template-id") or j.get("templateID", "?"),
                "host": j.get("host", "?"),
                "severity": j.get("info", {}).get("severity", "?"),
                "matched": j.get("matched-at", "?"),
            })
        except Exception:
            m = re.match(r"\[(.+?)\]\s+\[(.+?)\]\s+(\S+)", line)
            out.append({"raw": line[:300]} if not m else {"template": m.group(1), "severity": m.group(2), "host": m.group(3)})
    return out


def summarize_httpx(live_file: Path) -> dict:
    rows = parse_lines(live_file)
    codes: dict[str, int] = {}
    for r in rows:
        m = re.search(r"\s\[(\d{3})\]", r)
        if m:
            codes[m.group(1)] = codes.get(m.group(1), 0) + 1
    waf_hint = sum(1 for r in rows if "[403]" in r and "loudflare" in r.lower())
    return {"live_count": len(rows), "status_breakdown": codes, "waf_403_cloudflare": waf_hint, "sample": rows[:20]}


def extract_url(line: str) -> str | None:
    line = line.strip()
    if not line:
        return None
    tok = line.split()[0].strip().strip("'\"")
    if tok.startswith("http://") or tok.startswith("https://"):
        return tok
    return None


def extract_host(url: str) -> str | None:
    try:
        h = urlparse(url).netloc.split("@")[-1].split(":")[0].lower().rstrip(".")
        return h or None
    except Exception:
        return None


def build_clean_lists(rdir: Path) -> dict:
    """Derive clean inputs from raw httpx output (fixes nuclei/nmap false-negatives)."""
    raw = parse_lines(rdir / "live.txt")
    urls: list[str] = []
    for line in raw:
        u = extract_url(line)
        if u and u not in urls:
            urls.append(u)
    hosts: list[str] = []
    for u in urls:
        h = extract_host(u)
        if h and h not in hosts:
            hosts.append(h)
    atomic_write(rdir / "live_urls.txt", "\n".join(urls) + ("\n" if urls else ""))
    atomic_write(rdir / "live_hosts.txt", "\n".join(hosts) + ("\n" if hosts else ""))
    LOG.info("clean lists: raw=%d urls=%d hosts=%d", len(raw), len(urls), len(hosts))
    return {"raw": len(raw), "urls": len(urls), "hosts": len(hosts)}
