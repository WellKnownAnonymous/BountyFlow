"""Scope exclude handling."""
from __future__ import annotations

import re
from pathlib import Path

from .logging_setup import LOG
from .utils import atomic_write, parse_lines


def parse_excludes(s: str | None, exclude_file: str | None) -> set[str]:
    out: set[str] = set()
    if s:
        out |= {x.strip().lower().rstrip(".") for x in s.split(",") if x.strip()}
    if exclude_file:
        p = Path(exclude_file)
        if p.exists():
            out |= {l.strip().lower().rstrip(".") for l in p.read_text(errors="ignore").splitlines() if l.strip() and not l.strip().startswith("#")}
    return out


def apply_excludes(hosts: list[str], excludes: set[str]) -> tuple[list[str], list[str]]:
    """Return (kept, removed). Exact + subdomain match."""
    excl = {e.lower().rstrip(".") for e in excludes}
    kept, removed = [], []
    for h in hosts:
        host = h.strip().lower()
        m = re.search(r"https?://([^/\s\[]+)", host)
        bare = m.group(1).lower() if m else host
        drop = any(bare == e or bare.endswith("." + e) for e in excl)
        (removed if drop else kept).append(h)
    return kept, removed


def write_list_filtered(src: Path, excludes: set[str]) -> tuple[int, int]:
    rows = parse_lines(src)
    if not rows or not excludes:
        return len(rows), 0
    kept, removed = apply_excludes(rows, excludes)
    if removed:
        LOG.info("exclude filter: %s kept=%d removed=%d (%s)", src.name, len(kept), len(removed), ", ".join(removed[:5]))
        atomic_write(src, "\n".join(kept) + ("\n" if kept else ""))
    return len(kept), len(removed)
