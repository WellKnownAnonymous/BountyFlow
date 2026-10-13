"""Fetch JS bodies (bounded) + secret scan.

Only fetches first-party / in-scope hosts by default to avoid hammering CDNs.
Falls back to trufflehog/gitleaks when installed, plus regex.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from ..logging_setup import LOG
from ..utils import atomic_write, parse_lines, q

SECRET_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|xox[bap]-[0-9A-Za-z-]+|gh[pousr]_[A-Za-z0-9_]{36}|"
    r"AIza[0-9A-Za-z_-]{35}|sk-live-[0-9A-Za-z]{10,}|secret[_-]?key|api[_-]?key)",
    re.I,
)

FIRST_PARTY_HINTS = ("arc.io", "arc.network")


def pick_js_targets(urls_file: Path, limit: int = 40) -> list[str]:
    rows = parse_lines(urls_file)
    js = [l.split()[0] for l in rows if ".js" in l.split()[0]]
    # prefer first-party (arc.io / arc.network), then rest
    def score(u: str) -> int:
        try:
            h = urlparse(u).netloc.lower()
        except Exception:
            return 2
        return 0 if any(h == x or h.endswith("." + x) for x in FIRST_PARTY_HINTS) else 1
    js_sorted = sorted(set(js), key=score)
    picks = js_sorted[:limit]
    # source-maps: try URL + .map for each pick (bounded, deduped later)
    maps = [u + ".map" for u in picks if not u.endswith(".map")]
    return (picks + maps)[: limit + 10]


def fetch_js_bodies(js_urls: list[str], out_dir: Path, timeout_each: int = 15) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []
    for i, u in enumerate(js_urls):
        dest = out_dir / f"js_{i:03d}.js"
        # quoted, single file, bounded time
        cmd = f"curl -sk --max-time {timeout_each} -A 'Mozilla/5.0' {q(u)} -o {q(dest)}"
        try:
            p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout_each + 5)
            if dest.exists() and dest.stat().st_size > 0 and p.returncode == 0:
                # drop huge bundles >2MB to keep scans fast
                if dest.stat().st_size <= 2_000_000:
                    saved.append(dest)
                else:
                    dest.unlink(missing_ok=True)
            else:
                dest.unlink(missing_ok=True)
        except Exception as e:
            LOG.debug("js fetch fail %s: %s", u, e)
    LOG.info("js fetch: %d urls -> %d bodies", len(js_urls), len(saved))
    return saved


def regex_scan(files: list[Path]) -> list[dict]:
    hits: list[dict] = []
    for f in files:
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        for m in SECRET_RE.finditer(text):
            hits.append({"file": f.name, "match": m.group(0)[:120]})
            if len(hits) >= 100:
                return hits
    return hits


def run_trufflehog_gitleaks(target_dir: Path, rdir: Path) -> dict:
    out: dict = {}
    try:
        from ..tools import which
        if which("trufflehog"):
            # filesystem scan, JSON, bounded
            cmd = f"trufflehog filesystem {q(target_dir)} --json --no-update 2>/dev/null | head -c 20000 > {q(rdir / 'trufflehog.json')}"
            subprocess.run(cmd, shell=True, timeout=120)
            p = rdir / "trufflehog.json"
            out["trufflehog"] = len(parse_lines(p)) if p.exists() else 0
        if which("gitleaks"):
            cmd = f"gitleaks detect --source {q(target_dir)} --no-git -v 2>&1 | head -n 100 > {q(rdir / 'gitleaks.txt')}"
            subprocess.run(cmd, shell=True, timeout=120)
            p = rdir / "gitleaks.txt"
            out["gitleaks_lines"] = len(parse_lines(p)) if p.exists() else 0
    except Exception as e:
        LOG.debug("secret scanner err: %s", e)
    return out


def run_js_stage(urls_file: Path, rdir: Path, limit: int = 40) -> dict:
    js_urls = pick_js_targets(urls_file, limit=limit)
    atomic_write(rdir / "js_targets.txt", "\n".join(js_urls) + ("\n" if js_urls else ""))
    bodies_dir = rdir / "js_bodies"
    saved = fetch_js_bodies(js_urls, bodies_dir)
    hits = regex_scan(saved)
    atomic_write(rdir / "secrets_body.json", json.dumps(hits[:100], indent=2))
    tool_counts = run_trufflehog_gitleaks(bodies_dir, rdir)
    summ = {"js_targets": len(js_urls), "js_fetched": len(saved), "regex_hits": len(hits), **tool_counts}
    atomic_write(rdir / "SUMMARY_js.json", json.dumps(summ, indent=2))
    LOG.info("js secrets: targets=%d fetched=%d regex=%d %s", summ["js_targets"], summ["js_fetched"], summ["regex_hits"], tool_counts)
    return summ
