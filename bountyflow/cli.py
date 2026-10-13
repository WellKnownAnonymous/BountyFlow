"""CLI entrypoint."""
from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .config import FINDINGS, RunConfig, __version__
from .logging_setup import LOG, setup_logging
from .phases import phase1, phase2, phase3, summary
from .scope import parse_excludes
from .tools import httpx_bin, tools_check, which
from .utils import atomic_write, parse_phases, validate_domain, validate_url


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="bountyflow",
        description="Scoped bug-bounty recon: P1 wildcard + P2 app fuzz + P3 API. Only use on authorized targets.",
    )
    ap.add_argument("-d", "--domain", help="wildcard root, e.g. example.com")
    ap.add_argument("--phases", default="all", help="1,2,3 or all (default: all)")
    ap.add_argument("--single-url", default=None, help="P2 target (default https://<domain>)")
    ap.add_argument("--api-url", default=None, help="P3 target (default https://api.<domain>)")
    ap.add_argument("--aggressive", action="store_true", help="max threads/depth/ports")
    ap.add_argument("--dry-run", action="store_true", help="print commands only")
    ap.add_argument("--exclude", default="", help="comma-separated hosts to never scan (exact + subdomains)")
    ap.add_argument("--exclude-file", default=None, help="file with one excluded host per line")
    ap.add_argument("--threads", type=int, default=None, help="override thread count (default 100 aggressive, 40 normal)")
    ap.add_argument("--timeout", type=int, default=3600, help="per-step timeout seconds (default 3600)")
    ap.add_argument("--output-dir", default=None, help="custom output base dir (default ./finding)")
    ap.add_argument("--header", action="append", default=[], help="custom header 'Name: value' (repeatable, e.g. --header 'Cookie: sid=...')")
    ap.add_argument("--cookie", default=None, help="shorthand for --header 'Cookie: ...' (session from Burp/brower)")
    ap.add_argument("--proxy", default="", help="route scans via Burp, e.g. http://127.0.0.1:8080")
    ap.add_argument("--tools-check", action="store_true", help="check external binaries and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--version", action="store_true", help="print version and exit")
    return ap


def main(argv: list[str] | None = None) -> int:
    signal.signal(signal.SIGINT, lambda *_: (LOG.error("interrupted"), sys.exit(130)))
    ap = build_parser()
    a = ap.parse_args(argv)
    setup_logging(a.verbose)

    if a.version:
        print(__version__)
        return 0
    if a.tools_check:
        return tools_check()
    if not a.domain:
        ap.error("-d/--domain is required (or use --tools-check)")

    try:
        domain = validate_domain(a.domain)
        phases = parse_phases(a.phases)
        single_url = validate_url(a.single_url) if a.single_url else f"https://{domain}"
        api_url = validate_url(a.api_url) if a.api_url else f"https://api.{domain}"
        excludes = parse_excludes(a.exclude, a.exclude_file)
    except ValueError as e:
        ap.error(str(e))
        return 2

    threads = a.threads or (100 if a.aggressive else 40)
    out_base = Path(a.output_dir) if a.output_dir else FINDINGS
    try:
        headers = tuple(h.strip() for h in (a.header or []) if h.strip())
        if a.cookie:
            headers = headers + (f"Cookie: {a.cookie.strip()}",)
        # validate early
        from .utils import headers_flag, validate_url as _vu
        headers_flag(headers)
        proxy = (a.proxy or "").strip()
        if proxy:
            _vu(proxy.replace("http://", "https://") if "://" not in proxy else proxy)
    except ValueError as e:
        ap.error(str(e))
        return 2
    cfg = RunConfig(
        domain=domain, phases=phases, single_url=single_url, api_url=api_url,
        aggressive=a.aggressive, dry_run=a.dry_run, excludes=excludes,
        timeout=a.timeout, threads=threads, out_base=out_base, headers=headers, proxy=proxy,
    )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    rdir = out_base / domain / ts
    rdir.mkdir(parents=True, exist_ok=True)
    started = time.time()
    LOG.info("run dir: %s", rdir)
    LOG.info("tools: amass=%s pd-httpx=%s nuclei=%s ffuf=%s ferox=%s",
             bool(which("amass")), httpx_bin(), bool(which("nuclei")), bool(which("ffuf")), bool(which("feroxbuster")))
    if excludes:
        LOG.info("excludes (%d): %s", len(excludes), ", ".join(sorted(excludes)))

    atomic_write(rdir / "config.json", json.dumps({
        "tool": f"bountyflow/{__version__}", "domain": domain,
        "phases": sorted(phases), "single_url": single_url, "api_url": api_url,
        "aggressive": a.aggressive, "threads": threads, "excludes": sorted(excludes),
        "headers_set": bool(headers), "headers_count": len(headers),
        "proxy_set": bool(proxy),
        "started": datetime.now(timezone.utc).isoformat(),
    }, indent=2))

    s1 = s2 = s3 = None
    if 1 in phases:
        s1 = phase1.run(cfg, rdir)
    if 2 in phases:
        host = urlparse(single_url).netloc.split(":")[0].lower()
        if any(host == e or host.endswith("." + e) for e in excludes):
            LOG.error("P2 skipped: single-url host %s is excluded", host)
        else:
            s2 = phase2.run(cfg, rdir)
    if 3 in phases:
        host = urlparse(api_url).netloc.split(":")[0].lower()
        if any(host == e or host.endswith("." + e) for e in excludes):
            LOG.error("P3 skipped: api-url host %s is excluded", host)
        else:
            s3 = phase3.run(cfg, rdir)

    if not cfg.dry_run:
        summary.build(domain, rdir, s1, s2, s3, cfg, started)
    else:
        LOG.info("dry-run done")
    return 0
