"""P1 wildcard recon."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import RunConfig
from ..logging_setup import LOG
from ..scope import write_list_filtered
from ..summarize import build_clean_lists, summarize_httpx, summarize_nuclei
from ..tools import httpx_bin, which
from ..utils import atomic_write, headers_flag, parse_lines, proxy_flag, q, run_cmd, save_step


def run(cfg: RunConfig, rdir: Path) -> dict:
    LOG.info("=== PHASE 1: wildcard recon ===")
    subs = rdir / "subs.txt"
    cmds: list[tuple[str, str]] = []
    c1 = f"amass enum -brute -d {q(cfg.domain)} -o {q(rdir / 'amass.txt')}"
    if which("subfinder"):
        c1 += f" ; subfinder -d {q(cfg.domain)} -silent -o {q(rdir / 'subfinder.txt')}"
    else:
        LOG.warning("subfinder missing — amass only")
    if which("assetfinder"):
        c1 += f" ; assetfinder --subs-only {q(cfg.domain)} > {q(rdir / 'assetfinder.txt')} 2>/dev/null || true"
    if which("findomain"):
        c1 += f" ; findomain -t {q(cfg.domain)} -q -u {q(rdir / 'findomain.txt')} 2>/dev/null || true"
    c1 += f" ; cat {q(rdir / 'amass.txt')} {q(rdir / 'subfinder.txt')} {q(rdir / 'assetfinder.txt')} {q(rdir / 'findomain.txt')} 2>/dev/null | sort -u > {q(subs)} || cp {q(rdir / 'amass.txt')} {q(subs)}"
    cmds.append(("1a_subs", c1))

    hx = httpx_bin()
    hf = headers_flag(cfg.headers, "-H")
    px = proxy_flag(cfg.proxy, "httpx")
    c2 = f"{hx} -l {q(subs)} -silent -td -cdn -status-code -title -threads {cfg.threads}{hf}{px} -o {q(rdir / 'live.txt')}"
    cmds.append(("1b_httpx", c2))

    ports = "1000" if cfg.aggressive else "100"
    c3 = f"nmap -sV -T4 --top-ports {ports} -iL {q(rdir / 'live_hosts.txt')} -oN {q(rdir / 'nmap.txt')}"
    if which("naabu"):
        c3 = f"naabu -list {q(rdir / 'live_hosts.txt')} -top-ports {ports} -o {q(rdir / 'ports.txt')} ; " + c3
    cmds.append(("1c_ports", c3))

    url_parts = []
    if which("katana"):
        url_parts.append(f"katana -list {q(rdir / 'live_urls.txt')} -d 3 -silent{hf}{proxy_flag(cfg.proxy, 'katana')} -o {q(rdir / 'katana.txt')}")
    if which("hakrawler"):
        url_parts.append(f"cat {q(rdir / 'live_urls.txt')} | hakrawler -subs -u -d 2 2>/dev/null | sort -u > {q(rdir / 'hakrawler.txt')} || true")
    if which("gau"):
        url_parts.append(f"gau --subs {q(cfg.domain)} > {q(rdir / 'gau.txt')}")
    if which("waybackurls"):
        url_parts.append(f"cat {q(rdir / 'live_urls.txt')} | waybackurls > {q(rdir / 'wayback.txt')}")
    if url_parts:
        dedup = f"cat {q(rdir / 'katana.txt')} {q(rdir / 'hakrawler.txt')} {q(rdir / 'gau.txt')} {q(rdir / 'wayback.txt')} 2>/dev/null | sort -u"
        # uro dedup if present (handles params), else sort -u
        dedup = f"({dedup} | uro 2>/dev/null || cat) | sort -u > {q(rdir / 'urls.txt')} || true"
        cmds.append(("1d_urls", " ; ".join(url_parts) + f" ; {dedup}"))

    rate = 150 if cfg.aggressive else 50
    # shard note: full 6607-template scan times out on 30+ hosts; keep recon set tight, app/API sharded in P2/P3
    c5 = f"nuclei -l {q(rdir / 'live_urls.txt')} -severity critical,high,medium -c {rate}{hf}{proxy_flag(cfg.proxy, 'nuclei')} -jsonl -o {q(rdir / 'nuclei_recon.jsonl')}"
    cmds.append(("1e_nuclei", c5))

    # 1f fingerprint: waf + tech (fast, low-risk) on top live only
    cmds.append(("1f_fingerprint",
        f"head -n 20 {q(rdir / 'live_urls.txt')} | wafw00f -i - 2>/dev/null > {q(rdir / 'waf.txt')} || true ; "
        f"head -n 20 {q(rdir / 'live_urls.txt')} | xargs -I{{}} whatweb --no-errors -a 1 {{}} 2>/dev/null > {q(rdir / 'whatweb.txt')} || true"))
    # 1g takeovers: verify-oriented, no brute claim
    cmds.append(("1g_takeover",
        f"nuclei -l {q(rdir / 'live_urls.txt')} -t http/takeovers/ -c {rate} -jsonl -o {q(rdir / 'nuclei_takeover.jsonl')} 2>&1 || true ; "
        f"subzy run --targets {q(rdir / 'live_hosts.txt')} --output {q(rdir / 'subzy.txt')} 2>/dev/null || true"))

    for name, cmd in cmds:
        if cfg.dry_run:
            LOG.info("[dry] %s", cmd)
            save_step(rdir, name, cmd, "dry")
            continue
        if name in ("1c_ports", "1d_urls", "1e_nuclei", "1f_fingerprint", "1g_takeover"):
            build_clean_lists(rdir)
        rc, _ = run_cmd(cmd, rdir, rdir / f"{name}.log", timeout=cfg.timeout)
        save_step(rdir, name, cmd, rc)
        if name == "1a_subs" and cfg.excludes:
            write_list_filtered(subs, cfg.excludes)
        if name == "1b_httpx":
            build_clean_lists(rdir)
            if cfg.excludes:
                write_list_filtered(rdir / "live.txt", cfg.excludes)
                build_clean_lists(rdir)

    summ = {
        "subs": len(parse_lines(subs)),
        **summarize_httpx(rdir / "live.txt"),
        "urls": len(parse_lines(rdir / "urls.txt")),
        "hakrawler_lines": len(parse_lines(rdir / "hakrawler.txt")),
        "waf": parse_lines(rdir / "waf.txt")[:10],
        "whatweb": parse_lines(rdir / "whatweb.txt")[:10],
        "takeover": summarize_nuclei(rdir / "nuclei_takeover.jsonl")[:20],
        "nuclei": summarize_nuclei(rdir / "nuclei_recon.jsonl")[:50],
        "nuclei_total": len(summarize_nuclei(rdir / "nuclei_recon.jsonl")),
    }
    atomic_write(rdir / "SUMMARY_phase1.json", json.dumps(summ, indent=2))
    LOG.info("Phase1: %s subs, %s live, %s urls, %s nuclei hits", summ["subs"], summ["live_count"], summ["urls"], summ["nuclei_total"])
    return summ
