"""AI summary + findings."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from ..config import API_WORDS, DIR_MEDIUM, PARAM_WORDS, RunConfig, __version__
from ..logging_setup import LOG
from ..utils import atomic_write


def build(domain: str, rdir: Path, s1: dict | None, s2: dict | None, s3: dict | None, cfg: RunConfig, started: float) -> None:
    crit: list[dict] = []
    medium: list[dict] = []
    for s in (s1, s2, s3):
        if not s:
            continue
        for h in s.get("nuclei", []):
            sev = str(h.get("severity", "")).lower()
            if sev in ("critical", "high"):
                crit.append(h)
            elif sev == "medium":
                medium.append(h)
    ai = {
        "tool": f"bountyflow/{__version__}",
        "target": domain,
        "run_dir": str(rdir),
        "time": datetime.now(timezone.utc).isoformat(),
        "duration_s": round(time.time() - started, 1),
        "config": {
            "phases": sorted(cfg.phases),
            "aggressive": cfg.aggressive,
            "threads": cfg.threads,
            "excludes": sorted(cfg.excludes),
            "single_url": cfg.single_url,
            "api_url": cfg.api_url,
        },
        "wordlists": {"dir": DIR_MEDIUM, "params": PARAM_WORDS, "api": API_WORDS},
        "phase1": s1, "phase2": s2, "phase3": s3,
        "priority_review": crit[:30],
        "medium_review": medium[:30],
        "auth_headers_set": bool(cfg.headers),
        "next_manual": [
            "Verify nuclei critical/high/medium in Burp Repeater (false positives common)",
            "Review ferox 200/301 + 403 (bypass: X-Forwarded-For, /%2e/, method override)",
            "Review js_bodies/secrets_body.json + trufflehog/gitleaks (FP: publishable keys, asn1 strings)",
            "Explorer: test /api/v2/addresses/:hash vs other hash (IDOR), sort/order injection, rate-limit 20x",
            "RPC: compare providers (divergence), batch 10x, no sensitive methods (already disabled = pass)",
            "Run Burp active scan on 2-3 high-value endpoints only (avoid WAF ban)",
        ],
    }
    atomic_write(rdir / "AI_SUMMARY.json", json.dumps(ai, indent=2))
    top = [f"- [{h.get('severity')}] `{h.get('template')}` {h.get('host')}" for h in crit[:30]] or ["- none yet"]
    if medium:
        top += ["", "## Medium (review after critical/high)"] + [f"- [medium] `{h.get('template')}` {h.get('host')}" for h in medium[:15]]
    counts = {k: (v if not isinstance(v, list) else len(v)) for k, v in {**(s1 or {}), **(s2 or {}), **(s3 or {})}.items()}
    md = [
        f"# findings {domain}", "", f"- run: {rdir}", f"- critical/high: {len(crit)} medium: {len(medium)}", "",
        "## Top hits", *top, "", "## Counts", f"```json\n{json.dumps(counts, indent=2)}\n```",
        "", "## Manual queue", "- [ ] IDOR/BOLA  - [ ] authz  - [ ] rate-limit  - [ ] file upload  - [ ] SSRF/SSTI",
    ]
    atomic_write(rdir / "findings.md", "\n".join(md))
    # HackerOne-ready stub: one section per critical/high with repeater steps
    h1 = [f"# HackerOne draft — {domain}", "", f"Run: `{rdir}`", "",
          "## Summary", f"{len(crit)} critical/high, {len(medium)} medium. Verify each below in Burp Repeater before submitting.", ""]
    for h in (crit[:10] + medium[:5]):
        h1 += [f"### [{h.get('severity')}] {h.get('template')}",
               f"- Host: `{h.get('host')}`", f"- Matched: `{h.get('matched')}`",
               "- Repro: Burp Repeater → copy request from nuclei log → check status/body → screenshot",
               "- Impact: explain authz/data impact; mark FP if WAF block/headers-only", ""]
    h1 += ["## Attachments", "- nuclei jsonl lines", "- httpx live.txt + config.json", ""]
    atomic_write(rdir / "findings_hackerone.md", "\n".join(h1))
    # Burp bundle: scope + repeater (uses clean live_urls when available)
    try:
        from ..burp import write_burp_bundle
        from ..utils import parse_lines as _pl
        _live = _pl(rdir / "live_urls.txt") or _pl(rdir / "live.txt")
        _nuc = (s1 or {}).get("nuclei", []) + (s2 or {}).get("nuclei", []) + (s3 or {}).get("nuclei", [])
        _explorer = None
        if domain.endswith("arc.io"):
            _explorer = "https://explorer.testnet.arc.io"
        write_burp_bundle(rdir, domain, _live, _nuc, cfg.api_url, _explorer)
    except Exception as e:
        LOG.warning("burp bundle failed: %s", e)
    LOG.info("Wrote AI_SUMMARY.json + findings.md in %s", rdir)
