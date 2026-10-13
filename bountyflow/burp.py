"""Burp Suite integration: scope config + Repeater bundle (no secrets in git)."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from .logging_setup import LOG
from .utils import atomic_write, parse_lines


def _hosts_from_urls(urls: list[str]) -> list[str]:
    out: list[str] = []
    for u in urls:
        try:
            h = urlparse(u.split()[0]).netloc.split(":")[0].lower()
            if h and h not in out:
                out.append(h)
        except Exception:
            continue
    return sorted(out)


def write_burp_bundle(rdir: Path, domain: str, live_urls: list[str], nuclei_hits: list[dict], api_url: str, explorer_url: str | None) -> dict:
    burp = rdir / "burp"
    burp.mkdir(parents=True, exist_ok=True)
    hosts = _hosts_from_urls(live_urls)
    atomic_write(burp / "scope.txt", "\n".join(hosts) + ("\n" if hosts else ""))
    # Minimal Burp project config with target scope (Import: Project options -> Load)
    config = {
        "target": {"scope": {"include": [{"host": h, "protocol": "https"} for h in hosts],
                                         "exclude": []}},
        "note": f"bountyflow {domain}: set Upstream Proxy if needed, paste Cookie via --header. Excludes enforced at scan time.",
    }
    atomic_write(burp / "project-config.json", json.dumps(config, indent=2))
    # Repeater bundle: top hits + IDOR/RPC checks as raw HTTP/curl
    lines = [f"# Burp Repeater bundle — {domain}", "",
             "## 0. Proxy setup", "- Burp 127.0.0.1:8080, add CA, scope = scope.txt",
             "- Tool run: `bountyflow ... --proxy http://127.0.0.1:8080 --header 'Cookie: sid=YOURS'`", ""]
    lines += ["## 1. Nuclei hits to verify (Repeater → copy request from STEP log)", ""]
    if nuclei_hits:
        for h in nuclei_hits[:15]:
            lines += [f"### [{h.get('severity')}] {h.get('template')}",
                      f"- Host: `{h.get('host')}`", f"- Matched: `{h.get('matched')}`",
                      "- Steps: Repeater → resend → check body/status → screenshot → mark FP if WAF block", ""]
    else:
        lines += ["- No critical/high yet — verify medium/info below, then move to IDOR.", ""]
    lines += ["## 2. Explorer IDOR/BOLA (Blockscout)", "",
              f"- Base: `{explorer_url or 'https://explorer.testnet.arc.io'}`",
              "- `GET /api/v2/addresses/0xYOUR_HASH` vs `.../0xOTHER_HASH` → compare 200/404 + body diff",
              "- `GET /api/v2/search?q=0x...` → try `q=\"' OR 1=1--`, `q=<svg onload=alert(1)>` (read-only, check reflection)",
              "- `GET /api/v2/stats` → note gas/tvl, test `?page=99999&offset=1000` for pagination IDOR", ""]
    lines += ["## 3. RPC (testnet, low-rate)", "",
              f"- Base: `{api_url}`",
              "- `POST {{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}}` ×20 → any 429? (we saw 20/20 ok)",
              "- Batch 10× blockNumber in one POST → works (461b) → try 50×, measure time (stop if slow)",
              "- Sensitive must stay disabled: `eth_sendTransaction/personal/admin/debug/txpool` → expect -32601", ""]
    lines += ["## 4. Cookie/session", "- Login in browser → Burp HTTP history → Copy `Cookie:` → rerun tool with `--header 'Cookie: ...'` + `--proxy ...`",
              "- Auth-only: `/portal`, `/studio`, `/origin` (403 unauth) → retest 200/403 diff", ""]
    atomic_write(burp / "repeater.md", "\n".join(lines))
    LOG.info("burp bundle: %d hosts, %d hits", len(hosts), len(nuclei_hits))
    return {"hosts": len(hosts), "hits": len(nuclei_hits)}
