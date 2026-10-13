"""Generic web bug-hunting probes: fingerprint-first, then probe pack.

No portal-hardcoded paths: detects nextjs/webflow/blockscout/vercel/wallet,
then runs nonce-reuse, OTP/limit discovery, llms/CSP/takeover/explorer.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from ..logging_setup import LOG
from ..utils import atomic_write


def _curl(url: str, timeout: int = 15) -> tuple[str, str]:
    p = subprocess.run(["curl", "-sk", "--max-time", str(timeout), "-D", "-", url],
                       capture_output=True, text=True, timeout=timeout + 5)
    return p.stdout[:8000], p.stderr[:1000]


def _curl_body(url: str, timeout: int = 15) -> str:
    p = subprocess.run(["curl", "-sk", "--max-time", str(timeout), url],
                       capture_output=True, text=True, timeout=timeout + 5)
    return p.stdout[:8000]


def _curl_body_big(url: str, timeout: int = 20) -> str:
    p = subprocess.run(["curl", "-sk", "--max-time", str(timeout), url],
                       capture_output=True, text=True, timeout=timeout + 5)
    return p.stdout[:120000]


def fingerprint(base_url: str) -> dict:
    headers, _ = _curl(base_url)
    body = _curl_body_big(base_url)
    blob = (headers + body).lower()
    tags: list[str] = []
    if "__next_f" in blob or "x-powered-by: next.js" in blob:
        tags.append("nextjs")
    if "webflow" in blob or "cdn.webflow" in blob:
        tags.append("webflow")
    if "blockscout" in blob:
        tags.append("blockscout")
    if "server: vercel" in blob or ".vercel.app" in blob:
        tags.append("vercel")
    if "dynamic.xyz" in blob or "dynamicenvironmentid" in blob:
        tags.append("wallet-dynamic")
    if "googletagmanager" in blob:
        tags.append("gtm")
    server = re.search(r"server:\s*([^\r\n]+)", headers, re.I)
    return {"tags": tags, "server": server.group(1).strip()[:60] if server else "",
            "has_next": "__next_f" in blob}


def check_nonce_reuse(base_url: str) -> dict:
    """Fetch twice, compare CSP nonce. Same across responses = bypass."""
    def nonces(h: str, b: str) -> set[str]:
        out = set(re.findall(r"nonce-([A-Za-z0-9+/=]+)", h + b))
        return out
    try:
        h1, _ = _curl(base_url)
        b1 = _curl_body(base_url)
        h2, _ = _curl(base_url)
        b2 = _curl_body(base_url)
        n1, n2 = nonces(h1, b1), nonces(h2, b2)
        reused = bool(n1 and n1 == n2)
        return {"n1": sorted(n1)[:3], "n2": sorted(n2)[:3], "reused": reused,
                "verdict": "FAIL-reused" if reused else "pass-random-or-absent"}
    except Exception as e:
        return {"err": str(e)}


def discover_auth_limits(base_url: str) -> dict:
    body = _curl_body_big(base_url).lower()
    auth_hits = sorted({k for k in ["sendotp", "otp", "signin", "login", "verify", "resend"] if k in body})
    limit_hits = sorted({k for k in ["daily", "weekly", "monthly", "slippage", "minimum", "maximum", "spend limit"] if k in body})
    return {"auth_keywords": auth_hits, "limit_keywords": limit_hits,
            "needs_repeater": bool(auth_hits or limit_hits)}


def check_llms(base_url: str) -> dict:
    out, _ = _curl(base_url.rstrip("/") + "/llms.txt")
    return {"exposed": "200" in out[:30] or "# " in out, "sample": out[:600]}


def check_csp(base_url: str) -> dict:
    headers, _ = _curl(base_url)
    m = re.search(r"Content-Security-Policy:\s*([^\r\n]+)", headers, re.I)
    csp = m.group(1).strip() if m else ""
    weak = any(k in csp for k in ["unsafe-inline", "unsafe-eval", "*", "http:"])
    minimal = bool(csp) and ("script-src" not in csp and "default-src" not in csp)
    return {"csp": csp[:400], "weak": weak, "missing": not bool(csp), "minimal": minimal}


def check_takeover(host: str) -> dict:
    """DNS CNAME hint only — requires manual dig/verify, never claims takeover."""
    try:
        p = subprocess.run(["dig", "+short", "CNAME", host], capture_output=True, text=True, timeout=10)
        cname = p.stdout.strip().splitlines()
        return {"cname": cname[:5], "needs_manual": bool(cname)}
    except Exception as e:
        return {"err": str(e)}


def check_explorer(explorer_base: str) -> dict:
    """Blockscout surface: stats + search API (read-only, low-rate). Body-only."""
    res: dict = {}
    for path in ["/api/v2/stats", "/api/v2/search?q=0x0000000000000000000000000000000000000000"]:
        try:
            body = _curl_body(explorer_base.rstrip("/") + path)
            res[path] = body[:400]
        except Exception as e:
            res[path] = f"ERR {e}"
    return res


def run_web_checks(single_url: str, explorer_url: str | None, rdir: Path) -> dict:
    host = urlparse(single_url).netloc.split(":")[0]
    fp = fingerprint(single_url)
    out = {
        "fingerprint": fp,
        "nonce": check_nonce_reuse(single_url),
        "auth_limits": discover_auth_limits(single_url),
        "llms": check_llms(single_url),
        "csp": check_csp(single_url),
        "takeover": check_takeover(host),
        "explorer": check_explorer(explorer_url) if explorer_url else {"skipped": True},
    }
    atomic_write(rdir / "web_checks.json", json.dumps(out, indent=2))
    LOG.info("web checks %s: tags=%s nonce=%s auth=%s", single_url, fp.get("tags"), out["nonce"].get("verdict"), out["auth_limits"].get("needs_repeater"))
    return out
