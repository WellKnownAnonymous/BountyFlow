"""Public RPC hardening + rate-limit/batch probes (low-rate, testnet-safe)."""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from ..logging_setup import LOG
from ..utils import atomic_write

SENSITIVE_METHODS = [
    "eth_sendTransaction",
    "personal_listAccounts",
    "admin_nodeInfo",
    "debug_traceBlockByNumber",
    "txpool_status",
    "eth_mining",
]

SAFE_METHODS = [
    ("web3_clientVersion", []),
    ("net_version", []),
    ("eth_chainId", []),
    ("eth_blockNumber", []),
]


def _rpc(base: str, method: str, params: list, timeout: int = 10) -> str:
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1})
    p = subprocess.run(
        ["curl", "-sk", "--max-time", str(timeout), "-X", "POST", base,
         "-H", "Content-Type: application/json", "-d", payload],
        capture_output=True, text=True, timeout=timeout + 5,
    )
    return p.stdout.strip()[:800]


def run_rpc_checks(api_url: str, rdir: Path) -> dict:
    """Returns summary; writes rpc_checks.json. Never raises."""
    results: dict = {"base": api_url, "safe": {}, "sensitive": {}, "rate_limit": {}, "batch": {}}
    try:
        for m, params in SAFE_METHODS:
            try:
                results["safe"][m] = _rpc(api_url, m, params)
            except Exception as e:
                results["safe"][m] = f"ERR {e}"
        for m in SENSITIVE_METHODS:
            params = [{"from": "0x0000000000000000000000000000000000000000",
                       "to": "0x0000000000000000000000000000000000000001",
                       "value": "0x1"}] if m == "eth_sendTransaction" else ([] if m not in ("debug_traceBlockByNumber",) else ["0x1", {}])
            try:
                out = _rpc(api_url, m, params)
                # disabled = not supported; anything else needs manual review
                results["sensitive"][m] = out[:300]
            except Exception as e:
                results["sensitive"][m] = f"ERR {e}"
        # rate-limit: 20 rapid eth_blockNumber, count 429 / errors
        codes: list[str] = []
        start = time.time()
        for _ in range(20):
            try:
                out = _rpc(api_url, "eth_blockNumber", [])
                codes.append("ok" if '"result"' in out else out[:60])
            except Exception as e:
                codes.append(f"ERR {e}")
        results["rate_limit"] = {
            "requests": 20, "elapsed_s": round(time.time() - start, 1),
            "blocked_429": sum(1 for c in codes if "429" in c),
            "ok": sum(1 for c in codes if c == "ok"),
        }
        # batch: 10 requests in one HTTP call
        batch = [{"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": i} for i in range(10)]
        try:
            p = subprocess.run(
                ["curl", "-sk", "--max-time", "15", "-X", "POST", api_url,
                 "-H", "Content-Type: application/json", "-d", json.dumps(batch)],
                capture_output=True, text=True, timeout=20,
            )
            results["batch"] = {"bytes": len(p.stdout), "sample": p.stdout[:300]}
        except Exception as e:
            results["batch"] = {"err": str(e)}
    except Exception as e:
        results["error"] = str(e)
    atomic_write(rdir / "rpc_checks.json", json.dumps(results, indent=2))
    LOG.info("rpc checks: safe=%d sensitive_disabled=%d rate_ok=%s",
             len(results["safe"]),
             sum(1 for v in results["sensitive"].values() if "not supported" in str(v)),
             results["rate_limit"].get("ok"))
    return results
