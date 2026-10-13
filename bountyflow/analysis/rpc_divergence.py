"""Cross-provider RPC consensus divergence (read-only, low-rate).

For Arc: compare net_version/chainId/blockNumber across testnet RPC providers.
Divergence can indicate routing/sync issues — report as info, verify manually.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..logging_setup import LOG
from ..utils import atomic_write


def _rpc(base: str, method: str, timeout: int = 10) -> str:
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": [], "id": 1})
    p = subprocess.run(
        ["curl", "-sk", "--max-time", str(timeout), "-X", "POST", base,
         "-H", "Content-Type: application/json", "-d", payload],
        capture_output=True, text=True, timeout=timeout + 5,
    )
    try:
        j = json.loads(p.stdout)
        return str(j.get("result", p.stdout[:200]))
    except Exception:
        return p.stdout[:200]


def run_divergence(endpoints: list[str], rdir: Path) -> dict:
    rows: dict = {}
    for ep in endpoints:
        try:
            rows[ep] = {
                "net_version": _rpc(ep, "net_version"),
                "eth_chainId": _rpc(ep, "eth_chainId"),
                "eth_blockNumber": _rpc(ep, "eth_blockNumber"),
            }
        except Exception as e:
            rows[ep] = {"err": str(e)}
    # flag divergence
    chain_ids = {str(v.get("eth_chainId")) for v in rows.values() if isinstance(v, dict) and "eth_chainId" in v}
    nets = {str(v.get("net_version")) for v in rows.values() if isinstance(v, dict) and "net_version" in v}
    out = {"endpoints": rows, "chainId_diverged": len(chain_ids) > 1, "net_diverged": len(nets) > 1,
           "chainIds": sorted(chain_ids), "nets": sorted(nets)}
    atomic_write(rdir / "rpc_divergence.json", json.dumps(out, indent=2))
    LOG.info("rpc divergence: chainIds=%s nets=%s diverged=%s", out["chainIds"], out["nets"], out["chainId_diverged"] or out["net_diverged"])
    return out
