"""P3 API checks."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import RunConfig
from ..logging_setup import LOG
from ..summarize import summarize_nuclei
from ..utils import atomic_write, headers_flag, proxy_flag, q, run_cmd, save_step


def run(cfg: RunConfig, rdir: Path) -> dict:
    from ..config import API_WORDS

    api_url = cfg.api_url
    LOG.info("=== PHASE 3: API %s ===", api_url)
    t = cfg.threads
    hf = headers_flag(cfg.headers, "-H")
    pf_ff = proxy_flag(cfg.proxy, "ffuf")
    pf_nu = proxy_flag(cfg.proxy, "nuclei")
    pf_cu = proxy_flag(cfg.proxy, "curl")
    # curl headers: -H 'K: V' works for curl too
    cmds = [
        ("3a_api_fuzz", f"ffuf -u {q(api_url + '/FUZZ')} -w {q(API_WORDS)} -t {t} -mc 200,201,401,403,500 -ac{hf}{pf_ff} -o {q(rdir / 'api_fuzz.json')} -of json"),
        ("3b_nuclei_api", f"nuclei -u {q(api_url)} -t http/misconfiguration/,http/technologies/graphql/,http/misconfiguration/graphql/ -c {t}{hf}{pf_nu} -jsonl -o {q(rdir / 'nuclei_api.jsonl')}"),
        ("3c_graphql", f"curl -sk -X POST{hf}{pf_cu} {q(api_url + '/graphql')} -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' -o {q(rdir / 'graphql_introspect.json')} ; curl -sk{hf}{pf_cu} {q(api_url + '/swagger.json')} -o {q(rdir / 'swagger.json')} ; curl -sk{hf}{pf_cu} {q(api_url + '/openapi.json')} -o {q(rdir / 'openapi.json')} ; echo done"),
    ]
    for name, cmd in cmds:
        if cfg.dry_run:
            LOG.info("[dry] %s", cmd)
            save_step(rdir, name, cmd, "dry")
            continue
        rc, _ = run_cmd(cmd, rdir, rdir / f"{name}.log", timeout=min(cfg.timeout, 1800))
        save_step(rdir, name, cmd, rc)
    # 3d: RPC hardening + rate-limit/batch (low-rate, testnet-safe) + divergence
    if not cfg.dry_run:
        try:
            from ..analysis.rpc_checks import run_rpc_checks
            rpc_summ = run_rpc_checks(api_url, rdir)
        except Exception as e:
            LOG.warning("rpc checks failed: %s", e)
            rpc_summ = {"error": str(e)}
        try:
            from ..analysis.rpc_divergence import run_divergence
            endpoints = [api_url]
            if cfg.domain.endswith("arc.io") or "arc.network" in api_url:
                endpoints += [
                    "https://rpc.testnet.arc.network",
                    "https://rpc.drpc.testnet.arc.network",
                    "https://rpc.testnet.arc.io",
                    "https://rpc.drpc.testnet.arc.io",
                ]
                endpoints = sorted(set(endpoints))
            div_summ = run_divergence(endpoints, rdir)
        except Exception as e:
            LOG.warning("rpc divergence failed: %s", e)
            div_summ = {"error": str(e)}
        try:
            from ..analysis.web_checks import run_web_checks
            # explorer hint: explorer.testnet for arc.io runs
            explorer = None
            if cfg.domain.endswith("arc.io"):
                explorer = "https://explorer.testnet.arc.io"
            web_summ = run_web_checks(cfg.single_url, explorer, rdir)
        except Exception as e:
            LOG.warning("web checks failed: %s", e)
            web_summ = {"error": str(e)}
    else:
        LOG.info("[dry] rpc checks (safe/sensitive/20x rate-limit/batch+divergence) + web checks (llms/csp/takeover/explorer)")
        rpc_summ, div_summ, web_summ = {"dry": True}, {"dry": True}, {"dry": True}
    summ = {"nuclei": summarize_nuclei(rdir / "nuclei_api.jsonl")[:50], "nuclei_total": len(summarize_nuclei(rdir / "nuclei_api.jsonl")),
            "rpc": rpc_summ, "divergence": div_summ, "web": web_summ}
    checklist = [
        "BOLA: /users/123 -> /users/124, /api/orders/<other-id>",
        "Method tamper: GET vs POST vs PUT on same endpoint",
        'Mass assignment: add {"role":"admin","is_admin":true}',
        "JWT: none alg, empty sig, weak secret",
        "Rate-limit: 20x rapid 401/OTP/login",
        "GraphQL: introspection, batching, field suggestions",
        "IDOR in nested objects: /api/v1/users/me vs /api/v1/users/<id>",
    ]
    atomic_write(rdir / "API_MANUAL_CHECKLIST.md", "# API manual tests (Burp)\n" + "\n".join(f"- [ ] {c}" for c in checklist) + "\n")
    atomic_write(rdir / "SUMMARY_phase3.json", json.dumps(summ, indent=2))
    return summ
