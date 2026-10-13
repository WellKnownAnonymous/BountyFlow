"""P3 API checks."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import RunConfig
from ..logging_setup import LOG
from ..summarize import summarize_nuclei
from ..utils import atomic_write, q, run_cmd, save_step


def run(cfg: RunConfig, rdir: Path) -> dict:
    from ..config import API_WORDS

    api_url = cfg.api_url
    LOG.info("=== PHASE 3: API %s ===", api_url)
    t = cfg.threads
    cmds = [
        ("3a_api_fuzz", f"ffuf -u {q(api_url + '/FUZZ')} -w {q(API_WORDS)} -t {t} -mc 200,201,401,403,500 -ac -o {q(rdir / 'api_fuzz.json')} -of json"),
        ("3b_nuclei_api", f"nuclei -u {q(api_url)} -t http/misconfiguration/,http/technologies/graphql/,http/misconfiguration/graphql/ -c {t} -jsonl -o {q(rdir / 'nuclei_api.jsonl')}"),
        ("3c_graphql", f"curl -sk -X POST {q(api_url + '/graphql')} -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' -o {q(rdir / 'graphql_introspect.json')} ; curl -sk {q(api_url + '/swagger.json')} -o {q(rdir / 'swagger.json')} ; curl -sk {q(api_url + '/openapi.json')} -o {q(rdir / 'openapi.json')} ; echo done"),
    ]
    for name, cmd in cmds:
        if cfg.dry_run:
            LOG.info("[dry] %s", cmd)
            save_step(rdir, name, cmd, "dry")
            continue
        rc, _ = run_cmd(cmd, rdir, rdir / f"{name}.log", timeout=min(cfg.timeout, 1800))
        save_step(rdir, name, cmd, rc)
    summ = {"nuclei": summarize_nuclei(rdir / "nuclei_api.jsonl")[:50], "nuclei_total": len(summarize_nuclei(rdir / "nuclei_api.jsonl"))}
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
