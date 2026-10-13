"""P2 single-app fuzz."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import API_WORDS, DIR_MEDIUM, PARAM_WORDS, RunConfig
from ..logging_setup import LOG
from ..summarize import summarize_nuclei
from ..tools import which
from ..utils import atomic_write, parse_lines, q, run_cmd, save_step


def run(cfg: RunConfig, rdir: Path) -> dict:
    base_url = cfg.single_url
    LOG.info("=== PHASE 2: single-app fuzz on %s ===", base_url)
    t = cfg.threads
    depth = 3 if cfg.aggressive else 2
    ext = "js,json,php,env,git,bak,old,zip,config" if cfg.aggressive else "js,php,json,env"
    cmds: list[tuple[str, str]] = [
        ("2a_ferox", f"feroxbuster -u {q(base_url)} --depth {depth} -w {q(DIR_MEDIUM)} -x {q(ext)} -t {t} --filter-status 404 --auto-tune --auto-bail -o {q(rdir / 'ferox.txt')}"),
        ("2b_ffuf_params", f"ffuf -u {q(base_url + '/?FUZZ=test')} -w {q(PARAM_WORDS)} -t {t} -mc 200,301,302,403,500 -ac -o {q(rdir / 'ffuf_params.json')} -of json"),
        ("2c_nuclei_app", f"nuclei -u {q(base_url)} -t http/exposures/,http/misconfiguration/,http/takeovers/,http/vulnerabilities/ -c {t} -jsonl -o {q(rdir / 'nuclei_app.jsonl')}"),
    ]
    if which("arjun"):
        cmds.insert(2, ("2b2_arjun", f"arjun -u {q(base_url)} -t {t} -o {q(rdir / 'arjun.json')}"))
    else:
        LOG.warning("arjun missing: pip install arjun")
    if which("dalfox"):
        cmds.append(("2d_dalfox", f"dalfox file {q(rdir / 'urls.txt')} -o {q(rdir / 'dalfox.txt')} 2>&1 || dalfox url --url {q(base_url)} -o {q(rdir / 'dalfox.txt')}"))
    else:
        LOG.warning("dalfox missing — skip XSS automation")
    cmds.append(("2e_js_secrets",
        f"grep -Eo 'https?://[^\"'\\'' >]+\\.js(\\?[^\"'\\'' >]*)?' {q(rdir / 'urls.txt')} {q(rdir / 'katana.txt')} 2>/dev/null | sort -u > {q(rdir / 'jsfiles.txt')} ; "
        f"grep -rhoE '(AKIA[0-9A-Z]{{16}}|xox[bap]-[0-9A-Za-z-]+|gh[pousr]_[A-Za-z0-9_]{{36}}|AIza[0-9A-Za-z_-]{{35}}|secret[_-]?key|api[_-]?key)' {q(rdir)} 2>/dev/null | sort | uniq -c | sort -nr > {q(rdir / 'secrets.txt')} || true"))
    for name, cmd in cmds:
        if cfg.dry_run:
            LOG.info("[dry] %s", cmd)
            save_step(rdir, name, cmd, "dry")
            continue
        rc, _ = run_cmd(cmd, rdir, rdir / f"{name}.log", timeout=cfg.timeout)
        save_step(rdir, name, cmd, rc)
    summ = {
        "ferox_hits": len(parse_lines(rdir / "ferox.txt")),
        "js_files": len(parse_lines(rdir / "jsfiles.txt")),
        "nuclei": summarize_nuclei(rdir / "nuclei_app.jsonl")[:50],
        "nuclei_total": len(summarize_nuclei(rdir / "nuclei_app.jsonl")),
    }
    atomic_write(rdir / "SUMMARY_phase2.json", json.dumps(summ, indent=2))
    LOG.info("Phase2: ferox lines=%s js=%s nuclei=%s", summ["ferox_hits"], summ["js_files"], summ["nuclei_total"])
    return summ
