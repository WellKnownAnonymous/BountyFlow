"""P2 single-app fuzz."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import DIR_MEDIUM, PARAM_WORDS, RunConfig
from ..logging_setup import LOG
from ..summarize import summarize_nuclei
from ..tools import which
from ..utils import atomic_write, headers_flag, parse_lines, proxy_flag, q, run_cmd, save_step


def run(cfg: RunConfig, rdir: Path) -> dict:
    base_url = cfg.single_url
    LOG.info("=== PHASE 2: single-app fuzz on %s ===", base_url)
    t = cfg.threads
    hf = headers_flag(cfg.headers, "-H")
    pf_fx = proxy_flag(cfg.proxy, "ferox")
    pf_ff = proxy_flag(cfg.proxy, "ffuf")
    pf_nu = proxy_flag(cfg.proxy, "nuclei")
    # ferox -H repeatable; ffuf -H repeatable; nuclei -H repeatable
    depth = 3 if cfg.aggressive else 2
    ext = "js,json,php,env,git,bak,old,zip,config" if cfg.aggressive else "js,php,json,env"
    cmds: list[tuple[str, str]] = [
        ("2a_ferox", f"feroxbuster -u {q(base_url)} --depth {depth} -w {q(DIR_MEDIUM)} -x {q(ext)} -t {t} --filter-status 404 --auto-tune --auto-bail --collect-words --collect-backups{hf}{pf_fx} -o {q(rdir / 'ferox.txt')}"),
        ("2b_ffuf_params", f"ffuf -u {q(base_url + '/?FUZZ=test')} -w {q(PARAM_WORDS)} -t {t} -mc 200,301,302,403,500 -ac{hf}{pf_ff} -o {q(rdir / 'ffuf_params.json')} -of json"),
        ("2c_nuclei_app", f"nuclei -u {q(base_url)} -t http/exposures/,http/misconfiguration/,http/takeovers/,http/vulnerabilities/ -c {t}{hf}{pf_nu} -jsonl -o {q(rdir / 'nuclei_app.jsonl')}"),
    ]
    # vhost discovery (Cloudflare front) — passive wordlist, low-rate
    try:
        from urllib.parse import urlparse as _up
        _host = _up(base_url).netloc.split(":")[0]
        if which("gobuster"):
            cmds.append(("2a2_vhost", f"gobuster vhost -u {q(base_url)} --wordlist {q(DIR_MEDIUM)} -t {min(t,30)} -q -o {q(rdir / 'vhost.txt')} 2>&1 || true"))
    except Exception:
        pass
    if which("arjun"):
        cmds.insert(2, ("2b2_arjun", f"arjun -u {q(base_url)} -t {t} -o {q(rdir / 'arjun.json')}"))
    else:
        LOG.warning("arjun missing: pip install arjun")
    if which("dalfox"):
        cmds.append(("2d_dalfox", f"dalfox file {q(rdir / 'urls.txt')} -o {q(rdir / 'dalfox.txt')} 2>&1 || dalfox url --url {q(base_url)} -o {q(rdir / 'dalfox.txt')}"))
    else:
        LOG.warning("dalfox missing — skip XSS automation")
    cmds.append(("2e_js_secrets",
        f"grep -Eo 'https?://[^\"'\\'' >]+\\.js(\\?[^\"'\\'' >]*)?' {q(rdir / 'urls.txt')} {q(rdir / 'katana.txt')} {q(rdir / 'hakrawler.txt')} 2>/dev/null | sort -u > {q(rdir / 'jsfiles.txt')} ; "
        f"grep -rhoE '(AKIA[0-9A-Z]{{16}}|xox[bap]-[0-9A-Za-z-]+|gh[pousr]_[A-Za-z0-9_]{{36}}|AIza[0-9A-Za-z_-]{{35}}|secret[_-]?key|api[_-]?key)' {q(rdir)} 2>/dev/null | sort | uniq -c | sort -nr > {q(rdir / 'secrets.txt')} || true"))
    # 2e2 403-bypass + nikto (fast, top URL only)
    cmds.append(("2e2_bypass_nikto",
        f"for code in 403 401; do curl -sk --max-time 10 -o /dev/null -w '%{{http_code}} %{{size_download}}\\n' {q(base_url)} 2>/dev/null; break; done > {q(rdir / 'bypass_probe.txt')} ; "
        f"curl -sk --max-time 10 -H 'X-Forwarded-For: 127.0.0.1' -o /dev/null -w 'xff:%{{http_code}}\\n' {q(base_url)} >> {q(rdir / 'bypass_probe.txt')} 2>/dev/null || true ; "
        f"nikto -h {q(base_url)} -Tuning 2,4 -o {q(rdir / 'nikto.txt')} 2>&1 | head -n 100 > {q(rdir / 'nikto.txt')} || true"))
    # 2e3 dirsearch (bounded, passive wordlist) + sqlmap read-only on explorer-style search if present
    if which("dirsearch"):
        cmds.append(("2e3_dirsearch", f"dirsearch -u {q(base_url)} -w {q(DIR_MEDIUM)} --format=json -o {q(rdir / 'dirsearch.json')} --max-time=120 2>&1 | tail -n 5 || true"))
    if which("sqlmap"):
        cmds.append(("2e4_sqli",
            f"echo {q(base_url)} | grep -q 'explorer' && sqlmap -u {q(base_url + '/api/v2/search?q=test')} --batch --level 1 --risk 1 --random-agent --timeout 10 -o --output-dir={q(rdir / 'sqlmap_out')} 2>&1 | tail -n 20 || echo 'sqlmap skipped (non-explorer or no params)'"))
    for name, cmd in cmds:
        if cfg.dry_run:
            LOG.info("[dry] %s", cmd)
            save_step(rdir, name, cmd, "dry")
            continue
        rc, _ = run_cmd(cmd, rdir, rdir / f"{name}.log", timeout=cfg.timeout)
        save_step(rdir, name, cmd, rc)
    # 2f: fetch JS bodies (bounded) + trufflehog/gitleaks + regex — real secret check
    if not cfg.dry_run:
        try:
            from ..analysis.js_secrets import run_js_stage
            js_summ = run_js_stage(rdir / "urls.txt", rdir, limit=40)
        except Exception as e:
            LOG.warning("js stage failed: %s", e)
            js_summ = {"error": str(e)}
    else:
        LOG.info("[dry] js fetch 40 urls -> js_bodies/ + trufflehog/gitleaks")
        js_summ = {"dry": True}
    summ = {
        "ferox_hits": len(parse_lines(rdir / "ferox.txt")),
        "js_files": len(parse_lines(rdir / "jsfiles.txt")),
        "nuclei": summarize_nuclei(rdir / "nuclei_app.jsonl")[:50],
        "nuclei_total": len(summarize_nuclei(rdir / "nuclei_app.jsonl")),
        "js_stage": js_summ,
    }
    atomic_write(rdir / "SUMMARY_phase2.json", json.dumps(summ, indent=2))
    LOG.info("Phase2: ferox lines=%s js=%s nuclei=%s", summ["ferox_hits"], summ["js_files"], summ["nuclei_total"])
    return summ
