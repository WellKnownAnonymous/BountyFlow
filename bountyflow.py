#!/usr/bin/env python3
"""
BountyFlow v2 — scoped bug-bounty recon workflow.

Chains: wildcard recon (P1) + single-app fuzz (P2) + API checks (P3).
Saves raw output + AI-readable summaries under ./runs/<target>/<timestamp>/.

Only test in-scope / authorized targets. Excludes are enforced AFTER
enumeration and BEFORE live probing / scanning.

Usage:
  python3 bountyflow.py -d example.com --phases 1 --dry-run
  python3 bountyflow.py -d example.com --phases all --aggressive \\
      --single-url https://app.example.com --api-url https://api.example.com \\
      --exclude help.example.com,explorer.example.com
  python3 bountyflow.py --tools-check
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

__version__ = "2.0.0"

BASE = Path(__file__).resolve().parent
RUNS = BASE / "runs"

LOG = logging.getLogger("bountyflow")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class RunConfig:
    domain: str
    phases: set[int]
    single_url: str
    api_url: str
    aggressive: bool = False
    dry_run: bool = False
    excludes: set[str] = field(default_factory=set)
    timeout: int = 3600
    threads: int = 100
    out_base: Path = RUNS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[bountyflow] %(message)s"))
    LOG.setLevel(level)
    LOG.handlers = [handler]


def q(p: object) -> str:
    """Shell-quote a path/arg (workspace may contain spaces, e.g. 'My Tools')."""
    return shlex.quote(str(p))


def which(t: str) -> str | None:
    return shutil.which(t)


def httpx_bin() -> str:
    """Prefer ProjectDiscovery httpx. Kali ships python-httpx as /usr/bin/httpx."""
    for cand in ("httpx-toolkit", "httpx"):
        p = which(cand)
        if not p:
            continue
        if cand == "httpx":
            try:
                r = subprocess.run(
                    "httpx --help 2>&1 | head -n 20", shell=True,
                    capture_output=True, text=True, timeout=5,
                )
                blob = r.stdout + r.stderr
                if "No such option" in blob or "next generation HTTP client" in blob:
                    continue
            except Exception:
                continue
        return cand
    return "httpx-toolkit"


def tool_version(cmd: str) -> str:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        out = (r.stdout + r.stderr).strip().splitlines()
        return out[0][:120] if out else "unknown"
    except Exception:
        return "unknown"


def validate_domain(d: str) -> str:
    d = d.strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,248}[a-z0-9])?", d):
        raise ValueError(f"invalid domain: {d!r}")
    return d


def validate_url(u: str) -> str:
    p = urlparse(u.strip())
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError(f"invalid URL (need http(s)://host): {u!r}")
    return u.rstrip("/")


def parse_phases(s: str) -> set[int]:
    s = s.strip().lower()
    if s == "all":
        return {1, 2, 3}
    out: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if part not in ("1", "2", "3"):
            raise ValueError(f"--phases must be 1,2,3 or all (got {s!r})")
        out.add(int(part))
    return out


def parse_excludes(s: str | None, exclude_file: str | None) -> set[str]:
    out: set[str] = set()
    if s:
        out |= {x.strip().lower().rstrip(".") for x in s.split(",") if x.strip()}
    if exclude_file:
        p = Path(exclude_file)
        if p.exists():
            out |= {l.strip().lower().rstrip(".") for l in p.read_text(errors="ignore").splitlines() if l.strip() and not l.strip().startswith("#")}
    return out


def find_wordlist(*candidates: str) -> str:
    for c in candidates:
        if Path(c).exists():
            return c
    return candidates[0]


DIR_MEDIUM = find_wordlist(
    "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
)
PARAM_WORDS = find_wordlist(
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "/usr/share/wordlists/wfuzz/general/common.txt",
)
API_WORDS = find_wordlist(
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
)


def run_cmd(cmd: str, cwd: Path, out_file: Path | None = None, timeout: int = 3600) -> tuple[int, subprocess.CompletedProcess | None]:
    """Run shell cmd. Never raises. Saves combined blob to out_file."""
    LOG.info("$ %s", cmd)
    start = time.time()
    try:
        p = subprocess.run(cmd, shell=True, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
        elapsed = round(time.time() - start, 1)
        blob = (
            f"$ {cmd}\n[rc={p.returncode}] [{elapsed}s]\n"
            f"--- stdout ---\n{p.stdout[-20000:]}\n--- stderr ---\n{p.stderr[-5000:]}"
        )
        if out_file:
            out_file.write_text(blob)
        if p.returncode != 0:
            LOG.warning("rc=%s (see %s)", p.returncode, out_file)
        return p.returncode, p
    except subprocess.TimeoutExpired:
        LOG.error("TIMEOUT after %ss: %s", timeout, cmd[:200])
        if out_file:
            out_file.write_text(f"$ {cmd}\n[TIMEOUT {timeout}s]\n")
        return 124, None


def parse_lines(p: Path) -> list[str]:
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip()]


def atomic_write(p: Path, text: str) -> None:
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(text)
    tmp.replace(p)


def save_step(rdir: Path, name: str, cmd: str, rc: object, extra: dict | None = None) -> dict:
    data = {"step": name, "cmd": cmd, "rc": rc, "time": datetime.now(timezone.utc).isoformat(), **(extra or {})}
    atomic_write(rdir / f"STEP_{name}.json", json.dumps(data, indent=2))
    return data


def apply_excludes(hosts: list[str], excludes: set[str]) -> tuple[list[str], list[str]]:
    """Return (kept, removed). Exact + subdomain match: exclude foo.com drops bar.foo.com."""
    excl = {e.lower().rstrip(".") for e in excludes}
    kept, removed = [], []
    for h in hosts:
        host = h.strip().lower()
        # httpx live lines may be "https://host [200] ..." — extract host for matching
        m = re.search(r"https?://([^/\s\[]+)", host)
        bare = m.group(1).lower() if m else host
        drop = any(bare == e or bare.endswith("." + e) for e in excl)
        (removed if drop else kept).append(h)
    return kept, removed


def write_list_filtered(src: Path, excludes: set[str]) -> tuple[int, int]:
    """Filter a subs/live file in place. Returns (kept, removed)."""
    rows = parse_lines(src)
    if not rows or not excludes:
        return len(rows), 0
    kept, removed = apply_excludes(rows, excludes)
    if removed:
        LOG.info("exclude filter: %s kept=%d removed=%d (%s)", src.name, len(kept), len(removed), ", ".join(removed[:5]))
        atomic_write(src, "\n".join(kept) + ("\n" if kept else ""))
    return len(kept), len(removed)


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------

def summarize_nuclei(nfile: Path) -> list[dict]:
    p = Path(nfile)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
            out.append({
                "template": j.get("template-id") or j.get("templateID", "?"),
                "host": j.get("host", "?"),
                "severity": j.get("info", {}).get("severity", "?"),
                "matched": j.get("matched-at", "?"),
            })
        except Exception:
            m = re.match(r"\[(.+?)\]\s+\[(.+?)\]\s+(\S+)", line)
            out.append({"raw": line[:300]} if not m else {"template": m.group(1), "severity": m.group(2), "host": m.group(3)})
    return out


def summarize_httpx(live_file: Path) -> dict:
    rows = parse_lines(live_file)
    return {"live_count": len(rows), "sample": rows[:20]}


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

def phase1(cfg: RunConfig, rdir: Path) -> dict:
    LOG.info("=== PHASE 1: wildcard recon ===")
    subs = rdir / "subs.txt"
    cmds: list[tuple[str, str]] = []
    c1 = f"amass enum -brute -d {q(cfg.domain)} -o {q(rdir / 'amass.txt')}"
    if which("subfinder"):
        c1 += f" ; subfinder -d {q(cfg.domain)} -silent -o {q(rdir / 'subfinder.txt')}"
    else:
        LOG.warning("subfinder missing — amass only")
    c1 += f" ; cat {q(rdir / 'amass.txt')} {q(rdir / 'subfinder.txt')} 2>/dev/null | sort -u > {q(subs)} || cp {q(rdir / 'amass.txt')} {q(subs)}"
    cmds.append(("1a_subs", c1))

    hx = httpx_bin()
    c2 = f"{hx} -l {q(subs)} -silent -td -cdn -status-code -title -threads {cfg.threads} -o {q(rdir / 'live.txt')}"
    cmds.append(("1b_httpx", c2))

    ports = "1000" if cfg.aggressive else "100"
    c3 = f"nmap -sV -T4 --top-ports {ports} -iL {q(rdir / 'live.txt')} -oN {q(rdir / 'nmap.txt')}"
    if which("naabu"):
        c3 = f"naabu -list {q(rdir / 'live.txt')} -top-ports {ports} -o {q(rdir / 'ports.txt')} ; " + c3
    cmds.append(("1c_ports", c3))

    url_parts = []
    if which("katana"):
        url_parts.append(f"katana -list {q(rdir / 'live.txt')} -d 3 -silent -o {q(rdir / 'katana.txt')}")
    if which("gau"):
        url_parts.append(f"gau --subs {q(cfg.domain)} > {q(rdir / 'gau.txt')}")
    if which("waybackurls"):
        url_parts.append(f"cat {q(rdir / 'live.txt')} | waybackurls > {q(rdir / 'wayback.txt')}")
    if url_parts:
        cmds.append(("1d_urls", " ; ".join(url_parts) + f" ; cat {q(rdir / 'katana.txt')} {q(rdir / 'gau.txt')} {q(rdir / 'wayback.txt')} 2>/dev/null | sort -u > {q(rdir / 'urls.txt')} || true"))

    rate = 150 if cfg.aggressive else 50
    c5 = f"nuclei -l {q(rdir / 'live.txt')} -severity critical,high,medium -c {rate} -jsonl -o {q(rdir / 'nuclei_recon.jsonl')}"
    cmds.append(("1e_nuclei", c5))

    for name, cmd in cmds:
        if cfg.dry_run:
            LOG.info("[dry] %s", cmd)
            save_step(rdir, name, cmd, "dry")
            continue
        rc, _ = run_cmd(cmd, rdir, rdir / f"{name}.log", timeout=cfg.timeout)
        save_step(rdir, name, cmd, rc)
        # Enforce excludes right after enumeration, before any active probing
        if name == "1a_subs" and cfg.excludes:
            write_list_filtered(subs, cfg.excludes)

    summ = {
        "subs": len(parse_lines(subs)),
        **summarize_httpx(rdir / "live.txt"),
        "urls": len(parse_lines(rdir / "urls.txt")),
        "nuclei": summarize_nuclei(rdir / "nuclei_recon.jsonl")[:50],
        "nuclei_total": len(summarize_nuclei(rdir / "nuclei_recon.jsonl")),
    }
    atomic_write(rdir / "SUMMARY_phase1.json", json.dumps(summ, indent=2))
    LOG.info("Phase1: %s subs, %s live, %s urls, %s nuclei hits", summ["subs"], summ["live_count"], summ["urls"], summ["nuclei_total"])
    return summ


def phase2(cfg: RunConfig, rdir: Path) -> dict:
    base_url = cfg.single_url
    LOG.info("=== PHASE 2: single-app fuzz on %s ===", base_url)
    t = cfg.threads
    depth = 3 if cfg.aggressive else 2
    ext = "js,json,php,env,git,bak,old,zip,config" if cfg.aggressive else "js,php,json,env"
    cmds: list[tuple[str, str]] = [
        ("2a_ferox", f"feroxbuster -u {q(base_url)} --depth {depth} -w {q(DIR_MEDIUM)} -x {q(ext)} -t {t} --filter-status 404 -o {q(rdir / 'ferox.txt')}"),
        ("2b_ffuf_params", f"ffuf -u {q(base_url + '/?FUZZ=test')} -w {q(PARAM_WORDS)} -t {t} -mc 200,301,302,403,500 -o {q(rdir / 'ffuf_params.json')} -of json"),
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


def phase3(cfg: RunConfig, rdir: Path) -> dict:
    api_url = cfg.api_url
    LOG.info("=== PHASE 3: API %s ===", api_url)
    t = cfg.threads
    cmds = [
        ("3a_api_fuzz", f"ffuf -u {q(api_url + '/FUZZ')} -w {q(API_WORDS)} -t {t} -mc 200,201,401,403,500 -o {q(rdir / 'api_fuzz.json')} -of json"),
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


def build_ai_summary(domain: str, rdir: Path, s1: dict | None, s2: dict | None, s3: dict | None, cfg: RunConfig, started: float) -> None:
    crit = []
    for s in (s1, s2, s3):
        if not s:
            continue
        for h in s.get("nuclei", []):
            if str(h.get("severity", "")).lower() in ("critical", "high"):
                crit.append(h)
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
        "next_manual": [
            "Verify nuclei critical/high in Burp Repeater (false positives common)",
            "Review ferox 200/301 + 403 (bypass: X-Forwarded-For, /%2e/, method override)",
            "Review jsfiles.txt + secrets.txt for keys",
            "Run Burp active scan on 2-3 high-value endpoints only (avoid WAF ban)",
        ],
    }
    atomic_write(rdir / "AI_SUMMARY.json", json.dumps(ai, indent=2))
    top = [f"- [{h.get('severity')}] `{h.get('template')}` {h.get('host')}" for h in crit[:30]] or ["- none yet"]
    counts = {k: (v if not isinstance(v, list) else len(v)) for k, v in {**(s1 or {}), **(s2 or {}), **(s3 or {})}.items()}
    md = [
        f"# findings {domain}", "", f"- run: {rdir}", f"- critical/high: {len(crit)}", "",
        "## Top hits", *top, "", "## Counts", f"```json\n{json.dumps(counts, indent=2)}\n```",
        "", "## Manual queue", "- [ ] IDOR/BOLA  - [ ] authz  - [ ] rate-limit  - [ ] file upload  - [ ] SSRF/SSTI",
    ]
    atomic_write(rdir / "findings.md", "\n".join(md))
    LOG.info("Wrote AI_SUMMARY.json + findings.md in %s", rdir)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def tools_check() -> int:
    print(f"bountyflow {__version__} — tool check")
    rows = [
        ("amass", "amass version"),
        ("subfinder", "subfinder -version"),
        ("httpx-toolkit", "httpx-toolkit -version"),
        ("naabu", "naabu -version"),
        ("nmap", "nmap --version"),
        ("katana", "katana -version"),
        ("gau", "gau --version"),
        ("waybackurls", "waybackurls -version"),
        ("nuclei", "nuclei -version"),
        ("ffuf", "ffuf -V"),
        ("feroxbuster", "feroxbuster --version"),
        ("arjun", "arjun --help"),
        ("dalfox", "dalfox --help"),
    ]
    missing = 0
    for name, ver_cmd in rows:
        path = which(name) or which(name.split()[0])
        # special-case: python httpx shadows PD httpx
        if name == "httpx-toolkit" and not path:
            alt = which("httpx")
            print(f"  MISS {name} (found python httpx at {alt} — apt install httpx-toolkit)")
            missing += 1
            continue
        status = "OK  " if path else "MISS"
        if not path:
            missing += 1
        ver = tool_version(ver_cmd) if path else "—"
        print(f"  {status} {name:14} {path or '—':40} {ver}")
    print(f"wordlists: dir={DIR_MEDIUM} params={PARAM_WORDS} api={API_WORDS}")
    for p in (DIR_MEDIUM, PARAM_WORDS, API_WORDS):
        if not Path(p).exists():
            print(f"  WARN missing wordlist: {p}")
    return 1 if missing else 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="bountyflow",
        description="Scoped bug-bounty recon: P1 wildcard + P2 app fuzz + P3 API. Only use on authorized targets.",
    )
    ap.add_argument("-d", "--domain", help="wildcard root, e.g. example.com")
    ap.add_argument("--phases", default="all", help="1,2,3 or all (default: all)")
    ap.add_argument("--single-url", default=None, help="P2 target (default https://<domain>)")
    ap.add_argument("--api-url", default=None, help="P3 target (default https://api.<domain>)")
    ap.add_argument("--aggressive", action="store_true", help="max threads/depth/ports")
    ap.add_argument("--dry-run", action="store_true", help="print commands only")
    ap.add_argument("--exclude", default="", help="comma-separated hosts to never scan (exact + subdomains)")
    ap.add_argument("--exclude-file", default=None, help="file with one excluded host per line")
    ap.add_argument("--threads", type=int, default=None, help="override thread count (default 100 aggressive, 40 normal)")
    ap.add_argument("--timeout", type=int, default=3600, help="per-step timeout seconds (default 3600)")
    ap.add_argument("--output-dir", default=None, help="custom runs base dir (default ./runs)")
    ap.add_argument("--tools-check", action="store_true", help="check external binaries and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--version", action="store_true", help="print version and exit")
    return ap


def main(argv: list[str] | None = None) -> int:
    # graceful Ctrl-C
    signal.signal(signal.SIGINT, lambda *_: (LOG.error("interrupted"), sys.exit(130)))
    ap = build_parser()
    a = ap.parse_args(argv)
    setup_logging(a.verbose)

    if a.version:
        print(__version__)
        return 0
    if a.tools_check:
        return tools_check()
    if not a.domain:
        ap.error("-d/--domain is required (or use --tools-check)")

    try:
        domain = validate_domain(a.domain)
        phases = parse_phases(a.phases)
        single_url = validate_url(a.single_url) if a.single_url else f"https://{domain}"
        api_url = validate_url(a.api_url) if a.api_url else f"https://api.{domain}"
        excludes = parse_excludes(a.exclude, a.exclude_file)
    except ValueError as e:
        ap.error(str(e))
        return 2

    threads = a.threads or (100 if a.aggressive else 40)
    out_base = Path(a.output_dir) if a.output_dir else RUNS
    cfg = RunConfig(
        domain=domain, phases=phases, single_url=single_url, api_url=api_url,
        aggressive=a.aggressive, dry_run=a.dry_run, excludes=excludes,
        timeout=a.timeout, threads=threads, out_base=out_base,
    )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    rdir = out_base / domain / ts
    rdir.mkdir(parents=True, exist_ok=True)
    started = time.time()
    LOG.info("run dir: %s", rdir)
    LOG.info("tools: amass=%s pd-httpx=%s nuclei=%s ffuf=%s ferox=%s",
             bool(which("amass")), httpx_bin(), bool(which("nuclei")), bool(which("ffuf")), bool(which("feroxbuster")))
    if excludes:
        LOG.info("excludes (%d): %s", len(excludes), ", ".join(sorted(excludes)))

    atomic_write(rdir / "config.json", json.dumps({
        "tool": f"bountyflow/{__version__}", "domain": domain,
        "phases": sorted(phases), "single_url": single_url, "api_url": api_url,
        "aggressive": a.aggressive, "threads": threads, "excludes": sorted(excludes),
        "started": datetime.now(timezone.utc).isoformat(),
    }, indent=2))

    s1 = s2 = s3 = None
    if 1 in phases:
        s1 = phase1(cfg, rdir)
    if 2 in phases:
        # skip P2 if single-url host is excluded
        host = urlparse(single_url).netloc.split(":")[0].lower()
        if any(host == e or host.endswith("." + e) for e in excludes):
            LOG.error("P2 skipped: single-url host %s is excluded", host)
        else:
            s2 = phase2(cfg, rdir)
    if 3 in phases:
        host = urlparse(api_url).netloc.split(":")[0].lower()
        if any(host == e or host.endswith("." + e) for e in excludes):
            LOG.error("P3 skipped: api-url host %s is excluded", host)
        else:
            s3 = phase3(cfg, rdir)

    if not cfg.dry_run:
        build_ai_summary(domain, rdir, s1, s2, s3, cfg, started)
    else:
        LOG.info("dry-run done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
