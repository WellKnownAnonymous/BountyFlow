#!/usr/bin/env python3
"""
BountyFlow - aggressive 1+2+3 (wildcard recon + single-app fuzz + API) workflow
for AI agents (OpenCode etc.) and humans.

Usage:
  python3 bountyflow.py -d target.com [--phases 1,2,3|all] [--aggressive] [--dry-run]
  python3 bountyflow.py -d app.target.com --phases 2,3 --single-url https://app.target.com

Every run saves raw tool output + AI-readable summaries under:
  ./runs/<target>/<timestamp>/AI_SUMMARY.json, findings.md, STEP_*.json

Author: generated for Kali. Only test in-scope / authorized targets.
"""
import argparse, json, os, re, shutil, subprocess, sys, time
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
RUNS = BASE / "runs"

# ---------- helpers ----------
def log(msg): print(f"[bountyflow] {msg}", flush=True)

def which(t): return shutil.which(t)

def run_cmd(cmd, cwd, out_file=None, timeout=3600):
    """Run shell cmd, stream to file + return (rc, elapsed). Never raises."""
    log(f"$ {cmd}")
    start = time.time()
    try:
        p = subprocess.run(cmd, shell=True, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
        elapsed = round(time.time()-start,1)
        blob = f"$ {cmd}\n[rc={p.returncode}] [{elapsed}s]\n--- stdout ---\n{p.stdout[-20000:]}\n--- stderr ---\n{p.stderr[-5000:]}"
        if out_file:
            Path(out_file).write_text(blob)
        if p.returncode != 0:
            log(f"  -> rc={p.returncode} (see {out_file})")
        return p.returncode, p
    except subprocess.TimeoutExpired:
        log("  -> TIMEOUT")
        return 124, None

def find_wordlist(*candidates):
    for c in candidates:
        if Path(c).exists(): return c
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
SUB_WORDS = find_wordlist(
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/wordlists/dnsmap.txt",
)

def parse_lines(p):
    if not Path(p).exists(): return []
    return [l.strip() for l in Path(p).read_text(errors="ignore").splitlines() if l.strip()]

def save_step(rdir, name, cmd, rc, extra=None):
    data = {"step": name, "cmd": cmd, "rc": rc, "time": datetime.now().isoformat(), **(extra or {})}
    (rdir / f"STEP_{name}.json").write_text(json.dumps(data, indent=2))
    return data

def summarize_nuclei(nfile):
    """Understand nuclei -jsonl or plain output -> list of {template,host,severity}."""
    p = Path(nfile)
    if not p.exists(): return []
    out = []
    for line in p.read_text(errors="ignore").splitlines():
        line=line.strip()
        if not line: continue
        try:
            j=json.loads(line)
            out.append({"template": j.get("template-id") or j.get("templateID","?"),
                        "host": j.get("host","?"), "severity": j.get("info",{}).get("severity","?"),
                        "matched": j.get("matched-at","?")})
        except:  # plain text line: [template] [severity] host
            m=re.match(r"\[(.+?)\]\s+\[(.+?)\]\s+(\S+)", line)
            out.append({"raw": line[:300]} if not m else {"template":m.group(1),"severity":m.group(2),"host":m.group(3)})
    return out

def summarize_httpx(live_file):
    rows=parse_lines(live_file)
    return {"live_count": len(rows), "sample": rows[:20]}

# ---------- phases ----------
def phase1(domain, rdir, aggressive, dry):
    log("=== PHASE 1: wildcard recon ===")
    subs = rdir/"subs.txt"
    cmds = []
    # 1a subdomain enum
    c1 = f"amass enum -brute -d {domain} -o {rdir/'amass.txt'}"
    if which("subfinder"):
        c1 += f" ; subfinder -d {domain} -silent -o {rdir/'subfinder.txt'}"
    else: log("subfinder missing - amass only")
    c1 += f" ; cat {rdir/'amass.txt'} {rdir/'subfinder.txt'} 2>/dev/null | sort -u > {subs} || cp {rdir/'amass.txt'} {subs}"
    cmds.append(("1a_subs", c1))
    # 1b live probe
    threads = 100 if aggressive else 50
    c2 = f"httpx -l {subs} -silent -td -cdn -status-code -title -threads {threads} -o {rdir/'live.txt'}"
    cmds.append(("1b_httpx", c2))
    # 1c ports (top ports, aggressive = full top-1000)
    ports = "1000" if aggressive else "100"
    c3 = f"nmap -sV -T4 --top-ports {ports} -iL {rdir/'live.txt'} -oN {rdir/'nmap.txt'}"
    if which("naabu"):
        c3 = f"naabu -list {rdir/'live.txt'} -top-ports {ports} -o {rdir/'ports.txt'} ; " + c3
    cmds.append(("1c_ports", c3))
    # 1d urls: katana + gau + waybackurls
    url_parts=[]
    if which("katana"): url_parts.append(f"katana -list {rdir/'live.txt'} -d 3 -silent -o {rdir/'katana.txt'}")
    if which("gau"): url_parts.append(f"gau --subs {domain} > {rdir/'gau.txt'}")
    if which("waybackurls"): url_parts.append(f"cat {rdir/'live.txt'} | waybackurls > {rdir/'wayback.txt'}")
    if url_parts:
        cmds.append(("1d_urls", " ; ".join(url_parts) + f" ; cat {rdir/'katana.txt'} {rdir/'gau.txt'} {rdir/'wayback.txt'} 2>/dev/null | sort -u > {rdir/'urls.txt'} || true"))
    # 1e nuclei recon
    rate = 150 if aggressive else 50
    c5 = f"nuclei -l {rdir/'live.txt'} -severity critical,high,medium -c {rate} -jsonl -o {rdir/'nuclei_recon.jsonl'}"
    cmds.append(("1e_nuclei", c5))
    for name,cmd in cmds:
        if dry: log(f"[dry] {cmd}"); save_step(rdir,name,cmd,"dry"); continue
        rc,_ = run_cmd(cmd, rdir, rdir/f"{name}.log", timeout=3600)
        save_step(rdir,name,cmd,rc)
    # summary
    summ = {"subs": len(parse_lines(subs)), **summarize_httpx(rdir/"live.txt"),
            "urls": len(parse_lines(rdir/"urls.txt")),
            "nuclei": summarize_nuclei(rdir/"nuclei_recon.jsonl")[:50],
            "nuclei_total": len(summarize_nuclei(rdir/"nuclei_recon.jsonl"))}
    (rdir/"SUMMARY_phase1.json").write_text(json.dumps(summ,indent=2))
    log(f"Phase1: {summ['subs']} subs, {summ['live_count']} live, {summ['urls']} urls, {summ['nuclei_total']} nuclei hits")
    return summ

def phase2(base_url, rdir, aggressive, dry):
    log(f"=== PHASE 2: single-app fuzz on {base_url} ===")
    t = 100 if aggressive else 40
    depth = 3 if aggressive else 2
    ext = "js,json,php,env,git,bak,old,zip,config" if aggressive else "js,php,json,env"
    cmds = [
        ("2a_ferox", f"feroxbuster -u {base_url} --depth {depth} -w {DIR_MEDIUM} -x {ext} -t {t} -C 404 -o {rdir/'ferox.txt'}"),
        ("2b_ffuf_params", f"ffuf -u '{base_url}/?FUZZ=test' -w {PARAM_WORDS} -t {t} -mc 200,301,302,403,500 -o {rdir/'ffuf_params.json'} -of json"),
        ("2c_nuclei_app", f"nuclei -u {base_url} -t http/exposures/,http/misconfiguration/,http/takeovers/,http/vulnerabilities/ -c {t} -jsonl -o {rdir/'nuclei_app.jsonl'}"),
    ]
    if which("arjun"): cmds.insert(2, ("2b2_arjun", f"arjun -u {base_url} --get --post -t {t} -o {rdir/'arjun.json'}"))
    else: log("arjun missing: pip install arjun")
    if which("dalfox"): cmds.append(("2d_dalfox", f"dalfox file {rdir/'urls.txt'} -o {rdir/'dalfox.txt'} 2>&1 || dalfox url {base_url} -o {rdir/'dalfox.txt'}"))
    else: log("dalfox missing - skip XSS automation")
    # JS secrets (no dep): regex over katana/urls + live fetch via LinkFinder-style regex
    cmds.append(("2e_js_secrets", f"grep -Eo 'https?://[^\"'\\'' >]+\\.js(\\?[^\"'\\'' >]*)?' {rdir/'urls.txt'} {rdir/'katana.txt'} 2>/dev/null | sort -u > {rdir/'jsfiles.txt'} ; grep -rhoE '(AKIA[0-9A-Z]{{16}}|xox[bap]-[0-9A-Za-z-]+|gh[pousr]_[A-Za-z0-9_]{{36}}|AIza[0-9A-Za-z_-]{{35}}|secret[_-]?key|api[_-]?key)' {rdir} 2>/dev/null | sort | uniq -c | sort -nr > {rdir/'secrets.txt'} || true"))
    for name,cmd in cmds:
        if dry: log(f"[dry] {cmd}"); save_step(rdir,name,cmd,"dry"); continue
        rc,_ = run_cmd(cmd, rdir, rdir/f"{name}.log", timeout=3600)
        save_step(rdir,name,cmd,rc)
    summ={"ferox_hits": len(parse_lines(rdir/"ferox.txt")), "js_files": len(parse_lines(rdir/"jsfiles.txt")),
          "nuclei": summarize_nuclei(rdir/"nuclei_app.jsonl")[:50], "nuclei_total": len(summarize_nuclei(rdir/"nuclei_app.jsonl"))}
    (rdir/"SUMMARY_phase2.json").write_text(json.dumps(summ,indent=2))
    log(f"Phase2: ferox lines={summ['ferox_hits']} js={summ['js_files']} nuclei={summ['nuclei_total']}")
    return summ

def phase3(api_url, rdir, aggressive, dry):
    log(f"=== PHASE 3: API {api_url} ===")
    t = 100 if aggressive else 40
    cmds = [
        ("3a_api_fuzz", f"ffuf -u {api_url}/FUZZ -w {API_WORDS} -t {t} -mc 200,201,401,403,500 -o {rdir/'api_fuzz.json'} -of json"),
        ("3b_nuclei_api", f"nuclei -u {api_url} -t http/misconfiguration/,graphql/ -c {t} -jsonl -o {rdir/'nuclei_api.jsonl'}"),
        ("3c_graphql", f"curl -sk -X POST {api_url}/graphql -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' -o {rdir/'graphql_introspect.json'} ; curl -sk {api_url}/swagger.json -o {rdir/'swagger.json'} ; curl -sk {api_url}/openapi.json -o {rdir/'openapi.json'} ; echo done"),
    ]
    for name,cmd in cmds:
        if dry: log(f"[dry] {cmd}"); save_step(rdir,name,cmd,"dry"); continue
        rc,_ = run_cmd(cmd, rdir, rdir/f"{name}.log", timeout=1800)
        save_step(rdir,name,cmd,rc)
    summ={"nuclei": summarize_nuclei(rdir/"nuclei_api.jsonl")[:50], "nuclei_total": len(summarize_nuclei(rdir/"nuclei_api.jsonl"))}
    # manual API checklist for agent/human
    checklist = ["BOLA: /users/123 -> /users/124, /api/orders/<other-id>", "Method tamper: GET vs POST vs PUT on same endpoint",
      "Mass assignment: add {\"role\":\"admin\",\"is_admin\":true}", "JWT: none alg, empty sig, weak secret", "Rate-limit: 20x rapid 401/OTP/login",
      "GraphQL: introspection, batching, field suggestions", "IDOR in nested objects: /api/v1/users/me vs /api/v1/users/<id>"]
    (rdir/"API_MANUAL_CHECKLIST.md").write_text("# API manual tests (Burp)\n" + "\n".join(f"- [ ] {c}" for c in checklist) + "\n")
    (rdir/"SUMMARY_phase3.json").write_text(json.dumps(summ,indent=2))
    return summ

def build_ai_summary(domain, rdir, s1, s2, s3):
    crit=[]
    for s in [s1,s2,s3]:
        if not s: continue
        for h in s.get("nuclei",[]):
            if str(h.get("severity","")).lower() in ("critical","high"): crit.append(h)
    ai={"target":domain,"run_dir":str(rdir),"time":datetime.now().isoformat(),
        "wordlists":{"dir":DIR_MEDIUM,"params":PARAM_WORDS,"api":API_WORDS},
        "phase1":s1,"phase2":s2,"phase3":s3,
        "priority_review": crit[:30],
        "next_manual":["Verify nuclei critical/high in Burp Repeater (false positives common)",
          "Review ferox 200/301 + 403 (bypass: X-Forwarded-For, /%2e/, method override)",
          "Review jsfiles.txt + secrets.txt for keys","Run Burp active scan on 2-3 high-value endpoints only (avoid WAF ban)"]}
    (rdir/"AI_SUMMARY.json").write_text(json.dumps(ai,indent=2))
    top = [f"- [{h.get('severity')}] `{h.get('template')}` {h.get('host')}" for h in crit[:30]] or ["- none yet"]
    md=[f"# findings {domain}","",f"- run: {rdir}",f"- critical/high: {len(crit)}","",
        "## Top hits"] + top + [
        "","## Counts",f"```json\n{json.dumps({k:(v if not isinstance(v,list) else len(v)) for k,v in {**(s1 or {}),**(s2 or {}),**(s3 or {})}.items()},indent=2)}\n```",
        "","## Manual queue","- [ ] IDOR/BOLA  - [ ] authz  - [ ] rate-limit  - [ ] file upload  - [ ] SSRF/SSTI"]
    (rdir/"findings.md").write_text("\n".join(md))
    log(f"Wrote AI_SUMMARY.json + findings.md in {rdir}")

def main():
    ap=argparse.ArgumentParser(description="BountyFlow 1+2+3 aggressive workflow")
    ap.add_argument("-d","--domain",required=True,help="target.com (wildcard root)")
    ap.add_argument("--phases",default="all",help="1,2,3 or all")
    ap.add_argument("--single-url",default=None,help="https://app.target.com for phase 2 (default https://<domain>)")
    ap.add_argument("--api-url",default=None,help="https://api.target.com for phase 3")
    ap.add_argument("--aggressive",action="store_true",help="max threads/depth")
    ap.add_argument("--dry-run",action="store_true",help="print cmds only")
    a=ap.parse_args()
    ph = {1,2,3} if a.phases=="all" else {int(x) for x in a.phases.split(",")}
    ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    rdir=RUNS/a.domain/ts; rdir.mkdir(parents=True,exist_ok=True)
    log(f"run dir: {rdir}")
    for tool in ["amass","httpx","nmap","nuclei","ffuf","feroxbuster"]:
        log(f"  {'OK ' if which(tool) else 'MISS'} {tool}")
    s1=s2=s3=None
    if 1 in ph: s1=phase1(a.domain,rdir,a.aggressive,a.dry_run)
    if 2 in ph: s2=phase2(a.single_url or f"https://{a.domain}",rdir,a.aggressive,a.dry_run)
    if 3 in ph: s3=phase3(a.api_url or f"https://api.{a.domain}",rdir,a.aggressive,a.dry_run)
    if not a.dry_run: build_ai_summary(a.domain,rdir,s1,s2,s3)
    else: log("dry-run done")

if __name__=="__main__":
    main()
