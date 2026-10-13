# BountyFlow v2 — scoped 1+2+3 recon (AI-agent ready)

`bountyflow` chains **P1 wildcard recon → P2 single-app fuzz → P3 API checks**,
enforces `--exclude`, and saves raw output + `AI_SUMMARY.json` for agents/humans.

> Only test **in-scope / authorized** targets. Excluded hosts are filtered
> after enumeration and before any probing/scanning.

## Install

Needs Kali + ProjectDiscovery stack. Python itself is stdlib-only.

```bash
echo 'kali' | sudo -S DEBIAN_FRONTEND=noninteractive apt update
echo 'kali' | sudo -S DEBIAN_FRONTEND=noninteractive apt install -y \
  seclists subfinder httpx-toolkit katana dalfox findomain naabu \
  trufflehog gitleaks assetfinder golang-go nmap nuclei ffuf feroxbuster
pip install arjun --break-system-packages
export PATH=$PATH:/home/kali/go/bin
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
echo 'kali' | sudo -S ln -sf /home/kali/go/bin/gau /usr/local/bin/gau
echo 'kali' | sudo -S ln -sf /home/kali/go/bin/waybackurls /usr/local/bin/waybackurls

# optional: install CLI
pip install -e . --break-system-packages
python3 bountyflow.py --tools-check
python3 bountyflow.py --version
```

Note: Kali ships python `httpx` at `/usr/bin/httpx`. BountyFlow auto-prefers
`httpx-toolkit` (ProjectDiscovery). Install `httpx-toolkit`, not just `httpx`.

## Use

```bash
cd ~/Desktop/My\ Tools/BountyFlow
# checks
python3 bountyflow.py --tools-check
python3 bountyflow.py -d example.com --phases 1 --dry-run

# Arc example (excludes are enforced):
python3 bountyflow.py -d arc.io --phases 1 --dry-run \
  --exclude help.arc.io,explorer.arc.io,community.arc.io
python3 bountyflow.py -d arc.io --phases all --aggressive \
  --single-url https://arc.io --api-url https://rpc.testnet.arc.network \
  --exclude help.arc.io,explorer.arc.io,community.arc.io

# custom threads / timeout / output
python3 bountyflow.py -d example.com --phases 2,3 \
  --single-url https://app.example.com --threads 50 --timeout 1800
```

## What it does

- **P1:** `amass + subfinder → filter excludes → httpx-toolkit → naabu/nmap → katana+gau+waybackurls → nuclei`
- **P2:** `feroxbuster → ffuf params → arjun → dalfox (v3 syntax) → nuclei app → js/secrets regex`
- **P3:** `ffuf api-endpoints → nuclei misconfig+graphql → curl introspect/swagger/openapi` + `API_MANUAL_CHECKLIST.md`

All shell paths are quoted (workspace may contain spaces like `My Tools`).

## Output

```
finding/<target>/<timestamp>/
  config.json subs.txt live.txt live_urls.txt live_hosts.txt urls.txt katana.txt gau.txt
  nmap.txt nuclei_recon.jsonl nuclei_app.jsonl nuclei_api.jsonl
  ferox.txt ffuf_params.json api_fuzz.json dalfox.txt jsfiles.txt secrets.txt
  STEP_*.json + *.log
  SUMMARY_phase*.json
  AI_SUMMARY.json      # agent reads this first
  findings.md
  API_MANUAL_CHECKLIST.md
```

Agent loop: `AI_SUMMARY.json:priority_review[]` → verify in Burp Repeater →
review `ferox.txt/jsfiles.txt/secrets.txt` → manual IDOR/BOLA/rate-limit.
Nuclei FPs expected — always re-verify.

## Dev

```bash
python3 -m py_compile bountyflow.py
python3 bountyflow.py --tools-check
ruff check bountyflow.py || true
```

License: MIT.
