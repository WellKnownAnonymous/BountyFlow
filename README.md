# BountyFlow — 1+2+3 aggressive workflow (AI-agent ready)

Python CLI that chains **wildcard recon + single-app fuzz + API** and saves
raw output + AI-readable summaries. Built for `~/Desktop/My Tools/BountyFlow`.

## Install (already done on this box, `-y` auto-accept)
```bash
echo 'kali' | sudo -S DEBIAN_FRONTEND=noninteractive apt update
echo 'kali' | sudo -S DEBIAN_FRONTEND=noninteractive apt install -y \
  seclists subfinder katana dalfox findomain naabu hakrawler \
  trufflehog gitleaks assetfinder golang-go
pip install arjun --break-system-packages
export PATH=$PATH:/home/kali/go/bin
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
echo 'kali' | sudo -S ln -sf /home/kali/go/bin/gau /usr/local/bin/gau
echo 'kali' | sudo -S ln -sf /home/kali/go/bin/waybackurls /usr/local/bin/waybackurls
echo 'kali' | sudo -S ln -sf /home/kali/.local/bin/arjun /usr/local/bin/arjun
```

Verified tools: `amass subfinder assetfinder findomain httpx naabu nmap katana
hakrawler gau waybackurls ffuf gobuster feroxbuster arjun dalfox nuclei sqlmap
trufflehog gitleaks nikto wpscan`.

## Use
```bash
cd ~/Desktop/My\ Tools/BountyFlow
# dry-run (print only)
python3 bountyflow.py -d target.com --phases 1 --dry-run
python3 bountyflow.py -d target.com --phases 2,3 --single-url https://app.target.com --aggressive --dry-run
# real run - ONLY in-scope / authorized
python3 bountyflow.py -d target.com --phases 1 --aggressive
python3 bountyflow.py -d target.com --phases 2,3 --single-url https://app.target.com --api-url https://api.target.com --aggressive
python3 bountyflow.py -d target.com --phases all --aggressive
```

## What it does
- **P1 recon:** `amass + subfinder → httpx → naabu/nmap → katana+gau+waybackurls → nuclei`
- **P2 app:** `feroxbuster → ffuf params → arjun → dalfox → nuclei app → js/secrets regex`
- **P3 api:** `ffuf api-endpoints → nuclei graphql → curl graphql introspect + swagger/openapi` + `API_MANUAL_CHECKLIST.md`

## Output (for AI agents like OpenCode)
```
runs/<target>/<timestamp>/
  subs.txt live.txt urls.txt katana.txt gau.txt
  nmap.txt nuclei_recon.jsonl nuclei_app.jsonl nuclei_api.jsonl
  ferox.txt ffuf_params.json api_fuzz.json dalfox.txt jsfiles.txt secrets.txt
  STEP_*.json + *.log          # per-step cmd + rc
  SUMMARY_phase*.json          # counts
  AI_SUMMARY.json              # <-- agent reads this first
  findings.md                  # top critical/high + manual queue
  API_MANUAL_CHECKLIST.md
```

Agent loop: read `AI_SUMMARY.json` → verify `priority_review[]` in Burp Repeater →
review `ferox.txt/jsfiles.txt/secrets.txt` → do manual IDOR/BOLA/rate-limit checklist.
False positives expected from nuclei — always re-verify.
