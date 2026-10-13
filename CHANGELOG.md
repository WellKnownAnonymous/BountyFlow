# Changelog

## 2.7.0
- Generic web probes: fingerprint-first (nextjs/webflow/blockscout/vercel/wallet-dynamic/gtm), nonce-reuse fetch×2, auth/limit keyword discovery; big-body (120k) fingerprint; portal 403-challenge correctly yields no tags (needs --cookie/--proxy)
- Cookie+Burp: `--cookie sid=...` (= `--header 'Cookie: ...'`), `--proxy http://127.0.0.1:8080` forwarded to httpx/nuclei/katana/ffuf/ferox/gobuster/curl/dirsearch
- Burp bundle per run: `burp/scope.txt`, `burp/project-config.json`, `burp/repeater.md` (IDOR/RPC/Cookie steps)

## 2.5.0
- Auth: `--header 'Name: value'` repeatable → forwarded to httpx/nuclei/katana/ffuf/ferox/curl; recorded as `headers_set` (no values in logs list beyond commands)
- JS: source-map candidates (`URL.map`), first-party-first still
- P1 summary parses `waf.txt/whatweb.txt/takeover`; P3 adds `rpc_divergence.json`
- Reporting: `findings_hackerone.md` draft per hit
- Tools: 27-check incl. dirsearch/subzy/uro/hakrawler/gobuster/nikto/sqlmap/whatweb/wafw00f

## 2.4.0
- hakrawler + uro dedup, waf/whatweb fingerprint, takeover (nuclei+subzy)
- gobuster vhost, dirsearch (bounded), sqlmap explorer-only, nikto+bypass probe
- rpc divergence across providers

## 2.3.0
- analysis/: js_secrets (40 bodies + trufflehog/gitleaks), rpc_checks, web_checks

## 2.2.0
- Multi-file package (no single-file), tests
