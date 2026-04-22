# ⚡ ReconX

AI-powered recon orchestrator for bug bounty and pentesting.

One CLI that drives FinalRecon, httpx, subfinder, katana, nuclei, gau, waybackurls, ParamSpider, Arjun, theHarvester and exiftool through a 16-stage pipeline with strict deduplication, alive-gating, scope enforcement, and wildcard-200 filtering baked in.

![Python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Stages](https://img.shields.io/badge/stages-16-orange?style=flat-square)
![AI](https://img.shields.io/badge/AI-Ollama%20|%20OpenAI%20|%20Groq-purple?style=flat-square)


## Why

Most recon workflows are a tangle of shell pipes that scan the same host three times, keep dead services in the loop, and can't tell a real `/admin` from an SPA catch-all. ReconX fixes that by treating the pipeline as a graph: every tool writes into a shared JSONL store, every write goes through a canonical key and a scope check, and every downstream stage reads the store rather than the previous tool's stdout. Nothing runs twice. Nothing reaches vuln scanning until `httpx` says it's alive. Nothing gets flagged as a finding if a random unregistered path returns the same response.


## Lightweight

| | |
|---|---|
| Source | ~6,000 lines of pure Python |
| Source + configs on disk | 728 KB |
| Direct dependencies | 7 (`click`, `pyyaml`, `dnspython`, `rich`, `httpx`, `tldextract`, `validators`) |
| Install size without AI extras | ~71 MB in site-packages |
| CLI cold start | ~60 ms |

ReconX itself is just the orchestrator. The heavy stuff (Go binaries, headless Chromium for JS crawling, AI provider SDKs) is opt-in.


## Install

```bash
git clone https://github.com/yaswanth77/reconx.git
cd reconx
pip install -e .
pip install -e ".[ai]"          # optional, for OpenAI / Groq
python -m reconx doctor
```

If the `reconx` command isn't on PATH after install, use `python -m reconx`.


## External tools

ReconX has Python fallbacks for everything required, but each of these adds real coverage:

| Tool | Install | What it adds |
|------|---------|---|
| **httpx** (required) | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` | Service validation, fingerprinting |
| **finalrecon** | `pip install finalrecon` | Broad surface map: DNS, whois, SSL, CT |
| **katana** | `go install github.com/projectdiscovery/katana/cmd/katana@latest` | JS-aware crawling (essential for SPAs) |
| subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | Subdomain enumeration |
| gau | `go install github.com/lc/gau/v2/cmd/gau@latest` | Historical URLs |
| waybackurls | `go install github.com/tomnomnom/waybackurls@latest` | Wayback URLs |
| nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | Vulnerability scanning |
| paramspider | `pip install paramspider` | Passive parameter mining |
| arjun | `pip install arjun` | Active parameter discovery |
| theHarvester | `pip install theHarvester` | Email OSINT |
| exiftool | [exiftool.org](https://exiftool.org) | Document metadata |

Go tools need [Go](https://go.dev/dl/) and `$GOPATH/bin` on your PATH. `reconx doctor` verifies every tool, including a binary-identity check that catches same-name collisions (e.g. the `httpx` from `python3-httpx` on Debian/Kali, which is not ProjectDiscovery httpx and will silently fail every request). For tools that aren't installed, `reconx install` walks you through picking which ones you want.


## Quick start

```bash
python -m reconx doctor
cp configs/scope.example.yaml scope.yaml
# edit scope.yaml
python -m reconx run --target example.com --scope scope.yaml --profile fast
```


## Profiles

| Profile | Stages | AI | Typical runtime |
|---------|--------|----|---|
| `fast` | DNS, subs, validate, URLs, search | off | 2-5 min |
| `normal` | All recon + OSINT emails + Nuclei | on | 10-30 min |
| `deep` | Everything + XSS/SQLi/SSRF + full OSINT | on | 30-120 min |

```bash
# fast, passive only
python -m reconx run --target example.com --scope scope.yaml --profile fast

# normal with local Ollama
python -m reconx run --target example.com --scope scope.yaml --profile normal --ai --ai-provider ollama

# deep with OpenAI
python -m reconx run --target example.com --scope scope.yaml --profile deep --ai --ai-provider openai --ai-key sk-...
```


## Pipeline

```
DNS (+FinalRecon) → Subdomains → Zone Transfer → Service Validation (GATE)
                                                       ↓
VHosts → Fingerprint → URLs (katana + creepy + wildcard filter) → Search → Parameters
                                                       ↓
OSINT (Emails, Metadata, GitHub) → Vuln Scan (Nuclei, XSS, SQLi, SSRF/SSTI)
                                                       ↓
                                               AI Triage → Reports
```

### The 16 stages

| # | Stage | What it does | AI plug-in |
|---|-------|-------------|----------------|
| 1 | `dns` | FinalRecon + DNS records + wildcard detection | |
| 2 | `subs` | CT logs + subfinder | subdomain candidates |
| 3 | `axfr` | Zone transfer attempts | |
| 4 | `validate` | **gate** httpx probe, fails loudly on 0 alive | |
| 5 | `vhosts` | Virtual host discovery | |
| 6 | `fingerprint` | Headers, favicon, tech stack | attack vector analysis |
| 7 | `urls` | robots, well-known, katana, creepy (with wildcard filter) | dynamic wordlist |
| 8 | `search` | gau + waybackurls | |
| 9 | `params` | ParamSpider + Arjun (wildcard-aware, bounded) | injection risk scoring |
| 10 | `osint_emails` | theHarvester, scope-gated on `@domain` | |
| 11 | `osint_metadata` | exiftool on discovered docs | |
| 12 | `osint_github` | GitHub API dork queries | |
| 13 | `vuln_nuclei` | Template scanning | tag selection (allowlisted) |
| 14 | `vuln_xss` | Reflected XSS | |
| 15 | `vuln_sqli` | Error-based + time-based SQLi | |
| 16 | `vuln_misc` | Open redirect, SSRF, SSTI | finding triage |

### Noise control

| Mechanism | What it kills |
|-----------|---|
| JSONL dedup | Same host, URL, or param stored twice |
| Alive gating | Dead services reaching crawl or vuln stages |
| Scope enforcement | Out-of-scope data stored anywhere |
| Wildcard-200 filter | SPA catch-all routes showing up as findings |
| Tool identity check | Wrong binary on PATH silently producing empty output |
| AI cache + budget | Re-billing for identical prompts or runaway token costs |
| Nuclei tag allowlist | AI-hallucinated argv reaching the scanner |


## CLI

```bash
python -m reconx init                                 # scaffold workspace
python -m reconx doctor                               # dependency + identity check
python -m reconx install                              # interactive tool installer
python -m reconx run --target x.com --scope s.yaml    # full pipeline
python -m reconx stage subs --run runs/x.com/...      # rerun a single stage
python -m reconx scope check --scope s.yaml --target api.x.com
python -m reconx export --run ... --format burp       # csv, md, burp, nuclei, json
python -m reconx diff --old run1 --new run2           # compare two runs
python -m reconx --version
```


## AI providers

All three are optional. Pick whichever fits the host and budget.

```bash
# Ollama (free, local, recommended for first runs)
--ai --ai-provider ollama --ai-model llama3

# OpenAI (paid, strongest reasoning)
--ai --ai-provider openai --ai-key sk-...

# Groq (free tier, very fast)
--ai --ai-provider groq --ai-key gsk_...
```

Every provider shares:

* sha256-keyed response cache at `data/ai_cache.json` (resumes are free)
* per-run token budget (`ai.token_budget`, default 100k)
* sanitized prompt input (control characters stripped from untrusted values)
* generic error messages on failure (no URLs, keys, or payloads leaked to logs)


## Scope file

```yaml
in_scope:
  roots:
    - example.com
  include_subdomains: true
  allowed_ports: [80, 443, 8080, 8443]

out_of_scope:
  host_patterns:
    - "*.internal.example.com"
  url_patterns:
    - "*/logout*"
    - "*/delete*"
  extensions: [".jpg", ".png", ".css", ".woff2"]
```


## Output layout

```
runs/example.com/20260322T013500_example.com/
├── data/
│   ├── hosts.jsonl         # discovered subdomains
│   ├── services.jsonl      # alive services
│   ├── urls.jsonl          # discovered URLs with source tag (katana / robots / creepy / ...)
│   ├── params.jsonl        # parameters with risk tags
│   ├── findings.jsonl      # security findings (incl. WILDCARD_ROUTING markers)
│   ├── osint.jsonl         # emails, metadata, GitHub
│   ├── vulns.jsonl         # vulnerability detections
│   ├── ai_analysis.jsonl   # AI insights
│   └── ai_cache.json       # AI response cache
├── reports/
│   ├── summary.md          # human-readable report
│   ├── attack_surface.csv  # 7 sections: hosts, services, urls, params, findings, osint, vulns
│   └── ai_narrative.md     # AI-written attack summary
├── logs/                   # raw tool output
├── inputs/                 # scope + profile used
└── manifest.json           # run metadata
```


## Works on any target class

All filters are driven by what the target actually returns. The same code path handles each of these without special cases:

| Target shape | Behaviour |
|--------|----------|
| Traditional app with real 404s | Wildcard filter stays idle, every finding passes through |
| Angular / React / Vue SPA | Wildcard baseline filters the catch-all 200s; katana's JS parser surfaces `/rest/*` and `/api/*` |
| REST / JSON APIs | Standard pipeline; arjun prefers URLs that already carry `?` |
| WAF-blocked (all 403s) | Baseline becomes 403, other 403s auto-filtered |
| CDN edge-cached | Cache body becomes the baseline and gets filtered |
| Private IP, RFC1918, loopback | ParamSpider runs once with a short timeout instead of three long retries |
| Reserved TLDs (`.local`, `.internal`, `.test`) | Same private-target path |
| Host with a wrong-tool collision | Doctor fails; validate falls back to parallel Python httpx |


## License

MIT. See [LICENSE](LICENSE).
