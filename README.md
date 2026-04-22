<p align="center">
  <h1 align="center">⚡ ReconX</h1>
  <p align="center"><b>AI-Powered Automated Recon Orchestrator</b></p>
  <p align="center">
    <i>Strict dedup • Alive gating • Wildcard-aware discovery • Structured JSONL • Optional AI</i>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/stages-16-orange?style=flat-square" alt="Stages">
  <img src="https://img.shields.io/badge/AI-Ollama%20|%20OpenAI%20|%20Groq-purple?style=flat-square" alt="AI">
  <img src="https://img.shields.io/badge/footprint-lightweight-success?style=flat-square" alt="Footprint">
</p>

---

## What is ReconX?

ReconX is an **automated reconnaissance orchestrator** for bug bounty hunters and penetration testers. Unlike simple wrapper scripts, ReconX enforces **strict deduplication**, **alive-gating**, **scope enforcement**, and **wildcard-200 detection** at every stage — so you never scan noise.

With optional **AI integration**, ReconX dynamically generates subdomain candidates, selects Nuclei templates based on detected tech, scores parameters by injection risk, and writes attack narratives for your reports.

### Lightweight by design

| | |
|---|---|
| Source code | ~6,000 LoC of pure Python |
| On-disk size | 728 KB (source + configs) |
| Direct dependencies | 7 (`click`, `pyyaml`, `dnspython`, `rich`, `httpx`, `tldextract`, `validators`) |
| Install size (no AI) | ~71 MB site-packages |
| CLI cold-start | ~60 ms |
| Optional deps | `openai` (only if you use OpenAI/Groq), Go/pip tools (opt-in) |

ReconX itself is a pure-Python orchestrator. Everything heavy — Go-based scanners, Chromium for JS-aware crawling, AI provider SDKs — is **opt-in**.

---

## Installation

```bash
# 1. Clone
git clone https://github.com/yaswanth77/reconx.git
cd reconx

# 2. Install
pip install -e .

# 3. (Optional) Enable AI providers
pip install -e ".[ai]"

# 4. Verify
python -m reconx doctor
```

> If `reconx` command isn't found after install, use `python -m reconx` instead, or add your Python Scripts directory to PATH.

### External tools

ReconX works with Python-native fallbacks, but installing these adds real coverage:

| Tool | Install | Used for |
|------|---------|----------|
| **httpx** (required) | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` | Service validation, fingerprinting |
| **finalrecon** | `pip install finalrecon` | Broad surface map (DNS/whois/SSL/CT) |
| **katana** | `go install github.com/projectdiscovery/katana/cmd/katana@latest` | JS-aware crawling (critical for SPAs) |
| subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | Subdomain enumeration |
| gau | `go install github.com/lc/gau/v2/cmd/gau@latest` | Historical URLs |
| waybackurls | `go install github.com/tomnomnom/waybackurls@latest` | Wayback URLs |
| nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | Vuln scanning |
| paramspider | `pip install paramspider` | Passive parameter mining |
| arjun | `pip install arjun` | Active parameter discovery |
| theHarvester | `pip install theHarvester` | Email OSINT |
| exiftool | [exiftool.org](https://exiftool.org) | Metadata extraction |

> Go tools require [Go](https://go.dev/dl/). After install, ensure `$GOPATH/bin` is in your PATH. Run `reconx doctor` to verify — it also detects **wrong-binary collisions** (e.g. `python3-httpx` shadowing ProjectDiscovery httpx) and tells you exactly which upstream tool is missing.

**Interactive installer:** `python -m reconx install` walks you through installing the tools you're missing.

---

## Quick Start

```bash
# 1. Check what tools you have
python -m reconx doctor

# 2. Create a scope file
cp configs/scope.example.yaml scope.yaml
# Edit scope.yaml with your target

# 3. Run
python -m reconx run --target example.com --scope scope.yaml --profile fast
```

---

## Profiles

| Profile | Stages | AI | Best for |
|---------|--------|----|----------|
| `fast` | DNS, subs, validate, URLs, search | ❌ | Quick surface scan (2-5 min) |
| `normal` | All recon + OSINT emails + Nuclei | ✅ | Bug bounty (10-30 min) |
| `deep` | Everything + XSS/SQLi/SSRF + full OSINT | ✅ | Full pentest (30-120 min) |

```bash
# Fast — passive only
python -m reconx run --target example.com --scope scope.yaml --profile fast

# Normal — bug bounty default with AI
python -m reconx run --target example.com --scope scope.yaml --profile normal --ai --ai-provider ollama

# Deep — full pentest
python -m reconx run --target example.com --scope scope.yaml --profile deep --ai --ai-provider openai --ai-key sk-...
```

---

## Pipeline Architecture

```
DNS (+FinalRecon) → Subdomains → Zone Transfer → Service Validation (GATE)
                                                       ↓
VHosts → Fingerprint → URLs (katana+creepy+wildcard filter) → Search → Parameters
                                                       ↓
OSINT (Emails, Metadata, GitHub) → Vuln Scan (Nuclei, XSS, SQLi, SSRF/SSTI)
                                                       ↓
                                               AI Triage → Reports
```

### 16 Stages

| # | Stage | What it does | AI enhancement |
|---|-------|-------------|----------------|
| 1 | `dns` | FinalRecon broad scan + DNS records + wildcard detection | — |
| 2 | `subs` | CT logs + subfinder | AI generates subdomain candidates |
| 3 | `axfr` | Zone transfer attempts | — |
| 4 | `validate` | **GATE** — httpx probe (fails loudly on 0 alive) | — |
| 5 | `vhosts` | Virtual host discovery | — |
| 6 | `fingerprint` | Headers, favicon, tech stack | AI analyzes tech + suggests attack vectors |
| 7 | `urls` | robots → well-known → katana crawl → creepy (with wildcard-200 filter) | AI generates dynamic paths from tech |
| 8 | `search` | gau + waybackurls | — |
| 9 | `params` | ParamSpider + Arjun (wildcard-aware, bounded) | AI scores params by injection risk |
| 10 | `osint_emails` | theHarvester (scope-enforced on @domain) | — |
| 11 | `osint_metadata` | Document metadata via exiftool | — |
| 12 | `osint_github` | GitHub API dork queries | — |
| 13 | `vuln_nuclei` | Template scanning | AI selects relevant tags (allowlisted) |
| 14 | `vuln_xss` | Reflected XSS detection | — |
| 15 | `vuln_sqli` | Error-based + time-based SQLi | — |
| 16 | `vuln_misc` | Open redirect, SSRF, SSTI | AI triages all findings |

### Anti-Redundancy

| Mechanism | What it prevents |
|-----------|-----------------|
| **JSONL Dedup** | Same host/URL/param never stored twice |
| **Alive Gating** | Dead hosts never get crawled or scanned |
| **Scope Enforcement** | Every piece of data checked before storage |
| **Wildcard-200 Filter** | SPA catch-all routing can't produce false-positive findings |
| **Tool Identity Check** | Wrong binary on PATH (e.g. python3-httpx) fails doctor instead of silently returning empty results |
| **AI Cache + Budget** | Same prompts never re-charge; per-run token budget prevents runaway costs |
| **AI Tag Allowlist** | AI-suggested Nuclei tags filtered through a safe-set before argv |

---

## CLI Reference

```bash
python -m reconx init                                 # Scaffold workspace
python -m reconx doctor                               # Check dependencies + binary identity
python -m reconx install                              # Interactive tool installer
python -m reconx run --target x.com --scope s.yaml    # Full pipeline
python -m reconx stage subs --run runs/x.com/...      # Single stage
python -m reconx scope check --scope s.yaml --target api.x.com
python -m reconx export --run ... --format burp       # csv/md/burp/nuclei/json
python -m reconx diff --old run1 --new run2           # Compare runs
python -m reconx --version                            # Print version
```

---

## AI Providers

ReconX supports 3 AI backends (all optional):

```bash
# Ollama (free, local — recommended for getting started)
--ai --ai-provider ollama --ai-model llama3

# OpenAI (paid, powerful)
--ai --ai-provider openai --ai-key sk-...

# Groq (free tier, fast inference)
--ai --ai-provider groq --ai-key gsk_...
```

Every provider:
- goes through the same response cache (`data/ai_cache.json`)
- obeys the run-level token budget (`ai.token_budget`, default 100k)
- receives **sanitized** prompt input (control chars stripped from untrusted values)
- returns a generic error on failure (no internal URLs/keys leaked to logs)

---

## Scope File

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

---

## Output Structure

```
runs/example.com/20260322T013500_example.com/
├── data/
│   ├── hosts.jsonl         # Discovered subdomains
│   ├── services.jsonl      # Alive services
│   ├── urls.jsonl          # Discovered URLs (with source tag: katana/robots/wellknown/…)
│   ├── params.jsonl        # Parameters + risk tags
│   ├── findings.jsonl      # Security findings (includes WILDCARD_ROUTING markers)
│   ├── osint.jsonl         # Emails, metadata, GitHub
│   ├── vulns.jsonl         # Vulnerability detections
│   ├── ai_analysis.jsonl   # AI insights
│   └── ai_cache.json       # AI response cache (resumes are free)
├── reports/
│   ├── summary.md          # Human-readable report
│   ├── attack_surface.csv  # 7-section CSV (hosts/services/urls/params/findings/osint/vulns)
│   └── ai_narrative.md     # AI-written attack summary
├── logs/                   # Raw tool output
├── inputs/                 # Scope + profile used
└── manifest.json           # Run metadata
```

---

## Works on any target class

ReconX's filters are driven by the target's own responses, not by hardcoded target types. The same code path handles:

| Target | Behavior |
|--------|----------|
| Traditional app (real 404s) | Filter stays idle, every finding passes through |
| SPA / Angular / React / Vue | Wildcard baseline filters catch-all 200s; katana's JS parser surfaces `/rest/*`, `/api/*` |
| REST/JSON APIs | Standard pipeline; arjun targets `?`-carrying URLs first |
| WAF-blocked (all 403s) | Baseline=403 → other 403s filtered automatically |
| CDN edge-cached | Cache body becomes the baseline → filtered |
| Private IPs / RFC1918 / loopback | ParamSpider runs with short timeout + 1 attempt |
| Reserved TLDs (`.local`, `.internal`, `.test`) | Same private-target code path |
| Hosts with wrong-tool collisions (python3-httpx) | Doctor fails; validate falls back to Python httpx (parallel) |

---

## License

MIT — see [LICENSE](LICENSE)
