<p align="center">
  <h1 align="center">⚡ ReconX</h1>
  <p align="center"><b>AI-Powered Automated Recon Orchestrator</b></p>
  <p align="center">
    <i>Strict dedup • Alive gating • Structured JSONL output • AI-enhanced dynamic analysis</i>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/stages-16-orange?style=flat-square" alt="Stages">
  <img src="https://img.shields.io/badge/AI-Ollama%20|%20OpenAI%20|%20Groq-purple?style=flat-square" alt="AI">
</p>

---

## What is ReconX?

ReconX is an **automated reconnaissance orchestrator** for bug bounty hunters and penetration testers. Unlike simple wrapper scripts, ReconX enforces **strict deduplication**, **alive-gating**, and **scope enforcement** at every stage — so you never scan noise.

With optional **AI integration**, ReconX dynamically generates subdomain candidates, selects Nuclei templates based on detected tech, scores parameters by injection risk, and writes attack narratives for your reports.

---

## Installation

```bash
# 1. Clone
git clone https://github.com/yeswanth/reconx.git
cd reconx

# 2. Install
pip install -e .

# 3. Verify
python -m reconx doctor
```

> **Note:** If `reconx` command isn't found after install, use `python -m reconx` instead, or add your Python Scripts directory to PATH.

### External Tools

ReconX works with **zero external tools** (Python-native fallbacks), but installing these adds more coverage:

| Tool | Install | Used for |
|------|---------|----------|
| **httpx** (required) | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` | Service validation |
| subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | Subdomain enumeration |
| gau | `go install github.com/lc/gau/v2/cmd/gau@latest` | Historical URLs |
| waybackurls | `go install github.com/tomnomnom/waybackurls@latest` | Wayback URLs |
| nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | Vuln scanning |
| paramspider | `pip install paramspider` | Parameter mining |
| arjun | `pip install arjun` | Active param discovery |
| theHarvester | `pip install theHarvester` | Email OSINT |
| exiftool | [exiftool.org](https://exiftool.org) | Metadata extraction |

> Go tools require [Go](https://go.dev/dl/) installed. After install, ensure `$GOPATH/bin` (or `%GOPATH%\bin` on Windows) is in your PATH. Run `reconx doctor` to verify.

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
DNS → Subdomains → Zone Transfer → Service Validation (GATE)
                                          ↓
VHosts → Fingerprint → URLs → Search → Parameters
                                          ↓
OSINT (Emails, Metadata, GitHub) → Vuln Scan (Nuclei, XSS, SQLi, SSRF/SSTI)
                                          ↓
                                    AI Triage → Reports
```

### 16 Stages

| # | Stage | What it does | AI enhancement |
|---|-------|-------------|----------------|
| 1 | `dns` | DNS records + wildcard detection | — |
| 2 | `subs` | CT logs + subfinder | AI generates subdomain candidates |
| 3 | `axfr` | Zone transfer attempts | — |
| 4 | `validate` | **GATE** — httpx probe | — |
| 5 | `vhosts` | Virtual host discovery | — |
| 6 | `fingerprint` | Headers, favicon, tech stack | AI analyzes tech + suggests attack vectors |
| 7 | `urls` | robots → well-known → crawl → creepy | AI generates dynamic paths from tech |
| 8 | `search` | gau + waybackurls | — |
| 9 | `params` | ParamSpider + Arjun | AI scores params by injection risk |
| 10 | `osint_emails` | theHarvester | — |
| 11 | `osint_metadata` | Document metadata via exiftool | — |
| 12 | `osint_github` | GitHub API dork queries | — |
| 13 | `vuln_nuclei` | Template scanning | AI selects relevant template tags |
| 14 | `vuln_xss` | Reflected XSS detection | — |
| 15 | `vuln_sqli` | Error-based + time-based SQLi | — |
| 16 | `vuln_misc` | Open redirect, SSRF, SSTI | AI triages all findings |

### Anti-Redundancy

| Mechanism | What it prevents |
|-----------|-----------------|
| **JSONL Dedup** | Same host/URL/param never stored twice |
| **Alive Gating** | Dead hosts never get crawled or scanned |
| **Scope Enforcement** | Every piece of data checked before storage |
| **AI Filtering** | Only scans relevant templates and high-risk params |

---

## CLI Reference

```bash
python -m reconx init                               # Scaffold workspace
python -m reconx doctor                              # Check dependencies
python -m reconx run --target x.com --scope s.yaml   # Full pipeline
python -m reconx stage subs --run runs/x.com/...     # Single stage
python -m reconx scope check --scope s.yaml --target api.x.com   # Scope check
python -m reconx export --run ... --format burp      # Export (csv/md/burp/nuclei/json)
python -m reconx diff --old run1 --new run2          # Compare runs
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
│   ├── urls.jsonl          # Discovered URLs
│   ├── params.jsonl        # Parameters + risk tags
│   ├── findings.jsonl      # Security findings
│   ├── osint.jsonl         # Emails, metadata, GitHub
│   ├── vulns.jsonl         # Vulnerability detections
│   └── ai_analysis.jsonl   # AI insights
├── reports/
│   ├── summary.md          # Human-readable report
│   ├── attack_surface.csv  # Spreadsheet-ready
│   └── ai_narrative.md     # AI-written attack summary
├── logs/                   # Raw tool output
├── inputs/                 # Scope + profile used
└── manifest.json           # Run metadata
```

---

## License

MIT — see [LICENSE](LICENSE)
