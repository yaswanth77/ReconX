"""
HTML Report Generator — produces a professional, self-contained HTML report.

Single-file output with embedded CSS. No external dependencies.
"""

import json
from pathlib import Path
from datetime import datetime, timezone

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconX Report — {target}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --yellow: #d29922; --red: #f85149;
    --orange: #d18616; --purple: #bc8cff;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
  h1 span {{ color: var(--accent); }}
  h2 {{
    font-size: 1.4rem; margin: 2rem 0 1rem; padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
  }}
  h3 {{ font-size: 1.1rem; margin: 1.5rem 0 0.5rem; color: var(--accent); }}
  .meta {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 2rem; }}
  .stats {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem; margin: 1.5rem 0;
  }}
  .stat {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 1rem; text-align: center;
  }}
  .stat .number {{ font-size: 2rem; font-weight: bold; color: var(--accent); }}
  .stat .label {{ font-size: 0.85rem; color: var(--muted); }}
  table {{
    width: 100%; border-collapse: collapse; margin: 1rem 0;
    background: var(--surface); border-radius: 8px; overflow: hidden;
  }}
  th {{
    background: #1c2128; text-align: left; padding: 0.75rem 1rem;
    font-size: 0.85rem; text-transform: uppercase; color: var(--muted);
    border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 0.6rem 1rem; border-bottom: 1px solid var(--border);
    font-size: 0.9rem; word-break: break-all;
  }}
  tr:hover td {{ background: #1c2128; }}
  .sev-critical {{ color: var(--red); font-weight: bold; }}
  .sev-high {{ color: var(--orange); font-weight: bold; }}
  .sev-medium {{ color: var(--yellow); }}
  .sev-low {{ color: var(--muted); }}
  .sev-info {{ color: var(--accent); }}
  .badge {{
    display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
    font-size: 0.75rem; font-weight: 600;
  }}
  .badge-red {{ background: rgba(248,81,73,0.15); color: var(--red); }}
  .badge-yellow {{ background: rgba(210,153,34,0.15); color: var(--yellow); }}
  .badge-green {{ background: rgba(63,185,80,0.15); color: var(--green); }}
  .badge-blue {{ background: rgba(88,166,255,0.15); color: var(--accent); }}
  .pipeline-status {{
    display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 1rem 0;
  }}
  .stage-pill {{
    padding: 0.3rem 0.8rem; border-radius: 16px; font-size: 0.8rem;
    border: 1px solid var(--border);
  }}
  .stage-success {{ background: rgba(63,185,80,0.15); border-color: var(--green); color: var(--green); }}
  .stage-failed {{ background: rgba(248,81,73,0.15); border-color: var(--red); color: var(--red); }}
  .stage-skipped {{ background: rgba(139,148,158,0.1); color: var(--muted); }}
  .ai-narrative {{
    background: var(--surface); border: 1px solid var(--border);
    border-left: 3px solid var(--purple); padding: 1.5rem;
    border-radius: 0 8px 8px 0; margin: 1rem 0;
    white-space: pre-wrap; font-size: 0.9rem;
  }}
  .ai-narrative::before {{
    content: '🤖 AI Analysis'; display: block; font-weight: bold;
    color: var(--purple); margin-bottom: 0.5rem; font-size: 0.85rem;
  }}
  .empty {{ color: var(--muted); font-style: italic; padding: 1rem; }}
  footer {{
    margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
    color: var(--muted); font-size: 0.8rem; text-align: center;
  }}
</style>
</head>
<body>
<div class="container">
{content}
</div>
</body>
</html>"""


def generate_html_report(run_dir: str | Path, out_path: str | Path | None = None) -> Path:
    """Generate a self-contained HTML report from a run directory."""
    run_dir = Path(run_dir)
    data_dir = run_dir / "data"

    # Load all data
    hosts = _load_jsonl(data_dir / "hosts.jsonl")
    services = _load_jsonl(data_dir / "services.jsonl")
    urls = _load_jsonl(data_dir / "urls.jsonl")
    params = _load_jsonl(data_dir / "params.jsonl")
    findings = _load_jsonl(data_dir / "findings.jsonl")
    vulns = _load_jsonl(data_dir / "vulns.jsonl")
    osint = _load_jsonl(data_dir / "osint.jsonl")
    ai_data = _load_jsonl(data_dir / "ai_analysis.jsonl")

    # Load manifest
    manifest = {}
    manifest_path = run_dir / "manifest.json"
    if manifest_path.exists():
        with open(manifest_path) as f:
            manifest = json.load(f)

    target = manifest.get("target", run_dir.name)

    # Load AI narrative
    ai_narrative = ""
    narrative_path = run_dir / "reports" / "ai_narrative.md"
    if narrative_path.exists():
        ai_narrative = narrative_path.read_text(encoding="utf-8")

    # Build HTML content
    sections = []

    # Header
    sections.append(f"""
    <h1>⚡ <span>ReconX</span> Report</h1>
    <p class="meta">
        Target: <strong>{_esc(target)}</strong> &nbsp;|&nbsp;
        Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")} &nbsp;|&nbsp;
        Profile: {_esc(manifest.get('config', {}).get('_profile_name', 'custom'))} &nbsp;|&nbsp;
        Duration: {manifest.get('elapsed_seconds', '?')}s
    </p>
    """)

    # Stats
    sections.append("""<h2>📊 Summary</h2>""")
    sections.append(f"""
    <div class="stats">
        <div class="stat"><div class="number">{len(hosts)}</div><div class="label">Subdomains</div></div>
        <div class="stat"><div class="number">{len(services)}</div><div class="label">Alive Services</div></div>
        <div class="stat"><div class="number">{len(urls)}</div><div class="label">URLs</div></div>
        <div class="stat"><div class="number">{len(params)}</div><div class="label">Parameters</div></div>
        <div class="stat"><div class="number">{len(findings)}</div><div class="label">Findings</div></div>
        <div class="stat"><div class="number">{len(vulns)}</div><div class="label">Vulnerabilities</div></div>
        <div class="stat"><div class="number">{len(osint)}</div><div class="label">OSINT Items</div></div>
    </div>
    """)

    # Pipeline status
    stage_status = manifest.get("stage_status", {})
    if stage_status:
        sections.append("""<h3>Pipeline Status</h3><div class="pipeline-status">""")
        for stage, status in stage_status.items():
            css_class = f"stage-{status}"
            icon = {"success": "✓", "failed": "✗", "skipped": "⏭"}.get(status, "?")
            sections.append(
                f'<span class="stage-pill {css_class}">{icon} {_esc(stage)}</span>'
            )
        sections.append("</div>")

    # Vulnerabilities
    if vulns:
        sections.append("""<h2>🔴 Vulnerabilities</h2>""")
        sections.append(_build_table(
            vulns,
            columns=[
                ("Type", lambda v: f'<span class="badge badge-red">{_esc(v.get("type", ""))}</span>'),
                ("URL", lambda v: _esc(v.get("url", v.get("target", "")))),
                ("Parameter", lambda v: _esc(v.get("param", v.get("parameter", "")))),
                ("Severity", lambda v: _severity_badge(v.get("severity", "medium"))),
                ("Evidence", lambda v: _esc(str(v.get("evidence", v.get("payload", "")))[:100])),
            ],
        ))

    # Findings
    if findings:
        sections.append("""<h2>🟡 Findings</h2>""")
        sections.append(_build_table(
            findings,
            columns=[
                ("Type", lambda f: _esc(f.get("type", f.get("finding", "")))),
                ("Target", lambda f: _esc(f.get("target", f.get("service", "")))),
                ("Severity", lambda f: _severity_badge(f.get("severity", "info"))),
                ("Detail", lambda f: _esc(str(f.get("detail", f.get("value", "")))[:150])),
            ],
        ))

    # Alive Services
    if services:
        sections.append("""<h2>🟢 Alive Services</h2>""")
        sections.append(_build_table(
            services,
            columns=[
                ("Service", lambda s: _esc(s.get("service", ""))),
                ("Status", lambda s: str(s.get("status", ""))),
                ("Title", lambda s: _esc(s.get("title", "")[:80])),
                ("Server", lambda s: _esc(s.get("server", ""))),
                ("Tech", lambda s: _esc(", ".join(s.get("tech", []))[:100])),
            ],
        ))

    # Subdomains
    if hosts:
        sections.append(f"""<h2>🌐 Subdomains ({len(hosts)})</h2>""")
        sections.append(_build_table(
            hosts[:200],  # Cap at 200 for readability
            columns=[
                ("Hostname", lambda h: _esc(h.get("host", ""))),
                ("IP", lambda h: _esc(h.get("ip", ""))),
                ("Source", lambda h: _esc(", ".join(h.get("source", [])))),
            ],
        ))
        if len(hosts) > 200:
            sections.append(f'<p class="empty">Showing 200 of {len(hosts)} hosts. Export full list with: reconx export --format csv</p>')

    # Parameters (top 50 by risk)
    if params:
        sorted_params = sorted(params, key=lambda p: p.get("risk_score", 0), reverse=True)
        sections.append(f"""<h2>🎯 Parameters ({len(params)})</h2>""")
        sections.append(_build_table(
            sorted_params[:50],
            columns=[
                ("URL", lambda p: _esc(p.get("url", "")[:80])),
                ("Param", lambda p: _esc(p.get("param", p.get("name", "")))),
                ("Tags", lambda p: _esc(", ".join(p.get("tags", [])))),
                ("Risk", lambda p: f'{p.get("risk_score", 0):.1f}' if isinstance(p.get("risk_score"), (int, float)) else _esc(str(p.get("risk_score", "")))),
            ],
        ))

    # OSINT
    if osint:
        sections.append(f"""<h2>🔍 OSINT ({len(osint)})</h2>""")
        sections.append(_build_table(
            osint,
            columns=[
                ("Type", lambda o: _esc(o.get("type", ""))),
                ("Value", lambda o: _esc(str(o.get("value", o.get("email", o.get("data", ""))))[:120])),
                ("Source", lambda o: _esc(o.get("source", ""))),
            ],
        ))

    # AI Narrative
    if ai_narrative:
        sections.append("""<h2>🤖 AI Analysis</h2>""")
        sections.append(f'<div class="ai-narrative">{_esc(ai_narrative)}</div>')

    # AI analysis data
    if ai_data:
        for item in ai_data:
            analysis = item.get("analysis", {})
            if "triaged_findings" in analysis:
                sections.append("""<h3>AI Triage</h3>""")
                sections.append(_build_table(
                    analysis["triaged_findings"],
                    columns=[
                        ("Finding", lambda t: _esc(str(t.get("finding", t.get("type", ""))))),
                        ("Confidence", lambda t: f'{t.get("confidence", 0):.0%}' if isinstance(t.get("confidence"), (int, float)) else _esc(str(t.get("confidence", "")))),
                        ("Verdict", lambda t: _esc(t.get("verdict", t.get("assessment", "")))),
                    ],
                ))

    # Footer
    sections.append(f"""
    <footer>
        Generated by ReconX v1.0 &nbsp;|&nbsp;
        <a href="https://github.com/yaswanth77/ReconX" style="color: var(--accent);">GitHub</a>
    </footer>
    """)

    content = "\n".join(sections)
    html = HTML_TEMPLATE.format(target=_esc(target), content=content)

    # Write output
    if out_path:
        output = Path(out_path)
    else:
        output = run_dir / "reports" / "report.html"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")

    return output


def _load_jsonl(path: Path) -> list[dict]:
    """Load a JSONL file into a list of dicts."""
    if not path.exists():
        return []
    items = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return items


def _esc(text: str) -> str:
    """HTML-escape text."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _severity_badge(severity: str) -> str:
    """Return an HTML badge for severity level."""
    severity = severity.lower()
    css = {
        "critical": "badge-red",
        "high": "badge-red",
        "medium": "badge-yellow",
        "low": "badge-blue",
        "info": "badge-blue",
    }.get(severity, "badge-blue")
    return f'<span class="badge {css}">{_esc(severity)}</span>'


def _build_table(items: list[dict], columns: list[tuple]) -> str:
    """Build an HTML table from items and column definitions."""
    if not items:
        return '<p class="empty">No data</p>'

    rows = ["<table>", "<thead><tr>"]
    for col_name, _ in columns:
        rows.append(f"<th>{_esc(col_name)}</th>")
    rows.append("</tr></thead><tbody>")

    for item in items:
        rows.append("<tr>")
        for _, extractor in columns:
            try:
                cell = extractor(item)
            except Exception:
                cell = ""
            rows.append(f"<td>{cell}</td>")
        rows.append("</tr>")

    rows.append("</tbody></table>")
    return "\n".join(rows)
