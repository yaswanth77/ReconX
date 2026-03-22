"""
Report: Summary generator — creates summary.md from run data.
"""

from pathlib import Path
from datetime import datetime, timezone
from rich.console import Console

console = Console()


def generate_summary(ctx):
    """Generate summary.md report from pipeline results."""
    report_dir = ctx.run_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    summary = ctx.stores.summary()
    findings = ctx.stores.findings.read_all()
    vulns = ctx.stores.vulns.read_all()
    services = ctx.stores.services.read_all()

    lines = [
        f"# ReconX Report: {ctx.target}",
        f"",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Duration:** {ctx.elapsed:.1f}s",
        f"**Profile:** {ctx.config.get('_profile_name', 'custom')}",
        f"",
        f"## Attack Surface Summary",
        f"",
        f"| Entity | Count |",
        f"|--------|-------|",
    ]

    for key, count in summary.items():
        if count > 0:
            lines.append(f"| {key.title()} | {count} |")

    lines.append("")

    # Stage results
    lines.append("## Stage Results")
    lines.append("")
    lines.append("| Stage | Status |")
    lines.append("|-------|--------|")
    for stage, status in ctx.stage_status.items():
        icon = {"success": "✅", "failed": "❌", "skipped": "⏭"}.get(status, "?")
        lines.append(f"| {stage} | {icon} {status} |")
    lines.append("")

    # Key findings
    if findings or vulns:
        lines.append("## Key Findings")
        lines.append("")

        # Group by severity
        for severity in ["critical", "high", "medium", "low", "info"]:
            sev_findings = [
                f for f in (findings + vulns)
                if f.get("severity", "").lower() == severity
            ]
            if sev_findings:
                lines.append(f"### {severity.upper()} ({len(sev_findings)})")
                lines.append("")
                for f in sev_findings[:10]:
                    ftype = f.get("type", "unknown")
                    asset = f.get("asset", f.get("url", ""))
                    lines.append(f"- **{ftype}**: {asset}")
                lines.append("")

    # Alive services
    if services:
        lines.append("## Alive Services")
        lines.append("")
        lines.append("| URL | Status | Title | Server |")
        lines.append("|-----|--------|-------|--------|")
        for svc in services[:50]:
            url = svc.get("service", "")
            status = svc.get("status", "")
            title = svc.get("title", "")[:40]
            server = svc.get("server", "")
            lines.append(f"| {url} | {status} | {title} | {server} |")
        lines.append("")

    # OSINT
    osint = ctx.stores.osint.read_all()
    if osint:
        lines.append("## OSINT")
        lines.append("")
        emails = [o for o in osint if o.get("type") == "email"]
        github = [o for o in osint if o.get("type") == "github_dork"]
        metadata = [o for o in osint if o.get("type") == "metadata"]

        if emails:
            lines.append(f"### Emails ({len(emails)})")
            for e in emails[:20]:
                lines.append(f"- {e.get('value', '')}")
            lines.append("")

        if github:
            lines.append(f"### GitHub Exposure ({len(github)})")
            for g in github[:10]:
                lines.append(f"- [{g.get('repository', '')}]({g.get('value', '')})")
            lines.append("")

    # Write report
    report_path = report_dir / "summary.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"  [green]✓ Report saved: {report_path}[/green]")

    # Also generate attack_surface.csv
    _generate_csv(ctx, report_dir)


def _generate_csv(ctx, report_dir: Path):
    """Generate attack_surface.csv."""
    import csv

    csv_path = report_dir / "attack_surface.csv"
    services = ctx.stores.services.read_all()

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Service", "Host", "IP", "Status", "Title", "Server", "Tech"])
        for svc in services:
            writer.writerow([
                svc.get("service", ""),
                svc.get("host", ""),
                svc.get("ip", ""),
                svc.get("status", ""),
                svc.get("title", ""),
                svc.get("server", ""),
                "|".join(svc.get("tech", [])),
            ])

    console.print(f"  [green]✓ CSV saved: {csv_path}[/green]")
