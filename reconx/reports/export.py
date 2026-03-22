"""
Report: Export — convert run data to various formats.
"""

import json
import csv
from pathlib import Path
from rich.console import Console

console = Console()


def export_data(run_path: str, fmt: str, out_path: str | None):
    """Export run data to the specified format."""
    run_dir = Path(run_path)
    data_dir = run_dir / "data"

    if not data_dir.exists():
        console.print(f"[red]Data directory not found: {data_dir}[/red]")
        return

    if fmt == "csv":
        _export_csv(data_dir, out_path or str(run_dir / "reports" / "export.csv"))
    elif fmt == "md":
        _export_md(data_dir, out_path or str(run_dir / "reports" / "export.md"))
    elif fmt == "burp":
        _export_burp(data_dir, out_path or str(run_dir / "reports" / "burp_urls.txt"))
    elif fmt == "nuclei":
        _export_nuclei(data_dir, out_path or str(run_dir / "reports" / "nuclei_targets.txt"))
    elif fmt == "json":
        _export_json(data_dir, out_path or str(run_dir / "reports" / "export.json"))
    else:
        console.print(f"[red]Unknown format: {fmt}[/red]")


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    results = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return results


def _export_csv(data_dir: Path, out_path: str):
    """Export all data to a single CSV."""
    services = _read_jsonl(data_dir / "services.jsonl")
    urls = _read_jsonl(data_dir / "urls.jsonl")
    vulns = _read_jsonl(data_dir / "vulns.jsonl")

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Services sheet
        writer.writerow(["=== SERVICES ==="])
        writer.writerow(["URL", "Host", "Status", "Title", "Server"])
        for s in services:
            writer.writerow([s.get("service"), s.get("host"), s.get("status"),
                           s.get("title"), s.get("server")])

        writer.writerow([])
        writer.writerow(["=== VULNERABILITIES ==="])
        writer.writerow(["Type", "URL", "Param", "Severity", "Evidence"])
        for v in vulns:
            writer.writerow([v.get("type"), v.get("url"), v.get("param"),
                           v.get("severity"), json.dumps(v.get("evidence", {}))])

    console.print(f"[green]✓ Exported to {out_path}[/green]")


def _export_md(data_dir: Path, out_path: str):
    """Export as markdown."""
    services = _read_jsonl(data_dir / "services.jsonl")
    vulns = _read_jsonl(data_dir / "vulns.jsonl")
    findings = _read_jsonl(data_dir / "findings.jsonl")

    lines = ["# ReconX Export\n"]

    if vulns:
        lines.append("## Vulnerabilities\n")
        for v in vulns:
            lines.append(f"- **{v.get('severity', '').upper()} — {v.get('type')}**: {v.get('url')} (param: {v.get('param', 'N/A')})")
        lines.append("")

    if findings:
        lines.append("## Findings\n")
        for f in findings:
            lines.append(f"- **{f.get('type')}**: {f.get('asset', '')} [{f.get('severity', '')}]")
        lines.append("")

    Path(out_path).write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[green]✓ Exported to {out_path}[/green]")


def _export_burp(data_dir: Path, out_path: str):
    """Export alive URLs for Burp Suite import."""
    services = _read_jsonl(data_dir / "services.jsonl")
    urls = _read_jsonl(data_dir / "urls.jsonl")

    all_urls = set()
    for s in services:
        u = s.get("final_url", s.get("service", ""))
        if u:
            all_urls.add(u)
    for u in urls:
        url = u.get("url", "")
        if url:
            all_urls.add(url)

    Path(out_path).write_text("\n".join(sorted(all_urls)), encoding="utf-8")
    console.print(f"[green]✓ Exported {len(all_urls)} URLs for Burp → {out_path}[/green]")


def _export_nuclei(data_dir: Path, out_path: str):
    """Export alive base URLs for Nuclei scanning."""
    services = _read_jsonl(data_dir / "services.jsonl")
    base_urls = set()
    for s in services:
        u = s.get("service", "")
        if u and s.get("alive"):
            base_urls.add(u)

    Path(out_path).write_text("\n".join(sorted(base_urls)), encoding="utf-8")
    console.print(f"[green]✓ Exported {len(base_urls)} targets for Nuclei → {out_path}[/green]")


def _export_json(data_dir: Path, out_path: str):
    """Export all data as consolidated JSON."""
    data = {
        "hosts": _read_jsonl(data_dir / "hosts.jsonl"),
        "services": _read_jsonl(data_dir / "services.jsonl"),
        "urls": _read_jsonl(data_dir / "urls.jsonl"),
        "params": _read_jsonl(data_dir / "params.jsonl"),
        "findings": _read_jsonl(data_dir / "findings.jsonl"),
        "osint": _read_jsonl(data_dir / "osint.jsonl"),
        "vulns": _read_jsonl(data_dir / "vulns.jsonl"),
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

    console.print(f"[green]✓ Exported consolidated JSON → {out_path}[/green]")
