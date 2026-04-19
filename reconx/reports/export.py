"""
Report: Export — convert run data to various formats.
"""

import json
import csv
from pathlib import Path
from typing import Iterator
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


def _stream_jsonl(path: Path) -> Iterator[dict]:
    """Yield records from a JSONL file one at a time (constant memory)."""
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _section(writer: csv.writer, title: str, header: list[str]) -> None:
    writer.writerow([])
    writer.writerow([f"=== {title} ==="])
    writer.writerow(header)


def _export_csv(data_dir: Path, out_path: str):
    """Export every store to a single multi-section CSV."""
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        _section(writer, "HOSTS", ["Host", "IPs", "Sources", "First Seen Stage", "Timestamp"])
        for h in _stream_jsonl(data_dir / "hosts.jsonl"):
            ips = ",".join(h.get("dns", {}).get("a", []) or [])
            src = ",".join(h.get("source", []) or [])
            writer.writerow([h.get("host"), ips, src, h.get("first_seen_stage"), h.get("timestamp")])

        _section(writer, "SERVICES", ["Service", "Host", "IP", "Status", "Title", "Server", "Alive", "Final URL"])
        for s in _stream_jsonl(data_dir / "services.jsonl"):
            writer.writerow([
                s.get("service"), s.get("host"), s.get("ip"), s.get("status"),
                s.get("title"), s.get("server"), s.get("alive"), s.get("final_url"),
            ])

        _section(writer, "URLS", ["URL", "Service", "Status", "Content-Type", "Sources", "Depth", "Timestamp"])
        for u in _stream_jsonl(data_dir / "urls.jsonl"):
            writer.writerow([
                u.get("url"), u.get("service"), u.get("status"),
                u.get("content_type"), ",".join(u.get("source", []) or []),
                u.get("depth"), u.get("timestamp"),
            ])

        _section(writer, "PARAMETERS", ["Endpoint", "Method", "Params", "Discovered By", "Risk Tags"])
        for p in _stream_jsonl(data_dir / "params.jsonl"):
            writer.writerow([
                p.get("endpoint"), p.get("method", "GET"),
                ",".join(p.get("params", []) or []),
                ",".join(p.get("discovered_by", []) or []),
                ",".join(p.get("risk_tags", []) or []),
            ])

        _section(writer, "FINDINGS", ["Type", "Severity", "Asset", "Evidence", "Timestamp"])
        for fnd in _stream_jsonl(data_dir / "findings.jsonl"):
            writer.writerow([
                fnd.get("type"), fnd.get("severity"), fnd.get("asset"),
                json.dumps(fnd.get("evidence", {})), fnd.get("timestamp"),
            ])

        _section(writer, "OSINT", ["Type", "Value", "Source", "Domain", "Timestamp"])
        for o in _stream_jsonl(data_dir / "osint.jsonl"):
            writer.writerow([
                o.get("type"), o.get("value"), o.get("source"),
                o.get("domain"), o.get("timestamp"),
            ])

        _section(writer, "VULNERABILITIES", ["Type", "URL", "Param", "Severity", "Evidence"])
        for v in _stream_jsonl(data_dir / "vulns.jsonl"):
            writer.writerow([
                v.get("type"), v.get("url"), v.get("param"),
                v.get("severity"), json.dumps(v.get("evidence", {})),
            ])

    console.print(f"[green]✓ Exported to {out_path}[/green]")


def _export_md(data_dir: Path, out_path: str):
    """Export as markdown."""
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    lines = ["# ReconX Export\n"]

    vulns = list(_stream_jsonl(data_dir / "vulns.jsonl"))
    if vulns:
        lines.append("## Vulnerabilities\n")
        for v in vulns:
            lines.append(
                f"- **{(v.get('severity') or '').upper()} — {v.get('type')}**: "
                f"{v.get('url')} (param: {v.get('param', 'N/A')})"
            )
        lines.append("")

    findings = list(_stream_jsonl(data_dir / "findings.jsonl"))
    if findings:
        lines.append("## Findings\n")
        for fnd in findings:
            lines.append(
                f"- **{fnd.get('type')}**: {fnd.get('asset', '')} [{fnd.get('severity', '')}]"
            )
        lines.append("")

    Path(out_path).write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[green]✓ Exported to {out_path}[/green]")


def _export_burp(data_dir: Path, out_path: str):
    """Export alive URLs for Burp Suite import."""
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    all_urls: set[str] = set()
    for s in _stream_jsonl(data_dir / "services.jsonl"):
        u = s.get("final_url") or s.get("service") or ""
        if u:
            all_urls.add(u)
    for u in _stream_jsonl(data_dir / "urls.jsonl"):
        url = u.get("url", "")
        if url:
            all_urls.add(url)

    Path(out_path).write_text("\n".join(sorted(all_urls)), encoding="utf-8")
    console.print(f"[green]✓ Exported {len(all_urls)} URLs for Burp → {out_path}[/green]")


def _export_nuclei(data_dir: Path, out_path: str):
    """Export alive base URLs for Nuclei scanning."""
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    base_urls: set[str] = set()
    for s in _stream_jsonl(data_dir / "services.jsonl"):
        u = s.get("service", "")
        if u and s.get("alive"):
            base_urls.add(u)

    Path(out_path).write_text("\n".join(sorted(base_urls)), encoding="utf-8")
    console.print(f"[green]✓ Exported {len(base_urls)} targets for Nuclei → {out_path}[/green]")


def _export_json(data_dir: Path, out_path: str):
    """Stream every store into a consolidated JSON file without loading twice."""
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    stores = ["hosts", "services", "urls", "params", "findings", "osint", "vulns"]
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("{\n")
        for i, name in enumerate(stores):
            f.write(f'  "{name}": [')
            first = True
            for record in _stream_jsonl(data_dir / f"{name}.jsonl"):
                if not first:
                    f.write(", ")
                json.dump(record, f, default=str)
                first = False
            f.write("]")
            if i < len(stores) - 1:
                f.write(",")
            f.write("\n")
        f.write("}\n")

    console.print(f"[green]✓ Exported consolidated JSON → {out_path}[/green]")
