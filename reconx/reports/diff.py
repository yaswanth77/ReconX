"""
Report: Diff — compare two runs.
"""

import json
from pathlib import Path
from rich.console import Console

console = Console()


def diff_runs(old_path: str, new_path: str, out_path: str | None):
    """Compare two runs and generate a diff report."""
    old_dir = Path(old_path) / "data"
    new_dir = Path(new_path) / "data"

    if not old_dir.exists() or not new_dir.exists():
        console.print("[red]Both run directories must exist[/red]")
        return

    lines = ["# ReconX Diff Report\n"]
    lines.append(f"**Old run:** {old_path}")
    lines.append(f"**New run:** {new_path}\n")

    # Compare each entity type
    entity_files = ["hosts.jsonl", "services.jsonl", "urls.jsonl",
                    "params.jsonl", "findings.jsonl", "vulns.jsonl"]

    for fname in entity_files:
        old_records = _read_jsonl(old_dir / fname)
        new_records = _read_jsonl(new_dir / fname)

        # Key extraction
        if "hosts" in fname:
            key_fn = lambda r: r.get("host", "")
        elif "services" in fname:
            key_fn = lambda r: r.get("service", "")
        elif "urls" in fname:
            key_fn = lambda r: r.get("url", "")
        elif "params" in fname:
            key_fn = lambda r: f"{r.get('endpoint', '')}|{r.get('method', '')}"
        elif "findings" in fname:
            key_fn = lambda r: f"{r.get('type', '')}|{r.get('asset', '')}"
        elif "vulns" in fname:
            key_fn = lambda r: f"{r.get('type', '')}|{r.get('url', '')}"
        else:
            key_fn = lambda r: str(r)

        old_keys = set(key_fn(r) for r in old_records)
        new_keys = set(key_fn(r) for r in new_records)

        added = new_keys - old_keys
        removed = old_keys - new_keys

        entity = fname.replace(".jsonl", "").upper()
        lines.append(f"## {entity}")
        lines.append(f"Old: {len(old_keys)} | New: {len(new_keys)} | Added: {len(added)} | Removed: {len(removed)}\n")

        if added:
            lines.append("### New")
            for key in sorted(list(added))[:20]:
                lines.append(f"- ✅ `{key}`")
            lines.append("")

        if removed:
            lines.append("### Removed")
            for key in sorted(list(removed))[:20]:
                lines.append(f"- ❌ `{key}`")
            lines.append("")

    # Write output
    report_text = "\n".join(lines)

    if out_path:
        Path(out_path).write_text(report_text, encoding="utf-8")
        console.print(f"[green]✓ Diff report saved: {out_path}[/green]")
    else:
        console.print(report_text)


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
