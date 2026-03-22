"""
Stage 13: Vulnerability Scanning — Nuclei.

AI enhancement: selects template tags based on detected tech stack.
"""

from datetime import datetime, timezone
from rich.console import Console
import json

console = Console()


def run(ctx):
    """Execute Nuclei template scanning."""
    if not ctx.runner.is_available("nuclei"):
        console.print("  [yellow]⚠ Nuclei not installed, skipping vuln scan[/yellow]")
        return

    services = ctx.stores.services.read_all()
    if not services:
        console.print("  [dim]No services to scan[/dim]")
        return

    # Determine tags to use
    default_tags = ctx.config.get("vuln.nuclei_tags", ["exposure", "misconfig", "cve"])

    # AI-enhanced tag selection
    if ctx.ai_engine and ctx.ai_engine.enabled:
        # Gather tech stack from fingerprinting
        all_tech = set()
        for svc in services:
            all_tech.update(svc.get("tech", []))
            if svc.get("server"):
                all_tech.add(svc["server"])

        if all_tech:
            ai_tags = ctx.ai_engine.select_nuclei_templates(list(all_tech), services)
            if ai_tags:
                default_tags = ai_tags

    tags_str = ",".join(default_tags)
    console.print(f"  [dim]Running Nuclei with tags: {tags_str}[/dim]")

    # Build targets file
    import tempfile
    import os

    alive_urls = [svc.get("final_url", svc.get("service", ""))
                  for svc in services if svc.get("alive")]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(alive_urls))
        targets_file = f.name

    try:
        args = [
            "-l", targets_file,
            "-tags", tags_str,
            "-json",
            "-silent",
            "-rate-limit", str(ctx.config.get("network.rate_limit_rps", 10)),
            "-concurrency", str(min(ctx.config.get("network.concurrency", 25), 50)),
        ]

        result = ctx.runner.run("nuclei", args, timeout=900)

        count = 0
        if result.success or result.stdout:
            for line in result.lines:
                try:
                    data = json.loads(line)
                    vuln_record = {
                        "type": "nuclei",
                        "template_id": data.get("template-id", ""),
                        "name": data.get("info", {}).get("name", ""),
                        "severity": data.get("info", {}).get("severity", "info"),
                        "url": data.get("matched-at", data.get("host", "")),
                        "param": "",
                        "evidence": {
                            "matcher_name": data.get("matcher-name", ""),
                            "extracted_results": data.get("extracted-results", []),
                            "curl_command": data.get("curl-command", ""),
                        },
                        "tags": data.get("info", {}).get("tags", []),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    if ctx.stores.vulns.add(vuln_record):
                        count += 1
                        severity = vuln_record["severity"]
                        color = {"critical": "bold red", "high": "red", "medium": "yellow",
                                 "low": "cyan", "info": "dim"}.get(severity, "white")
                        console.print(
                            f"  [{color}]🔥 {severity.upper()}: "
                            f"{vuln_record['name']} → {vuln_record['url']}[/{color}]"
                        )
                except json.JSONDecodeError:
                    continue

        console.print(f"  [dim]Nuclei findings: {count}[/dim]")

    finally:
        os.unlink(targets_file)
