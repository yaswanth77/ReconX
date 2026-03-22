"""
Stage 10: OSINT — Email Harvesting via theHarvester.
"""

from datetime import datetime, timezone
from rich.console import Console

console = Console()


def run(ctx):
    """Execute email harvesting."""
    target = ctx.target

    if not ctx.config.get("osint.emails_enabled", True):
        console.print("  [dim]Email harvesting disabled[/dim]")
        return

    if ctx.runner.is_available("theHarvester"):
        console.print("  [dim]Running theHarvester...[/dim]")
        result = ctx.runner.run(
            "theHarvester",
            ["-d", target, "-b", "all", "-l", "200"],
            timeout=300,
        )
        if result.success:
            count = 0
            for line in result.lines:
                line = line.strip()
                if "@" in line and target in line:
                    if ctx.stores.osint.add({
                        "type": "email",
                        "value": line,
                        "source": "theHarvester",
                        "domain": target,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }):
                        count += 1
            console.print(f"  [dim]Emails found: {count}[/dim]")
    else:
        # Fallback: basic email patterns from crawled pages
        console.print("  [dim]theHarvester not found, extracting from crawled pages...[/dim]")
        import re
        urls = ctx.stores.urls.read_all()
        count = 0
        for url_record in urls:
            url = url_record.get("url", "")
            # We don't have page content stored, so this is limited
            # In a full implementation, crawl stage would store content

        console.print(f"  [dim]Install theHarvester for full email discovery[/dim]")
