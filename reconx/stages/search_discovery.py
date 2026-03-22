"""
Stage 8: Search Engine Discovery — gau + waybackurls.

Passive URL gathering from historical archives without hitting the target.
"""

from datetime import datetime, timezone
from rich.console import Console

console = Console()


def run(ctx):
    """Execute search/historical URL discovery."""
    target = ctx.target
    hosts = [h["host"] for h in ctx.stores.hosts.read_all()]

    if not hosts:
        hosts = [target]

    total_new = 0

    # Source 1: gau (GetAllUrls)
    if ctx.runner.is_available("gau"):
        console.print("  [dim]Running gau...[/dim]")
        result = ctx.runner.run(
            "gau", [target, "--threads", "5", "--subs"],
            timeout=300,
        )
        if result.success:
            for url in result.lines:
                url = url.strip()
                if url and ctx.scope.url_in_scope(url):
                    if ctx.stores.urls.add({
                        "url": url,
                        "service": "",
                        "status": None,
                        "content_type": None,
                        "source": ["gau"],
                        "depth": 0,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }):
                        total_new += 1
            console.print(f"  [dim]gau: {total_new} new URLs[/dim]")

    # Source 2: waybackurls
    gau_count = total_new
    if ctx.runner.is_available("waybackurls"):
        console.print("  [dim]Running waybackurls...[/dim]")
        result = ctx.runner.run(
            "waybackurls", [target],
            timeout=300,
            input_data=target,
        )
        if result.success:
            wb_new = 0
            for url in result.lines:
                url = url.strip()
                if url and ctx.scope.url_in_scope(url):
                    if ctx.stores.urls.add({
                        "url": url,
                        "service": "",
                        "status": None,
                        "content_type": None,
                        "source": ["waybackurls"],
                        "depth": 0,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }):
                        wb_new += 1
            total_new += wb_new
            console.print(f"  [dim]waybackurls: {wb_new} new URLs (deduped against gau)[/dim]")

    if not ctx.runner.is_available("gau") and not ctx.runner.is_available("waybackurls"):
        console.print("  [yellow]⚠ Neither gau nor waybackurls installed, skipping[/yellow]")

    console.print(f"  [dim]Total new historical URLs: {total_new}[/dim]")
