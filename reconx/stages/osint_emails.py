"""
Stage 10: OSINT — Email Harvesting via theHarvester.
"""

import re
from datetime import datetime, timezone
from rich.console import Console

console = Console()

# Simple RFC-5322-ish email pattern; good enough for harvesting lines.
_EMAIL_RE = re.compile(r"\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")


def run(ctx):
    """Execute email harvesting."""
    target = ctx.target

    if not ctx.config.get("osint.emails_enabled", True):
        console.print("  [dim]Email harvesting disabled[/dim]")
        return

    if not ctx.runner.is_available("theHarvester"):
        console.print("  [dim]theHarvester not installed — skipping email harvesting[/dim]")
        console.print("  [dim]Install: pip install theHarvester[/dim]")
        return

    console.print("  [dim]Running theHarvester...[/dim]")
    result = ctx.runner.run(
        "theHarvester",
        ["-d", target, "-b", "all", "-l", "200"],
        timeout=300,
    )
    if not result.success:
        console.print("  [yellow]theHarvester returned non-zero; no emails harvested[/yellow]")
        return

    count = 0
    seen: set[str] = set()
    for line in result.lines:
        for match in _EMAIL_RE.finditer(line):
            email = match.group(0).lower()
            if email in seen:
                continue
            seen.add(email)

            domain = match.group(2).lower()
            # Enforce scope on the email's domain, not a substring match.
            if not ctx.scope.host_in_scope(domain):
                continue

            if ctx.stores.osint.add({
                "type": "email",
                "value": email,
                "source": "theHarvester",
                "domain": domain,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }):
                count += 1

    console.print(f"  [dim]Emails found: {count}[/dim]")
