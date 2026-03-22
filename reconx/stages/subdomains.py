"""
Stage 2: Subdomain Discovery — passive (crt.sh, CT logs) + optional brute.

Collects subdomains from passive sources, normalizes, deduplicates,
resolves, and stores. AI can generate additional candidates.
"""

from datetime import datetime, timezone
from rich.console import Console
import json

console = Console()


def run(ctx):
    """Execute subdomain discovery stage."""
    target = ctx.target
    found_subs = []

    # --- Source 1: crt.sh (Certificate Transparency logs) ---
    console.print("  [dim]Querying crt.sh for CT log entries...[/dim]")
    try:
        import httpx as httpx_lib
        resp = httpx_lib.get(
            f"https://crt.sh/?q=%.{target}&output=json",
            timeout=30,
            follow_redirects=True,
        )
        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub and sub.endswith(target) and "*" not in sub:
                        found_subs.append(sub)
            console.print(f"  [dim]crt.sh: {len(found_subs)} raw entries[/dim]")
    except Exception as e:
        console.print(f"  [yellow]crt.sh query failed: {e}[/yellow]")

    # --- Source 2: subfinder (if available) ---
    if ctx.runner.is_available("subfinder"):
        console.print("  [dim]Running subfinder...[/dim]")
        result = ctx.runner.run("subfinder", ["-d", target, "-silent"], timeout=120)
        if result.success:
            for line in result.lines:
                sub = line.strip().lower()
                if sub and sub.endswith(target):
                    found_subs.append(sub)
            console.print(f"  [dim]subfinder: {len(result.lines)} entries[/dim]")

    # --- Source 3: AI-generated candidates ---
    if ctx.ai_engine and ctx.ai_engine.enabled:
        unique_so_far = list(set(found_subs))[:30]
        ai_candidates = ctx.ai_engine.generate_subdomains(target, unique_so_far)
        for candidate in ai_candidates:
            candidate = candidate.strip().lower()
            if "." not in candidate:
                candidate = f"{candidate}.{target}"
            if candidate.endswith(target):
                found_subs.append(candidate)

    # --- Deduplicate and resolve ---
    unique_subs = list(set(found_subs))
    console.print(f"  [dim]Deduplicating: {len(found_subs)} → {len(unique_subs)} unique[/dim]")

    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ctx.config.get("dns.resolvers", ["8.8.8.8", "1.1.1.1"])

    resolved_count = 0
    for sub in unique_subs:
        # Scope check
        if not ctx.scope.host_in_scope(sub):
            continue

        # Resolve
        a_records = []
        try:
            answers = resolver.resolve(sub, "A")
            a_records = [str(r) for r in answers]
        except Exception:
            pass

        if not a_records:
            continue

        host_record = {
            "host": sub,
            "source": ["ct" if sub in found_subs else "brute"],
            "dns": {"a": a_records},
            "wildcard_suspect": False,
            "first_seen_stage": "subs",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if ctx.stores.hosts.add(host_record):
            resolved_count += 1

    console.print(f"  [dim]Resolved and stored: {resolved_count} new hosts[/dim]")
