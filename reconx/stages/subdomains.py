"""
Stage 2: Subdomain Discovery — passive (crt.sh, CT logs) + optional brute.

Collects subdomains from passive sources, normalizes, deduplicates,
resolves, and stores. AI can generate additional candidates.
"""

from datetime import datetime, timezone
from rich.console import Console

console = Console()


def run(ctx):
    """Execute subdomain discovery stage."""
    target = ctx.target
    # Track source provenance per-subdomain so the final record reflects reality.
    sources: dict[str, set[str]] = {}

    def _record(sub: str, source: str) -> None:
        sub = sub.strip().lower()
        if not sub or "*" in sub or not sub.endswith(target):
            return
        sources.setdefault(sub, set()).add(source)

    # --- Source 1: crt.sh (Certificate Transparency logs) ---
    console.print("  [dim]Querying crt.sh for CT log entries...[/dim]")
    try:
        ctx.rate_limiter.acquire()
        import httpx as httpx_lib
        resp = httpx_lib.get(
            f"https://crt.sh/?q=%.{target}&output=json",
            timeout=30,
            follow_redirects=True,
        )
        if resp.status_code == 200:
            entries = resp.json()
            before = len(sources)
            for entry in entries:
                for sub in (entry.get("name_value") or "").split("\n"):
                    _record(sub, "ct")
            console.print(f"  [dim]crt.sh: {len(sources) - before} new names[/dim]")
    except Exception as e:
        console.print(f"  [yellow]crt.sh query failed: {e}[/yellow]")

    # --- Source 2: subfinder (if available) ---
    if ctx.runner.is_available("subfinder"):
        console.print("  [dim]Running subfinder...[/dim]")
        result = ctx.runner.run("subfinder", ["-d", target, "-silent"], timeout=120)
        if result.success:
            before = len(sources)
            for line in result.lines:
                _record(line, "subfinder")
            console.print(f"  [dim]subfinder: {len(sources) - before} new names[/dim]")

    # --- Source 3: AI-generated candidates ---
    if ctx.ai_engine and ctx.ai_engine.enabled:
        unique_so_far = list(sources.keys())[:30]
        ai_candidates = ctx.ai_engine.generate_subdomains(target, unique_so_far)
        before = len(sources)
        for candidate in ai_candidates:
            candidate = candidate.strip().lower()
            if candidate and "." not in candidate:
                candidate = f"{candidate}.{target}"
            _record(candidate, "ai")
        console.print(f"  [dim]ai: {len(sources) - before} new candidates[/dim]")

    unique_subs = sorted(sources.keys())
    console.print(f"  [dim]Unique candidates to resolve: {len(unique_subs)}[/dim]")

    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ctx.config.get("dns.resolvers", ["8.8.8.8", "1.1.1.1"])
    resolver.timeout = ctx.config.get("dns.query_timeout", 3)
    resolver.lifetime = ctx.config.get("dns.lifetime", 5)

    resolved_count = 0
    for sub in unique_subs:
        if not ctx.scope.host_in_scope(sub):
            continue

        a_records: list[str] = []
        try:
            answers = resolver.resolve(sub, "A")
            a_records = [str(r) for r in answers]
        except Exception:
            pass

        if not a_records:
            continue

        host_record = {
            "host": sub,
            "source": sorted(sources[sub]),
            "dns": {"a": a_records},
            "wildcard_suspect": False,
            "first_seen_stage": "subs",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if ctx.stores.hosts.add(host_record):
            resolved_count += 1

    console.print(f"  [dim]Resolved and stored: {resolved_count} new hosts[/dim]")
