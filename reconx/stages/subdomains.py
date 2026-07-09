"""
Stage 2: Subdomain Discovery — passive (crt.sh, CT logs) + optional brute.

Collects subdomains from passive sources, normalizes, deduplicates,
resolves, and stores. AI can generate additional candidates.
"""

from datetime import datetime, timezone
from rich.console import Console

console = Console()


def roots_from_ctx(ctx) -> list[str]:
    """Every in-scope root to enumerate: the CLI --target plus all scope roots.

    A multi-root scope (roots: [a.com, b.io, c.example.net]) must discover
    subdomains of all of them, otherwise the run silently under-covers
    everything but --target. Deduped, order-stable, --target first.
    """
    roots: list[str] = []
    for r in [getattr(ctx, "target", None), *getattr(ctx.scope, "roots", [])]:
        r = (r or "").strip().lower().lstrip(".")
        if r and r not in roots:
            roots.append(r)
    return roots


def belongs_to_roots(sub: str, roots: list[str]) -> bool:
    """True if `sub` is one of the roots or a subdomain of one.

    The dot-anchored suffix check avoids false matches like "notexample.com"
    matching root "example.com".
    """
    sub = (sub or "").strip().lower()
    if not sub or "*" in sub:
        return False
    return any(sub == root or sub.endswith("." + root) for root in roots)


def run(ctx):
    """Execute subdomain discovery stage."""
    target = ctx.target
    roots = roots_from_ctx(ctx)

    # Track source provenance per-subdomain so the final record reflects reality.
    sources: dict[str, set[str]] = {}

    def _record(sub: str, source: str) -> None:
        sub = sub.strip().lower()
        if not belongs_to_roots(sub, roots):
            return
        sources.setdefault(sub, set()).add(source)

    # --- Source 1: crt.sh (Certificate Transparency logs), per root ---
    import httpx as httpx_lib
    for root in roots:
        console.print(f"  [dim]Querying crt.sh for CT log entries ({root})...[/dim]")
        try:
            ctx.rate_limiter.acquire()
            resp = httpx_lib.get(
                f"https://crt.sh/?q=%.{root}&output=json",
                timeout=30,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                entries = resp.json()
                before = len(sources)
                for entry in entries:
                    for sub in (entry.get("name_value") or "").split("\n"):
                        _record(sub, "ct")
                console.print(f"  [dim]crt.sh {root}: {len(sources) - before} new names[/dim]")
        except Exception as e:
            console.print(f"  [yellow]crt.sh query failed for {root}: {e}[/yellow]")

    # --- Source 2: subfinder (if available), per root ---
    if ctx.runner.is_available("subfinder"):
        for root in roots:
            console.print(f"  [dim]Running subfinder ({root})...[/dim]")
            result = ctx.runner.run("subfinder", ["-d", root, "-all", "-silent"], timeout=180)
            if result.success:
                before = len(sources)
                for line in result.lines:
                    _record(line, "subfinder")
                console.print(f"  [dim]subfinder {root}: {len(sources) - before} new names[/dim]")

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
    from concurrent.futures import ThreadPoolExecutor
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ctx.config.get("dns.resolvers", ["8.8.8.8", "1.1.1.1"])
    resolver.timeout = ctx.config.get("dns.query_timeout", 3)
    resolver.lifetime = ctx.config.get("dns.lifetime", 5)

    # DNS resolution goes to the configured resolvers, NOT the target, so it is
    # safe to run concurrently and it does not consume the target rps budget.
    # Resolving thousands of candidates one at a time was the main subs bottleneck.
    in_scope_subs = [s for s in unique_subs if ctx.scope.host_in_scope(s)]

    def _resolve(sub: str):
        try:
            return sub, [str(r) for r in resolver.resolve(sub, "A")]
        except Exception:
            return sub, []

    workers = min(int(ctx.config.get("dns.resolve_workers", 50)), 100)
    resolved_count = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for sub, a_records in pool.map(_resolve, in_scope_subs):
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
