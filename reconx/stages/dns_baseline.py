"""
Stage 1: DNS Baseline — records + wildcard detection.

Queries A/AAAA/CNAME/NS/SOA/MX/TXT records for the target domain.
Detects wildcard DNS to prevent garbage subdomains downstream.
"""

from datetime import datetime, timezone
from rich.console import Console

console = Console()


def run(ctx):
    """Execute DNS baseline stage."""
    import dns.resolver
    import dns.zone
    import random
    import string

    target = ctx.target
    console.print(f"  [dim]Querying DNS records for {target}[/dim]")

    record_types = ["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT"]
    dns_data = {}

    resolver = dns.resolver.Resolver()
    resolvers = ctx.config.get("dns.resolvers", ["8.8.8.8", "1.1.1.1"])
    resolver.nameservers = resolvers

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            dns_data[rtype.lower()] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            dns_data[rtype.lower()] = []
        except Exception:
            dns_data[rtype.lower()] = []

    # Wildcard detection
    wildcard = False
    if ctx.config.get("dns.wildcard_detection", True):
        random_sub = "".join(random.choices(string.ascii_lowercase, k=12))
        try:
            resolver.resolve(f"{random_sub}.{target}", "A")
            wildcard = True
            console.print("  [yellow]⚠ Wildcard DNS detected![/yellow]")
        except Exception:
            wildcard = False

    # Store host record
    host_record = {
        "host": target,
        "source": ["dns_baseline"],
        "dns": dns_data,
        "wildcard_suspect": wildcard,
        "first_seen_stage": "dns",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    ctx.stores.hosts.add(host_record)

    # Store NS servers for zone transfer stage
    ns_records = dns_data.get("ns", [])
    if ns_records:
        ctx.stores.findings.add({
            "type": "DNS_NS",
            "severity": "info",
            "asset": target,
            "evidence": {"nameservers": ns_records},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # Summary
    total = sum(len(v) for v in dns_data.values())
    console.print(f"  [dim]Found {total} DNS records, wildcard: {wildcard}[/dim]")
