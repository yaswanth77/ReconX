"""
Stage 3: Zone Transfer — AXFR attempt against each discovered NS.

High-signal finding: if zone transfer succeeds, it leaks the entire DNS zone.
"""

from datetime import datetime, timezone
from rich.console import Console

console = Console()


def run(ctx):
    """Execute zone transfer checks."""
    import dns.query
    import dns.zone
    import dns.resolver

    target = ctx.target

    # Get nameservers from findings
    ns_findings = [
        f for f in ctx.stores.findings.read_all()
        if f.get("type") == "DNS_NS" and f.get("asset") == target
    ]

    nameservers = []
    for f in ns_findings:
        nameservers.extend(f.get("evidence", {}).get("nameservers", []))

    if not nameservers:
        # Try resolving NS directly
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(target, "NS")
            nameservers = [str(r).rstrip(".") for r in answers]
        except Exception:
            pass

    if not nameservers:
        console.print("  [dim]No nameservers found, skipping AXFR[/dim]")
        return

    console.print(f"  [dim]Testing AXFR against {len(nameservers)} nameservers[/dim]")

    for ns in nameservers:
        ns_clean = ns.rstrip(".")
        console.print(f"  [dim]Trying AXFR: {ns_clean}[/dim]")

        try:
            # Resolve NS to IP first
            resolver = dns.resolver.Resolver()
            ns_ips = [str(r) for r in resolver.resolve(ns_clean, "A")]

            for ns_ip in ns_ips:
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_ip, target, timeout=10)
                    )
                    # Zone transfer succeeded!
                    console.print(
                        f"  [bold red]🔥 AXFR SUCCESS on {ns_clean} ({ns_ip})![/bold red]"
                    )

                    # Extract hosts from zone
                    new_hosts = 0
                    for name, node in zone.nodes.items():
                        hostname = f"{name}.{target}".rstrip(".")
                        if hostname != target and ctx.scope.host_in_scope(hostname):
                            record = {
                                "host": hostname,
                                "source": ["axfr"],
                                "dns": {"a": []},
                                "wildcard_suspect": False,
                                "first_seen_stage": "axfr",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }
                            if ctx.stores.hosts.add(record):
                                new_hosts += 1

                    ctx.stores.findings.add({
                        "type": "DNS_AXFR",
                        "severity": "high",
                        "asset": target,
                        "evidence": {
                            "nameserver": ns_clean,
                            "ip": ns_ip,
                            "result": "SUCCESS",
                            "records_found": new_hosts,
                        },
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

                    console.print(f"  [dim]Imported {new_hosts} new hosts from zone[/dim]")
                    break  # One successful transfer is enough

                except Exception:
                    continue

        except Exception as e:
            ctx.stores.findings.add({
                "type": "DNS_AXFR",
                "severity": "info",
                "asset": target,
                "evidence": {
                    "nameserver": ns_clean,
                    "result": "REFUSED",
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
