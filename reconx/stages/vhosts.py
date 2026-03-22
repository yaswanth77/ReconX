"""
Stage 5: Virtual Host Discovery — evidence-based acceptance.

For each IP:port, tries Host header permutations.
Only accepts vhosts that produce meaningfully different responses.
"""

from datetime import datetime, timezone
from rich.console import Console
import hashlib

console = Console()


def run(ctx):
    """Execute virtual host discovery."""
    import httpx as httpx_lib
    from pathlib import Path

    services = ctx.stores.services.read_all()
    if not services:
        console.print("  [dim]No alive services for vhost discovery[/dim]")
        return

    if not ctx.config.get("vhosts.enabled", True):
        console.print("  [dim]VHost discovery disabled in profile[/dim]")
        return

    # Load vhost wordlist
    wordlist_path = Path(ctx.config.get("wordlists.vhosts", "configs/wordlists/vhosts.txt"))
    vhost_candidates = []
    if wordlist_path.exists():
        with open(wordlist_path, "r") as f:
            vhost_candidates = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not vhost_candidates:
        # Default small list
        vhost_candidates = [
            "admin", "dev", "staging", "test", "api", "internal",
            "portal", "mail", "webmail", "vpn", "dashboard", "panel",
            "beta", "old", "new", "legacy", "cms", "shop", "store",
        ]

    # Group services by IP
    ip_services = {}
    for svc in services:
        ip = svc.get("ip", svc.get("host", ""))
        if ip not in ip_services:
            ip_services[ip] = []
        ip_services[ip].append(svc)

    console.print(
        f"  [dim]Testing {len(vhost_candidates)} vhost candidates "
        f"against {len(ip_services)} IPs[/dim]"
    )

    new_vhosts = 0
    for ip, svcs in ip_services.items():
        svc = svcs[0]  # Use first service as baseline
        base_url = svc.get("service", "")
        if not base_url:
            continue

        # Get baseline response hash
        baseline_hash = _get_response_hash(base_url, svc.get("host", ""), ctx)
        if not baseline_hash:
            continue

        for candidate in vhost_candidates:
            vhost = f"{candidate}.{ctx.target}"
            ctx.rate_limiter.acquire()

            # Get response with candidate Host header
            candidate_hash = _get_response_hash(base_url, vhost, ctx)
            if not candidate_hash:
                continue

            # Evidence-based acceptance: only if meaningfully different
            if candidate_hash != baseline_hash:
                if ctx.scope.host_in_scope(vhost):
                    ctx.stores.hosts.add({
                        "host": vhost,
                        "source": ["vhost"],
                        "dns": {"a": [ip]},
                        "wildcard_suspect": False,
                        "first_seen_stage": "vhosts",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

                    ctx.stores.findings.add({
                        "type": "VHOST_DISCOVERED",
                        "severity": "medium",
                        "asset": vhost,
                        "evidence": {
                            "ip": ip,
                            "base_host": svc.get("host", ""),
                            "response_diff": True,
                        },
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    new_vhosts += 1
                    console.print(f"  [green]✓ VHost found: {vhost}[/green]")

    console.print(f"  [dim]New vhosts discovered: {new_vhosts}[/dim]")


def _get_response_hash(base_url: str, host: str, ctx) -> str | None:
    """Get a hash of the response for comparison."""
    import httpx as httpx_lib
    from urllib.parse import urlparse

    try:
        parsed = urlparse(base_url)
        url = f"{parsed.scheme}://{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"

        resp = httpx_lib.get(
            url,
            headers={"Host": host},
            timeout=10,
            follow_redirects=False,
            verify=False,
        )

        # Hash: status + title + body length bucket (±100 chars)
        title = ""
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()

        content = f"{resp.status_code}|{title}|{len(resp.content) // 100}"
        return hashlib.md5(content.encode()).hexdigest()

    except Exception:
        return None
