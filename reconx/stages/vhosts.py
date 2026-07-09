"""
Stage 5: Virtual Host Discovery — evidence-based acceptance.

For each IP:port, tries Host header permutations.
Only accepts vhosts that produce meaningfully different responses.
"""

from datetime import datetime, timezone
from rich.console import Console
import hashlib

console = Console()
from reconx.core.normalize import safe_port


from reconx.core import http as rx_http


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
    seen_vhosts: set[str] = set()
    for ip, svcs in ip_services.items():
        svc = svcs[0]  # Use first service as baseline
        base_url = svc.get("service", "")
        if not base_url:
            continue

        # Vhost discovery by response-diff is only reliable when responses are
        # STABLE. On a target with dynamic content or a catch-all, every Host
        # yields a slightly different response, which flags the whole wordlist
        # (this produced 61 false positives on a real target). Guard with two
        # controls, both required to be reproducible:
        #  - baseline: the real Host, hashed twice; skip the IP if it is unstable.
        #  - garbage: a Host that cannot exist, hashed twice; skip the IP if the
        #    catch-all itself is unstable (we then cannot tell signal from noise).
        # A candidate is accepted only if it is itself stable AND differs from
        # both the baseline and the garbage control.
        baseline_hash = _stable_hash(base_url, svc.get("host", ""), ctx)
        garbage_hash = _stable_hash(
            base_url, f"nonexistent-vhost-control-check.{ctx.target}", ctx
        )
        if not baseline_hash or not garbage_hash:
            console.print(f"  [dim]  vhost: {ip} responds unstably, skipping (unreliable)[/dim]")
            continue

        for candidate in vhost_candidates:
            vhost = f"{candidate}.{ctx.target}"
            if vhost in seen_vhosts:
                continue

            # Stable hash across repeat requests; None if the candidate is unstable.
            candidate_hash = _stable_hash(base_url, vhost, ctx)
            if not candidate_hash:
                continue

            # Accept only if reproducibly different from BOTH controls.
            if candidate_hash != baseline_hash and candidate_hash != garbage_hash:
                seen_vhosts.add(vhost)
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
                        "severity": "info",
                        "asset": vhost,
                        "evidence": {
                            "ip": ip,
                            "base_host": svc.get("host", ""),
                            "differs_from_baseline_and_control": True,
                            "note": "unverified: confirm the vhost serves distinct content before reporting",
                        },
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    new_vhosts += 1
                    console.print(f"  [green]✓ VHost found: {vhost}[/green]")

    console.print(f"  [dim]New vhosts discovered: {new_vhosts}[/dim]")


def _stable_hash(base_url: str, host: str, ctx, tries: int = 2) -> str | None:
    """Response fingerprint only if it reproduces across `tries` requests.

    Returns the hash when every attempt agrees, else None (the response is
    unstable/dynamic and cannot be used as a reliable vhost signal). This is what
    stops dynamic pages and unstable catch-alls from flooding false positives.
    """
    first = None
    for _ in range(max(1, tries)):
        ctx.rate_limiter.acquire()
        h = _get_response_hash(base_url, host, ctx)
        if h is None:
            return None
        if first is None:
            first = h
        elif h != first:
            return None
    return first


def _get_response_hash(base_url: str, host: str, ctx) -> str | None:
    """Get a hash of the response for comparison."""
    import httpx as httpx_lib
    from urllib.parse import urlparse

    try:
        parsed = urlparse(base_url)
        url = f"{parsed.scheme}://{parsed.hostname}:{safe_port(parsed) or (443 if parsed.scheme == 'https' else 80)}"

        resp = rx_http.get(ctx.config, 
            url,
            headers={"Host": host},
            timeout=10,
            follow_redirects=False,
        )

        # Fingerprint: status + title + redirect Location host. Deliberately NOT
        # body length: dynamic pages (tokens, timestamps, IDs) shift length on
        # every request, which made near-identical responses hash differently and
        # produced a flood of false vhosts. Status + title + redirect target is
        # stable and still distinguishes a genuinely different vhost.
        title = ""
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()
        location = ""
        if resp.is_redirect or 300 <= resp.status_code < 400:
            from urllib.parse import urlparse
            location = urlparse(resp.headers.get("location", "")).hostname or ""

        content = f"{resp.status_code}|{title}|{location}"
        return hashlib.md5(content.encode()).hexdigest()

    except Exception:
        return None
