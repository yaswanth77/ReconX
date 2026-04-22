"""
Stage 4: Service Validation — the gatekeeper.

Probes each discovered host on configured ports using httpx.
Only alive services proceed downstream. This is THE redundancy killer.
"""

from datetime import datetime, timezone
from rich.console import Console
import json

console = Console()


def run(ctx):
    """Execute service validation using httpx."""
    hosts = ctx.stores.hosts.read_all()
    if not hosts:
        console.print("  [dim]No hosts to validate[/dim]")
        return

    hostnames = list(set(h["host"] for h in hosts))
    ports = ctx.config.get("http.ports", [80, 443, 8080, 8443])

    console.print(f"  [dim]Validating {len(hostnames)} hosts × {len(ports)} ports[/dim]")

    # Build probe targets
    targets = []
    for host in hostnames:
        for port in ports:
            scheme = "https" if port in (443, 8443) else "http"
            targets.append(f"{scheme}://{host}:{port}")

    # Prefer ProjectDiscovery httpx when the binary on PATH is really the
    # ProjectDiscovery one. On Debian/Kali `python3-httpx` also ships a
    # binary called `httpx` that silently accepts our flags wrong, so the
    # identity check is load-bearing here.
    if ctx.runner.is_available("httpx") and ctx.runner.identity_ok("httpx"):
        alive = _validate_with_httpx_cli(ctx, targets)
    else:
        if ctx.runner.is_available("httpx"):
            console.print(
                "  [yellow]⚠ `httpx` on PATH isn't ProjectDiscovery httpx "
                "(likely python3-httpx); using Python fallback.[/yellow]"
            )
            console.print(
                "  [dim]Install: go install -v "
                "github.com/projectdiscovery/httpx/cmd/httpx@latest[/dim]"
            )
        alive = _validate_with_python(ctx, targets)

    if alive == 0 and targets:
        # Tell the scheduler the gate didn't produce usable data so
        # downstream stages (fingerprint/urls/vuln_*) skip cleanly.
        raise RuntimeError(
            f"validate: 0 of {len(targets)} targets came up alive — "
            "check that httpx/network is working before rerunning"
        )


def _validate_with_httpx_cli(ctx, targets) -> int:
    """Use the httpx CLI tool for validation. Returns alive count."""
    import tempfile
    import os

    # Write targets to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        targets_file = f.name

    try:
        args = [
            "-l", targets_file,
            "-json",
            "-silent",
            "-timeout", str(ctx.config.get("network.timeout", 30)),
            "-threads", str(min(ctx.config.get("network.concurrency", 50), 100)),
            "-follow-redirects",
            "-status-code",
            "-title",
            "-tech-detect",
            "-server",
        ]

        if ctx.config.get("http.insecure", False):
            args.append("-no-verify")

        result = ctx.runner.run("httpx", args, timeout=600)

        alive_count = 0
        for line in result.lines:
            try:
                data = json.loads(line)
                service_record = {
                    "service": data.get("url", ""),
                    "host": data.get("host", ""),
                    "ip": data.get("a", [""])[0] if data.get("a") else "",
                    "status": data.get("status_code", 0),
                    "final_url": data.get("final_url", data.get("url", "")),
                    "title": data.get("title", ""),
                    "headers": data.get("header", {}),
                    "tls": data.get("tls", {}),
                    "tech": data.get("tech", []),
                    "server": data.get("webserver", ""),
                    "content_length": data.get("content_length", 0),
                    "alive": True,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                if ctx.stores.services.add(service_record):
                    alive_count += 1
            except json.JSONDecodeError:
                continue

        console.print(f"  [dim]Alive services: {alive_count}[/dim]")
        return alive_count

    finally:
        os.unlink(targets_file)


def _validate_with_python(ctx, targets) -> int:
    """
    Fallback: validate using Python httpx library, in parallel.

    Each target hits its own connect/read timeout, so a serial loop pays
    that cost N times on down ports. We fan out probes across a thread
    pool bounded by ``network.concurrency`` and keep the rate limiter in
    the hot path so the overall pace is still governed. Writes to the
    store still happen on the main thread — JsonlStore isn't thread safe.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from urllib.parse import urlparse
    import httpx as httpx_lib

    timeout = ctx.config.get("network.timeout", 10)
    insecure = ctx.config.get("http.insecure", False)
    # Cap the pool: parallelism is bounded by either the user's
    # configured concurrency or the number of targets (whichever is
    # smaller), with an absolute ceiling so we don't DoS the target.
    workers = min(len(targets), ctx.config.get("network.concurrency", 20), 50)

    def _probe(target_url: str):
        ctx.rate_limiter.acquire()
        try:
            resp = httpx_lib.get(
                target_url,
                timeout=timeout,
                follow_redirects=True,
                verify=not insecure,
            )
        except Exception:
            return None
        parsed = urlparse(target_url)
        return {
            "service": target_url,
            "host": parsed.hostname or "",
            "ip": "",
            "status": resp.status_code,
            "final_url": str(resp.url),
            "title": _extract_title(resp.text),
            "headers": dict(resp.headers),
            "tls": {},
            "tech": [],
            "server": resp.headers.get("server", ""),
            "content_length": len(resp.content),
            "alive": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    alive_count = 0
    with ThreadPoolExecutor(max_workers=max(workers, 1)) as pool:
        futures = [pool.submit(_probe, t) for t in targets]
        for fut in as_completed(futures):
            record = fut.result()
            if record and ctx.stores.services.add(record):
                alive_count += 1

    console.print(f"  [dim]Alive services: {alive_count}[/dim]")
    return alive_count


def _extract_title(html: str) -> str:
    """Extract <title> from HTML."""
    import re
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""
