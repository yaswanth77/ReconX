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

    # Use httpx CLI if available (faster, handles TLS better)
    if ctx.runner.is_available("httpx"):
        _validate_with_httpx_cli(ctx, targets)
    else:
        _validate_with_python(ctx, targets)


def _validate_with_httpx_cli(ctx, targets):
    """Use the httpx CLI tool for validation."""
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

    finally:
        os.unlink(targets_file)


def _validate_with_python(ctx, targets):
    """Fallback: validate using Python httpx library."""
    import httpx as httpx_lib

    alive_count = 0
    for target_url in targets:
        ctx.rate_limiter.acquire()
        try:
            resp = httpx_lib.get(
                target_url,
                timeout=ctx.config.get("network.timeout", 10),
                follow_redirects=True,
                verify=not ctx.config.get("http.insecure", False),
            )

            from urllib.parse import urlparse
            parsed = urlparse(target_url)

            service_record = {
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
            if ctx.stores.services.add(service_record):
                alive_count += 1

        except Exception:
            continue

    console.print(f"  [dim]Alive services: {alive_count}[/dim]")


def _extract_title(html: str) -> str:
    """Extract <title> from HTML."""
    import re
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""
