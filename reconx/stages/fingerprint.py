"""
Stage 6: Fingerprinting — headers, title, favicon, TLS, tech detection.

Enriches services.jsonl with tech stack details.
AI post-hook: analyzes stack and generates recommendations.
"""

from datetime import datetime, timezone
from rich.console import Console
import hashlib

console = Console()


def run(ctx):
    """Execute fingerprinting stage."""
    import httpx as httpx_lib

    services = ctx.stores.services.read_all()
    if not services:
        console.print("  [dim]No services to fingerprint[/dim]")
        return

    console.print(f"  [dim]Fingerprinting {len(services)} services[/dim]")

    all_tech = set()
    all_headers = {}

    for svc in services:
        url = svc.get("final_url", svc.get("service", ""))
        if not url:
            continue

        # Collect tech hints
        tech = svc.get("tech", [])
        server = svc.get("server", "")
        headers = svc.get("headers", {})
        title = svc.get("title", "")

        # Extract more tech hints from headers
        if server:
            tech.append(server)
        powered_by = headers.get("x-powered-by", headers.get("X-Powered-By", ""))
        if powered_by:
            tech.append(powered_by)

        # Favicon hash (for tech identification)
        favicon_hash = _get_favicon_hash(url, ctx)
        if favicon_hash:
            tech.append(f"favicon:{favicon_hash}")

        all_tech.update(tech)
        all_headers.update(headers)

        # Check for security headers (findings)
        _check_security_headers(ctx, url, headers)

    console.print(f"  [dim]Technologies detected: {', '.join(list(all_tech)[:10])}[/dim]")

    # AI post-hook: analyze tech stack
    if ctx.ai_engine and ctx.ai_engine.enabled and all_tech:
        tech_dict = {"tech": list(all_tech)}
        analysis = ctx.ai_engine.analyze_target(tech_dict, all_headers, services[0].get("title", ""))
        if analysis:
            ctx.stores.ai_analysis.add({
                "stage": "fingerprint",
                "target": ctx.target,
                "analysis": analysis,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })


def _get_favicon_hash(base_url: str, ctx) -> str | None:
    """Get MD5 hash of favicon for tech identification."""
    import httpx as httpx_lib
    try:
        ctx.rate_limiter.acquire()
        resp = httpx_lib.get(
            f"{base_url}/favicon.ico",
            timeout=10,
            follow_redirects=True,
            verify=False,
        )
        if resp.status_code == 200 and len(resp.content) > 0:
            return hashlib.md5(resp.content).hexdigest()
    except Exception:
        pass
    return None


def _check_security_headers(ctx, url: str, headers: dict):
    """Check for missing security headers."""
    important_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
    ]

    lower_headers = {k.lower(): v for k, v in headers.items()}
    missing = [h for h in important_headers if h not in lower_headers]

    if missing:
        ctx.stores.findings.add({
            "type": "MISSING_SECURITY_HEADERS",
            "severity": "low",
            "asset": url,
            "evidence": {"missing": missing},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
