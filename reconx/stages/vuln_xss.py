"""
Stage 14: XSS Detection — test reflected parameters.

Filters params with reflection potential, sends test payloads.
"""

from datetime import datetime, timezone
from rich.console import Console
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import re

console = Console()

# XSS test payloads (non-destructive, detection only)
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '{{7*7}}',
    '${7*7}',
    '<svg/onload=alert(1)>',
]

XSS_CANARY = "reconx_xss_"


def run(ctx):
    """Execute XSS detection on discovered params."""
    import httpx as httpx_lib

    if not ctx.config.get("vuln.xss_enabled", True):
        console.print("  [dim]XSS detection disabled[/dim]")
        return

    params = ctx.stores.params.read_all()
    if not params:
        console.print("  [dim]No params to test for XSS[/dim]")
        return

    # Filter for likely XSS candidates
    candidates = []
    for p in params:
        tags = p.get("risk_tags", [])
        endpoint = p.get("endpoint", "")
        param_names = p.get("params", [])
        if "sqli_candidate" in tags or "lfi_candidate" in tags:
            # These params might reflect input
            candidates.append((endpoint, param_names))
        elif param_names:
            candidates.append((endpoint, param_names))

    candidates = candidates[:30]  # Safety limit
    console.print(f"  [dim]Testing {len(candidates)} endpoints for XSS...[/dim]")

    count = 0
    for endpoint, param_names in candidates:
        for param in param_names:
            canary = f"{XSS_CANARY}{count}"
            ctx.rate_limiter.acquire()

            try:
                # Test with canary first (reflection check)
                test_url = f"{endpoint}?{urlencode({param: canary})}"
                resp = httpx_lib.get(
                    test_url, timeout=15, follow_redirects=True, verify=False
                )

                if canary in resp.text:
                    # Reflected! Now test with actual payloads
                    for payload in XSS_PAYLOADS[:3]:
                        ctx.rate_limiter.acquire()
                        xss_url = f"{endpoint}?{urlencode({param: payload})}"
                        xss_resp = httpx_lib.get(
                            xss_url, timeout=15, follow_redirects=True, verify=False
                        )

                        if payload in xss_resp.text:
                            if ctx.stores.vulns.add({
                                "type": "xss_reflected",
                                "url": endpoint,
                                "param": param,
                                "severity": "medium",
                                "evidence": {
                                    "payload": payload,
                                    "reflected": True,
                                    "response_snippet": xss_resp.text[
                                        max(0, xss_resp.text.index(payload) - 50):
                                        xss_resp.text.index(payload) + len(payload) + 50
                                    ],
                                },
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }):
                                count += 1
                                console.print(
                                    f"  [red]🔥 XSS: {param} on {endpoint}[/red]"
                                )
                            break  # One confirmed payload is enough

            except Exception:
                continue

    console.print(f"  [dim]XSS findings: {count}[/dim]")
