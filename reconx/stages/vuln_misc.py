"""
Stage 16: Vuln Misc — Open Redirect, SSRF, SSTI checks.

Targeted checks on parameters auto-tagged for these vuln types.
"""

from datetime import datetime, timezone
from rich.console import Console
from urllib.parse import urlencode
import re

console = Console()


def run(ctx):
    """Execute miscellaneous vulnerability checks."""
    import httpx as httpx_lib

    if not ctx.config.get("vuln.misc_enabled", True):
        console.print("  [dim]Misc vuln checks disabled[/dim]")
        return

    params = ctx.stores.params.read_all()
    if not params:
        console.print("  [dim]No params for misc vuln checks[/dim]")
        return

    total = 0
    total += _check_open_redirect(ctx, params, httpx_lib)
    total += _check_ssrf(ctx, params, httpx_lib)
    total += _check_ssti(ctx, params, httpx_lib)

    console.print(f"  [dim]Misc vuln findings: {total}[/dim]")


def _check_open_redirect(ctx, params, httpx_lib) -> int:
    """Check for open redirect vulnerabilities."""
    redirect_candidates = []
    for p in params:
        if "open_redirect_candidate" in p.get("risk_tags", []):
            redirect_candidates.append((p["endpoint"], p["params"]))

    if not redirect_candidates:
        return 0

    console.print(f"  [dim]Testing {len(redirect_candidates)} endpoints for open redirect...[/dim]")

    test_domain = "https://evil.com"
    count = 0

    for endpoint, param_names in redirect_candidates[:15]:
        for param in param_names:
            if not any(k in param.lower() for k in ["redirect", "url", "next", "return", "goto", "dest"]):
                continue

            ctx.rate_limiter.acquire()
            try:
                test_url = f"{endpoint}?{urlencode({param: test_domain})}"
                resp = httpx_lib.get(
                    test_url, timeout=15, follow_redirects=False, verify=False
                )

                location = resp.headers.get("location", "")
                if "evil.com" in location:
                    if ctx.stores.vulns.add({
                        "type": "open_redirect",
                        "url": endpoint,
                        "param": param,
                        "severity": "medium",
                        "evidence": {
                            "payload": test_domain,
                            "redirect_location": location,
                            "status_code": resp.status_code,
                        },
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }):
                        count += 1
                        console.print(f"  [yellow]🔥 Open Redirect: {param} on {endpoint}[/yellow]")

            except Exception:
                continue

    return count


def _check_ssrf(ctx, params, httpx_lib) -> int:
    """Check for SSRF indicators."""
    ssrf_candidates = []
    for p in params:
        if "ssrf_candidate" in p.get("risk_tags", []):
            ssrf_candidates.append((p["endpoint"], p["params"]))

    if not ssrf_candidates:
        return 0

    console.print(f"  [dim]Testing {len(ssrf_candidates)} endpoints for SSRF...[/dim]")

    # Test with internal IP (detection only — checks if server fetches)
    ssrf_payloads = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://169.254.169.254/latest/meta-data/",
    ]

    count = 0
    for endpoint, param_names in ssrf_candidates[:10]:
        for param in param_names:
            if not any(k in param.lower() for k in ["url", "host", "proxy", "target", "fetch", "load"]):
                continue

            for payload in ssrf_payloads:
                ctx.rate_limiter.acquire()
                try:
                    test_url = f"{endpoint}?{urlencode({param: payload})}"
                    resp = httpx_lib.get(
                        test_url, timeout=15, follow_redirects=True, verify=False
                    )

                    # Look for internal content indicators
                    indicators = [
                        "root:x:", "localhost", "ami-id", "instance-id",
                        "AWS_ACCESS", "meta-data", "127.0.0.1",
                    ]
                    if any(ind in resp.text for ind in indicators):
                        if ctx.stores.vulns.add({
                            "type": "ssrf",
                            "url": endpoint,
                            "param": param,
                            "severity": "high",
                            "evidence": {
                                "payload": payload,
                                "response_length": len(resp.content),
                                "status": resp.status_code,
                            },
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }):
                            count += 1
                            console.print(f"  [red]🔥 SSRF: {param} on {endpoint}[/red]")
                        break

                except Exception:
                    continue

    return count


def _check_ssti(ctx, params, httpx_lib) -> int:
    """Check for Server-Side Template Injection."""
    # Test all params since any could be vulnerable
    all_endpoints = []
    for p in params:
        all_endpoints.append((p["endpoint"], p["params"]))

    if not all_endpoints:
        return 0

    ssti_payloads = {
        "{{7*7}}": "49",
        "${7*7}": "49",
        "{{7*'7'}}": "7777777",
        "<%= 7*7 %>": "49",
    }

    count = 0
    tested = 0
    for endpoint, param_names in all_endpoints[:15]:
        for param in param_names:
            for payload, expected in ssti_payloads.items():
                ctx.rate_limiter.acquire()
                tested += 1
                try:
                    test_url = f"{endpoint}?{urlencode({param: payload})}"
                    resp = httpx_lib.get(
                        test_url, timeout=15, follow_redirects=True, verify=False
                    )

                    if expected in resp.text and payload not in resp.text:
                        if ctx.stores.vulns.add({
                            "type": "ssti",
                            "url": endpoint,
                            "param": param,
                            "severity": "critical",
                            "evidence": {
                                "payload": payload,
                                "expected": expected,
                                "found_in_response": True,
                            },
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }):
                            count += 1
                            console.print(
                                f"  [bold red]🔥 SSTI: {param} on {endpoint}[/bold red]"
                            )
                        break

                except Exception:
                    continue

    if tested > 0:
        console.print(f"  [dim]SSTI tests: {tested}, findings: {count}[/dim]")

    return count
