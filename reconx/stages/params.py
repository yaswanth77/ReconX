"""
Stage 9: Parameter Discovery — ParamSpider (passive) + Arjun (active, filtered).

AI enhancement: scores each parameter by injection risk.
"""

from datetime import datetime, timezone
from rich.console import Console

console = Console()

# Keywords that indicate high-value parameters
HIGH_VALUE_KEYWORDS = [
    "id", "user", "uid", "account", "order", "item", "product",
    "search", "query", "q", "filter", "sort", "page",
    "redirect", "url", "next", "return", "callback", "goto", "dest",
    "file", "path", "dir", "doc", "template", "include",
    "email", "username", "name", "token", "key", "secret",
]


def run(ctx):
    """Execute parameter discovery."""
    target = ctx.target

    total_new = 0

    # Source 1: ParamSpider (passive)
    if ctx.runner.is_available("paramspider"):
        console.print("  [dim]Running ParamSpider...[/dim]")
        result = ctx.runner.run(
            "paramspider", ["-d", target, "--level", "high", "-o", "-"],
            timeout=180,
        )
        if result.success:
            for url in result.lines:
                url = url.strip()
                if url and "FUZZ" in url and ctx.scope.url_in_scope(url.replace("FUZZ", "test")):
                    # Extract params from URL
                    params = _extract_params(url)
                    endpoint = url.split("?")[0]
                    if params and ctx.stores.params.add({
                        "endpoint": endpoint,
                        "method": "GET",
                        "params": params,
                        "discovered_by": ["paramspider"],
                        "risk_tags": _auto_tag_params(params),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }):
                        total_new += 1

    # Source 2: Extract params from discovered URLs
    console.print("  [dim]Extracting params from discovered URLs...[/dim]")
    urls = ctx.stores.urls.read_all()
    for url_record in urls:
        url = url_record.get("url", "")
        if "?" in url:
            params = _extract_params(url)
            endpoint = url.split("?")[0]
            if params and ctx.stores.params.add({
                "endpoint": endpoint,
                "method": "GET",
                "params": params,
                "discovered_by": ["url_extraction"],
                "risk_tags": _auto_tag_params(params),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }):
                total_new += 1

    # Source 3: Arjun (active, filtered endpoints only)
    if ctx.config.get("params.arjun_enabled", True) and ctx.runner.is_available("arjun"):
        _run_arjun(ctx)

    # AI scoring
    if ctx.ai_engine and ctx.ai_engine.enabled:
        all_params = ctx.stores.params.read_all()
        if all_params:
            scored = ctx.ai_engine.score_params(all_params)
            if scored:
                ctx.stores.ai_analysis.add({
                    "stage": "params",
                    "target": ctx.target,
                    "analysis": {"scored_params": scored},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

    console.print(f"  [dim]Total param endpoints: {total_new}[/dim]")


def _run_arjun(ctx):
    """Run Arjun only on filtered high-value endpoints."""
    services = ctx.stores.services.read_all()
    if not services:
        return

    # Filter: endpoints with query strings or interesting keywords in path
    filters = ctx.config.get("params.endpoint_filters", HIGH_VALUE_KEYWORDS)
    urls = ctx.stores.urls.read_all()

    targets = []
    for url_record in urls:
        url = url_record.get("url", "")
        path = url.split("?")[0].lower()
        if any(kw in path for kw in filters):
            targets.append(url.split("?")[0])  # Strip existing params
        elif "?" in url:
            targets.append(url.split("?")[0])

    targets = list(set(targets))[:20]  # Limit to avoid long scans

    if not targets:
        return

    console.print(f"  [dim]Running Arjun on {len(targets)} filtered endpoints...[/dim]")

    for endpoint in targets:
        ctx.rate_limiter.acquire()
        result = ctx.runner.run(
            "arjun",
            ["-u", endpoint, "--stable", "-oJ", "-"],
            timeout=120,
        )
        if result.success:
            try:
                import json
                data = json.loads(result.stdout)
                if isinstance(data, list):
                    for item in data:
                        params = item.get("params", [])
                        if params:
                            ctx.stores.params.add({
                                "endpoint": endpoint,
                                "method": item.get("method", "GET"),
                                "params": params,
                                "discovered_by": ["arjun"],
                                "risk_tags": _auto_tag_params(params),
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            })
            except Exception:
                pass


def _extract_params(url: str) -> list[str]:
    """Extract parameter names from a URL."""
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return list(params.keys())


def _auto_tag_params(params: list[str]) -> list[str]:
    """Auto-tag parameters based on naming patterns."""
    tags = []
    for p in params:
        p_lower = p.lower()
        if any(k in p_lower for k in ["id", "uid", "user_id", "account_id", "order_id"]):
            tags.append("idor_candidate")
        if any(k in p_lower for k in ["redirect", "url", "next", "return", "goto", "dest"]):
            tags.append("open_redirect_candidate")
        if any(k in p_lower for k in ["search", "query", "q", "filter", "sort"]):
            tags.append("sqli_candidate")
        if any(k in p_lower for k in ["file", "path", "dir", "include", "template"]):
            tags.append("lfi_candidate")
        if any(k in p_lower for k in ["url", "host", "proxy", "target"]):
            tags.append("ssrf_candidate")
    return list(set(tags))
