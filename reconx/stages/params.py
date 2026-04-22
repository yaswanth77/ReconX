"""
Stage 9: Parameter Discovery — ParamSpider (passive) + Arjun (active, filtered).

AI enhancement: scores each parameter by injection risk.

Design notes:
- ParamSpider pulls from public archives (archive.org / CommonCrawl). For
  private-range or reserved-TLD targets the archive can never have data,
  so we still invoke it once (someone may have seeded archives manually)
  but short-circuit retries and timeouts to avoid multi-minute waits.
- Arjun needs a stable response baseline. Unstable or catch-all targets
  make it stall for its full timeout; we run with ``attempts=1`` and a
  tighter per-call timeout so one dud endpoint can't burn minutes.
- Arjun is scoped to endpoints that are *likely* to take params (already
  carry ``?``, or match a positive keyword list, or explicitly opted in
  via ``params.arjun_scan_all``). This prevents scanning JSON metadata
  endpoints and static assets.
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

# Path segments that commonly accept query parameters on real apps.
_PARAM_LIKELY_PATH_KEYWORDS = (
    "search", "find", "query", "lookup",
    "user", "users", "account", "accounts", "profile",
    "order", "orders", "item", "items", "product", "products",
    "login", "auth", "oauth", "signin", "callback",
    "redirect", "goto", "return", "next",
    "api/v", "rest/", "graphql",
    "report", "download", "export", "view",
)


def run(ctx):
    """Execute parameter discovery."""
    target = ctx.target

    total_new = 0

    # --- Source 1: ParamSpider (passive, archive-backed) ---
    if ctx.runner.is_available("paramspider"):
        total_new += _run_paramspider(ctx, target)

    # --- Source 2: Extract params from URLs already in the store ---
    console.print("  [dim]Extracting params from discovered URLs...[/dim]")
    for url_record in ctx.stores.urls.read_all():
        url = url_record.get("url", "")
        if "?" not in url:
            continue
        params = _extract_params(url)
        if not params:
            continue
        endpoint = url.split("?")[0]
        if ctx.stores.params.add({
            "endpoint": endpoint,
            "method": "GET",
            "params": params,
            "discovered_by": ["url_extraction"],
            "risk_tags": _auto_tag_params(params),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }):
            total_new += 1

    # --- Source 3: Arjun (active, bounded) ---
    if ctx.config.get("params.arjun_enabled", True) and ctx.runner.is_available("arjun"):
        total_new += _run_arjun(ctx)

    # --- AI scoring ---
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


# --------------------------------------------------------------------
# ParamSpider
# --------------------------------------------------------------------

def _target_is_private(target: str) -> bool:
    """
    Return True if the target is a private IP, loopback, or a reserved
    TLD (.local, .internal, .test, .example, .invalid, .localhost) that
    archive.org can't have records for. Hostnames on real TLDs return
    False so we still attempt the normal archive lookup.
    """
    import ipaddress
    t = (target or "").strip().lower().rstrip(".")
    if not t:
        return True
    try:
        ip = ipaddress.ip_address(t)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        pass
    # RFC 2606 / RFC 6761 reserved names: never public.
    reserved_tlds = (".local", ".localhost", ".internal",
                     ".test", ".example", ".invalid")
    return any(t == s.lstrip(".") or t.endswith(s) for s in reserved_tlds)


def _run_paramspider(ctx, target: str) -> int:
    """
    Run ParamSpider against ``target``. For private/reserved targets we
    downgrade retries+timeout so a guaranteed-empty lookup doesn't burn
    minutes, but we still run it in case archives were seeded manually.
    """
    private = _target_is_private(target)
    if private:
        console.print(
            "  [dim]Running ParamSpider (target is private/reserved; "
            "archive lookup unlikely to return data, using short timeout)[/dim]"
        )
        timeout = ctx.config.get("params.paramspider_timeout_private", 30)
        attempts = 1
    else:
        console.print("  [dim]Running ParamSpider...[/dim]")
        timeout = ctx.config.get("params.paramspider_timeout", 180)
        attempts = ctx.config.get("params.paramspider_attempts", 2)

    result = ctx.runner.run(
        "paramspider",
        ["-d", target, "--level", "high", "-o", "-"],
        timeout=timeout,
        attempts=attempts,
    )

    if not result.success:
        if not private:
            console.print("  [dim]ParamSpider returned no data (archive has no records?)[/dim]")
        return 0

    added = 0
    for url in result.lines:
        url = url.strip()
        if not url or "FUZZ" not in url:
            continue
        if not ctx.scope.url_in_scope(url.replace("FUZZ", "test")):
            continue
        params = _extract_params(url)
        if not params:
            continue
        endpoint = url.split("?")[0]
        if ctx.stores.params.add({
            "endpoint": endpoint,
            "method": "GET",
            "params": params,
            "discovered_by": ["paramspider"],
            "risk_tags": _auto_tag_params(params),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }):
            added += 1
    return added


# --------------------------------------------------------------------
# Arjun
# --------------------------------------------------------------------

def _endpoint_is_param_likely(url: str) -> bool:
    """Positive signal that this endpoint is worth fuzzing for params."""
    if "?" in url:
        return True
    path = url.split("?")[0].lower()
    # Static-extension URLs never take params worth fuzzing.
    static_exts = (".css", ".js", ".json", ".xml", ".png", ".jpg",
                   ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
                   ".ttf", ".map", ".txt", ".pdf")
    if path.endswith(static_exts):
        return False
    # Metadata paths (/.well-known/*) are overwhelmingly JSON docs, not
    # param-taking endpoints.
    if "/.well-known/" in path:
        return False
    return any(kw in path for kw in _PARAM_LIKELY_PATH_KEYWORDS)


def _run_arjun(ctx) -> int:
    """Run Arjun against a bounded, pre-filtered list of endpoints."""
    services = ctx.stores.services.read_all()
    if not services:
        return 0

    cap = ctx.config.get("params.arjun_max_endpoints", 25)
    scan_all = ctx.config.get("params.arjun_scan_all", False)

    # Services with wildcard routing (SPA catch-alls) starve arjun's
    # baseline detector; on those we only trust URLs that already carry
    # a query string (definitely have params) instead of letting arjun
    # time out on every speculative keyword match.
    wildcard_services: set[str] = set()
    for finding in ctx.stores.findings.read_all():
        if finding.get("type") == "WILDCARD_ROUTING":
            asset = finding.get("asset")
            if asset:
                wildcard_services.add(asset)

    def _service_is_wildcard(url: str) -> bool:
        return any(url.startswith(svc) for svc in wildcard_services)

    candidates: list[str] = []
    seen: set[str] = set()
    for url_record in ctx.stores.urls.read_all():
        url = url_record.get("url", "") or ""
        if not url:
            continue
        endpoint = url.split("?")[0]
        if endpoint in seen:
            continue
        seen.add(endpoint)
        on_wildcard = _service_is_wildcard(url)
        if scan_all:
            candidates.append(endpoint)
        elif on_wildcard:
            # Only URLs that already carried a `?` are worth trying.
            if "?" in url:
                candidates.append(endpoint)
        elif _endpoint_is_param_likely(url):
            candidates.append(endpoint)

    if not candidates:
        if wildcard_services:
            console.print(
                "  [dim]Arjun: target has wildcard routing and no URLs with "
                "query strings — skipping to avoid fruitless timeouts[/dim]"
            )
        else:
            console.print("  [dim]Arjun: no param-likely endpoints to scan[/dim]")
        return 0

    targets = candidates[:cap]
    if len(candidates) > cap:
        console.print(
            f"  [dim]Arjun: {len(candidates)} candidates; scanning top {cap} "
            f"(override via params.arjun_max_endpoints)[/dim]"
        )
    else:
        console.print(f"  [dim]Running Arjun on {len(targets)} filtered endpoints...[/dim]")

    per_call_timeout = ctx.config.get("params.arjun_timeout", 60)
    added = 0

    for endpoint in targets:
        ctx.rate_limiter.acquire()
        # attempts=1: arjun timeouts are almost always permanent (unstable
        # target / wildcard routing), so retrying just multiplies the wait.
        result = ctx.runner.run(
            "arjun",
            ["-u", endpoint, "--stable", "-oJ", "-"],
            timeout=per_call_timeout,
            attempts=1,
        )
        if not result.success:
            continue
        try:
            import json
            data = json.loads(result.stdout) if result.stdout.strip() else []
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for item in data:
            params = item.get("params", [])
            if not params:
                continue
            if ctx.stores.params.add({
                "endpoint": endpoint,
                "method": item.get("method", "GET"),
                "params": params,
                "discovered_by": ["arjun"],
                "risk_tags": _auto_tag_params(params),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }):
                added += 1
    return added


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------

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
