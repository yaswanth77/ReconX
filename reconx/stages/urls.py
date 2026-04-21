"""
Stage 7: URL Expansion — robots.txt -> well-known -> crawl -> creepy.

Controlled URL discovery with source tagging and strict dedup.
AI enhancement: generates dynamic creepy paths based on tech stack.

Every static-path probe (well-known, creepy) first captures a
"wildcard baseline" by requesting a random unregistered path. Targets
that return 200 for every path (SPAs, catch-all routers, CDN edges)
produce a baseline that subsequent probes are compared against; any
probe whose response is byte-identical to the baseline is treated as
noise and skipped. Targets with real 404s produce a baseline that
differs from real responses, so the filter is a no-op and no
legitimate finding is lost.
"""

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from rich.console import Console
import re
import secrets

console = Console()


def run(ctx):
    """Execute URL expansion with sub-stages."""
    services = ctx.stores.services.read_all()
    if not services:
        console.print("  [dim]No services for URL expansion[/dim]")
        return

    base_urls = list(set(
        svc.get("final_url", svc.get("service", ""))
        for svc in services if svc.get("alive")
    ))

    console.print(f"  [dim]Expanding URLs for {len(base_urls)} services[/dim]")

    # Baselines are computed once per base_url and shared across probe
    # functions so we don't pay the probe cost twice.
    baselines: dict[str, dict | None] = {}

    total_new = 0
    for base_url in base_urls:
        baselines[base_url] = _get_wildcard_baseline(ctx, base_url)
        _note_wildcard(ctx, base_url, baselines[base_url])

        total_new += _fetch_robots(ctx, base_url)
        total_new += _fetch_wellknown(ctx, base_url, baselines[base_url])
        total_new += _crawl(ctx, base_url)
        total_new += _creepy_paths(ctx, base_url, baselines[base_url])

    console.print(f"  [dim]Total new URLs discovered: {total_new}[/dim]")


# --------------------------------------------------------------------
# Wildcard baseline helpers
# --------------------------------------------------------------------

def _get_wildcard_baseline(ctx, base_url: str) -> dict | None:
    """
    Probe an unregistered random path to discover how the target responds
    to "this path doesn't exist". Returns a fingerprint dict or None if
    the probe itself fails (in which case filtering is disabled).
    """
    import httpx as httpx_lib

    probe_path = "/reconx-probe-" + secrets.token_hex(16)
    url = f"{base_url.rstrip('/')}{probe_path}"

    try:
        ctx.rate_limiter.acquire()
        resp = httpx_lib.get(
            url, timeout=10, follow_redirects=False, verify=False
        )
    except Exception:
        return None

    body = resp.content or b""
    return {
        "status": resp.status_code,
        "body_sha256": sha256(body).hexdigest(),
        "body_len": len(body),
        "content_type": (resp.headers.get("content-type") or "").split(";")[0].strip(),
    }


def _response_matches_baseline(resp, baseline: dict | None) -> bool:
    """Return True if ``resp`` looks like the wildcard fallback response."""
    if not baseline:
        return False
    if resp.status_code != baseline["status"]:
        return False
    body = resp.content or b""
    # Fast pre-check: identical byte length is almost always required
    # for genuinely identical responses. Different-length responses can
    # never be byte-identical so we short-circuit before hashing.
    if len(body) != baseline["body_len"]:
        return False
    return sha256(body).hexdigest() == baseline["body_sha256"]


def _note_wildcard(ctx, base_url: str, baseline: dict | None) -> None:
    """Record a RECON_META finding describing the baseline for this service."""
    if not baseline:
        return
    # Only interesting if the wildcard returned something client-success-ish;
    # a real 404 is the expected case and doesn't need a finding.
    if baseline["status"] >= 400:
        return
    ctx.stores.findings.add({
        "type": "WILDCARD_ROUTING",
        "severity": "info",
        "asset": base_url,
        "evidence": {
            "baseline_status": baseline["status"],
            "baseline_body_len": baseline["body_len"],
            "content_type": baseline["content_type"],
            "note": "Service returns a non-4xx response for unregistered paths; "
                    "path-discovery probes that match this fingerprint were "
                    "filtered as false positives.",
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# --------------------------------------------------------------------
# robots.txt
# --------------------------------------------------------------------

def _fetch_robots(ctx, base_url: str) -> int:
    """Fetch and parse robots.txt."""
    import httpx as httpx_lib

    count = 0
    try:
        ctx.rate_limiter.acquire()
        resp = httpx_lib.get(
            f"{base_url}/robots.txt", timeout=10, follow_redirects=True, verify=False
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if ":" in line:
                    directive, path = line.split(":", 1)
                    directive = directive.strip().lower()
                    path = path.strip()
                    if directive in ("disallow", "allow", "sitemap") and path:
                        if path.startswith("http"):
                            url = path
                        else:
                            url = f"{base_url.rstrip('/')}{path}"

                        if ctx.scope.url_in_scope(url):
                            if ctx.stores.urls.add({
                                "url": url,
                                "service": base_url,
                                "status": None,
                                "content_type": None,
                                "source": ["robots"],
                                "depth": 0,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }):
                                count += 1
    except Exception:
        pass

    if count:
        console.print(f"  [dim]  robots.txt: {count} new URLs[/dim]")
    return count


# --------------------------------------------------------------------
# Well-known paths
# --------------------------------------------------------------------

def _fetch_wellknown(ctx, base_url: str, baseline: dict | None) -> int:
    """Check well-known URLs, filtering wildcard-200 responses."""
    import httpx as httpx_lib

    wellknown_paths = [
        "/.well-known/security.txt",
        "/.well-known/openid-configuration",
        "/.well-known/assetlinks.json",
        "/.well-known/apple-app-site-association",
        "/.well-known/change-password",
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/.well-known/jwks.json",
    ]

    wk_path = Path(ctx.config.get("wordlists.wellknown", "configs/wordlists/wellknown.txt"))
    if wk_path.exists():
        with open(wk_path, "r") as f:
            wellknown_paths = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    count = 0
    filtered = 0
    for path in wellknown_paths:
        url = f"{base_url.rstrip('/')}{path}"
        ctx.rate_limiter.acquire()
        try:
            # GET instead of HEAD so we can compare bodies against the baseline.
            resp = httpx_lib.get(url, timeout=10, follow_redirects=False, verify=False)
            if resp.status_code >= 400:
                continue
            if _response_matches_baseline(resp, baseline):
                filtered += 1
                continue
            if ctx.scope.url_in_scope(url) and ctx.stores.urls.add({
                "url": url,
                "service": base_url,
                "status": resp.status_code,
                "content_type": resp.headers.get("content-type", ""),
                "source": ["wellknown"],
                "depth": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }):
                count += 1
        except Exception:
            continue

    if count:
        console.print(f"  [dim]  well-known: {count} new URLs[/dim]")
    if filtered:
        console.print(
            f"  [dim]  well-known: {filtered} paths matched wildcard baseline (filtered)[/dim]"
        )
    return count


# --------------------------------------------------------------------
# Crawl (katana preferred, regex fallback)
# --------------------------------------------------------------------

def _crawl(ctx, base_url: str) -> int:
    """Depth-limited same-origin crawl. Prefers katana when installed."""
    try:
        from reconx.adapters import katana
        if katana.is_available(ctx):
            count = katana.crawl(ctx, base_url)
            if count:
                console.print(f"  [dim]  crawl (katana): {count} new URLs[/dim]")
            return count
    except Exception as e:
        console.print(f"  [yellow]katana adapter failed: {e}; falling back to built-in crawler[/yellow]")

    import httpx as httpx_lib
    from urllib.parse import urljoin, urlparse

    max_depth = ctx.config.get("crawl.max_depth", 3)
    max_urls = ctx.config.get("crawl.max_urls_per_host", 500)

    queue = [(base_url, 0)]
    visited = set()
    count = 0

    while queue and count < max_urls:
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        ctx.rate_limiter.acquire()
        try:
            resp = httpx_lib.get(url, timeout=15, follow_redirects=True, verify=False)
            content_type = resp.headers.get("content-type", "")

            if ctx.scope.url_in_scope(url) and ctx.stores.urls.add({
                "url": url,
                "service": base_url,
                "status": resp.status_code,
                "content_type": content_type,
                "source": ["crawl"],
                "depth": depth,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }):
                count += 1

            if "text/html" in content_type:
                links = re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']+)', resp.text)
                base_parsed = urlparse(base_url)

                for link in links:
                    abs_url = urljoin(url, link)
                    link_parsed = urlparse(abs_url)

                    if ctx.config.get("crawl.same_origin_only", True):
                        if link_parsed.hostname != base_parsed.hostname:
                            continue

                    if abs_url not in visited:
                        queue.append((abs_url, depth + 1))

        except Exception:
            continue

    if count:
        console.print(f"  [dim]  crawl: {count} new URLs[/dim]")
    return count


# --------------------------------------------------------------------
# Creepy paths (high-signal wordlist + optional AI expansion)
# --------------------------------------------------------------------

def _creepy_paths(ctx, base_url: str, baseline: dict | None) -> int:
    """Check hidden/interesting paths, filtering wildcard-200 responses."""
    import httpx as httpx_lib

    creepy = [
        "/.git/HEAD", "/.env", "/.DS_Store", "/backup", "/admin",
        "/.svn/entries", "/wp-admin", "/wp-login.php", "/phpinfo.php",
        "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
        "/web.config", "/elmah.axd", "/trace.axd", "/api/swagger",
        "/swagger-ui.html", "/api-docs", "/.aws/credentials",
        "/debug", "/console", "/actuator", "/actuator/health",
        "/graphql", "/.well-known/openapi.json",
    ]

    cp_path = Path(ctx.config.get("wordlists.creepy_paths", "configs/wordlists/creepy_paths.txt"))
    if cp_path.exists():
        with open(cp_path, "r") as f:
            creepy = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if ctx.ai_engine and ctx.ai_engine.enabled:
        ai_analysis = ctx.stores.ai_analysis.read_all()
        tech_stack = []
        for a in ai_analysis:
            analysis = a.get("analysis", {})
            tech_stack.extend(analysis.get("identified_technologies", []))

        if tech_stack:
            existing = [p for p in creepy]
            ai_paths = ctx.ai_engine.generate_wordlist(tech_stack, existing)
            creepy.extend(ai_paths)

    count = 0
    filtered = 0
    for path in creepy:
        url = f"{base_url.rstrip('/')}{path}"
        ctx.rate_limiter.acquire()
        try:
            resp = httpx_lib.get(url, timeout=10, follow_redirects=False, verify=False)
            if resp.status_code >= 400:
                continue
            if _response_matches_baseline(resp, baseline):
                filtered += 1
                continue
            if ctx.scope.url_in_scope(url) and ctx.stores.urls.add({
                "url": url,
                "service": base_url,
                "status": resp.status_code,
                "content_type": resp.headers.get("content-type", ""),
                "source": ["creepy"],
                "depth": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }):
                count += 1
                console.print(f"  [yellow]⚡ Found: {path} ({resp.status_code})[/yellow]")
        except Exception:
            continue

    if count:
        console.print(f"  [dim]  creepy paths: {count} new URLs[/dim]")
    if filtered:
        console.print(
            f"  [dim]  creepy paths: {filtered} paths matched wildcard baseline (filtered)[/dim]"
        )
    return count
