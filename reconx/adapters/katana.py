"""
Katana adapter — ProjectDiscovery's crawler.

Preferred over the built-in regex crawler whenever katana is on PATH.
Key wins vs. the regex fallback:
  * parses script bodies for URL literals (``-jc``), which is the only
    way to see the routes of an Angular/React/Vue SPA whose nav is
    driven by ``fetch('/rest/…')`` and ``router.navigate(['/admin'])``;
  * follows ``<form>``, ``<a>``, ``<link>``, sitemap, robots, and
    known-file endpoints (``-kf all``);
  * JSON Lines output so we can capture per-URL status and
    source/tag metadata instead of a flat URL list.

When chromium-based headless crawling (``-hl`` / ``-headless``) is
desired the user can opt in via ``crawl.headless: true``; we don't
default to it because it pulls a 150 MB Playwright dependency.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from rich.console import Console

console = Console()


def is_available(ctx) -> bool:
    return ctx.runner.is_available("katana")


def crawl(ctx, base_url: str) -> int:
    """
    Crawl ``base_url`` with katana and write new in-scope URLs to
    ctx.stores.urls. Returns the count of genuinely new URLs.
    """
    max_depth = ctx.config.get("crawl.max_depth", 3)
    max_urls = ctx.config.get("crawl.max_urls_per_host", 500)
    timeout = ctx.config.get("network.timeout", 30)
    concurrency = ctx.config.get("network.concurrency", 20)
    same_origin = ctx.config.get("crawl.same_origin_only", True)
    headless = ctx.config.get("crawl.headless", False)

    args = [
        "-u", base_url,
        "-d", str(max_depth),
        "-c", str(concurrency),
        "-jc",          # parse inline + external JS for endpoints (the SPA win)
        "-kf", "all",   # pull URLs from robots, sitemap, .js sourcemaps, etc.
        "-jsonl",       # one JSON object per line → carries path+source+status
        "-silent",
        "-timeout", str(timeout),
    ]
    if same_origin:
        args.extend(["-fs", "fqdn"])
    if headless:
        args.append("-hl")

    proxy = ctx.config.get("http.proxy")
    if proxy:
        args.extend(["-proxy", proxy])

    # For TLS verification we leave katana's default on unless the user
    # explicitly asks for insecure mode via `-insecure`.
    if ctx.config.get("http.insecure", False):
        args.append("-insecure")

    result = ctx.runner.run(
        "katana",
        args,
        timeout=max(timeout * 10, 120),
        attempts=1,
    )
    if not result.success:
        return 0

    count = 0
    ts = datetime.now(timezone.utc).isoformat()
    for line in result.lines[:max_urls]:
        line = line.strip()
        if not line:
            continue

        # Prefer JSON Lines (present when -jsonl is honored). Fall back
        # to plain-URL lines for older katana builds.
        url: str | None = None
        status: int | None = None
        source_tag = "katana"
        try:
            data = json.loads(line)
            req = data.get("request") or {}
            resp = data.get("response") or {}
            url = req.get("endpoint") or data.get("endpoint") or data.get("url")
            status = resp.get("status_code") or data.get("status_code")
            # katana tags each URL with where it came from (``script``,
            # ``body``, ``header``, ``form`` …). Carry that forward so
            # downstream stages can prefer endpoints discovered in JS.
            tag = data.get("source") or resp.get("source")
            if tag:
                source_tag = f"katana:{tag}"
        except json.JSONDecodeError:
            url = line

        if not url or not ctx.scope.url_in_scope(url):
            continue
        if ctx.stores.urls.add({
            "url": url,
            "service": base_url,
            "status": status,
            "content_type": None,
            "source": [source_tag],
            "depth": None,
            "timestamp": ts,
        }):
            count += 1
    return count
