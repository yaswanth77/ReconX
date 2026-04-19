"""
Katana adapter — ProjectDiscovery's crawler.

Preferred over the built-in regex crawler whenever katana is on PATH:
handles JS rendering (when chromium available), respects robots, parses
<a>, <form>, JSON, sitemap, etc., and emits one URL per line.
"""

from __future__ import annotations

from datetime import datetime, timezone
from rich.console import Console

console = Console()


def is_available(ctx) -> bool:
    return ctx.runner.is_available("katana")


def crawl(ctx, base_url: str) -> int:
    """
    Crawl ``base_url`` with katana and write new in-scope URLs to ctx.stores.urls.
    Returns the count of genuinely new URLs.
    """
    max_depth = ctx.config.get("crawl.max_depth", 3)
    max_urls = ctx.config.get("crawl.max_urls_per_host", 500)
    timeout = ctx.config.get("network.timeout", 30)
    concurrency = ctx.config.get("network.concurrency", 20)
    same_origin = ctx.config.get("crawl.same_origin_only", True)

    args = [
        "-u", base_url,
        "-d", str(max_depth),
        "-c", str(concurrency),
        "-silent",
        "-timeout", str(timeout),
    ]
    if same_origin:
        args.extend(["-fs", "fqdn"])

    proxy = ctx.config.get("http.proxy")
    if proxy:
        args.extend(["-proxy", proxy])

    insecure = ctx.config.get("http.insecure", False)
    if insecure:
        # katana uses -iqp / -retry flags; `-disable-redirects` is not what we want.
        args.append("-no-sandbox")

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
        url = line.strip()
        if not url or not ctx.scope.url_in_scope(url):
            continue
        if ctx.stores.urls.add({
            "url": url,
            "service": base_url,
            "status": None,
            "content_type": None,
            "source": ["katana"],
            "depth": None,
            "timestamp": ts,
        }):
            count += 1
    return count
