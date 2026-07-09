"""
Shared HTTP helpers so every request the tool makes itself honors the configured
User-Agent, custom headers, and proxy. Rules-of-engagement often mandate an exact
identifying User-Agent or header and require traffic to go through an intercept
proxy, so target-facing requests must not bypass those settings.

Third-party OSINT calls (crt.sh, the AI provider) are NOT target traffic and do
not use this helper on purpose: they should not carry the program's identifying
header nor be forced through the target proxy.
"""

import httpx


def build_headers(config) -> dict:
    """Header dict from config: the User-Agent plus any `http.headers` entries.

    Custom headers are stored as "Name: Value" strings (repeatable CLI flag).
    """
    headers: dict[str, str] = {}
    if config is None:
        return headers
    ua = config.get("http.user_agent")
    if ua:
        headers["User-Agent"] = ua
    for item in config.get("http.headers", []) or []:
        if isinstance(item, str) and ":" in item:
            name, value = item.split(":", 1)
            if name.strip():
                headers[name.strip()] = value.strip()
    return headers


def client(config, **kwargs) -> httpx.Client:
    """An httpx.Client pre-loaded with the configured UA, headers, proxy, verify."""
    proxy = config.get("http.proxy") if config else None
    verify = not (config.get("http.insecure") if config else False)
    merged = build_headers(config)
    merged.update(kwargs.pop("headers", {}) or {})
    client_kwargs = {"headers": merged, "verify": verify}
    if proxy:
        client_kwargs["proxy"] = proxy  # httpx >= 0.26 single-proxy form
    client_kwargs.update(kwargs)
    return httpx.Client(**client_kwargs)


def get(config, url, **kwargs):
    """One-shot GET that honors UA, headers, proxy, and verify from config."""
    follow = kwargs.pop("follow_redirects", True)
    timeout = kwargs.pop("timeout", 30)
    with client(config, follow_redirects=follow, timeout=timeout) as c:
        return c.get(url, **kwargs)
