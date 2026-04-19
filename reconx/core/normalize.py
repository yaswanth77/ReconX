"""
Normalization utilities for hosts, URLs, and services.

Every piece of data flows through these functions before storage,
ensuring a single canonical form and killing redundancy upstream.
"""

from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import re

try:
    import tldextract
    _TLDEXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except ImportError:
    _TLDEXTRACT = None


def normalize_host(host: str) -> str:
    """Canonical hostname: lowercase, strip trailing dot, strip whitespace."""
    host = host.strip().lower()
    if host.endswith("."):
        host = host[:-1]
    return host


def normalize_url(url: str) -> str:
    """
    Canonical URL form:
    - lowercase scheme + host
    - strip default ports (80 for http, 443 for https)
    - collapse double slashes in path
    - strip fragment
    - sort query parameters by key
    - strip trailing slash on path (unless path is just '/')
    """
    if not url:
        return ""

    # Ensure scheme (case-insensitive check)
    url_lower = url.lower()
    if not url_lower.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    host = normalize_host(parsed.hostname or "")

    # Port handling — strip defaults
    port = parsed.port
    if port == 80 and scheme == "http":
        port = None
    elif port == 443 and scheme == "https":
        port = None

    netloc = host
    if port:
        netloc = f"{host}:{port}"

    # Path: collapse double slashes, strip trailing slash (keep root /)
    path = re.sub(r"/+", "/", parsed.path or "/")
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    # Query: sort keys, drop empty values
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    sorted_query = urlencode(
        sorted(
            [(k, v[0] if v else "") for k, v in query_params.items()]
        )
    )

    return urlunparse((scheme, netloc, path, "", sorted_query, ""))


def normalize_service(url: str) -> str:
    """
    Canonical service key: scheme + host + port.
    Example: https://api.example.com:443 → https://api.example.com
    """
    if not url:
        return ""

    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = normalize_host(parsed.hostname or "")

    port = parsed.port
    if port == 80 and scheme == "http":
        port = None
    elif port == 443 and scheme == "https":
        port = None

    if port:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def extract_domain(host: str) -> str:
    """Return the registrable domain (eTLD+1) for a hostname; IPs pass through."""
    host = normalize_host(host)
    if not host:
        return ""
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if _TLDEXTRACT is not None:
        extracted = _TLDEXTRACT(host)
        registered = getattr(extracted, "top_domain_under_public_suffix", None) \
            or extracted.registered_domain
        if registered:
            return registered
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def url_key(url: str) -> str:
    """
    Stable key for URL dedup.
    scheme + host + port + path + sorted_query_keys (values ignored).
    """
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    key_only_query = "&".join(sorted(query_params.keys()))
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{key_only_query}" if key_only_query else f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
