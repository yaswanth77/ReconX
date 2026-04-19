from reconx.core.normalize import (
    normalize_host,
    normalize_url,
    normalize_service,
    extract_domain,
    url_key,
)


def test_normalize_host_strips_and_lowercases():
    assert normalize_host("  SUB.Example.COM.  ") == "sub.example.com"


def test_normalize_url_canonicalizes():
    assert normalize_url("HTTPS://Example.COM:443/a//b/?z=1&a=2") == \
        "https://example.com/a/b?a=2&z=1"


def test_normalize_service_drops_default_ports():
    assert normalize_service("https://api.example.com:443") == "https://api.example.com"
    assert normalize_service("http://api.example.com:8080") == "http://api.example.com:8080"


def test_extract_domain_multi_level_tld():
    # The canonical regression case that motivated the fix.
    assert extract_domain("api.example.co.uk") == "example.co.uk"
    assert extract_domain("x.y.example.com.br") == "example.com.br"
    assert extract_domain("api.example.com") == "example.com"


def test_extract_domain_passes_through_ips():
    assert extract_domain("10.0.0.1") == "10.0.0.1"
    assert extract_domain("::1") == "::1"


def test_url_key_strips_query_values():
    a = url_key("https://ex.com/a?id=1&x=2")
    b = url_key("https://ex.com/a?id=999&x=7")
    assert a == b
