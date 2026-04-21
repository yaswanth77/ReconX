"""
Unit tests for the param-stage helpers: private-target detection and
arjun endpoint pre-filter.
"""

from reconx.stages.params import (
    _target_is_private,
    _endpoint_is_param_likely,
)


# ---- _target_is_private --------------------------------------------

def test_loopback_is_private():
    assert _target_is_private("127.0.0.1") is True
    assert _target_is_private("::1") is True


def test_rfc1918_is_private():
    assert _target_is_private("10.0.0.5") is True
    assert _target_is_private("192.168.1.1") is True
    assert _target_is_private("172.20.1.1") is True


def test_reserved_tlds_are_private():
    assert _target_is_private("host.local") is True
    assert _target_is_private("foo.internal") is True
    assert _target_is_private("bar.test") is True
    assert _target_is_private("example.invalid") is True


def test_public_hostnames_are_not_private():
    assert _target_is_private("example.com") is False
    assert _target_is_private("api.example.co.uk") is False
    assert _target_is_private("scanme.nmap.org") is False


# ---- _endpoint_is_param_likely -------------------------------------

def test_url_with_query_is_always_likely():
    assert _endpoint_is_param_likely("https://ex.com/anything?id=1") is True


def test_param_keyword_paths_are_likely():
    assert _endpoint_is_param_likely("https://ex.com/search") is True
    assert _endpoint_is_param_likely("https://ex.com/api/v1/users") is True
    assert _endpoint_is_param_likely("https://ex.com/oauth/callback") is True


def test_static_assets_are_not_likely():
    assert _endpoint_is_param_likely("https://ex.com/app.js") is False
    assert _endpoint_is_param_likely("https://ex.com/logo.png") is False
    assert _endpoint_is_param_likely("https://ex.com/styles.css") is False


def test_well_known_metadata_is_skipped():
    assert _endpoint_is_param_likely(
        "https://ex.com/.well-known/openid-configuration"
    ) is False


def test_unknown_plain_paths_are_not_likely():
    # Avoids running arjun on arbitrary static HTML pages.
    assert _endpoint_is_param_likely("https://ex.com/about") is False
    assert _endpoint_is_param_likely("https://ex.com/terms") is False
