import textwrap

from reconx.core.scope import Scope


def _scope(tmp_path, body: str) -> Scope:
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent(body))
    return Scope(p)


def test_host_in_scope_root_and_subdomain(tmp_path):
    s = _scope(tmp_path, """
        in_scope:
          roots:
            - example.com
          include_subdomains: true
        out_of_scope: {}
    """)
    assert s.host_in_scope("example.com")
    assert s.host_in_scope("api.example.com")
    assert not s.host_in_scope("example.org")


def test_plain_exclusion_is_subdomain_aware(tmp_path):
    # A plain host_pattern must exclude the host AND its subdomains.
    s = _scope(tmp_path, """
        in_scope:
          roots:
            - example.com
          include_subdomains: true
        out_of_scope:
          host_patterns:
            - academy.example.com
    """)
    assert not s.host_in_scope("academy.example.com")
    assert not s.host_in_scope("studio.academy.example.com")   # regression: used to leak
    assert s.host_in_scope("api.example.com")                  # unrelated sub still in scope


def test_glob_exclusion_behavior_preserved(tmp_path):
    # Existing glob patterns must keep matching exactly as before.
    s = _scope(tmp_path, """
        in_scope:
          roots:
            - example.com
          include_subdomains: true
        out_of_scope:
          host_patterns:
            - "*.internal.example.com"
            - "dev-*"
    """)
    assert not s.host_in_scope("db.internal.example.com")
    assert not s.host_in_scope("dev-api.example.com")
    assert s.host_in_scope("prod-api.example.com")
    # A glob is not over-eager: internal.example.com itself is not matched by *.internal.example.com
    assert s.host_in_scope("internal.example.com")


def test_url_in_scope_enforces_port_and_extension(tmp_path):
    s = _scope(tmp_path, """
        in_scope:
          roots:
            - example.com
          include_subdomains: true
          allowed_ports: [443]
        out_of_scope:
          extensions: [".png"]
    """)
    assert s.url_in_scope("https://api.example.com/a")
    assert not s.url_in_scope("https://api.example.com:8443/a")
    assert not s.url_in_scope("https://api.example.com/logo.png")
