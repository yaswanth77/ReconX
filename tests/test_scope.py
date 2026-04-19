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
