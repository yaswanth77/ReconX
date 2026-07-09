from reconx.core.runner import ToolRunner
from reconx.core import http as rx_http


class FakeConfig:
    def __init__(self, values):
        self.values = values

    def get(self, key, default=None):
        return self.values.get(key, default)


def _runner(values):
    r = ToolRunner.__new__(ToolRunner)
    r.config = FakeConfig(values)
    return r


def test_build_headers_includes_ua_and_custom():
    cfg = FakeConfig({
        "http.user_agent": "Intigriti-yaswanthrs007",
        "http.headers": ["X-Bug-Bounty: yaswanthrs007", "no-colon-ignored"],
    })
    h = rx_http.build_headers(cfg)
    assert h["User-Agent"] == "Intigriti-yaswanthrs007"
    assert h["X-Bug-Bounty"] == "yaswanthrs007"
    assert "no-colon-ignored" not in h


def test_http_flags_injected_for_http_tools():
    r = _runner({
        "http.user_agent": "MyUA",
        "http.headers": ["X-Bug-Bounty: h4x"],
        "http.proxy": "http://127.0.0.1:8080",
    })
    hx = r._http_flags("httpx", ["-l", "hosts.txt"])
    assert "-H" in hx and "User-Agent: MyUA" in hx
    assert "X-Bug-Bounty: h4x" in hx
    assert "-http-proxy" in hx and "http://127.0.0.1:8080" in hx
    # nuclei uses -proxy, not -http-proxy
    nu = r._http_flags("nuclei", [])
    assert "-proxy" in nu and "-http-proxy" not in nu


def test_http_flags_skips_non_http_tools_and_avoids_double_proxy():
    r = _runner({"http.user_agent": "UA", "http.proxy": "http://127.0.0.1:8080"})
    # subfinder is passive / API based, not an HTTP-target tool: no injection
    assert r._http_flags("subfinder", ["-d", "example.com"]) == []
    # katana already carries -proxy from its adapter: do not add a second one
    kat = r._http_flags("katana", ["-proxy", "http://127.0.0.1:8080"])
    assert kat.count("-proxy") == 0


def test_http_flags_arjun_uses_headers_and_oB():
    # arjun takes one --headers (newline-joined) and -oB for a proxy, not -H.
    r = _runner({
        "http.user_agent": "MyUA",
        "http.headers": ["X-Bug-Bounty: h4x"],
        "http.proxy": "http://127.0.0.1:8080",
    })
    aj = r._http_flags("arjun", ["-u", "http://t/"])
    assert "--headers" in aj
    combined = aj[aj.index("--headers") + 1]
    assert "User-Agent: MyUA" in combined and "X-Bug-Bounty: h4x" in combined
    assert "-H" not in aj                       # arjun does not use -H
    assert "-oB" in aj and "http://127.0.0.1:8080" in aj


def test_http_flags_noop_without_config():
    r = ToolRunner.__new__(ToolRunner)
    r.config = None
    assert r._http_flags("httpx", []) == []
