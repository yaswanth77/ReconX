"""
Regression tests for the AI path sanitization/prompt-building contract.

Guards the bug where analyze_target ran dict arguments through the scalar
sanitizer (flattening them to a string), which then crashed the prompt
builder's dict indexing (headers.get(...), tech_stack.get('tech')). Also
verifies control-character stripping still happens on nested target data.
"""
import json

from reconx.ai.engine import AIEngine, _sanitize_struct, _sanitize_for_prompt


class _FakeProvider:
    """Captures the last prompt and returns a canned JSON completion."""
    def __init__(self, response: str):
        self.response = response
        self.last_system = None
        self.last_user = None

    def complete(self, prompt, system_prompt="", temperature=0.3,
                 max_tokens=2000, json_mode=False):
        self.last_system = system_prompt
        self.last_user = prompt
        return self.response

    def is_available(self):
        return True


def _engine_with(provider):
    eng = AIEngine(enabled=False)   # skip real provider construction
    eng.enabled = True
    eng.provider = provider
    return eng


def test_sanitize_struct_preserves_shape():
    data = {"tech": ["nginx", "gun\x00icorn"], "n": 3, "ok": True, "x": None}
    out = _sanitize_struct(data)
    assert isinstance(out, dict)
    assert isinstance(out["tech"], list)
    assert out["tech"] == ["nginx", "gunicorn"]   # control char stripped
    assert out["n"] == 3 and out["ok"] is True and out["x"] is None


def test_sanitize_scalar_flattens():
    assert _sanitize_for_prompt({"a": 1}) == json.dumps({"a": 1})
    assert _sanitize_for_prompt("hi\x07there") == "hithere"
    assert _sanitize_for_prompt(None) == ""


def test_analyze_target_does_not_crash_with_dict_contract():
    # Exactly what the fingerprint stage passes.
    fake = _FakeProvider(json.dumps({
        "identified_technologies": ["nginx"],
        "recommended_nuclei_tags": ["misconfig"],
        "risk_level": "low",
    }))
    eng = _engine_with(fake)
    tech_dict = {"tech": ["nginx", "gunicorn", "HTTP/3"]}
    headers = {"server": "nginx", "x-powered-by": "gunicorn"}
    result = eng.analyze_target(tech_dict, headers, "Exoscale Console")
    assert isinstance(result, dict)
    assert result["risk_level"] == "low"
    # The prompt must contain the real server value, proving the dict survived.
    assert "nginx" in fake.last_user
    assert "Exoscale Console" in fake.last_user


def test_control_chars_stripped_from_nested_header_value():
    fake = _FakeProvider(json.dumps({"risk_level": "low"}))
    eng = _engine_with(fake)
    # A target trying to smuggle an instruction override via a header value.
    headers = {"server": "eng\x00ine\x1bINJECT"}
    eng.analyze_target({"tech": ["x"]}, headers, "t")
    assert "\x00" not in fake.last_user
    assert "\x1b" not in fake.last_user
    assert "engineINJECT" in fake.last_user   # chars removed, text preserved


def test_other_helpers_accept_structured_input():
    fake = _FakeProvider(json.dumps({
        "scored_params": [], "paths": [], "candidates": [],
        "triaged": [], "selected_tags": [],
    }))
    eng = _engine_with(fake)
    # None of these should raise.
    eng.score_params([{"endpoint": "/a", "params": ["id"], "method": "GET"}])
    eng.generate_wordlist(["nginx"], ["/"])
    eng.generate_subdomains("exoscale.com", ["api.exoscale.com"])
    eng.triage_findings([{"type": "X", "url": "/", "evidence": {}}])
    eng.select_nuclei_templates(["nginx"], [{"service": "https://x/"}])
