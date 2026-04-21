"""
Unit tests for the wildcard-baseline filter used in stages/urls.py.

The baseline helpers compare a probe response to a captured fingerprint.
We drive them with minimal fake response objects so no HTTP layer is
involved.
"""

from hashlib import sha256
from types import SimpleNamespace

from reconx.stages.urls import _response_matches_baseline


def _fake_resp(status: int, body: bytes):
    return SimpleNamespace(status_code=status, content=body, headers={})


def _fingerprint(status: int, body: bytes, content_type: str = "text/html"):
    return {
        "status": status,
        "body_sha256": sha256(body).hexdigest(),
        "body_len": len(body),
        "content_type": content_type,
    }


def test_no_baseline_never_filters():
    # When the baseline probe itself failed we keep every real response.
    assert _response_matches_baseline(_fake_resp(200, b"anything"), None) is False


def test_identical_response_is_filtered():
    body = b"<html>...SPA catch-all index...</html>"
    baseline = _fingerprint(200, body)
    assert _response_matches_baseline(_fake_resp(200, body), baseline) is True


def test_same_status_but_different_body_is_kept():
    baseline = _fingerprint(200, b"<html>index</html>")
    real = _fake_resp(200, b"refs/heads/main\n")  # looks like /.git/HEAD
    assert _response_matches_baseline(real, baseline) is False


def test_same_body_but_different_status_is_kept():
    body = b"forbidden"
    baseline = _fingerprint(403, body)
    # A 401 with the same body body is still worth keeping (different class).
    assert _response_matches_baseline(_fake_resp(401, body), baseline) is False


def test_real_404_baseline_never_filters_successes():
    # Classic well-behaved app: baseline is 404; real finding is 200 with
    # distinct body. The filter must be a no-op here.
    baseline = _fingerprint(404, b"Not Found")
    real = _fake_resp(200, b"<html>admin panel</html>")
    assert _response_matches_baseline(real, baseline) is False
