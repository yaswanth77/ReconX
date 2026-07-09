from types import SimpleNamespace

from reconx.stages.subdomains import roots_from_ctx, belongs_to_roots


def _ctx(target, scope_roots):
    return SimpleNamespace(target=target, scope=SimpleNamespace(roots=scope_roots))


def test_roots_from_ctx_unions_target_and_scope_roots():
    ctx = _ctx("exoscale.com", ["exoscale.com", "exo.io", "internal.exoscale.ch"])
    # every in-scope root is enumerated, deduped, --target first
    assert roots_from_ctx(ctx) == ["exoscale.com", "exo.io", "internal.exoscale.ch"]


def test_roots_from_ctx_single_root_is_unchanged():
    ctx = _ctx("example.com", ["example.com"])
    assert roots_from_ctx(ctx) == ["example.com"]


def test_roots_from_ctx_handles_missing_scope_roots():
    ctx = SimpleNamespace(target="example.com", scope=SimpleNamespace())
    assert roots_from_ctx(ctx) == ["example.com"]


def test_belongs_to_roots_accepts_subs_of_any_root():
    roots = ["exoscale.com", "exo.io", "internal.exoscale.ch"]
    assert belongs_to_roots("portal.exoscale.com", roots)
    assert belongs_to_roots("sos-de-fra-1.exo.io", roots)          # was dropped before the fix
    assert belongs_to_roots("grafana.internal.exoscale.ch", roots)  # was dropped before the fix
    assert belongs_to_roots("exo.io", roots)                        # a root itself


def test_belongs_to_roots_rejects_lookalikes_and_wildcards():
    roots = ["example.com"]
    assert not belongs_to_roots("notexample.com", roots)   # dot-anchored, no false suffix match
    assert not belongs_to_roots("example.org", roots)
    assert not belongs_to_roots("*.example.com", roots)    # wildcard entries are skipped
    assert not belongs_to_roots("", roots)
