from reconx.core.dedupe import DedupeStore


def test_add_returns_true_on_first_then_false():
    d = DedupeStore()
    assert d.add("x.example.com") is True
    assert d.add("x.example.com") is False
    assert d.add("X.Example.COM ") is False  # normalized
    assert d.count == 1


def test_add_many_returns_only_new():
    d = DedupeStore()
    assert d.add_many(["a", "b", "a", "c", "b"]) == ["a", "b", "c"]
