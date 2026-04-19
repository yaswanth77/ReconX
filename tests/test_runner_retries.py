from reconx.core.runner import ToolRunner


def test_run_with_missing_tool_returns_failed_result():
    r = ToolRunner()
    # A tool that almost certainly isn't on PATH; should not raise.
    result = r.run("definitely-not-a-real-tool-xyzzy", ["--help"], attempts=1, timeout=5)
    assert result.success is False
    assert result.return_code == -1


def test_retries_alias_accepted():
    r = ToolRunner()
    # Backwards-compat shim: passing ``retries`` keeps working for one release.
    result = r.run("definitely-not-a-real-tool-xyzzy", ["--help"], retries=1, timeout=5)
    assert result.success is False
