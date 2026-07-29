from angerona.engines import self_compiler


def test_generated_python_cannot_hot_reload_even_when_authorized(tmp_path):
    candidate = tmp_path / "candidate.py"
    candidate.write_text("VALUE = 42\n", encoding="utf-8")
    ok, message = self_compiler.hot_reload_capability(
        "candidate", candidate, authorized=True,
    )
    assert not ok
    assert "never executed or hot-reloaded" in message


def test_generated_python_deny_scan_still_reports_danger(tmp_path):
    candidate = tmp_path / "candidate.py"
    candidate.write_text("import os\nos.system('whoami')\n", encoding="utf-8")
    ok, message = self_compiler.hot_reload_capability(
        "candidate", candidate, authorized=True,
    )
    assert not ok
    assert "disallowed constructs" in message
