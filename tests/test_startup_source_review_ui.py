"""Independent post-ready source review returns choices without source writes."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "angerona_recovery.py"
SPEC = importlib.util.spec_from_file_location("source_review_under_test", SCRIPT)
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)


@pytest.fixture
def source_report(tmp_path):
    path = tmp_path / "report.json"
    document = dict(schema=1, report_id="a" * 32, outcome="ready-confirmed", strategy="last-ready",
                    message="The source recovery helper selected a preserved working candidate.",
                    startup_error="Original startup returned 82: expected=reviewed, actual=different.",
                    changed_files=["src/angerona/app.py", "src/angerona/gui/main_window.py"], changed_file_count=2,
                    actions=["Preserved original source edits privately.", "Restored selected source bytes."],
                    pending_decision="pending", protection_status="active")
    path.write_text(json.dumps(document), encoding="utf-8")
    return path, document


def test_source_review_distinguishes_reported_error_actions_and_suspected_files(source_report):
    path, document = source_report
    model = review.load_source_model(path, expected_report_id=document["report_id"])
    text = review.display_text(model)
    assert model["source_decision_allowed"] and model["report_valid"]
    assert model["protection_status"] == "unknown"
    assert "Original startup returned 82" in text and "Preserved original source edits" in text
    assert "src/angerona/app.py" in text
    assert "does not prove which change" in text and "NEXT startup" in text
    assert "resolved backup to rotate" in text and "never deleted automatically" in text
    assert "Protection is not verified" in text
    assert model["log_path"] == str(path)


def test_report_can_be_reviewed_when_error_log_root_is_a_different_owned_directory(source_report, tmp_path):
    path, _ = source_report
    other = tmp_path / "other-logs"
    other.mkdir()
    model = review.load_source_model(path, log_root=other)
    assert model["source_decision_allowed"] and model["log_path"] == str(path)


@pytest.mark.parametrize("change", ["../outside.py", "src/angerona/../outside.py", "C:/source.py",
                                  "src\\angerona\\app.py", "tools/run.py", "src/angerona/odd\n.py",
                                  "src/angerona/odd\u202e.py"])
def test_source_paths_are_literal_bounded_package_paths(source_report, change):
    path, document = source_report
    document["changed_files"] = [change]
    path.write_text(json.dumps(document))
    model = review.load_source_model(path)
    assert not model["source_decision_allowed"] and not model["report_valid"]


@pytest.mark.parametrize("expected", ["b" * 32, "not-an-id", "A" * 32])
def test_stale_or_invalid_expected_report_cannot_return_a_decision(source_report, expected):
    path, _ = source_report
    arguments = ["--review-source", "--status-file", str(path), "--expected-report-id", expected]
    assert review.main(arguments, show=lambda _model: 21) == review.UI_UNAVAILABLE
    assert review.main(arguments, show=lambda _model: 20) == review.UI_UNAVAILABLE
    assert review.main(arguments, show=lambda _model: 0) == 0


def test_source_list_display_is_capped_with_explicit_omissions(source_report):
    path, document = source_report
    document["changed_files"] = [f"src/angerona/part_{index}.py" for index in range(70)]
    document["changed_file_count"] = 75
    path.write_text(json.dumps(document))
    model = review.load_source_model(path)
    assert len(model["changed_files"]) == 32 and model["omitted_source_changes"] == 43
    assert "43 additional paths omitted" in review.display_text(model)


@pytest.mark.parametrize("choice", [20, 21, 0])
def test_review_decisions_are_only_return_codes_and_do_not_write_state(source_report, choice):
    path, document = source_report
    before = path.read_bytes()
    assert review.main(["--review-source", "--status-file", str(path), "--expected-report-id", document["report_id"]],
                       show=lambda _model: choice) == choice
    assert path.read_bytes() == before
    assert list(path.parent.iterdir()) == [path]


def test_retry_code_is_not_a_post_ready_source_decision(source_report):
    path, _ = source_report
    assert review.main(["--review-source", "--status-file", str(path)], show=lambda _model: 10) == review.UI_UNAVAILABLE


@pytest.mark.parametrize("button,expected", [("Keep working version", 20), ("Try preserved edits NEXT startup", 21), ("Review later", 0)])
def test_source_review_tk_buttons_return_only_parent_owned_choices(source_report, button, expected):
    path, document = source_report
    buttons = []
    class Widget:
        def __init__(self, *_args, **options):
            self.options = options
        def pack(self, **_kwargs): pass
        def title(self, *_args): pass
        def geometry(self, *_args): pass
        def insert(self, *_args): pass
        def configure(self, **_kwargs): pass
        def protocol(self, *_args): pass
        def destroy(self): pass
    class Window(Widget):
        def mainloop(self):
            selected = next(value for value in buttons if value.options["text"] == button)
            assert selected.options.get("state", "normal") == "normal"
            selected.options["command"]()
    class Button(Widget):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            buttons.append(self)
    fake = SimpleNamespace(Tk=Window, Label=Widget, Text=Widget, Frame=Widget, Button=Button)
    model = review.load_source_model(path, expected_report_id=document["report_id"])
    assert review.show_window(model, tk_module=fake) == expected
    assert not any(value.options["text"] == "Retry safe recovery" for value in buttons)


def test_headless_source_review_does_not_import_broken_application_or_execute_text(source_report, tmp_path):
    path, document = source_report
    marker = tmp_path / "must-not-execute"
    document["startup_error"] = f"__import__('pathlib').Path({str(marker)!r}).touch()"
    path.write_text(json.dumps(document))
    broken = tmp_path / "angerona"
    broken.mkdir()
    (broken / "__init__.py").write_text("def syntax_broken(\n")
    environment = dict(os.environ, PYTHONPATH=str(tmp_path))
    result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--review-source", "--headless",
                             "--status-file", str(path), "--expected-report-id", document["report_id"]],
                            cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    model = json.loads(result.stdout)
    assert model["source_decision_allowed"] and not marker.exists()
