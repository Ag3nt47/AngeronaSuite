"""A retired Session refresh authenticates retained bytes without rescoring."""
from angerona.core import report_attest
from angerona.gui.pages import _read_aar_review
from angerona.shark import aar_report


def _publish(tmp_path, monkeypatch, run_id="shark-session-saved"):
    key = tmp_path / "report.key"
    key.write_text(bytes(range(32)).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key)
    return aar_report._write_report(tmp_path,
        {"kind": "shark", "run_id": run_id, "status": "completed", "steps": []},
        [], "SHARK ATTACK — retained signed report\n", basename="shark_aar")


def _refresh(tmp_path, report):
    binding = {"run_id": report.run_id, "sha256": report.report_sha256,
        "head_sha256": report.head_sha256, "sequence": report.sequence,
        "session_owned": True, "handoff_verified": True, "error": ""}
    return _read_aar_review(tmp_path, False, binding,
        (report.run_id, report.report_sha256, report.head_sha256, report.sequence),
        (None, None, None))


def _forbid_generation(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("A retired Session must never regenerate or rescore its AAR")
    monkeypatch.setattr(aar_report, "generate_aar", forbidden)


def test_session_shark_refresh_loads_exact_real_signed_writer_bundle(tmp_path, monkeypatch):
    report = _publish(tmp_path, monkeypatch)
    _forbid_generation(monkeypatch)
    text, binding, expected, saved_verified = _refresh(tmp_path, report)
    assert text == report.text and saved_verified is True and not binding["error"]
    assert expected == (report.run_id, report.report_sha256, report.head_sha256, report.sequence)


def test_changed_saved_shark_text_is_held_without_new_report(tmp_path, monkeypatch):
    report = _publish(tmp_path, monkeypatch)
    (tmp_path / "shark_aar.txt").write_text("Changed untrusted text", encoding="utf-8")
    _forbid_generation(monkeypatch)
    text, binding, _, saved_verified = _refresh(tmp_path, report)
    assert saved_verified is False and binding["error"]
    assert text.startswith("Could not load authenticated report:")


def test_new_authentic_generation_cannot_replace_open_session_review(tmp_path, monkeypatch):
    report = _publish(tmp_path, monkeypatch)
    _publish(tmp_path, monkeypatch, run_id="shark-newer-run")
    _forbid_generation(monkeypatch)
    text, binding, expected, saved_verified = _refresh(tmp_path, report)
    assert saved_verified is False and binding["error"]
    assert expected[0] == report.run_id and "Could not load authenticated" in text
