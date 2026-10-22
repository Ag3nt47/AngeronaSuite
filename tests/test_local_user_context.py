from __future__ import annotations

import getpass
import os
import zipfile

import pytest

from angerona.core import ir_bundle
from angerona.core.local_user_context import LocalUsernameUnavailable, local_username_hint


def fail(exception):
    def lookup():
        raise exception
    return lookup


@pytest.mark.parametrize("error", [ImportError("missing pwd"), OSError("no username")])
def test_missing_getpass_uses_native_username_hint(monkeypatch, error):
    monkeypatch.setattr(getpass, "getuser", fail(error))
    monkeypatch.setattr(os, "getlogin", lambda: "native-fixture-user")
    assert local_username_hint() == "native-fixture-user"


def test_getpass_success_and_existing_mocks_remain_compatible(monkeypatch):
    monkeypatch.setattr(getpass, "getuser", lambda: "getpass-fixture-user")
    monkeypatch.setattr(os, "getlogin", fail(AssertionError("unneeded fallback")))
    assert local_username_hint() == "getpass-fixture-user"


@pytest.mark.parametrize("invalid", [None, True, "", " ", "x" * 257, "line\nbreak", "nul\0"])
def test_malformed_or_unbounded_hint_uses_native_fallback(monkeypatch, invalid):
    monkeypatch.setattr(getpass, "getuser", lambda: invalid)
    monkeypatch.setattr(os, "getlogin", lambda: "bounded-native-user")
    assert local_username_hint() == "bounded-native-user"


@pytest.mark.parametrize("native", [None, "", "x" * 257, "bad\nname"])
def test_both_unusable_lookups_raise_without_an_invented_identity(monkeypatch, native):
    monkeypatch.setattr(getpass, "getuser", fail(ImportError("missing pwd")))
    monkeypatch.setattr(os, "getlogin", lambda: native)
    with pytest.raises(LocalUsernameUnavailable, match="unavailable"):
        local_username_hint()


@pytest.mark.parametrize("error", [ImportError("missing pwd"), OSError("no username")])
def test_privacy_filter_redacts_native_fallback_username(monkeypatch, error):
    for name in ("LOGNAME", "USER", "LNAME", "USERNAME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(getpass, "getuser", fail(error))
    monkeypatch.setattr(os, "getlogin", lambda: "Native_Fixture_User")
    redactor = ir_bundle._PrivacyFilter()
    output = redactor.text("Owner Native_Fixture_User and NATIVE_FIXTURE_USER")
    assert "native_fixture_user" not in output.casefold()
    assert output.count("<user:") == 2


def test_single_character_username_is_still_a_required_redaction_seed(monkeypatch):
    monkeypatch.setattr(getpass, "getuser", lambda: "q")
    output = ir_bundle._PrivacyFilter().text("owner q")
    assert "q" not in output
    assert "<user:" in output


@pytest.mark.parametrize("native_error", [OSError("native unavailable"), ImportError("absent")])
def test_ir_export_refuses_before_collection_or_output_when_user_seed_is_unavailable(
    tmp_path, monkeypatch, native_error,
):
    for name in ("LOGNAME", "USER", "LNAME", "USERNAME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(getpass, "getuser", fail(ImportError("missing pwd")))
    monkeypatch.setattr(os, "getlogin", fail(native_error))
    monkeypatch.setattr(ir_bundle, "_system_info", fail(AssertionError("collection started")))
    monkeypatch.setattr(ir_bundle, "_process_list", fail(AssertionError("collection started")))
    output = tmp_path / "must-not-be-created"
    with pytest.raises(LocalUsernameUnavailable, match="unavailable"):
        ir_bundle.collect_triage_bundle(output, consent=True)
    assert not output.exists()
    assert not list(tmp_path.rglob("*.zip"))


def test_ir_archive_contains_native_fallback_redaction_not_raw_username(tmp_path, monkeypatch):
    for name in ("LOGNAME", "USER", "LNAME", "USERNAME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(getpass, "getuser", fail(ImportError("missing pwd")))
    monkeypatch.setattr(os, "getlogin", lambda: "Native_Fixture_User")
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "daily_briefing.txt").write_text(
        "Native_Fixture_User observed this benign fixture", encoding="utf-8")
    monkeypatch.setattr(ir_bundle, "_shared_logs", lambda: logs)
    monkeypatch.setattr(ir_bundle, "_system_info", lambda: {"collected_at": "fixture-time"})
    monkeypatch.setattr(ir_bundle, "_process_list", lambda _redactor: [])
    monkeypatch.setattr(ir_bundle, "_connections", lambda _redactor: [])
    archive_path = ir_bundle.collect_triage_bundle(tmp_path / "out", consent=True)
    with zipfile.ZipFile(archive_path) as archive:
        output = b"\n".join(archive.read(name) for name in archive.namelist())
    assert b"native_fixture_user" not in output.lower()
    assert b"<user:" in output


@pytest.mark.skipif(os.name != "nt", reason="native Windows no-environment lookup")
def test_actual_native_hint_and_privacy_work_without_any_username_environment(monkeypatch):
    native = os.getlogin()
    for name in ("LOGNAME", "USER", "LNAME", "USERNAME"):
        monkeypatch.delenv(name, raising=False)
    assert local_username_hint() == native
    assert native.casefold() not in ir_bundle._PrivacyFilter().text(
        f"owner {native}").casefold()
