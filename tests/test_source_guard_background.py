from types import SimpleNamespace
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from angerona import __main__ as entry


@pytest.mark.parametrize("argument", [
    "--community-tool-probe", "--red-team-tool-worker", "--red-team-inert-probe",
    "--process-snapshot-worker", "--curated-tool-worker", "--kernel-telemetry-canary",
    "--ugcap-worker", "--spyware-beacon-watch", "--engine-service", "--response-service",
    "--automatic-start", "--community-tool-probe-malformed",
])
def test_background_custody_failure_remains_held_without_native_dialog(monkeypatch, capsys, argument):
    import ctypes
    import sys
    monkeypatch.setattr(entry, "sys", SimpleNamespace(platform="win32", frozen=False, argv=["angerona", argument], stderr=sys.stderr))
    monkeypatch.delenv("ANGERONA_SUPERVISED_RECOVERY", raising=False)
    calls = []
    def native(name, **kwargs):
        calls.append(name)
        if name == "user32":
            pytest.fail("A background failure must not open a user-facing native dialog")
        raise OSError("fixture failure")
    monkeypatch.setattr(ctypes, "WinDLL", native, raising=False)
    assert entry._source_activation_pending_guard() is True
    assert "engines were not started" in capsys.readouterr().err
    assert "user32" not in calls


def test_explicit_interactive_launch_retains_one_review_dialog(monkeypatch):
    import ctypes
    import sys
    monkeypatch.setattr(entry, "sys", SimpleNamespace(platform="win32", frozen=False, argv=["angerona"], stderr=sys.stderr))
    monkeypatch.delenv("ANGERONA_SUPERVISED_RECOVERY", raising=False)
    monkeypatch.delenv("ANGERONA_EXTERNAL_WATCHDOG", raising=False)
    shown = []
    def message(*args):
        shown.append(args)
        return 1
    def native(name, **kwargs):
        if name == "user32":
            return SimpleNamespace(MessageBoxW=message)
        raise OSError("fixture folder failure")
    monkeypatch.setattr(ctypes, "WinDLL", native, raising=False)
    assert entry._source_activation_pending_guard() is True
    assert len(shown) == 1


def test_supervised_recovery_does_not_popup_even_without_worker_flag(monkeypatch):
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    assert entry._background_entry_requested(["--chill"]) is True


@pytest.mark.parametrize("pending", [False, True])
def test_external_watchdog_first_launch_stays_held_and_quiet(monkeypatch, capsys, pending):
    import ctypes

    monkeypatch.setattr(entry, "sys", SimpleNamespace(platform="win32", frozen=False,
                                                     argv=["angerona"], stderr=sys.stderr))
    monkeypatch.setenv("ANGERONA_EXTERNAL_WATCHDOG", "1")
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "0")

    def folder():
        if not pending:
            raise OSError("fixture folder failure")
        return Path("C:/fixture-local-data")

    monkeypatch.setattr(entry, "_source_storage_known_folder", folder)
    monkeypatch.setattr(entry, "_source_activation_pending_at", lambda _: True)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: pytest.fail(
        "An externally supervised source failure must not open a native dialog"), raising=False)
    assert entry.main() == 85
    assert "engines were not started" in capsys.readouterr().err
    assert os.environ["ANGERONA_SUPERVISED_RECOVERY"] == "0"


def test_quiet_helper_flag_does_not_bypass_the_custody_hold(monkeypatch):
    import sys
    monkeypatch.setattr(entry, "sys", SimpleNamespace(argv=["angerona", "--community-tool-probe"], stderr=sys.stderr))
    monkeypatch.setattr(entry, "_source_activation_pending_guard", lambda: True)
    assert entry.main() == 85


@pytest.mark.skipif(os.name != "nt", reason="Real Windows current-user token regression")
def test_private_helper_profile_checks_the_real_user_activation_store(tmp_path):
    expected = entry._source_storage_known_folder()
    profile = tmp_path / "private-profile"
    # Existing and absent profile subfolders previously produced either a false
    # custody hold or a check against the private scratch tree. Neither is valid.
    (profile / "AppData" / "Local").mkdir(parents=True)
    environment = dict(os.environ)
    environment.update({key: str(profile) for key in (
        "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "ANGERONA_DATA")})
    code = (
        "import importlib.util,json;"
        f"s=importlib.util.spec_from_file_location('source_guard_fixture',{str(Path(entry.__file__).absolute())!r});"
        "e=importlib.util.module_from_spec(s);s.loader.exec_module(e);"
        "print(json.dumps(str(e._source_storage_known_folder())))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code], env=environment,
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert result.returncode == 0, result.stderr
    assert Path(json.loads(result.stdout)) == expected
    assert profile not in expected.parents
