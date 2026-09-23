"""Linked-token policy tests use inert handles and never create a process."""
from __future__ import annotations

import ctypes
import os
import subprocess
import time
from dataclasses import replace

import pytest

from angerona.core import ollama_windows_token as token_launch


class FakeNative:
    def __init__(self, image):
        self.path = image
        self.parent = token_launch._TokenIdentity("fixture-user", 2, True, 0x3000, 1, 2, False)
        self.medium = replace(self.parent, elevated=False, integrity=0x2000, elevation_type=3)
        self.linked = self.medium
        self.primary = self.medium
        self.child = self.medium
        self.closed = []
        self.terminated = []
        self.calls = []
        self.models = None

    def current_token(self):
        return 10

    def linked_token(self, current):
        assert current == 10
        return 20

    def child_token(self, process):
        assert process == 30
        return 50

    def primary_token(self, token):
        assert token == 20
        self.calls.append(("duplicate", token))
        return 60

    def identity(self, token):
        self.calls.append(("identity", token))
        return {10: self.parent, 20: self.linked, 50: self.child, 60: self.primary}[token]

    def model_directory(self, token):
        assert token == (60 if self.linked.token_type == 2 else 20)
        return self.models

    def create_suspended(self, linked, image, environment):
        assert linked == (60 if self.linked.token_type == 2 else 20) and image == self.path
        self.calls.append(("create", dict(environment)))
        return 30, 40, 600

    def image(self, process):
        assert process == 30
        return self.path

    def resume(self, thread):
        assert thread == 40
        self.calls.append(("resume", thread))
        return 1

    def close(self, handle):
        self.closed.append(handle)

    def terminate(self, process):
        self.terminated.append(process)

    def poll(self, process):
        assert process == 30
        return None


@pytest.fixture
def fixture_native(tmp_path):
    image = tmp_path / "ollama.exe"
    image.write_bytes(b"inert fixture")
    return FakeNative(image)


def run(native, **kwargs):
    return token_launch._launch(native, native.path, {"OLLAMA_NO_CLOUD": "1"},
                                kwargs.get("deadline", time.monotonic() + 5))


def test_same_user_medium_child_verified_before_resume(fixture_native):
    native = fixture_native
    process = run(native)
    assert process.pid == 600 and process.poll() is None
    assert native.calls == [
        ("identity", 10), ("identity", 20), ("create", {"OLLAMA_NO_CLOUD": "1"}),
        ("identity", 50), ("resume", 40),
    ]
    assert native.closed == [50, 40, 20, 10]
    assert not native.terminated
    del process
    assert native.closed[-1] == 30


@pytest.mark.parametrize("changes", [
    {"sid": "another-user"}, {"session": 3}, {"session": 0},
    {"elevated": True}, {"integrity": 0x3000}, {"integrity": 0x2100},
    {"token_type": 0}, {"elevation_type": 2}, {"ui_access": True},
])
@pytest.mark.parametrize("target", ["linked", "child"])
def test_wrong_authority_fails_before_resume(fixture_native, changes, target):
    native = fixture_native
    setattr(native, target, replace(native.medium, **changes))
    with pytest.raises(ValueError, match="linked medium user token"):
        run(native)
    assert not any(call[0] == "resume" for call in native.calls)
    assert native.terminated == ([30] if target == "child" else [])
    assert sorted(native.closed) == ([10, 20, 30, 40, 50] if target == "child" else [10, 20])


@pytest.mark.parametrize("changes", [
    {"elevated": False}, {"elevation_type": 1}, {"token_type": 2},
    {"integrity": 0x4000}, {"session": 0},
])
def test_non_split_or_service_parent_is_rejected(fixture_native, changes):
    native = fixture_native
    native.parent = replace(native.parent, **changes)
    with pytest.raises(ValueError):
        run(native)
    assert native.calls == [("identity", 10)]
    assert native.closed == [10]


def test_linked_impersonation_is_converted_and_rechecked_before_creation(fixture_native):
    native = fixture_native
    native.linked = replace(native.medium, token_type=2)
    process = run(native)
    assert native.calls == [
        ("identity", 10), ("identity", 20), ("duplicate", 20), ("identity", 60),
        ("create", {"OLLAMA_NO_CLOUD": "1"}), ("identity", 50), ("resume", 40),
    ]
    assert native.closed == [50, 40, 60, 20, 10]
    assert not native.terminated and process.pid == 600


@pytest.mark.parametrize("changes", [
    {"sid": "another-user"}, {"session": 3}, {"session": 0},
    {"elevated": True}, {"integrity": 0x3000}, {"integrity": 0x2100},
    {"token_type": 2}, {"elevation_type": 2}, {"ui_access": True},
])
def test_converted_token_authority_is_not_assumed(fixture_native, changes):
    native = fixture_native
    native.linked = replace(native.medium, token_type=2)
    native.primary = replace(native.medium, **changes)
    with pytest.raises(ValueError):
        run(native)
    assert native.closed == [60, 20, 10]
    assert not any(call[0] == "create" for call in native.calls)


def test_linked_impersonation_wrong_user_cannot_be_duplicated(fixture_native):
    native = fixture_native
    native.linked = replace(native.medium, token_type=2, sid="another-user")
    with pytest.raises(ValueError):
        run(native)
    assert native.calls == [("identity", 10), ("identity", 20)]
    assert native.closed == [20, 10]


def test_primary_conversion_failure_never_creates_child_or_falls_back(fixture_native):
    native = fixture_native
    native.linked = replace(native.medium, token_type=2)

    def denied(_token):
        raise OSError("Fixture token conversion denied")

    native.primary_token = denied
    with pytest.raises(ValueError):
        run(native)
    assert native.closed == [20, 10]
    assert not any(call[0] == "create" for call in native.calls)


def test_impersonation_child_is_rejected_even_after_primary_conversion(fixture_native):
    native = fixture_native
    native.linked = native.child = replace(native.medium, token_type=2)
    with pytest.raises(ValueError):
        run(native)
    assert native.terminated == [30]
    assert native.closed == [30, 50, 40, 60, 20, 10]
    assert not any(call[0] == "resume" for call in native.calls)


@pytest.mark.skipif(os.name != "nt", reason="Windows ctypes ABI; native call is replaced")
@pytest.mark.parametrize("succeeds", [True, False])
def test_primary_conversion_binding_has_minimum_rights_and_noninherited_handle(monkeypatch, succeeds):
    class Duplicate:
        def __call__(self, token, rights, attributes, level, token_type, result):
            assert (token, rights, attributes, level, token_type) == (20, 0xB, None, 1, 1)
            if succeeds:
                result._obj.value = 60
            return succeeds

    class Library:
        DuplicateTokenEx = Duplicate()

    monkeypatch.setattr(token_launch.ctypes, "WinDLL", lambda *_a, **_k: Library())
    native = token_launch._Native.__new__(token_launch._Native)
    if succeeds:
        assert native.primary_token(20) == 60
    else:
        with pytest.raises(OSError, match="conversion failed"):
            native.primary_token(20)


def test_wrong_suspended_image_is_terminated_by_owned_handle(fixture_native, tmp_path):
    native = fixture_native
    other = tmp_path / "other.exe"
    other.write_bytes(b"inert other")
    native.image = lambda _process: other
    with pytest.raises(ValueError):
        run(native)
    assert native.terminated == [30]
    assert not any(call[0] == "resume" for call in native.calls)


def test_expired_deadline_never_creates_child(fixture_native):
    with pytest.raises(TimeoutError):
        run(fixture_native, deadline=time.monotonic() - 1)
    assert not any(call[0] == "create" for call in fixture_native.calls)


def test_bad_resume_count_kills_only_our_child(fixture_native):
    native = fixture_native
    native.resume = lambda _thread: 0
    with pytest.raises(ValueError):
        run(native)
    assert native.terminated == [30]
    assert sorted(native.closed) == [10, 20, 30, 40, 50]


def test_missing_linked_token_never_falls_back(fixture_native):
    native = fixture_native

    def unavailable(_current):
        raise OSError("No split token")

    native.linked_token = unavailable
    with pytest.raises(ValueError, match="linked medium user token"):
        run(native)
    assert native.closed == [10]
    assert not any(call[0] == "create" for call in native.calls)


def test_custom_models_directory_is_only_user_environment_value(fixture_native, tmp_path):
    native = fixture_native
    native.models = str(tmp_path / "Model Store")
    process = run(native)
    environment = next(value for name, value in native.calls if name == "create")
    assert environment == {"OLLAMA_NO_CLOUD": "1", "OLLAMA_MODELS": native.models}
    assert process.pid == 600


@pytest.mark.parametrize("models", ["relative/models", "bad\x00path", 77, 0, False])
def test_bad_user_model_path_cannot_reach_creation(fixture_native, models):
    native = fixture_native
    native.models = models
    with pytest.raises(ValueError):
        run(native)
    assert not any(call[0] == "create" for call in native.calls)


def test_cleanup_closes_remaining_handles_even_if_termination_fails(fixture_native):
    native = fixture_native
    native.child = replace(native.medium, elevated=True)

    def denied(_process):
        raise OSError("Fixture termination failure")

    native.terminate = denied
    with pytest.raises(ValueError):
        run(native)
    assert sorted(native.closed) == [10, 20, 30, 40, 50]


@pytest.mark.parametrize("cancel_at", [1, 2])
@pytest.mark.parametrize("linked_impersonation", [False, True])
def test_cancellation_after_token_checks_never_resumes(fixture_native, cancel_at, linked_impersonation):
    native = fixture_native
    if linked_impersonation:
        native.linked = replace(native.medium, token_type=2)
    checks = []

    def cancel():
        checks.append(1)
        if len(checks) == cancel_at:
            raise InterruptedError

    with pytest.raises(InterruptedError):
        token_launch._launch(native, native.path, {}, time.monotonic() + 5,
                             check_cancelled=cancel)
    assert not any(call[0] == "resume" for call in native.calls)
    assert native.terminated == ([30] if cancel_at == 2 else [])
    if linked_impersonation:
        assert 60 in native.closed


@pytest.mark.skipif(os.name != "nt", reason="Windows ctypes ABI; native call is replaced")
def test_native_binding_uses_explicit_image_fixed_args_suspension_and_no_handles(
    fixture_native, monkeypatch,
):
    seen = []

    class Create:
        def __call__(self, token, logon_flags, image, command, flags,
                     environment, directory, startup_pointer, process_pointer):
            startup = startup_pointer._obj
            assert token == 20 and logon_flags == 0
            assert image == str(fixture_native.path)
            assert command.value == subprocess.list2cmdline([image, "serve"])
            assert directory == str(fixture_native.path.parent)
            assert flags == 0x08000404
            assert startup.cb == ctypes.sizeof(startup)
            assert startup.dwFlags == 1 and startup.wShowWindow == 0
            assert not any((startup.hStdInput, startup.hStdOutput, startup.hStdError))
            expected = "OLLAMA_NO_CLOUD=1\0\0"
            assert ctypes.wstring_at(environment, len(expected)) == expected
            process = process_pointer._obj
            process.hProcess, process.hThread, process.dwProcessId = 30, 40, 600
            seen.append(True)
            return True

    class Library:
        CreateProcessWithTokenW = Create()

    monkeypatch.setattr(token_launch.ctypes, "WinDLL", lambda *_a, **_k: Library())
    native = token_launch._Native.__new__(token_launch._Native)
    assert native.create_suspended(20, fixture_native.path, {"OLLAMA_NO_CLOUD": "1"}) == (30, 40, 600)
    assert seen == [True]
