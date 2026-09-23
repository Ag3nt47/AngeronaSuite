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

    def identity(self, token):
        self.calls.append(("identity", token))
        return {10: self.parent, 20: self.linked, 50: self.child}[token]

    def model_directory(self, token):
        assert token == 20
        return self.models

    def create_suspended(self, linked, image, environment):
        assert linked == 20 and image == self.path
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
    {"token_type": 2}, {"elevation_type": 2}, {"ui_access": True},
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
def test_cancellation_after_token_checks_never_resumes(fixture_native, cancel_at):
    native = fixture_native
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
