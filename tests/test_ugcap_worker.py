"""Isolated-worker fixtures use temporary state and inert injected executors."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from angerona.core import ugcap_worker as worker


@pytest.fixture
def runtime(tmp_path):
    from angerona.core.engine_transport import private_directory
    return private_directory(tmp_path / "private-runtime")


def payload(runtime):
    return {"repo_root": str(runtime), "vault_path": str(runtime / "fixture.ugcap"),
            "key_name": "Angerona.UGCAP.fixture"}


def fixture_launcher(body, *, extra="", captured=None):
    source = str(Path(worker.__file__).resolve().parents[2])
    code = (
        "import sys,os,time\n"
        f"sys.path.insert(0,{source!r})\n"
        "import angerona.core.ugcap_worker as module\n"
        + extra + "\n"
        + "def execute(command,payload,secret):\n"
        + "    if command == 'shutdown': return {'status':'shutdown'}\n"
        + "\n".join("    " + line for line in body.splitlines())
        + "\nraise SystemExit(module.serve(sys.stdin.buffer,sys.stdout.buffer,executor=execute))\n"
    )
    def launch(command, **kwargs):
        if captured is not None:
            captured.append((list(command), dict(kwargs)))
        return subprocess.Popen([sys.executable, "-I", "-c", code], **kwargs)
    return launch


def test_real_child_status_reuses_session_and_graceful_shutdown(runtime):
    instance = worker.UGCAPDaemonClient(runtime)
    try:
        first = instance.execute("status", {})
        assert first["status"] == "ready" and first["worker_process"] is True
        assert first["os_enclave"] is False
        assert first["hardware"]["probed"] is False
        assert instance.execute("status", {})["status"] == "ready"
        assert instance.snapshot()["starts"] == 1
        assert instance.execute("shutdown", {}) == {"status": "shutdown"}
        assert instance.snapshot()["running"] is False
    finally:
        instance.close()
    assert instance.snapshot()["closed"]


def test_real_status_context_never_opens_or_provisions_tpm(runtime):
    instance = worker.UGCAPDaemonClient(runtime)
    try:
        result = instance.execute("status", payload(runtime))
        assert result["initialized"] is False
        assert result["hardware"]["probed"] is False
        assert not (runtime / "fixture.ugcap").exists()
    finally:
        instance.close()


@pytest.mark.parametrize("command,changes", [("unknown", {}), ("verify", {"extra": "no"}),
    ("verify", {"repo_root": "relative/path"}), ("verify", {"key_name": "software"}),
    ("verify", {"vault_path": "//server/share/vault"})])
def test_invalid_schemas_do_not_launch_worker(runtime, command, changes):
    launched = []
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=lambda *_args, **_kwargs: launched.append(True))
    with pytest.raises(worker.UGCAPWorkerError):
        instance.execute(command, {**payload(runtime), **changes}, secret=bytearray(b"private-passphrase"))
    assert not launched
    instance.close()


def test_response_correlation_and_schema_are_exact():
    request = worker._request("status", {})
    response = worker._response(request, result={"status": "ready"})
    assert worker.UGCAPDaemonClient._accept_response(worker._application(response), request) == {"status": "ready"}
    for field, value in (("request_id", "0" * 32), ("nonce", "0" * 32), ("command", "verify"),
                         ("version", True), ("ok", "true")):
        bad = {**response, field: value}
        with pytest.raises(worker.UGCAPWorkerUnavailable):
            worker.UGCAPDaemonClient._accept_response(worker._application(bad), request)


def test_mismatched_signed_response_destroys_channel(runtime):
    extra = (
        "original = module._response\n"
        "def wrong(request, **kwargs):\n"
        "    response=original(request,**kwargs)\n"
        "    response['request_id']='f'*32\n"
        "    return response\n"
        "module._response=wrong\n"
    )
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=fixture_launcher("return {'status':'fixture'}", extra=extra))
    try:
        with pytest.raises(worker.UGCAPWorkerUnavailable, match="correlation"):
            instance.execute("status", {})
        assert not instance.snapshot()["running"]
    finally:
        instance.close()


def test_slow_operation_keeps_fresh_mesh_epochs_and_compacts_report(runtime):
    body = (
        "time.sleep(2.2)\n"
        "return {'status':'verified','report_id':'a'*32,'generation':'b'*32,"
        "'observations':{'private':'omitted'},'backups':{'data':'omitted'},"
        "'verified_files':{'src/test.py':'c'*64},"
        "'verification_receipt':{'verified_files':{'src/test.py':'c'*64}}}"
    )
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=fixture_launcher(body), rotation_seconds=1)
    secret = bytearray(b"caller-keeps-this-passphrase")
    try:
        result = instance.execute("verify", payload(runtime), secret=secret, timeout=10)
        assert result["status"] == "verified"
        assert not {"observations", "backups", "verified_files"} & set(result)
        assert result["verification_receipt"]["verified_files"] == {"src/test.py": "c" * 64}
        assert instance.snapshot()["channel"]["channel"]["epoch"] >= 2
        assert secret == b"caller-keeps-this-passphrase"
    finally:
        instance.close()


def test_exception_and_launch_metadata_never_expose_secret(runtime, monkeypatch, capsys):
    captured = []
    secret = bytearray(b"VERY_PRIVATE_OPERATOR_PASSPHRASE")
    monkeypatch.setenv("OPENAI_API_KEY", "not-inherited-private-token")
    body = "raise RuntimeError(secret.decode())"
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=fixture_launcher(body, captured=captured))
    try:
        with pytest.raises(worker.UGCAPWorkerError) as failure:
            instance.execute("verify", payload(runtime), secret=secret)
        text = str(failure.value) + json.dumps(instance.snapshot())
        assert secret.decode() not in text
        assert secret.decode() not in repr(captured)
        assert "not-inherited-private-token" not in repr(captured)
        assert captured[0][1]["stderr"] == subprocess.DEVNULL
        assert captured[0][0][1] == "-I"
        assert not capsys.readouterr().out
    finally:
        instance.close()


def test_timeout_kills_only_owned_job_and_next_call_restarts(runtime):
    body = "\n".join(("if command == 'verify': time.sleep(10)", "return {'status':'fixture'}"))
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=fixture_launcher(body))
    try:
        assert instance.execute("status", {})["status"] == "fixture"
        before = time.monotonic()
        with pytest.raises(worker.UGCAPWorkerUnavailable):
            instance.execute("verify", payload(runtime), secret=bytearray(b"private-passphrase"), timeout=.3)
        assert time.monotonic() - before < 4
        assert not instance.snapshot()["running"]
        assert instance.execute("status", {})["status"] == "fixture"
        assert instance.snapshot()["starts"] == 2
    finally:
        instance.close()


def test_child_crash_is_sanitized_and_restart_is_fresh(runtime):
    body = "\n".join(("if command == 'verify': os._exit(7)", "return {'status':'fixture'}"))
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=fixture_launcher(body))
    try:
        with pytest.raises(worker.UGCAPWorkerUnavailable):
            instance.execute("verify", payload(runtime), secret=bytearray(b"private-passphrase"))
        assert not instance.snapshot()["running"]
        assert instance.execute("status", {})["status"] == "fixture"
        assert instance.snapshot()["starts"] == 2
    finally:
        instance.close()


def test_restore_report_cannot_cross_child_restart_or_context(runtime):
    body = (
        "if command == 'verify': return {'status':'drift','report_id':'a'*32,'generation':'b'*32}\n"
        "return {'status':'restored'}"
    )
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=fixture_launcher(body))
    secret, original = bytearray(b"private-passphrase"), payload(runtime)
    restore = {**original, "paths": ["src/fixture.py"], "report_id": "a" * 32}
    try:
        instance.execute("verify", original, secret=secret)
        with pytest.raises(worker.UGCAPWorkerError, match="stale_report"):
            instance.execute("restore", {**restore, "vault_path": str(runtime / "different.ugcap")}, secret=secret)
        assert instance.execute("restore", restore, secret=secret)["status"] == "restored"
        instance.execute("verify", original, secret=secret)
        instance._process.kill()
        instance._process.wait(timeout=3)
        with pytest.raises(worker.UGCAPWorkerError, match="stale_report"):
            instance.execute("restore", restore, secret=secret)
        assert instance.snapshot()["starts"] == 2
    finally:
        instance.close()


def test_session_recycled_before_expiry(runtime):
    current = [time.monotonic()]
    instance = worker.UGCAPDaemonClient(runtime, clock=lambda: current[0])
    try:
        instance.execute("status", {})
        expiry = instance.snapshot()["channel"]["channel"]["session_expires"]
        current[0] = expiry - 100
        instance.execute("status", {})
        assert instance.snapshot()["starts"] == 2
    finally:
        instance.close()


def test_response_size_budget_fails_closed(runtime):
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=fixture_launcher(
        "return {'status':'verified','padding':'x'*(4*1024*1024)}"))
    try:
        with pytest.raises(worker.UGCAPWorkerError, match="response_too_large"):
            instance.execute("status", {}, timeout=10)
    finally:
        instance.close()


def test_close_interrupts_active_request(runtime):
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=fixture_launcher("time.sleep(10)\nreturn {}"))
    errors = []
    def execute():
        try:
            instance.execute("status", {}, timeout=15)
        except worker.UGCAPWorkerError as exc:
            errors.append(type(exc).__name__)
    task = threading.Thread(target=execute)
    task.start()
    deadline = time.monotonic() + 4
    while not instance.snapshot()["running"] and time.monotonic() < deadline:
        time.sleep(.01)
    instance.close()
    task.join(5)
    assert not task.is_alive() and errors
    assert not instance.snapshot()["running"]


def test_vault_cache_keeps_exact_context_and_initialize_does_not_provision(runtime, monkeypatch):
    from angerona.core import ugcap, ugcap_hardware
    created, provisioned = [], []
    class FakeHardware:
        def __init__(self, key):
            self.key = key
        def provision(self):
            provisioned.append(self.key)
            return {"hardware_backed": True}
    class FakeVault:
        def __init__(self, root, vault, hardware):
            created.append((root, vault, hardware.key))
            self.report = None
        def initialize(self, _secret):
            return {"status": "initialized"}
        def verify(self, _secret):
            self.report = "a" * 32
            return {"status": "drift", "report_id": self.report}
        def restore(self, _secret, _paths, *, expected_report_id):
            assert self.report == expected_report_id
            return {"status": "restored"}
        def lock(self):
            self.report = None
            return {"status": "locked"}
    monkeypatch.setattr(ugcap_hardware, "WindowsTPMHardware", FakeHardware)
    monkeypatch.setattr(ugcap, "UGCAPVault", FakeVault)
    executor = worker._VaultExecutor()
    clean, secret = payload(runtime), bytearray(b"private-passphrase")
    assert executor.execute("initialize", clean, secret)["status"] == "initialized"
    assert not provisioned
    executor.execute("verify", clean, secret)
    assert executor.execute("restore", {**clean, "paths": ["src/a.py"], "report_id": "a" * 32}, secret)["status"] == "restored"
    assert len(created) == 1
    executor.execute("provision", {"key_name": clean["key_name"]}, None)
    assert provisioned == [clean["key_name"]]
    executor.close()


def test_invalid_secret_encoding_and_restore_paths_are_rejected(runtime):
    request = worker._request("verify", payload(runtime), bytearray(b"private-passphrase"))
    invalid = copy.deepcopy(request)
    invalid["secret"] = "%%%"
    with pytest.raises(worker.UGCAPWorkerError):
        worker._validate_request(invalid)
    for path in ("../escape.py", "/absolute.py", "src\\a.py", "src//a.py"):
        with pytest.raises(worker.UGCAPWorkerError):
            worker._payload("restore", {**payload(runtime), "report_id": "a" * 32, "paths": [path]})


def test_unsafe_runtime_custody_refuses_launch(runtime, monkeypatch):
    from angerona.core import secure_store
    monkeypatch.setattr(secure_store, "_path_traverses_reparse", lambda _path: True)
    with pytest.raises(worker.UGCAPWorkerUnavailable):
        worker._custody(runtime)
