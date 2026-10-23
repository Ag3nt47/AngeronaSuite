"""Private protocol fixtures: inert executors, owned children and no vault/TPM work."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import psutil
import pytest

from angerona.core import enclave_mesh as mesh, ugcap_worker as worker
from angerona.core.engine_transport import private_directory
from ugcap_native_observer import ObserverPool


@pytest.fixture
def runtime(tmp_path):
    return private_directory(tmp_path / "owned-runtime")


@pytest.fixture
def launches(tmp_path, monkeypatch):
    owned = []
    observers = ObserverPool() if os.name == 'nt' else None
    if observers is not None:
        observers.observe_capture(monkeypatch)

    def factory(*, extra="", body="return {'status':'verified'}", custom=None):
        index = len(owned)
        identity_path = tmp_path / f"actual-child-{index}.json"
        body_path = tmp_path / f"body-{index}.json"
        source = str(Path(worker.__file__).resolve().parents[2])
        code = (
            "import os,sys,json,time\nfrom pathlib import Path\nimport psutil\n"
            f"sys.path.insert(0,{source!r})\n"
            "from angerona.core import ugcap_worker as module, enclave_mesh as mesh\n"
            "identity={'pid':os.getpid(),'birth':psutil.Process().create_time()}\n"
            "if os.name=='nt': identity['birth_raw']=module.NativeJobMemberAPI().identity(-1)[1]\n"
            f"Path({str(identity_path)!r}).write_text(json.dumps(identity))\n"
            + extra + "\n"
            + (custom if custom is not None else (
                "def execute(command,payload,secret):\n"
                "    if command=='shutdown': return {'status':'shutdown'}\n"
                f"    Path({str(body_path)!r}).write_text('{{\"entered\":true}}')\n"
                + "\n".join("    " + line for line in body.splitlines())
                + "\nraise SystemExit(module.serve(sys.stdin.buffer,sys.stdout.buffer,executor=execute))\n"
            ))
        )

        def launch(_command, **kwargs):
            assert kwargs["stderr"] == subprocess.DEVNULL
            process = subprocess.Popen([sys.executable, "-I", "-c", code], **kwargs)
            owned.append((process, identity_path))
            return process

        return launch, identity_path, body_path

    try:
        yield factory
        proof = []
        for process, path in owned:
            assert process.poll() is not None, "owned launcher has not retired"
            assert path.is_file(), "actual executing child's identity is unavailable"
            identity = json.loads(path.read_text())
            retirement = _owned_retirement(process, identity, observers)
            proof.append(dict(actual_child=identity, retirement=retirement,
                              launcher_pid=process.pid, launcher_exit=process.returncode))
        if observers is not None:
            observers.require_all_retired()
        (tmp_path / "owned-child-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
    finally:
        if observers is not None:
            observers.close()


def _owned_retirement(process, identity, observers):
    if observers is not None:
        return dict(platform='windows', kernel=observers.require_retired(
            (identity['pid'], identity['birth_raw'])))
    # On POSIX the source Python is the actual owned Popen child. wait/poll
    # reap that exact child; PID existence is not used as retirement proof.
    assert identity['pid'] == process.pid, 'actual child differs from owned POSIX Popen'
    code = process.wait(timeout=0)
    assert type(code) is int and process.returncode == code
    return dict(platform='posix', owned_pid=process.pid, wait_reaped=True,
                exit_code=code, windows_kernel_observer=False)


def test_portable_retirement_requires_owned_pid_and_successful_reap():
    calls = []
    process = SimpleNamespace(pid=123, returncode=-9,
        wait=lambda **kwargs: calls.append(kwargs) or -9)
    proof = _owned_retirement(process, {'pid':123}, None)
    assert calls == [{'timeout':0}] and proof['wait_reaped'] is True
    assert proof['windows_kernel_observer'] is False and 'kernel' not in proof
    with pytest.raises(AssertionError, match='differs'):
        _owned_retirement(process, {'pid':124}, None)
    assert calls == [{'timeout':0}]


def test_portable_retirement_never_credits_live_or_unknown_child():
    def live(**_kwargs):
        raise subprocess.TimeoutExpired('owned-inert-child', 0)
    process = SimpleNamespace(pid=123, returncode=None, wait=live)
    with pytest.raises(subprocess.TimeoutExpired):
        _owned_retirement(process, {'pid':123}, None)
    process.wait = lambda **_kwargs: None
    with pytest.raises(AssertionError):
        _owned_retirement(process, {'pid':123}, None)


def _payload(runtime):
    return dict(repo_root=str(runtime), vault_path=str(runtime / "never-opened.fixture"),
                key_name="Angerona.UGCAP.inert")


def test_delayed_preparation_precedes_epoch_mint_and_slow_work_rotates(runtime, launches, monkeypatch):
    launch, _identity, body_path = launches(extra="time.sleep(1.25)", body=(
        "time.sleep(2.2)\nreturn {'status':'verified','observations':{'private':'omitted'},"
        "'verified_files':{'a':'b'},'verification_receipt':{'verified_files':{'a':'b'}}}"
    ))
    order = []
    original_write = worker._startup_write
    original_pair = worker.CrossProcessMeshChannel.create_pair.__func__

    def observe_write(process, wire):
        if b'"kind":"prepare"' in wire:
            clean = json.loads(wire)
            assert set(clean) == {"version", "kind", "data_root", "client_nonce"}
            assert not {"mesh", "secret", "signing_private", "exchange_private"} & set(clean)
            order.append("prepare")
        return original_write(process, wire)

    def pair(cls, **kwargs):
        order.append("mint")
        return original_pair(cls, **kwargs)

    monkeypatch.setattr(worker, "_startup_write", observe_write)
    monkeypatch.setattr(worker.CrossProcessMeshChannel, "create_pair", classmethod(pair))
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=launch, rotation_seconds=1)
    secret = bytearray(b"INERT_SECRET_NEVER_PREPARED")
    try:
        result = instance.execute("verify", _payload(runtime), secret=secret, timeout=10)
        assert result == {"status":"verified", "verification_receipt":{"verified_files":{"a":"b"}}}
        assert body_path.is_file() and order == ["prepare", "mint"]
        assert instance.snapshot()["channel"]["channel"]["epoch"] >= 2
        assert instance.snapshot()["startup_failure"] is None
        assert secret == b"INERT_SECRET_NEVER_PREPARED"
    finally:
        instance.close()
    assert not instance.snapshot()["startup_cleanup_pending"]


def test_prepared_timeout_mints_no_epochs_and_retires_reader(runtime, launches, monkeypatch):
    launch, _identity, body_path = launches(extra="time.sleep(5)")
    calls = []
    monkeypatch.setattr(worker.CrossProcessMeshChannel, "create_pair", lambda **_kwargs: calls.append(True))
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=launch, startup_timeout=3)
    try:
        with pytest.raises(worker.UGCAPWorkerUnavailable):
            instance.execute("verify", _payload(runtime), secret=bytearray(b"inert-secret"), timeout=4)
        failure = instance.snapshot()["startup_failure"]
        assert failure["stage"] == "prepared-read" and failure["reason"] == "timeout"
        assert not calls and not body_path.exists()
        assert not instance.snapshot()["startup_cleanup_pending"]
        assert not any(t.name == "UGCAP-startup-io" for t in threading.enumerate())
    finally:
        instance.close()


@pytest.mark.parametrize("reply", [b"wrong\n", b"x" * 128])
def test_invalid_prepared_reply_cannot_mint_mesh(runtime, launches, monkeypatch, reply):
    code = f"sys.stdin.buffer.readline(65537)\nsys.stdout.buffer.write({reply!r})\nsys.stdout.buffer.flush()\ntime.sleep(5)\n"
    launch, _identity, body_path = launches(custom=code)
    calls = []
    monkeypatch.setattr(worker.CrossProcessMeshChannel, "create_pair", lambda **_kwargs: calls.append(True))
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=launch)
    try:
        with pytest.raises(worker.UGCAPWorkerUnavailable):
            instance.execute("status", {}, timeout=5)
        assert instance.snapshot()["startup_failure"]["stage"] == "prepared-read"
        assert not calls and not body_path.exists()
    finally:
        instance.close()


def test_plain_prepared_is_no_authenticated_ready_or_operation_authority(runtime, launches):
    code = (
        "sys.stdin.buffer.readline(65537)\nsys.stdout.buffer.write(module._PREPARED)\nsys.stdout.buffer.flush()\n"
        "sys.stdin.buffer.readline(65537)\nsys.stdout.buffer.write(b'{\"kind\":\"ready\"}\\n')\n"
        "sys.stdout.buffer.flush()\ntime.sleep(5)\n"
    )
    launch, _identity, body_path = launches(custom=code)
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=launch)
    secret = bytearray(b"INERT_SECRET_NOT_RAW_READY")
    try:
        with pytest.raises(worker.UGCAPWorkerUnavailable):
            instance.execute("verify", _payload(runtime), secret=secret, timeout=5)
        assert not body_path.exists() and secret == b"INERT_SECRET_NOT_RAW_READY"
        assert instance.snapshot()["startup_failure"]["stage"] == "protected-ready"
    finally:
        instance.close()


def test_delay_after_epoch_mint_still_rejects_expired_bootstrap(runtime, launches):
    extra = (
        "original=mesh.CrossProcessMeshChannel.from_bootstrap.__func__\n"
        "@classmethod\ndef expired(cls,bootstrap,**kwargs):\n"
        "    time.sleep(1.25)\n    return original(cls,bootstrap,**kwargs)\n"
        "mesh.CrossProcessMeshChannel.from_bootstrap=expired\n"
    )
    launch, _identity, body_path = launches(extra=extra)
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=launch, rotation_seconds=1)
    try:
        with pytest.raises(worker.UGCAPWorkerUnavailable):
            instance.execute("verify", _payload(runtime), secret=bytearray(b"inert-secret"), timeout=5)
        assert not body_path.exists()
        assert instance.snapshot()["startup_failure"]["stage"] == "protected-ready"
    finally:
        instance.close()


@pytest.mark.parametrize("field,value", [("client_nonce", "0" * 32), ("data_root", "different")])
def test_prepare_context_cannot_change_before_mesh(runtime, field, value):
    preparation = dict(version=1, kind="prepare", data_root=str(runtime), client_nonce="a" * 32)
    initial = dict(version=1, mesh={}, data_root=str(runtime), client_nonce="a" * 32)
    initial[field] = value
    output = io.BytesIO()
    called = []
    code = worker.serve(io.BytesIO(mesh.canonical(preparation) + b"\n" + mesh.canonical(initial) + b"\n"),
                        output, executor=lambda *_args: called.append(True))
    assert code == 2 and not called and output.getvalue() == worker._PREPARED


def test_startup_diagnostics_never_include_exception_secret_or_argv(runtime, capsys):
    secret = bytearray(b"PRIVATE_FIXTURE_EXCEPTION_TEXT")

    def launch(*_args, **_kwargs):
        raise OSError(secret.decode())

    instance = worker.UGCAPDaemonClient(runtime, launch_factory=launch)
    try:
        with pytest.raises(worker.UGCAPWorkerUnavailable) as failure:
            instance.execute("verify", _payload(runtime), secret=secret)
        snapshot = instance.snapshot()
        assert snapshot["startup_failure"]["stage"] == "launch"
        assert snapshot["startup_failure"]["reason"] == "io-unavailable"
        assert secret.decode() not in str(failure.value) + json.dumps(snapshot)
        assert set(snapshot["startup_failure"]) == {"stage", "reason", "elapsed_seconds", "child_exit_code"}
        assert not capsys.readouterr().out
    finally:
        instance.close()


def test_close_cancels_premesh_read_and_joins_exact_owner(runtime, launches):
    launch, identity, body_path = launches(extra="time.sleep(5)")
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=launch)
    errors = []

    def execute():
        try:
            instance.execute("status", {}, timeout=10)
        except worker.UGCAPWorkerUnavailable:
            errors.append(True)

    thread = threading.Thread(target=execute, name="inert-ugcap-prepared-client")
    try:
        thread.start()
        deadline = time.monotonic() + 5
        while not identity.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert identity.exists()
        instance.close()
        thread.join(5)
        assert not thread.is_alive() and errors
        assert not body_path.exists() and not instance.snapshot()["startup_cleanup_pending"]
        assert not any(t.name == "UGCAP-startup-io" for t in threading.enumerate())
    finally:
        instance.close()
        if thread.ident is not None:
            thread.join(5)
        assert not thread.is_alive()


def test_pending_startup_custody_is_retained_and_blocks_new_launch(runtime, monkeypatch):
    from angerona.resilience import _selftest_environment
    monkeypatch.setattr(_selftest_environment, "_stop_process_custody", lambda *_args: None)
    streams = [io.BytesIO(), io.BytesIO()]
    process = SimpleNamespace(stdin=streams[0], stdout=streams[1], poll=lambda: 0)
    joined = [False]
    owner = SimpleNamespace(cancel=lambda: None, join=lambda _timeout: joined[0])
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=lambda *_args, **_kwargs: pytest.fail("new launch"))
    try:
        assert not instance._retire_owned((process, None, None, owner))
        assert not any(stream.closed for stream in streams)
        assert instance.snapshot()["startup_cleanup_pending"]
        with pytest.raises(worker.UGCAPWorkerUnavailable, match="cleanup is pending"):
            instance.execute("status", {})
        assert not any(stream.closed for stream in streams)
        joined[0] = True
    finally:
        instance.close()
    assert all(stream.closed for stream in streams)
    assert not instance.snapshot()["startup_cleanup_pending"]


def test_operation_deadline_is_not_reset_after_preparation(runtime, launches):
    launch, _identity, body_path = launches(extra="time.sleep(2)", body="time.sleep(2.2)\nreturn {'status':'verified'}")
    instance = worker.UGCAPDaemonClient(runtime, launch_factory=launch)
    started = time.monotonic()
    try:
        with pytest.raises(worker.UGCAPWorkerUnavailable):
            instance.execute("verify", _payload(runtime), secret=bytearray(b"inert-secret"), timeout=3)
        assert time.monotonic() - started < 8
        assert body_path.exists()
    finally:
        instance.close()
