"""Explicit Windows gate: real standalone Qt child, marker and native retirement.

Run only in a coordinated stable-source window with
ANGERONA_STANDALONE_NATIVE=1. This starts the actual Red Team window, no Core,
sensors or automatic response. It does not establish live detector efficacy.
"""
from __future__ import annotations

import os
from dataclasses import asdict
import json
from pathlib import Path
import secrets
import threading
import time

import pytest

from angerona.gui.red_team_bridge import RedTeamToolOwner, ReservedMarkerWriter
from angerona.resilience.source_guard import SourceGuard
from angerona.shark.red_team_ipc import VERIFICATION_SECONDS, WHOLE_STARTUP_SECONDS


pytestmark = pytest.mark.skipif(os.name != "nt" or os.environ.get("ANGERONA_STANDALONE_NATIVE") != "1",
    reason="Explicit source-frozen Windows standalone gate")


def background(operation):
    result, failures = [], []
    def run():
        try:
            result.append(operation())
        except BaseException as exc:
            failures.append(exc)
    worker = threading.Thread(target=run, name="StandaloneNativeGate", daemon=False)
    worker.start()
    worker.join(20)
    assert not worker.is_alive(), "native gate did not return within its original bound"
    if failures:
        raise failures[0]
    return result[0]


@pytest.mark.parametrize("close_mode", ["graceful", "suite-stop"])
def test_actual_child_paints_writes_only_reserved_marker_and_retires_complete_job(tmp_path, monkeypatch, close_mode):
    from angerona.gui import red_team_bridge as bridge
    from angerona.core.windows_process_lease import _Native
    from angerona.shark.shark_attack import SharkAttackEngine
    from angerona.telemetry.process_snapshot_worker import _Pin
    import psutil
    # Presentation-only fixture: the real worker entry, source seal, inherited
    # transport, native Job and authority paths remain production code.
    sanitize = bridge.sanitized_child_environment
    monkeypatch.setattr(bridge, "sanitized_child_environment",
        lambda: sanitize({"QT_QPA_PLATFORM": "offscreen"}))
    root = Path(__file__).resolve().parents[1]
    seal = SourceGuard.capture(root, deadline=time.monotonic() + VERIFICATION_SECONDS)
    monkeypatch.setenv("ANGERONA_PEER_SOURCE_DIGEST", seal.digest)
    data = tmp_path / "tool-data"
    data.mkdir()
    received = []
    def receive(kind, payload, nonce):
        received.append((kind, payload))
        if kind == "readiness":
            owner.send("readiness-result", {"ready": False, "state": "PENDING", "reason": "Native UI test only."})
        elif kind == "history-list":
            owner.send("reply", {"ok": True, "result": {"rows": [], "limited": False}}, reply_to=nonce)
        elif kind == "history-read":
            owner.send("reply", {"ok": True, "result": "No reports in this isolated test."}, reply_to=nonce)
        elif kind == "device-lab":
            assert payload == {"operation": "list-enrollments", "args": [], "kwargs": {}}
            owner.send("reply", {"ok": True, "result": []}, reply_to=nonce)
    owner = RedTeamToolOwner(receive, source_digest=seal.digest, initialize={
        "data_dir": str(data), "default_target": str(tmp_path), "stylesheet": "", "version": "1.15.0"})
    owner.start()
    native_rows = ()
    probe_pin = None
    probe_identity = None
    try:
        # The real15s paint cap starts AFTER both source seals/authenticated
        # native admission/initialize. This waiter covers the whole105s attempt.
        assert owner._ui_ready.wait(WHOLE_STARTUP_SECONDS), owner.lifecycle_snapshot()
        assert owner._ready.is_set() and not owner._stop.is_set()
        assert owner._bootstrap_deadline_ns - owner._startup_started_ns == int(VERIFICATION_SECONDS * 1e9)
        assert owner._presentation_started_ns is not None
        assert owner._startup_started_ns <= owner._presentation_started_ns < owner._bootstrap_deadline_ns
        assert owner._stderr_reader is not None and owner._stderr_reader.is_alive()
        assert any(kind == "ui-ready" for kind, _payload in received)
        native_rows = background(owner.observe_owned_process_identities)
        assert {owner._wrapper.pid, owner._child.pid} <= {row.pid for row in native_rows}
        assert all(row.role == "redteam-tool" for row in native_rows)
        path = tmp_path / "owned-inert-marker.txt"
        creation = SharkAttackEngine._open_new_artifact(path, delete_access=False)
        descriptor = background(lambda: ReservedMarkerWriter(owner).complete_new_marker(
            creation, path, b"standalone-child-inert-marker\n"))
        try:
            assert os.read(descriptor, 100) == b"standalone-child-inert-marker\n"
            with pytest.raises(OSError):
                os.write(descriptor, b"changed")
            with pytest.raises(OSError):
                path.rename(tmp_path / "renamed.txt")
        finally:
            os.close(descriptor)
        # Execution-only probe. This intentionally does not manufacture the
        # issuer lease/registry/event needed for response or catch credit.
        probe_id, token = secrets.token_hex(16), "ANGERONA_REDTEAM_" + secrets.token_hex(4)
        probe = owner.request("start-probe", {"probe_id": probe_id, "token": token}).wait(5)
        probe_pin = _Pin(probe["pid"])
        probe_identity = _Native().identity(probe_pin.handle)
        assert probe_pin.birth == probe["birth"]
        assert probe_identity.pid not in {os.getpid(), owner._wrapper.pid, owner._child.pid}
        process = psutil.Process(probe_identity.pid)
        assert process.ppid() == owner._child.pid
        assert process.cmdline()[1:] == ["-I", "-S", "-c", "import time; time.sleep(30)", token]
        assert background(lambda: owner._native_owner.contains_native_process(probe_identity))
        native_rows = background(owner.observe_owned_process_identities)
        assert probe_identity.pid in {row.pid for row in native_rows}
        witness = tmp_path / "native-witness.json"
        def preserve(phase):
            probe_row = asdict(probe_identity) if probe_identity is not None else None
            if probe_row is not None:
                probe_row["birth_ticks"] = str(probe_identity.birth_ticks)
            witness.write_text(json.dumps({"phase": phase, "mode": close_mode,
                "members": [asdict(row) for row in native_rows],
                "probe": probe_row,
                "probe_retirement": probe_pin.proof if probe_pin is not None else None,
                "execution_only": True, "detector_catch_coverage": False,
                "lifecycle": owner.lifecycle_snapshot(),
                "tree_retirement": owner._native_owner.tree_retirement_snapshot(),
                "source_digest": seal.digest}, indent=2), encoding="utf-8")
        preserve("before-close")
        print("Native witness: " + str(witness))
        if close_mode == "graceful":
            assert owner.send("close-ready", {})
            deadline = time.monotonic() + 5
            while owner._child.alive() and time.monotonic() < deadline:
                time.sleep(.05)
            assert not owner._child.alive()
        assert background(lambda: owner.stop(10)), owner.lifecycle_snapshot()
        assert owner._retired.is_set()
        assert all(row["wait_signaled"] and row["handle_closed"] for row in owner._proofs)
        retirement = owner._native_owner.tree_retirement_snapshot()
        assert retirement["signals_proven"] and retirement["handles_closed"] and not retirement["close_held"], retirement
        assert retirement["error_type"] == "", retirement
        assert probe_pin.retire(3., terminate=False)
        assert owner.lifecycle_snapshot()["workers_retired"]
        assert not owner._stderr_reader.is_alive()
        assert owner._process.stderr.closed and not owner._pipe_close_held
        child_diagnostics = owner.lifecycle_snapshot()["startup_child_diagnostics"]
        assert child_diagnostics["advisory_only"] and not child_diagnostics["exhausted"]
        assert any(row["phase"] == "source-seal" and row["status"] == "completed"
                   for row in child_diagnostics["records"])
        assert SourceGuard.capture(root, expected_digest=seal.digest,
            deadline=time.monotonic() + VERIFICATION_SECONDS).digest == seal.digest
        preserve("retired")
    finally:
        stopped = background(lambda: owner.stop(10))
        if "preserve" in locals():
            preserve("retired" if stopped else "retirement-held")
        assert stopped, owner.lifecycle_snapshot()
        if probe_pin is not None and not probe_pin.closed:
            assert probe_pin.retire(3., terminate=False)
    # Native rows were complete at their capture; this gate does not fabricate
    # a claim that their two-second leases remain fresh after retirement.
    assert native_rows
