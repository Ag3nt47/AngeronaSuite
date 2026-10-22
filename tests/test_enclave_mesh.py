"""Offline adversarial and real inherited-pipe mesh fixtures; no network/TPM."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from angerona.core import enclave_mesh as mesh


class Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value


def local(clock=None, gate=None, verified=True):
    authority = mesh.MeshAuthority(verified=verified, clock=clock or time.monotonic, gate=gate)
    return authority, authority.enroll("module.scanner", "a" * 64), authority.enroll("bus.receiver")


def test_local_certified_roundtrip_replay_and_bound_source():
    authority, sender, receiver = local()
    packet = sender.seal(b'{"message":"detected"}', receiver, "telemetry.event")
    assert receiver.open(packet, "telemetry.event", expected_sender=sender) == b'{"message":"detected"}'
    with pytest.raises(mesh.MeshError, match="replayed"):
        receiver.open(packet, "telemetry.event")
    assert packet["header"]["certificate"]["body"]["source_digest"] == "a" * 64
    assert sender.label == "module.scanner"
    with pytest.raises(mesh.MeshError):
        authority.enroll("module.scanner")
    authority.close()


@pytest.mark.parametrize("field,value", [("sender", "0" * 32), ("receiver", "0" * 32),
    ("purpose", "response.isolate"), ("epoch", True), ("seq", True),
    ("boot", "0" * 32), ("session", "0" * 32), ("expires", 1)])
def test_packet_tampering_never_consumes_valid_sequence(field, value):
    authority, sender, receiver = local()
    packet = sender.seal(b"secret", receiver, "telemetry.event")
    bad = copy.deepcopy(packet)
    bad["header"][field] = value
    with pytest.raises(mesh.MeshError):
        receiver.open(bad, "telemetry.event")
    assert receiver.open(packet, "telemetry.event") == b"secret"
    authority.close()


def test_bad_signature_and_modified_certificate_are_rejected_without_aliasing():
    authority, sender, receiver = local()
    packet = sender.seal(b"secret", receiver, "telemetry.event")
    bad = copy.deepcopy(packet)
    bad["signature"] = mesh._b64(b"x" * 64)
    with pytest.raises(mesh.MeshError, match="signature"):
        receiver.open(bad, "telemetry.event")
    packet["header"]["certificate"]["body"]["label"] = "forged"
    assert sender.label == "module.scanner"
    with pytest.raises(mesh.MeshError):
        receiver.open(packet, "telemetry.event")
    assert receiver.open(sender.seal(b"valid", receiver), "telemetry.event") == b"valid"
    authority.close()


def test_cross_receiver_and_foreign_authority_are_rejected():
    authority, sender, receiver = local()
    other = authority.enroll("other.receiver")
    packet = sender.seal(b"private", receiver)
    with pytest.raises(mesh.MeshError):
        other.open(packet)
    foreign, foreign_sender, _foreign_receiver = local()
    with pytest.raises(mesh.MeshError, match="not enrolled"):
        foreign_sender.seal(b"x", receiver)
    with pytest.raises(mesh.MeshError, match="bound capability"):
        receiver.open(packet, expected_sender=other)
    authority.close()
    foreign.close()


def test_frozen_default_gate_revocation_and_thaw_generate_fresh_keys():
    clock, approved = Clock(), [True]
    authority, sender, receiver = local(clock, lambda: approved[0], verified=False)
    with pytest.raises(mesh.MeshFrozen):
        sender.seal(b"blocked", receiver)
    authority.set_verified(True)
    old = sender.seal(b"valid", receiver)
    assert receiver.open(old) == b"valid"
    old_x, old_key = sender._x, next(iter(sender._keys.values()))
    approved[0] = False
    with pytest.raises(mesh.MeshFrozen):
        sender.seal(b"blocked", receiver)
    assert not any(old_x) and not any(old_key)
    approved[0] = True
    authority.set_verified(True)
    with pytest.raises(mesh.MeshError):
        receiver.open(old)
    assert receiver.open(sender.seal(b"new", receiver)) == b"new"
    authority.close()


def test_rotation_replaces_both_x25519_keys_and_erases_mutable_buffers():
    clock = Clock()
    authority, sender, receiver = local(clock)
    old = sender.seal(b"old", receiver)
    old_x, old_key = sender._x, next(iter(sender._keys.values()))
    public = [peer._local_cert["body"]["x25519"] for peer in (sender, receiver)]
    clock.value += 10
    authority.tick()
    assert [peer._local_cert["body"]["x25519"] for peer in (sender, receiver)] != public
    assert not any(old_x) and not any(old_key)
    with pytest.raises(mesh.MeshError):
        receiver.open(old)
    assert receiver.open(sender.seal(b"fresh", receiver)) == b"fresh"
    authority.close()


def test_nonce_uniqueness_expiry_strict_bounds_and_sequence_limit():
    clock = Clock()
    authority, sender, receiver = local(clock)
    packets = [sender.seal(b"x", receiver, purpose) for purpose in ["event.one", "event.two"] * 5]
    assert len({packet["header"]["nonce"] for packet in packets}) == 10
    clock.value += 4
    with pytest.raises(mesh.MeshError):
        receiver.open(packets[-1], "event.two")
    with pytest.raises(mesh.MeshError):
        sender.seal(b"x" * (mesh.LOCAL_MAX_PAYLOAD + 1), receiver)
    sender._sequence = 2**63 - 1
    with pytest.raises(mesh.MeshError, match="sequence"):
        sender.seal(b"x", receiver)
    authority.close()


def test_atomic_transaction_concurrency_and_boundary_refresh():
    clock = Clock()
    authority, sender, receiver = local(clock)
    clock.value += 9.999
    with authority.transaction():
        packet = sender.seal(b"boundary", receiver)
        clock.value += 0.002
        assert receiver.open(packet) == b"boundary"
    def exchange(index):
        with authority.transaction():
            data = str(index).encode()
            return receiver.open(sender.seal(data, receiver)) == data
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert all(pool.map(exchange, range(100)))
    authority.close()


def test_authority_session_auto_renewal_preserves_bound_handles_and_changes_identity():
    clock = Clock()
    authority, sender, receiver = local(clock)
    old_packet = sender.seal(b"old", receiver)
    old_ca, old_ed, old_session = authority._ca_public, sender._local_identity["body"]["ed25519"], authority.session
    clock.value += 3600
    authority.tick()
    assert authority.session != old_session and authority._ca_public != old_ca
    assert sender._local_identity["body"]["ed25519"] != old_ed
    with pytest.raises(mesh.MeshError):
        receiver.open(old_packet)
    assert receiver.open(sender.seal(b"renewed", receiver)) == b"renewed"
    assert authority.snapshot()["session_expires"] > clock.value
    authority.close()


def cross(clock=None, **kwargs):
    clock = clock or time.monotonic
    parent, bootstrap = mesh.CrossProcessMeshChannel.create_pair(verified=True, clock=clock, **kwargs)
    child = mesh.CrossProcessMeshChannel.from_bootstrap(json.loads(json.dumps(bootstrap)), verified=True, clock=clock)
    return parent, child, bootstrap


def handshake(parent, child):
    proposal = parent.control_frames()[0]
    reply = child.accept_control(proposal)[0]
    commit = parent.accept_control(reply)[0]
    ack = child.accept_control(commit)[0]
    with pytest.raises(mesh.MeshHandshakeRequired):
        child.seal(b"cannot overtake ack", "ugcap.response")
    child.control_sent(ack)
    assert parent.accept_control(ack) == []
    return proposal, reply, commit, ack


def test_private_bootstrap_roundtrip_and_snapshots_have_no_key_material():
    parent, child, bootstrap = cross()
    assert child.open(parent.seal(b"command", "ugcap.request"), "ugcap.request") == b"command"
    assert parent.open(child.seal(b"response", "ugcap.response"), "ugcap.response") == b"response"
    snapshot = json.dumps(parent.snapshot())
    for name in ("signing_private", "exchange_private", "ca_public"):
        assert bootstrap[name] not in snapshot
    bootstrap["remote_cert"]["body"]["label"] = "tampered"
    assert parent._local_cert["body"]["label"] == "ugcap.parent"
    parent.close()
    child.close()


def test_crossprocess_rekey_is_fresh_both_sides_and_rejects_old_packets_control_replay():
    clock = Clock()
    parent, child, _bootstrap = cross(clock)
    old_packet = parent.seal(b"old", "ugcap.request")
    old_keys = (parent._x, child._x)
    previous_public = (parent._local_cert["body"]["x25519"], child._local_cert["body"]["x25519"])
    clock.value += 9.0
    frames = handshake(parent, child)
    assert (parent._local_cert["body"]["x25519"], child._local_cert["body"]["x25519"]) != previous_public
    assert all(not any(value) for value in old_keys)
    assert parent.snapshot()["epoch"] == child.snapshot()["epoch"] == 1
    with pytest.raises(mesh.MeshError):
        child.open(old_packet, "ugcap.request")
    for endpoint, frame in ((child, frames[0]), (parent, frames[1]), (child, frames[2]), (parent, frames[3])):
        with pytest.raises(mesh.MeshError):
            endpoint.accept_control(frame)
    assert child.open(parent.seal(b"new", "ugcap.request"), "ugcap.request") == b"new"
    parent.close()
    child.close()


def test_quiescence_prevents_old_epoch_sends_at_boundary():
    clock = Clock()
    parent, child, _bootstrap = cross(clock)
    clock.value += 9.999
    with pytest.raises(mesh.MeshHandshakeRequired):
        parent.seal(b"late", "ugcap.request")
    handshake(parent, child)
    clock.value += 0.002
    assert child.open(parent.seal(b"new", "ugcap.request"), "ugcap.request") == b"new"
    parent.close()
    child.close()


def test_invalid_bootstrap_and_cross_session_are_rejected():
    parent, child, bootstrap = cross()
    bad = copy.deepcopy(bootstrap)
    bad["exchange_private"] = mesh._b64(b"x" * 32)
    with pytest.raises(mesh.MeshError):
        mesh.CrossProcessMeshChannel.from_bootstrap(bad, verified=True)
    stranger, _stranger_bootstrap = mesh.CrossProcessMeshChannel.create_pair(verified=True)
    with pytest.raises(mesh.MeshError):
        stranger.open(child.seal(b"secret", "ugcap.response"), "ugcap.response")
    with pytest.raises(mesh.MeshError):
        mesh.decode_frame(b'{"same":1,"same":2}')
    parent.close()
    child.close()
    stranger.close()


@pytest.fixture
def pipe_pair():
    opened = []
    def build(**kwargs):
        clock = kwargs.pop("clock", time.monotonic)
        gate = kwargs.pop("gate", None)
        parent, bootstrap = mesh.CrossProcessMeshChannel.create_pair(verified=True, gate=gate, clock=clock, **kwargs)
        child = mesh.CrossProcessMeshChannel.from_bootstrap(bootstrap, verified=True, gate=gate, clock=clock)
        child_read, parent_write = os.pipe()
        parent_read, child_write = os.pipe()
        streams = [os.fdopen(parent_read, "rb"), os.fdopen(parent_write, "wb"),
                   os.fdopen(child_read, "rb"), os.fdopen(child_write, "wb")]
        purposes = {"ugcap.request", "ugcap.response"}
        first = mesh.MeshPipe(parent, streams[0], streams[1], allowed_purposes=purposes)
        second = mesh.MeshPipe(child, streams[2], streams[3], allowed_purposes=purposes)
        opened.append((first, second, streams))
        return first, second
    yield build
    for first, second, streams in opened:
        first.close()
        second.close()
        streams[1].close()
        streams[3].close()
        first._reader_thread.join(2)
        second._reader_thread.join(2)
        streams[0].close()
        streams[2].close()


def wait_until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "bounded mesh condition did not occur"


def test_pipe_rotates_during_idle_application_and_concurrent_messages(pipe_pair):
    parent, child = pipe_pair(rotation_seconds=0.5)
    wait_until(lambda: parent.endpoint.snapshot()["epoch"] >= 2 and child.endpoint.snapshot()["epoch"] >= 2)
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda index: parent.send(str(index).encode(), "ugcap.request"), range(30)))
    assert {child.receive("ugcap.request", timeout=2) for _ in range(30)} == {str(i).encode() for i in range(30)}
    child.send(b"response", "ugcap.response")
    assert parent.receive("ugcap.response", timeout=2) == b"response"


def test_pipe_supports_large_bounded_attestation_and_rejects_oversize(pipe_pair):
    parent, child = pipe_pair()
    payload = b"v" * (2 * 1024 * 1024)
    parent.send(payload, "ugcap.request")
    assert child.receive("ugcap.request", timeout=3) == payload
    with pytest.raises(mesh.MeshError):
        parent.send(b"x" * (mesh.MAX_PAYLOAD + 1), "ugcap.request")


def test_queued_plaintext_cannot_escape_gate_revocation_or_expiry(pipe_pair):
    approved = [True]
    parent, child = pipe_pair(gate=lambda: approved[0])
    child.send(b"queued", "ugcap.response")
    wait_until(lambda: parent.snapshot()["queued"] == 1)
    approved[0] = False
    with pytest.raises(mesh.MeshFrozen):
        parent.receive("ugcap.response", timeout=0.1)
    wait_until(lambda: parent.snapshot()["closed"])
    assert parent.snapshot()["queued"] == 0

    clock = Clock()
    other, remote = pipe_pair(clock=clock)
    remote.send(b"expires", "ugcap.response")
    wait_until(lambda: other.snapshot()["queued"] == 1)
    clock.value += 4
    with pytest.raises(TimeoutError):
        other.receive("ugcap.response", timeout=0.05)
    assert other.snapshot()["queued"] == 0


def test_blocked_os_writer_cannot_block_send_past_timeout():
    parent, _bootstrap = mesh.CrossProcessMeshChannel.create_pair(verified=True)
    release = threading.Event()
    class Reader:
        def readline(self, _limit):
            release.wait(3)
            return b""
    class Writer:
        def write(self, _data):
            release.wait(3)
        def flush(self):
            pass
    channel = mesh.MeshPipe(parent, Reader(), Writer(), allowed_purposes={"ugcap.request"})
    before = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            channel.send(b"blocked", "ugcap.request", timeout=0.1)
        assert time.monotonic() - before < 0.75
        assert channel.snapshot()["closed"]
    finally:
        release.set()
        channel.close()
        channel._writer_thread.join(2)
        channel._reader_thread.join(2)


def test_real_subprocess_anonymous_bootstrap_and_rotation():
    parent, bootstrap = mesh.CrossProcessMeshChannel.create_pair(verified=True, rotation_seconds=1)
    source = str(Path(mesh.__file__).resolve().parents[2])
    code = (
        "import sys,time;"
        f"sys.path.insert(0,{source!r});"
        "from angerona.core.enclave_mesh import CrossProcessMeshChannel,MeshPipe,decode_frame;"
        "boot=decode_frame(sys.stdin.buffer.readline(100000));"
        "endpoint=CrossProcessMeshChannel.from_bootstrap(boot,verified=True);"
        "pipe=MeshPipe(endpoint,sys.stdin.buffer,sys.stdout.buffer,allowed_purposes={'ugcap.request','ugcap.response'});"
        "pipe.send(b'ready','ugcap.response');"
        "request=pipe.receive('ugcap.request',timeout=5);time.sleep(1.3);"
        "pipe.send(request[::-1],'ugcap.response');"
        "pipe.receive('ugcap.request',timeout=5);pipe.close()"
    )
    process = subprocess.Popen([sys.executable, "-I", "-c", code], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    process.stdin.write(mesh.canonical(bootstrap) + b"\n")
    process.stdin.flush()
    pipe = mesh.MeshPipe(parent, process.stdout, process.stdin, allowed_purposes={"ugcap.request", "ugcap.response"})
    try:
        assert pipe.receive("ugcap.response", timeout=5) == b"ready"
        pipe.send(b"bound command", "ugcap.request")
        assert pipe.receive("ugcap.response", timeout=5) == b"dnammoc dnuob"
        assert parent.snapshot()["epoch"] >= 1
        pipe.send(b"stop", "ugcap.request")
        assert process.wait(timeout=5) == 0
        assert not process.stderr.read()
    finally:
        pipe.close()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        process.stdin.close()
        pipe._reader_thread.join(2)
        process.stdout.close()
        process.stderr.close()
