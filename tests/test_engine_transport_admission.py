"""Engine IPC admission/mutual proofs with inert sockets, clocks and workers."""
from __future__ import annotations

import struct
import threading
from types import SimpleNamespace

import pytest

from angerona.core import engine_transport as transport
from ipc_transcript_fixture import InertListener, InertThread, TranscriptSocket, frame


@pytest.fixture
def controlled_server(tmp_path, monkeypatch):
    clock = SimpleNamespace(now=100.0)
    monkeypatch.setattr(transport, "time", SimpleNamespace(monotonic=lambda: clock.now))
    monkeypatch.setattr(transport, "private_directory", lambda path: path)
    monkeypatch.setattr(transport, "read_discovery", lambda _path: (_ for _ in ()).throw(transport.EngineError("fixture has no discovery")))
    current = [object()]
    workers = []

    def thread_factory(**kwargs):
        worker = InertThread(**kwargs)
        original_run = worker.run

        def run():
            prior, current[0] = current[0], worker
            try:
                return original_run()
            finally:
                current[0] = prior

        worker.run = run
        workers.append(worker)
        return worker

    facade = SimpleNamespace(Event=threading.Event, RLock=threading.RLock,
                             BoundedSemaphore=threading.BoundedSemaphore,
                             Thread=thread_factory, current_thread=lambda: current[0])
    monkeypatch.setattr(transport, "threading", facade)

    def create(clients, dispatch=lambda request: dict(request), *, fail_start=False):
        listener = InertListener(clients)
        monkeypatch.setattr(transport.socket, "socket", lambda *_a, **_k: listener)
        server = transport.EngineServer(tmp_path / "unused-private-fixture", dispatch)
        if fail_start:
            original_factory = facade.Thread

            def fail(**kwargs):
                worker = original_factory(**kwargs)
                worker.fail_start = kwargs.get("name") == "EngineExchange"
                return worker

            facade.Thread = fail
        return server, listener, workers, clock

    return create


def available(semaphore, limit):
    taken = sum(semaphore.acquire(blocking=False) for _ in range(limit + 1))
    for _ in range(taken):
        semaphore.release()
    return taken


def valid_peer(server, request=None, *, bad=None):
    nonce = "a" * 32
    hello = {"protocol": transport.PROTOCOL, "instance": server.instance, "nonce": nonce}
    if bad == "v1":
        hello["protocol"] = "angerona-local-engine-v1"

    def respond(peer, proof):
        if len(peer.sent) != 1:
            return
        body = transport._verify(proof, server.key, transport._HELLO_DOMAIN)
        reply = {"instance": server.instance, "challenge": body["challenge"],
                 "nonce": nonce, "request": request or {"operation": "status"}}
        if bad == "nonce":
            reply["nonce"] = "b" * 32
        envelope = transport._wrap(reply, b"x" * 32 if bad == "key" else server.key,
                                   transport._REQUEST_DOMAIN)
        if bad == "unicode-mac":
            envelope["mac"] = "é" * 64
        if bad == "reflection":
            envelope = proof
        peer.incoming.extend(frame(envelope))

    return TranscriptSocket(frame(hello), respond)


def test_four_idle_pre_auth_peers_do_not_occupy_authenticated_dispatch(controlled_server):
    dispatches = []
    server, listener, workers, _clock = controlled_server([], lambda request: dispatches.append(request) or {"ok": "observed"})
    idle = [TranscriptSocket() for _ in range(4)]
    good = valid_peer(server)
    listener.accepted = idle + [good]
    server._loop()
    assert server.admission_snapshot()["preauth_pending"] == 5
    assert available(server.slots, transport.MAX_EXCHANGES) == transport.MAX_EXCHANGES
    next(worker for worker in workers if worker.args and worker.args[0] is good).run()
    assert dispatches == [{"operation": "status"}]
    response = transport._verify(good.sent[-1], server.key, transport._RESPONSE_DOMAIN)
    assert response["ok"] is True
    assert server.admission_snapshot()["preauth_pending"] == 4
    server.close()
    assert not server._workers and not server._clients
    assert available(server.preauth_slots, transport.MAX_PREAUTH) == transport.MAX_PREAUTH
    assert available(server.slots, transport.MAX_EXCHANGES) == transport.MAX_EXCHANGES


def test_pre_auth_pool_and_total_retained_workers_are_finite(controlled_server):
    clients = [TranscriptSocket() for _ in range(transport.MAX_PREAUTH + 100)]
    server, _listener, workers, _clock = controlled_server(clients)
    server._loop()
    assert len([worker for worker in workers if worker.name == "EngineExchange"]) == transport.MAX_PREAUTH
    assert server.admission_snapshot()["preauth_pending"] == transport.MAX_PREAUTH
    assert all(client.closed for client in clients[transport.MAX_PREAUTH:])
    assert available(server.slots, transport.MAX_EXCHANGES) == transport.MAX_EXCHANGES
    server.close()
    assert not server._workers and not server._clients


def test_worker_start_failure_closes_only_owned_client_and_restores_admission(controlled_server):
    clients = [TranscriptSocket(), TranscriptSocket()]
    server, _listener, _workers, _clock = controlled_server(clients, fail_start=True)
    server._loop()
    snapshot = server.admission_snapshot()
    assert snapshot["worker_start_failures"] == 2 and snapshot["preauth_pending"] == 0
    assert all(client.closed for client in clients)
    assert not server._workers and not server._clients
    assert available(server.preauth_slots, transport.MAX_PREAUTH) == transport.MAX_PREAUTH
    assert available(server.slots, transport.MAX_EXCHANGES) == transport.MAX_EXCHANGES
    server.close()


def test_admission_expiry_is_bound_to_accept_not_later_worker_schedule(controlled_server):
    server, listener, workers, clock = controlled_server([])
    peer = valid_peer(server)
    listener.accepted = [peer]
    server._loop()
    clock.now += transport.PREAUTH_TIMEOUT + 1
    next(worker for worker in workers if worker.name == "EngineExchange").run()
    assert peer.closed and not peer.sent and peer.recv_calls == 0
    assert server.admission_snapshot()["preauth_pending"] == 0
    server.close()


@pytest.mark.parametrize("bad", ["key", "nonce", "unicode-mac", "reflection", "v1"])
def test_invalid_pre_auth_proof_never_gets_dispatch_capacity(controlled_server, bad):
    dispatched = []
    server, listener, workers, _clock = controlled_server([], lambda request: dispatched.append(request) or {})
    peer = valid_peer(server, bad=bad)
    listener.accepted = [peer]
    server._loop()
    next(worker for worker in workers if worker.name == "EngineExchange").run()
    assert not dispatched and peer.closed
    assert server.admission_snapshot()["authenticated_pending"] == 0
    assert available(server.slots, transport.MAX_EXCHANGES) == transport.MAX_EXCHANGES
    server.close()


def test_authenticated_busy_reply_is_signed_without_dispatch_or_slot_leak(controlled_server):
    server, listener, workers, _clock = controlled_server([])
    for _ in range(transport.MAX_EXCHANGES):
        assert server.slots.acquire(blocking=False)
    peer = valid_peer(server)
    listener.accepted = [peer]
    server._loop()
    next(worker for worker in workers if worker.name == "EngineExchange").run()
    body = transport._verify(peer.sent[-1], server.key, transport._RESPONSE_DOMAIN)
    assert body["ok"] is False and "busy" in body["error"]
    assert available(server.preauth_slots, transport.MAX_PREAUTH) == transport.MAX_PREAUTH
    for _ in range(transport.MAX_EXCHANGES):
        server.slots.release()
    server.close()


def test_close_keeps_unfinished_owned_worker_visible_and_does_not_reassign_slots(controlled_server):
    peer = TranscriptSocket()
    server, _listener, workers, _clock = controlled_server([peer])
    server._loop()
    worker = next(worker for worker in workers if worker.name == "EngineExchange")
    worker.run_on_join = False
    server.close()
    snapshot = server.admission_snapshot()
    assert peer.closed and snapshot["state"] == "closing"
    assert snapshot["retirement_pending"] == 1 and snapshot["preauth_pending"] == 1
    assert available(server.preauth_slots, transport.MAX_PREAUTH) == transport.MAX_PREAUTH - 1
    worker.run()
    assert not server._workers and server.admission_snapshot()["preauth_pending"] == 0


def test_unconfirmed_socket_close_holds_admission_without_retrying_unknown_object(controlled_server):
    peer = TranscriptSocket()
    peer.close_error = True
    server, _listener, _workers, _clock = controlled_server([peer])
    server._loop()
    server.close()
    snapshot = server.admission_snapshot()
    assert snapshot["state"] == "held" and snapshot["unclosed_connections"] == 1
    assert peer in server._clients and peer.close_calls == 1
    server.close()
    assert peer.close_calls == 1 and peer.shutdown_calls == 1


def test_frame_header_and_payload_share_one_absolute_deadline(monkeypatch):
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(transport, "time", SimpleNamespace(monotonic=lambda: clock.now))
    peer = TranscriptSocket(frame({"ok": True}))
    recv = peer.recv

    def delayed(count):
        clock.now += 0.75 if peer.recv_calls == 0 else 0.4
        return recv(count)

    peer.recv = delayed
    with pytest.raises(transport.EngineError, match="deadline"):
        transport.receive(peer, 1024, deadline=1.0)
    assert peer.timeouts == pytest.approx([1.0, 0.25])


def test_oversized_initial_hello_is_refused_before_body_allocation(controlled_server):
    peer = TranscriptSocket(struct.pack("!I", transport.MAX_HELLO + 1))
    server, _listener, workers, _clock = controlled_server([peer])
    server._loop()
    next(worker for worker in workers if worker.name == "EngineExchange").run()
    assert peer.recv_calls == 1 and peer.closed and not peer.sent
    server.close()


@pytest.mark.parametrize("damage", ["key", "nonce", "role", "v1"])
def test_client_sends_no_secret_dependent_request_before_valid_server_proof(monkeypatch, tmp_path, damage):
    import psutil
    key, instance = b"k" * 32, "a" * 32
    record = dict(protocol=transport.PROTOCOL, port=43210, key=key.hex(), instance=instance,
                  pid=123, created=1.0)
    monkeypatch.setattr(transport, "read_discovery", lambda _directory: record)
    monkeypatch.setattr(psutil, "Process", lambda _pid: SimpleNamespace(create_time=lambda: 1.0))

    def respond(peer, hello):
        assert "mac" not in hello
        proof = dict(hello, challenge="b" * 64)
        if damage == "nonce":
            proof["nonce"] = "c" * 32
        response = transport._wrap(proof, b"x" * 32 if damage == "key" else key,
                                   transport._REQUEST_DOMAIN if damage == "role" else transport._HELLO_DOMAIN)
        if damage == "v1":
            response = {"protocol": "angerona-local-engine-v1", "instance": instance, "challenge": "b" * 64}
        peer.incoming.extend(frame(response))

    peer = TranscriptSocket(on_send=respond)
    monkeypatch.setattr(transport.socket, "create_connection", lambda *_a, **_k: peer)
    with pytest.raises(transport.EngineError):
        transport.exchange(tmp_path, {"operation": "stop_engine", "confirmation": "stop-protection"})
    assert len(peer.sent) == 1 and "mac" not in peer.sent[0] and peer.closed


def test_client_valid_mutual_transcript_binds_response_nonce_and_instance(monkeypatch, tmp_path):
    import psutil
    key, instance = b"k" * 32, "a" * 32
    record = dict(protocol=transport.PROTOCOL, port=43210, key=key.hex(), instance=instance,
                  pid=123, created=1.0)
    monkeypatch.setattr(transport, "read_discovery", lambda _directory: record)
    monkeypatch.setattr(psutil, "Process", lambda _pid: SimpleNamespace(create_time=lambda: 1.0))

    def respond(peer, message):
        if len(peer.sent) == 1:
            peer.incoming.extend(frame(transport._wrap(dict(message, challenge="b" * 64), key, transport._HELLO_DOMAIN)))
        else:
            body = transport._verify(message, key, transport._REQUEST_DOMAIN)
            assert body["request"] == {"operation": "status"}
            peer.incoming.extend(frame(transport._wrap(dict(instance=instance, nonce=body["nonce"],
                challenge=body["challenge"], ok=True, result={"state": "ready"}), key, transport._RESPONSE_DOMAIN)))

    peer = TranscriptSocket(on_send=respond)
    monkeypatch.setattr(transport.socket, "create_connection", lambda *_a, **_k: peer)
    assert transport.exchange(tmp_path, {"operation": "status"}) == {"state": "ready"}
    assert len(peer.sent) == 2 and peer.closed


def test_worker_constructor_failure_restores_exact_pre_auth_ownership(controlled_server, monkeypatch):
    peer = TranscriptSocket()
    server, _listener, _workers, _clock = controlled_server([peer])
    monkeypatch.setattr(transport.threading, "Thread", lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("fixture allocation failed")))
    server._loop()
    assert peer.closed and not server._clients and not server._workers
    assert server.admission_snapshot()["worker_start_failures"] == 1
    assert available(server.preauth_slots, transport.MAX_PREAUTH) == transport.MAX_PREAUTH
    assert available(server.slots, transport.MAX_EXCHANGES) == transport.MAX_EXCHANGES
    server.close()


@pytest.mark.parametrize("close_fails", [False, True])
def test_concurrent_worker_and_server_close_have_one_exact_object_owner(controlled_server, close_fails):
    server, listener, _workers, _clock = controlled_server([])
    peer = TranscriptSocket()
    peer.close_error = close_fails
    server._clients.add(peer)
    entered, release = threading.Event(), threading.Event()
    attempts, errors = [], []
    close = peer.close

    def blocked_close():
        attempts.append("exact-object-close")
        entered.set()
        if not release.wait(timeout=3.0):
            raise AssertionError("fixture close owner was not released")
        close()

    def worker_finally():
        try:
            server._retire_client(peer)
        except BaseException as error:
            errors.append(error)

    peer.close = blocked_close
    owner = threading.Thread(target=worker_finally, name="inert-exact-close-owner")
    owner.start()
    try:
        assert entered.wait(timeout=3.0)
        # A second worker finalizer and the server close overlap the first
        # owner's native-close return window. Neither may close/shutdown it.
        server._retire_client(peer)
        active = server.admission_snapshot()
        assert active["state"] == "busy" and active["closing_connections"] == 1
        assert active["unclosed_connections"] == 0
        server.close()
        pending = server.admission_snapshot()
        assert pending["state"] == "closing" and pending["closing_connections"] == 1
        assert attempts == ["exact-object-close"] and peer.shutdown_calls == 0
    finally:
        release.set()
        owner.join(timeout=3.0)
    assert not owner.is_alive() and not errors
    finished = server.admission_snapshot()
    assert finished["closing_connections"] == 0 and peer.close_calls == 1
    if close_fails:
        assert finished["state"] == "held" and peer in server._unclosed_clients
        assert peer in server._clients
    else:
        assert finished["state"] == "closed" and peer.closed
        assert not server._clients and not server._unclosed_clients
    # Stale snapshots after a successful close must not create a new owner.
    server._retire_client(peer)
    server.close()
    assert attempts == ["exact-object-close"] and listener.close_calls == 1
