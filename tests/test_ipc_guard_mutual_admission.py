"""AUTH v2 mutual proofs and degraded retry under private inert transports."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from angerona.core import config, engine_transport as transport
from angerona.modules import ipc_guard as guard
from ipc_transcript_fixture import InertListener, InertThread, TranscriptSocket, frame


KEY = b"k" * 32


def test_private_mutual_codec_accepts_only_matching_key_and_has_no_socket_effect(monkeypatch):
    module = guard.IpcGuardModule()
    module._key, module.accepted, module.denied = b"p" * 32, 7, 11
    monkeypatch.setattr(guard.socket, "socket", lambda *_a, **_k: pytest.fail("codec proof must not bind"))
    monkeypatch.setattr(guard.socket, "create_connection", lambda *_a, **_k: pytest.fail("codec proof must not connect"))
    assert module._probe_exchange(KEY, KEY)
    assert not module._probe_exchange(b"x" * 32, KEY)
    ok, detail = module.self_test()
    assert ok and "live TCP routing unverified" in detail
    assert (module._key, module.accepted, module.denied) == (b"p" * 32, 7, 11)


@pytest.mark.parametrize("damage", ["key", "role", "nonce", "v1", "non-ascii-mac"])
def test_no_client_mac_before_server_proof_for_its_fresh_nonce(monkeypatch, damage):
    def respond(peer, hello):
        assert set(hello) == {"protocol", "nonce"} and "mac" not in hello
        proof = guard._server_proof(hello, b"x" * 32 if damage == "key" else KEY)
        if damage == "role":
            proof = transport._wrap(proof["body"], KEY, guard._CLIENT_DOMAIN)
        elif damage == "nonce":
            proof = transport._wrap(dict(proof["body"], nonce="b" * 32), KEY, guard._SERVER_DOMAIN)
        elif damage == "v1":
            proof = {"challenge": "raw-untrusted-nonce"}
        elif damage == "non-ascii-mac":
            proof["mac"] = "é" * 64
        peer.incoming.extend(frame(proof))

    peer = TranscriptSocket(on_send=respond)
    monkeypatch.setattr(guard, "sign", lambda *_a: pytest.fail("network path must not answer raw-nonce signing oracle"))
    with pytest.raises(transport.EngineError):
        guard._authenticate_socket(peer, KEY)
    assert len(peer.sent) == 1 and "mac" not in peer.sent[0]


def test_complete_framed_mutual_exchange_accepts_authenticated_ack():
    captured = {}

    def respond(peer, message):
        if len(peer.sent) == 1:
            captured["proof"] = guard._server_proof(message, KEY)
            peer.incoming.extend(frame(captured["proof"]))
        else:
            peer.incoming.extend(frame(guard._server_accept(captured["proof"], message, KEY)))

    peer = TranscriptSocket(on_send=respond)
    assert guard._authenticate_socket(peer, KEY)
    assert len(peer.sent) == 2
    assert transport._verify(peer.sent[1], KEY, guard._CLIENT_DOMAIN) == captured["proof"]["body"]


@pytest.mark.parametrize("damage", ["nonce", "role", "accepted"])
def test_server_ack_cannot_be_replaced_or_reflected(damage):
    hello = {"protocol": guard._AUTH_PROTOCOL, "nonce": "a" * 32}
    proof = guard._server_proof(hello, KEY)
    reply = guard._client_proof(proof, hello, KEY)
    ack = guard._server_accept(proof, reply, KEY)
    if damage == "nonce":
        ack = transport._wrap(dict(ack["body"], nonce="b" * 32), KEY, guard._ACK_DOMAIN)
    elif damage == "role":
        ack = reply
    else:
        ack = transport._wrap(dict(ack["body"], accepted=False), KEY, guard._ACK_DOMAIN)
    with pytest.raises(transport.EngineError):
        guard._client_accept(ack, proof, KEY)


def test_replay_and_server_to_client_reflection_are_rejected():
    hello = {"protocol": guard._AUTH_PROTOCOL, "nonce": "a" * 32}
    old = guard._server_proof(hello, KEY)
    reply = guard._client_proof(old, hello, KEY)
    fresh = guard._server_proof(hello, KEY)
    assert old["body"]["challenge"] != fresh["body"]["challenge"]
    for response in (reply, fresh):
        with pytest.raises(transport.EngineError):
            guard._server_accept(fresh, response, KEY)


@pytest.mark.parametrize("bad", [False, True])
def test_real_handler_logic_uses_bounded_framed_v2_and_keeps_result_counters(bad, monkeypatch):
    module = guard.IpcGuardModule()
    module._key = KEY
    emitted = []
    monkeypatch.setattr(module, "emit", lambda *args, **kwargs: emitted.append((args, kwargs)))
    hello = {"protocol": guard._AUTH_PROTOCOL, "nonce": "a" * 32}

    def respond(peer, proof):
        if len(peer.sent) != 1:
            return
        reply = guard._client_proof(proof, hello, KEY)
        if bad:
            reply["mac"] = "0" * 64
        peer.incoming.extend(frame(reply))

    peer = TranscriptSocket(frame(hello), respond)
    module._serve_conn(peer, ("127.0.0.1", 1234))
    assert peer.closed and peer.close_calls == 1
    assert module.accepted == (0 if bad else 1)
    assert module.denied == (1 if bad else 0)
    if bad:
        assert emitted[0][1]["response_authorized"] is False
    else:
        assert peer.sent[-1]["body"]["accepted"] is True


def test_raw_v1_or_truncated_frame_is_denied_without_server_signing(monkeypatch):
    module = guard.IpcGuardModule()
    module._key = KEY
    monkeypatch.setattr(module, "emit", lambda *_a, **_k: None)
    for raw in (b"CHALLENGE old-nonce\n", b"\x00\x00"):
        peer = TranscriptSocket(raw)
        module._serve_conn(peer, "fixture")
        assert peer.closed and not peer.sent
    assert module.denied == 2 and module.accepted == 0


@pytest.mark.parametrize("port,host", [(0, guard._HOST), (65432, "example.invalid"), (True, guard._HOST)])
def test_client_requires_explicit_valid_loopback_endpoint_without_fallback(monkeypatch, port, host):
    monkeypatch.setattr(guard.socket, "create_connection", lambda *_a, **_k: pytest.fail("no ambient endpoint fallback"))
    assert guard.authenticate(KEY, host, port) is False


def generation_fixture(tmp_path, monkeypatch, *, worker_alive=True):
    module = guard.IpcGuardModule()
    generation = guard._IpcGeneration(threading.Event())
    listener = InertListener()
    workers = []
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(config, "Config", lambda: SimpleNamespace(data_dir=tmp_path))
    monkeypatch.setattr(guard, "_load_or_create_key", lambda _path: KEY)
    monkeypatch.setattr(guard.socket, "socket", lambda *_a, **_k: listener)
    monkeypatch.setattr(guard, "time", SimpleNamespace(monotonic=lambda: clock.now))

    def thread_factory(**kwargs):
        worker = InertThread(**kwargs)
        original = worker.start

        def start():
            original()
            worker.alive = worker_alive

        worker.start = start
        workers.append(worker)
        return worker

    monkeypatch.setattr(guard, "threading", SimpleNamespace(Thread=thread_factory))
    return module, generation, listener, workers, clock


def test_probe_failure_stays_visible_degraded_then_retries_without_crash(tmp_path, monkeypatch):
    module, generation, listener, workers, clock = generation_fixture(tmp_path, monkeypatch)
    checks, observations, events = [], [], []
    outcomes = iter((False, True))

    def probe(*_args):
        checks.append(clock.now)
        return next(outcomes)

    def sleep(_seconds):
        observations.append((clock.now, module.health, module.health_note))
        clock.now += 5.0
        if len(observations) == 7:
            generation.generation_stop.set()

    monkeypatch.setattr(module, "_probe_exchange", probe)
    monkeypatch.setattr(module, "sleep", sleep)
    monkeypatch.setattr(module, "emit", lambda *args, **kwargs: events.append((args, kwargs)))
    module._run_generation(generation)
    assert checks == [0.0, 30.0]
    assert all(health == 20 for _when, health, _note in observations[:6])
    assert observations[-1][1] == 100 and "live TCP routing unverified" in observations[-1][2]
    assert module._crash_count == 0 and generation.fatal_error == "" and generation.probe_ok
    assert module.last_error == ""
    failures = [event for event in events if event[1].get("finding_code") == "ipc.diagnostic.codec-unavailable"]
    assert len(failures) == 1 and failures[0][1]["response_authorized"] is False
    assert listener.bound == (guard._HOST, 0)
    assert all(option[1] != guard.socket.SO_REUSEADDR for option in listener.options)
    if guard.os.name == "nt":
        assert (guard.socket.SOL_SOCKET, guard.socket.SO_EXCLUSIVEADDRUSE, 1) in listener.options
    workers[0].alive = False
    generation.retire()


def test_probe_exception_is_degraded_not_a_worker_crash(tmp_path, monkeypatch):
    module, generation, _listener, workers, _clock = generation_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "_probe_exchange", lambda *_a: (_ for _ in ()).throw(RuntimeError("fixture codec unavailable")))
    monkeypatch.setattr(module, "emit", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "sleep", lambda _seconds: generation.generation_stop.set())
    module._run_generation(generation)
    assert module.health == 20 and generation.fatal_error == ""
    assert module._crash_count == 0 and "unavailable" in generation.probe_error
    workers[0].alive = False
    generation.retire()


def test_genuine_accept_worker_death_remains_a_generation_failure(tmp_path, monkeypatch):
    module, generation, _listener, _workers, _clock = generation_fixture(tmp_path, monkeypatch, worker_alive=False)
    monkeypatch.setattr(module, "emit", lambda *_a, **_k: None)
    with pytest.raises(RuntimeError, match="listener accept worker exited"):
        module._run_generation(generation)
    assert module.health == 20 and generation.fatal_error
    generation.retire()


def test_auth_worker_constructor_failure_closes_owned_peer_and_restores_slots(monkeypatch):
    module = guard.IpcGuardModule()
    generation = guard._IpcGeneration(threading.Event())
    peer = TranscriptSocket()
    generation.srv = InertListener([peer])
    monkeypatch.setattr(module, "emit", lambda *_a, **_k: None)
    monkeypatch.setattr(guard, "threading", SimpleNamespace(Thread=lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("fixture allocation failed"))))
    module._accept_loop(generation)
    assert peer.closed and not generation.helpers and not generation.connections
    assert generation.fatal_error and generation.helper_stop.is_set()
    acquired = sum(generation.connection_slots.acquire(blocking=False) for _ in range(guard._MAX_CONNECTIONS + 1))
    assert acquired == guard._MAX_CONNECTIONS and module.denied == 1
    for _ in range(acquired):
        generation.connection_slots.release()
