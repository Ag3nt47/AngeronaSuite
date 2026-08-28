from __future__ import annotations

import os
import threading

import pytest

from angerona.modules.ipc_guard import (
    IpcGuardModule,
    _IpcGeneration,
    _MAX_CONNECTIONS,
    _load_or_create_key,
)


def test_self_test_never_changes_live_authentication_material_or_counters() -> None:
    module = IpcGuardModule()
    module._key = os.urandom(32)
    original = module._key
    module.accepted = 7
    module.denied = 11

    ok, detail = module.self_test()

    assert ok, detail
    assert module._key == original
    assert module.accepted == 7
    assert module.denied == 11
    assert "isolated" in detail


def test_self_test_does_not_erase_concurrent_production_counter_updates(
    monkeypatch,
) -> None:
    module = IpcGuardModule()
    module.accepted = 7
    original_serve = module._serve_conn

    def serve_with_live_activity(*args, **kwargs):
        original_serve(*args, **kwargs)
        # Model a production authorization completing while the isolated test
        # is in flight. The self-test must never restore an older snapshot over
        # this independently-owned observation.
        with module.state_lock:
            module.accepted += 1

    monkeypatch.setattr(module, "_serve_conn", serve_with_live_activity)

    ok, detail = module.self_test()

    assert ok, detail
    assert module.accepted == 9


def test_connection_capacity_and_denial_telemetry_are_bounded(monkeypatch) -> None:
    generation = _IpcGeneration(threading.Event())
    acquired = sum(
        generation.connection_slots.acquire(blocking=False)
        for _ in range(_MAX_CONNECTIONS + 100)
    )
    assert acquired == _MAX_CONNECTIONS

    module = IpcGuardModule()
    emitted = []
    monkeypatch.setattr(module, "emit", lambda *args, **kwargs: emitted.append((args, kwargs)))
    monkeypatch.setattr("angerona.modules.ipc_guard.time.monotonic", lambda: 100.0)
    for index in range(10_000):
        module._record_denial(("127.0.0.1", index), reason="capacity")

    assert module.denied == 10_000
    assert len(emitted) == 1
    assert module._suppressed_denials == 9_999
    assert emitted[0][1]["response_authorized"] is False


def test_legacy_plaintext_ipc_key_migrates_to_verified_os_store(tmp_path, monkeypatch) -> None:
    from angerona.core import secure_store

    legacy = tmp_path / "ipc_auth.key"
    key = b"k" * 32
    legacy.write_bytes(key)
    protected: dict[str, str] = {}

    monkeypatch.setattr(
        secure_store,
        "read_secret_values",
        lambda names, data_root=None, strict=False: {
            name: protected[name] for name in names if name in protected
        },
    )
    monkeypatch.setattr(
        secure_store,
        "write_secret_map",
        lambda updates, data_root=None: protected.update(updates) or tmp_path,
    )

    assert _load_or_create_key(legacy) == key
    assert protected["ANGERONA_IPC_AUTH_KEY"] == key.hex()
    assert not legacy.exists()


def test_ipc_key_creation_fails_closed_when_os_store_rejects_write(tmp_path, monkeypatch) -> None:
    from angerona.core import secure_store

    monkeypatch.setattr(secure_store, "read_secret_values", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        secure_store,
        "write_secret_map",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("store offline")),
    )

    with pytest.raises(RuntimeError, match="store offline"):
        _load_or_create_key(tmp_path / "ipc_auth.key")
