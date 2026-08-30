from __future__ import annotations

import struct
import time

from angerona.core.module_base import Severity
from angerona.modules import kernel_bridge
from angerona.modules.kernel_bridge import KernelBridgeModule


def _version(
    *,
    tag: bytes = b"ANGRSENS",
    instance: int = 7,
    write_sequence: int = 0,
    dropped: int = 0,
    heartbeat: int = 10,
) -> bytes:
    return struct.pack(
        kernel_bridge._VERSION_FMT,
        2,
        0,
        0,
        tag,
        2,
        kernel_bridge._REQUIRED_CAPABILITIES,
        instance,
        write_sequence,
        dropped,
        heartbeat,
    )


def _event(sequence: int = 1) -> bytes:
    image = "C:\\Windows\\System32\\safe.exe".encode("utf-16-le")
    command = "safe.exe --fixture".encode("utf-16-le")
    return struct.pack(
        kernel_bridge._EVENT_FMT,
        kernel_bridge._EVT_PROCESS_CREATE,
        sequence,
        42,
        4,
        9,
        0,
        len(image) // 2,
        image.ljust(520, b"\x00"),
        len(command) // 2,
        command.ljust(520, b"\x00"),
    )


def _batch(
    *events: bytes,
    instance: int = 7,
    dropped: int = 0,
    write_sequence: int | None = None,
) -> bytes:
    if write_sequence is None:
        write_sequence = len(events)
    return struct.pack(
        kernel_bridge._EVENTS_HEADER_FMT,
        len(events),
        2,
        instance,
        dropped,
        write_sequence,
    ) + b"".join(events)


def test_protocol_layout_matches_packed_v2_contract() -> None:
    assert kernel_bridge._VERSION_SIZE == 60
    assert kernel_bridge._EVENTS_HEADER_SIZE == 32
    assert kernel_bridge._EVENT_SIZE == 1080


def test_open_handle_never_counts_as_handshake_or_identity(monkeypatch) -> None:
    module = KernelBridgeModule()
    module._handle = 1
    monkeypatch.setattr(kernel_bridge, "_ioctl", lambda *_args: _version())

    assert module._verify_version() is True
    module._update_health()

    assert module.health == 60
    assert "identity" in module.health_note
    assert module._identity_verified is False


def test_old_short_or_wrong_tag_handshake_fails_closed(monkeypatch) -> None:
    module = KernelBridgeModule(identity_verifier=lambda: (True, "fixture"))
    module._handle = 1

    monkeypatch.setattr(kernel_bridge, "_ioctl", lambda *_args: b"\x00" * 16)
    assert module._verify_version() is False
    monkeypatch.setattr(
        kernel_bridge,
        "_ioctl",
        lambda *_args: _version(tag=b"SUBSTITU"),
    )
    assert module._verify_version() is False
    assert module._protocol_ok is False


def test_exact_batch_sequence_and_identity_can_reach_green(monkeypatch) -> None:
    module = KernelBridgeModule(identity_verifier=lambda: (True, "pinned fixture"))
    module._handle = 1
    emitted = []
    module.emit = lambda message, severity, **details: emitted.append(
        (message, severity, details)
    )
    responses = iter([_version(write_sequence=1), _batch(_event(), write_sequence=1)])
    monkeypatch.setattr(kernel_bridge, "_ioctl", lambda *_args: next(responses))

    assert module._verify_version() is True
    module._identity_verified = True
    module._identity_reason = "pinned fixture"
    module._last_handshake_at = time.monotonic()
    assert module._drain() is True

    assert module.health == 100
    kernel_event = next(item for item in emitted if item[2].get("source") == "kernel")
    assert kernel_event[2]["kernel_sequence"] == 1
    assert kernel_event[2]["kernel_identity_verified"] is True
    assert kernel_event[2]["response_authorized"] is False


def test_loss_counter_and_sequence_gap_are_visible_and_non_green(monkeypatch) -> None:
    module = KernelBridgeModule(identity_verifier=lambda: (True, "pinned fixture"))
    module._handle = 1
    module._protocol_ok = True
    module._identity_verified = True
    module._identity_reason = "pinned fixture"
    module._instance_id = 7
    module._last_sequence = 1
    module._last_handshake_at = time.monotonic()
    emitted = []
    module.emit = lambda message, severity, **details: emitted.append(
        (message, severity, details)
    )
    monkeypatch.setattr(
        kernel_bridge,
        "_ioctl",
        lambda *_args: _batch(
            _event(sequence=3),
            dropped=1,
            write_sequence=3,
        ),
    )

    assert module._drain() is True

    assert module.health == 70
    assert any(item[1] == Severity.HIGH and "overwritten" in item[0] for item in emitted)
    assert any(item[1] == Severity.HIGH and "sequence gap" in item[0] for item in emitted)


def test_malformed_count_or_transport_failure_reconnects(monkeypatch) -> None:
    module = KernelBridgeModule(identity_verifier=lambda: (True, "fixture"))
    module._handle = 123
    module._protocol_ok = True
    module._instance_id = 7
    module._last_handshake_at = time.monotonic()
    malformed = struct.pack(
        kernel_bridge._EVENTS_HEADER_FMT,
        65,
        2,
        7,
        0,
        0,
    )
    monkeypatch.setattr(kernel_bridge, "_ioctl", lambda *_args: malformed)
    closed = []
    monkeypatch.setattr(kernel_bridge, "_close_device", closed.append)

    assert module._drain() is False
    module._transport_failure("fixture failure")

    assert closed == [123]
    assert module._handle is None
    assert module.health == 20
