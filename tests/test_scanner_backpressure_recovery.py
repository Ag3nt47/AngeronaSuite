"""Private-ring recovery contracts; no host sensors, authority files or providers."""
from __future__ import annotations

import json
import struct
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from angerona.resilience import ipc_ring, scanner


_KEY = b"p" * 32  # Synthetic test authority; never an installation key.
_SLOTS = 8
_SLOT_BYTES = 256
_WAIT_SECONDS = 5


@pytest.fixture(autouse=True)
def refuse_installation_authority(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("private ring fixture attempted installation authority access")
    monkeypatch.setattr(ipc_ring, "_load_or_create_key", forbidden)


@contextmanager
def _pair(path, *, reader_key=_KEY):
    with ipc_ring.RingWriter(path, _SLOTS, _SLOT_BYTES, key=_KEY) as writer:
        with ipc_ring.RingReader(path, _SLOTS, _SLOT_BYTES, key=reader_key) as reader:
            yield writer, reader


def _fill(writer, count):
    start = writer.write_seq
    for sequence in range(start, start + count):
        assert writer.write(f"fixture-{sequence}".encode(), sensor_id=7)
    return list(range(start, start + count))


def _persisted_pressure(writer):
    return struct.unpack_from("<I", writer._mm, 40)[0]


def test_drained_ring_recovers_without_an_extra_producer_write(tmp_path):
    with _pair(tmp_path / "telemetry.ring") as (writer, reader):
        expected = _fill(writer, 7)
        assert writer.occupancy == 7 and writer.backpressure is True
        frames = reader.read_batch()
        assert [frame["seq"] for frame in frames] == expected
        assert reader.authentication_failures == 0
        assert writer.occupancy == 0 and _persisted_pressure(writer) == 1
        before = (writer.write_seq, writer.read_seq, writer.drops)
        assert writer.backpressure is False
        assert _persisted_pressure(writer) == 0
        assert (writer.write_seq, writer.read_seq, writer.drops) == before == (7, 7, 0)


@pytest.mark.parametrize("remaining", [0, 1, 6, 7, 8])
def test_live_threshold_preserves_shedding_until_occupancy_is_below_85_percent(tmp_path, remaining):
    with _pair(tmp_path / "threshold.ring") as (writer, reader):
        _fill(writer, 8)
        assert writer.backpressure is True
        if remaining < 8:
            frames = reader.read_batch(max_frames=8 - remaining)
            assert len(frames) == 8 - remaining
        assert writer.occupancy == remaining
        assert _persisted_pressure(writer) == 1  # Reader does not clear producer state.
        before = (writer.write_seq, writer.read_seq, writer.drops)
        expected = remaining / _SLOTS >= ipc_ring.BACKPRESSURE_FRAC
        assert writer.backpressure is expected
        assert _persisted_pressure(writer) == int(expected)
        assert (writer.write_seq, writer.read_seq, writer.drops) == before
        assert reader.authentication_failures == 0


def test_repeated_fill_drain_cycles_keep_sequences_and_prior_drop_accounting(tmp_path):
    with _pair(tmp_path / "cycles.ring") as (writer, reader):
        for cycle in range(4):
            expected = _fill(writer, 7)
            assert writer.backpressure is True
            frames = reader.read_batch()
            assert [frame["seq"] for frame in frames] == expected
            assert [frame["payload"] for frame in frames] == [
                f"fixture-{sequence}".encode() for sequence in expected
            ]
            assert _persisted_pressure(writer) == 1
            assert writer.backpressure is False
            assert writer.write_seq == writer.read_seq == (cycle + 1) * 7
            assert writer.drops == reader.authentication_failures == 0


@pytest.mark.parametrize("remaining", [0, 3, 7])
def test_reattach_preserves_pending_frames_and_rechecks_stale_pressure(tmp_path, remaining):
    path = tmp_path / "reattach.ring"
    with _pair(path) as (writer, reader):
        _fill(writer, 8)
        assert writer.backpressure is True
        reader.read_batch(max_frames=8 - remaining)
        assert _persisted_pressure(writer) == 1
        before = (writer.write_seq, writer.read_seq, writer.drops)
    with _pair(path) as (writer, reader):
        assert (writer.write_seq, writer.read_seq, writer.drops) == before
        assert _persisted_pressure(writer) == 1
        assert writer.backpressure is (remaining / _SLOTS >= ipc_ring.BACKPRESSURE_FRAC)
        frames = reader.read_batch()
        assert [frame["seq"] for frame in frames] == list(range(8 - remaining, 8))
        assert writer.backpressure is False
        assert writer.write(b"after-reattach", sensor_id=7)
        frames = reader.read_batch()
        assert [(frame["seq"], frame["payload"]) for frame in frames] == [(8, b"after-reattach")]
        assert writer.drops == reader.authentication_failures == 0


@pytest.mark.parametrize("corruption", ["wrong-key", "changed-tag"])
def test_pressure_refresh_never_turns_unauthenticated_frames_into_delivery(tmp_path, corruption):
    path = tmp_path / "authentication.ring"
    reader_key = b"q" * 32 if corruption == "wrong-key" else _KEY
    with ipc_ring.RingWriter(path, _SLOTS, _SLOT_BYTES, key=_KEY) as writer:
        with ipc_ring.RingReader(path, _SLOTS, _SLOT_BYTES, key=reader_key) as reader:
            _fill(writer, 7)
            assert writer.backpressure is True
            if corruption == "changed-tag":
                offset = writer._slot_off(0)
                length = struct.unpack_from("<I", writer._mm, offset)[0]
                tag_byte = offset + 4 + length - 1
                writer._mm[tag_byte] ^= 1
            frames = reader.read_batch()
            expected = [] if corruption == "wrong-key" else list(range(1, 7))
            assert [frame["seq"] for frame in frames] == expected
            assert reader.authentication_failures == (7 if corruption == "wrong-key" else 1)
            assert writer.occupancy == 0 and writer.drops == 0
            assert writer.backpressure is False
        with ipc_ring.RingReader(path, _SLOTS, _SLOT_BYTES, key=_KEY) as reader:
            assert writer.write(b"authenticated-after-gap", sensor_id=7)
            frames = reader.read_batch()
            assert [(frame["seq"], frame["payload"]) for frame in frames] == [
                (7, b"authenticated-after-gap")
            ]
            assert reader.authentication_failures == 0


def test_recovery_preserves_overrun_and_oversize_drops(tmp_path):
    with _pair(tmp_path / "overrun.ring") as (writer, reader):
        _fill(writer, 20)
        assert writer.backpressure is True and writer.drops == 12
        frames = reader.read_batch()
        assert [frame["seq"] for frame in frames] == list(range(12, 20))
        assert writer.backpressure is False
        assert writer.write_seq == writer.read_seq == 20 and writer.drops == 12
        assert writer.write(b"z" * _SLOT_BYTES, sensor_id=7) is False
        assert writer.backpressure is False
        assert writer.write_seq == writer.read_seq == 20 and writer.drops == 13
        assert reader.authentication_failures == 0


@pytest.mark.parametrize("offset,format_,value", [
    (0, "<I", 0),
    (4, "<I", 999),
    (8, "<I", 9),
    (12, "<I", 512),
    (24, "<Q", 8),
], ids=["magic", "version", "slots", "size", "read-ahead-of-write"])
def test_malformed_header_is_not_permission_to_clear_pressure(tmp_path, offset, format_, value):
    with _pair(tmp_path / "malformed.ring") as (writer, _reader):
        _fill(writer, 7)
        assert _persisted_pressure(writer) == 1
        struct.pack_into(format_, writer._mm, offset, value)
        before = bytes(writer._mm)
        with pytest.raises(ipc_ring.FrameError, match="header failed integrity validation"):
            _ = writer.backpressure
        assert bytes(writer._mm) == before


def test_closed_writer_still_raises_without_a_fabricated_pressure_decision(tmp_path):
    writer = ipc_ring.RingWriter(tmp_path / "closed.ring", _SLOTS, _SLOT_BYTES, key=_KEY)
    writer.close()
    assert writer._mm.closed and writer._f.closed
    with pytest.raises(ValueError):
        _ = writer.backpressure


class _TurnGate:
    """Replace only the test loop's idle wait with explicit, bounded handoffs."""

    def __init__(self):
        self.arrived = [threading.Event() for _ in range(4)]
        self.release = [threading.Event() for _ in range(4)]
        self.turn = 0
        self.stopped = threading.Event()

    def wait(self, _timeout):
        turn = self.turn
        self.turn += 1
        assert turn < len(self.arrived), "unexpected unowned scanner turn"
        self.arrived[turn].set()
        assert self.release[turn].wait(_WAIT_SECONDS), "test did not release scanner turn"
        return self.stopped.is_set()

    def set(self):
        self.stopped.set()
        for release in self.release:
            release.set()


class _InertProcessSensor(scanner.RawProcessSensor):
    def __init__(self):
        super().__init__()
        self.enrichment = []

    def poll(self, *, enrich=True):
        self.enrichment.append(enrich)
        pid = 1000 + len(self.enrichment)
        return [json.dumps({
            "type": "process_creation", "pid": pid, "ppid": 0,
            "name": "fixture.exe", "ts": 1.0,
        }, separators=(",", ":")).encode("utf-8")]


def test_actual_scanner_loop_resumes_after_two_barrier_controlled_drains(tmp_path, monkeypatch):
    # Real RingWriter/Reader and unchanged ScannerHost.run; only the sensor,
    # heartbeat/status/stand-down boundaries and idle scheduling are inert.
    path = tmp_path / "host.ring"
    writer = ipc_ring.RingWriter(path, _SLOTS, _SLOT_BYTES, key=_KEY)
    reader = None
    host = None
    thread = None
    started = False
    closed = []
    errors = []
    gate = _TurnGate()
    original_close = writer.close

    def writer_close():
        assert "ring" not in closed, "writer was closed twice"
        original_close()
        closed.append("ring")

    monkeypatch.setattr(writer, "close", writer_close)
    try:
        reader = ipc_ring.RingReader(path, _SLOTS, _SLOT_BYTES, key=_KEY)
        monkeypatch.setattr(scanner.ipc_ring, "ring_path", lambda _name: path)
        monkeypatch.setattr(scanner.ipc_ring, "RingWriter", lambda *args, **kwargs: writer)
        monkeypatch.setattr(scanner.hb, "HeartbeatWriter", lambda *args, **kwargs: SimpleNamespace(
            beat=lambda: None, close=lambda: closed.append("beat"),
        ))
        monkeypatch.setattr(scanner.diag, "write_status", lambda *args, **kwargs: None)
        monkeypatch.setattr(scanner.tok, "is_standdown_requested", lambda: False)
        monkeypatch.setattr(scanner.ScannerHost, "_read_ping", lambda self: "")
        _fill(writer, 7)
        host = scanner.ScannerHost(interval=3600)
        host._stop_event = gate
        sensor = _InertProcessSensor()
        host.sensors = [sensor]

        def run():
            try:
                host.run()
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=run, name="scanner-pressure-fixture")
        thread.start()
        started = True
        for high_turn, low_turn in ((0, 1), (2, 3)):
            assert gate.arrived[high_turn].wait(_WAIT_SECONDS)
            assert writer.occupancy == 7
            assert host._events == high_turn // 2
            assert host._dropped == high_turn // 2 + 1
            assert sensor.enrichment[-1] is False
            assert len(reader.read_batch()) == 7
            assert _persisted_pressure(writer) == 1
            gate.release[high_turn].set()
            assert gate.arrived[low_turn].wait(_WAIT_SECONDS)
            frames = reader.read_batch()
            assert len(frames) == 1
            record = ipc_ring.decode_sensor_payload(scanner.SENSOR_PROC, frames[0]["payload"])
            assert record["pid"] == 1000 + low_turn + 1
            assert host._events == low_turn // 2 + 1
            assert host._dropped == low_turn // 2 + 1  # Earlier shedding is not erased/replayed.
            if low_turn == 1:
                _fill(writer, 7)  # Exclusive handoff while the producer is gated.
                gate.release[low_turn].set()
        assert sensor.enrichment == [False, True, False, True]
        assert reader.authentication_failures == writer.drops == 0
    finally:
        if host is not None:
            host.stop()
        else:
            gate.set()
        if started:
            thread.join(_WAIT_SECONDS)
            assert not thread.is_alive(), "owned scanner thread retirement unresolved; mappings retained"
        if host is not None and not started:
            host._shutdown()
        if "ring" not in closed:
            writer.close()
        if reader is not None:
            reader.close()
    assert errors == []
    assert closed == ["beat", "ring"]
    assert writer._mm.closed and writer._f.closed
    assert reader._mm.closed and reader._f.closed
