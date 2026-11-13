"""PW06e private transport fixtures: synthetic authority and no host collectors."""
from __future__ import annotations

import struct
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from angerona.resilience import ipc_ring, scanner


KEY = b"e" * 32
SLOTS, SLOT_BYTES = 8, 256


@pytest.fixture(autouse=True)
def no_installation_authority(monkeypatch):
    monkeypatch.setattr(ipc_ring, "_load_or_create_key",
                        lambda: pytest.fail("installation ring authority queried"))


@contextmanager
def pair(tmp_path, *, reader_key=KEY):
    with ipc_ring.RingWriter(tmp_path / "private.ring", SLOTS, SLOT_BYTES, key=KEY) as writer:
        with ipc_ring.RingReader(writer.path, SLOTS, SLOT_BYTES, key=reader_key) as reader:
            yield writer, reader


def fill(writer, count):
    for _index in range(count):
        assert writer.write(b"original raw observation", sensor_id=7)


@pytest.mark.parametrize("kind", [ipc_ring.RingWriter, ipc_ring.RingReader])
@pytest.mark.parametrize("damage", ["short", "long", "magic", "layout", "cursor"])
def test_existing_corrupt_ring_is_preserved_without_reset(tmp_path, kind, damage):
    path = tmp_path / "private.ring"
    with ipc_ring.RingWriter(path, SLOTS, SLOT_BYTES, key=KEY) as writer:
        fill(writer, 2)
    raw = bytearray(path.read_bytes())
    if damage == "short":
        del raw[-1:]
    elif damage == "long":
        raw.extend(b"preserve trailing evidence")
    elif damage == "magic":
        struct.pack_into("<I", raw, 0, 0)
    elif damage == "layout":
        struct.pack_into("<I", raw, 8, SLOTS + 1)
    else:
        struct.pack_into("<Q", raw, 24, 3)
    path.write_bytes(raw)
    with pytest.raises(ipc_ring.FrameError, match="integrity"):
        kind(path, SLOTS, SLOT_BYTES, key=KEY)
    assert path.read_bytes() == raw
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("kind", [ipc_ring.RingWriter, ipc_ring.RingReader])
def test_unverifiable_existing_tail_rejects_and_closes_exact_resources(tmp_path, monkeypatch, kind):
    path = tmp_path / "private.ring"
    with ipc_ring.RingWriter(path, SLOTS, SLOT_BYTES, key=KEY) as writer:
        fill(writer, 2)
        off = writer._slot_off(1)
        length = struct.unpack_from("<I", writer._mm, off)[0]
        writer._mm[off + 4 + length - 1] ^= 1
    original = path.read_bytes()
    captured = []
    close = ipc_ring._RingBase.close

    def observed_close(owner):
        close(owner)
        captured.append((owner._mm.closed, owner._f.closed))

    monkeypatch.setattr(ipc_ring._RingBase, "close", observed_close)
    with pytest.raises(ipc_ring.FrameError):
        kind(path, SLOTS, SLOT_BYTES, key=KEY)
    assert captured == [(True, True)] and path.read_bytes() == original


def test_active_writer_ignores_poisoned_shared_counters_and_retains_first_header(tmp_path):
    with pair(tmp_path) as (writer, reader):
        fill(writer, 1)
        first_slot = bytes(writer._mm[writer._slot_off(0):writer._slot_off(0) + SLOT_BYTES])
        for offset in (16, 24, 32):
            struct.pack_into("<Q", writer._mm, offset, (1 << 64) - 1)
        poisoned = bytes(writer._mm[:64])
        with pytest.raises(ipc_ring.FrameError):
            _ = writer.backpressure
        assert writer.write(b"fresh raw observation", sensor_id=7)
        assert writer.write_seq == 2 and writer.drops == 0
        assert writer.rejected_header == poisoned and writer.header_rejections >= 2
        assert bytes(writer._mm[writer._slot_off(0):writer._slot_off(0) + SLOT_BYTES]) == first_slot
        frames = reader.read_batch()
        assert [frame["seq"] for frame in frames] == [0, 1]
        assert [frame["payload"] for frame in frames] == [b"original raw observation", b"fresh raw observation"]


@pytest.mark.parametrize("rewind", [0, 1])
def test_reader_high_water_survives_shared_ack_rewind(tmp_path, rewind):
    with pair(tmp_path) as (writer, reader):
        fill(writer, 4)
        originals = reader.read_batch()
        assert [frame["seq"] for frame in originals] == [0, 1, 2, 3]
        struct.pack_into("<Q", writer._mm, 24, rewind)
        assert reader.read_batch() == [] and reader.next_sequence == 4
        assert reader.authentication_failures == 1
        assert writer.write(b"new generation-local observation", sensor_id=7)
        assert [frame["seq"] for frame in reader.read_batch()] == [4]
        assert reader.initial_continuity_verified is False


def test_unverified_huge_write_claim_cannot_advance_local_cursor(tmp_path, monkeypatch):
    with pair(tmp_path) as (writer, reader):
        fill(writer, 1)
        struct.pack_into("<Q", writer._mm, 16, (1 << 64) - 1)
        calls, decode = [], reader._frame_at

        def bounded_decode(sequence):
            calls.append(sequence)
            return decode(sequence)

        monkeypatch.setattr(reader, "_frame_at", bounded_decode)
        assert reader.read_batch() == []
        assert len(calls) == SLOTS and reader.next_sequence == 0 and reader.read_seq == 0
        assert writer.write(b"after forged claim", sensor_id=7)
        assert [frame["seq"] for frame in reader.read_batch()] == [0, 1]


def test_small_batch_scans_past_bad_prefix_without_acknowledging_forgery(tmp_path):
    with pair(tmp_path) as (writer, reader):
        fill(writer, 3)
        offset = writer._slot_off(0)
        length = struct.unpack_from("<I", writer._mm, offset)[0]
        writer._mm[offset + 4 + length - 1] ^= 1
        assert reader.read_batch(max_frames=1) == []
        assert reader.next_sequence == reader.read_seq == 0
        frames = reader.read_batch(max_frames=1)
        assert [(frame["seq"], frame["missed"]) for frame in frames] == [(1, 1)]
        assert reader.missed_frames == 1
        assert [frame["seq"] for frame in reader.read_batch(max_frames=1)] == [2]


def test_wrong_key_preserves_unacknowledged_originals_for_verified_reader(tmp_path):
    with pair(tmp_path, reader_key=b"w" * 32) as (writer, reader):
        fill(writer, 3)
        assert reader.read_batch() == [] and reader.next_sequence == reader.read_seq == 0
        assert reader.authentication_failures == 3
        with ipc_ring.RingReader(writer.path, SLOTS, SLOT_BYTES, key=KEY) as verified:
            assert [frame["seq"] for frame in verified.read_batch()] == [0, 1, 2]


def test_verified_overrun_reports_lower_bound_and_never_replays_retention(tmp_path):
    with pair(tmp_path) as (writer, reader):
        fill(writer, 20)
        frames = reader.read_batch()
        assert [frame["seq"] for frame in frames] == list(range(12, 20))
        assert frames[0]["missed"] == reader.missed_frames == 12
        struct.pack_into("<Q", writer._mm, 24, 0)
        assert reader.read_batch() == [] and reader.next_sequence == 20
        assert writer.write(b"fresh after known gap", sensor_id=7)
        assert [(frame["seq"], frame["missed"]) for frame in reader.read_batch()] == [(20, 0)]


class FakeRing:
    backpressure = True
    drops = 0

    def __init__(self):
        self.writes, self.closes = [], 0

    def write(self, payload, **_kwargs):
        self.writes.append(payload)
        return True

    def close(self):
        self.closes += 1


class InertSensor(scanner.RawProcessSensor):
    def __init__(self):
        self.enrichment = []

    def poll(self, *, enrich=True):
        self.enrichment.append(enrich)
        return [b"inert raw frame " + str(len(self.enrichment)).encode()]


def scanner_harness(monkeypatch, *, ring_factory=None):
    clock, beats, closed, statuses = [0.0], [], [], []
    ring = FakeRing()
    monkeypatch.setattr(scanner, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(scanner.ipc_ring, "ring_path", lambda _name: "inert-private-path")
    monkeypatch.setattr(scanner.ipc_ring, "RingWriter", ring_factory or (lambda *_args: ring))
    monkeypatch.setattr(scanner.hb, "HeartbeatWriter", lambda *_args, **_kwargs: SimpleNamespace(
        beat=lambda: beats.append(clock[0]), close=lambda: closed.append("beat")))
    monkeypatch.setattr(scanner.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(scanner.ScannerHost, "_read_ping", lambda self: "")
    monkeypatch.setattr(scanner.diag, "write_status", lambda *args: statuses.append(args))
    host = scanner.ScannerHost()
    sensor = InertSensor()
    host.sensors = [sensor]

    def run(times):
        remaining = iter(times)
        clock[0] = next(remaining)

        class Turns:
            def wait(self, _timeout):
                try:
                    clock[0] = next(remaining)
                except StopIteration:
                    host.stop()

            def set(self):
                pass

        host._stop_event = Turns()
        host.run()

    return SimpleNamespace(host=host, sensor=sensor, ring=ring, clock=clock,
                           beats=beats, closed=closed, statuses=statuses, run=run)


def test_scanner_forwards_raw_under_untrusted_pressure(monkeypatch):
    h = scanner_harness(monkeypatch)
    h.run([0.0, 1.0, 2.0])
    assert len(h.ring.writes) == h.host._events == 3 and h.host._dropped == 0
    assert h.sensor.enrichment == [False, False, False]
    assert h.host._enrichment_omitted == 3 and len(h.beats) == 3
    assert h.ring.closes == 1 and h.closed == ["beat"]


def test_scanner_attach_failure_stays_alive_and_retries_at_bounded_deadline(monkeypatch):
    attempts, ring = [], FakeRing()

    def attach(*_args):
        attempts.append(True)
        if len(attempts) == 1:
            raise ipc_ring.FrameError("inert corrupt existing ring")
        return ring

    h = scanner_harness(monkeypatch, ring_factory=attach)
    h.run([0.0, 1.0, 29.0, 30.0, 31.0])
    assert len(attempts) == 2 and len(h.beats) == 5
    assert len(ring.writes) == 2 and h.host._dropped == 3
    assert h.sensor.enrichment == [False] * 5
    assert ring.closes == 1 and h.closed == ["beat"]
    assert any(state == "degraded" for _name, state, _details in h.statuses)
    coverage = h.statuses[-1][2]["ring_coverage"]
    assert coverage["unforwarded_observations"] == 3
    assert coverage["initial_continuity_verified"] is False and coverage["response_authorized"] is False
    assert coverage["collector_efficacy_verified"] is False


def test_scanner_write_fault_retains_same_writer_and_progresses_while_held(monkeypatch):
    h = scanner_harness(monkeypatch)
    calls = []

    def write(payload, **_kwargs):
        calls.append(h.clock[0])
        if len(calls) == 1:
            raise ipc_ring.FrameError("inert active layout corruption")
        h.ring.writes.append(payload)
        return True

    monkeypatch.setattr(h.ring, "write", write)
    h.run([0.0, 1.0, 29.0, 30.0, 31.0])
    assert calls == [0.0, 30.0, 31.0] and len(h.beats) == 5
    assert len(h.ring.writes) == 2 and h.host._dropped == 3 and h.ring.closes == 1


def test_scanner_pressure_error_cannot_veto_raw_frames(monkeypatch):
    class UnavailablePressure(FakeRing):
        @property
        def backpressure(self):
            raise ipc_ring.FrameError("inert forged consumer ACK")

    ring = UnavailablePressure()
    h = scanner_harness(monkeypatch, ring_factory=lambda *_args: ring)
    h.run([0.0, 1.0, 2.0])
    assert len(ring.writes) == 3 and h.host._dropped == 0 and len(h.beats) == 3
    assert h.host._ring_failures >= 3 and ring.closes == 1


def test_failed_heartbeat_constructor_closes_already_owned_ring(monkeypatch):
    h = scanner_harness(monkeypatch)
    h.host._shutdown()
    ring = FakeRing()
    monkeypatch.setattr(scanner.ipc_ring, "RingWriter", lambda *_args: ring)
    monkeypatch.setattr(scanner.hb, "HeartbeatWriter", lambda *_args, **_kwargs:
                        (_ for _ in ()).throw(OSError("inert heartbeat failure")))
    with pytest.raises(OSError, match="heartbeat"):
        scanner.ScannerHost()
    assert ring.closes == 1


def test_ambiguous_close_retains_exact_owner_without_repeated_close(monkeypatch):
    h = scanner_harness(monkeypatch)

    def close():
        h.ring.closes += 1
        raise OSError("inert ambiguous mapping close")

    monkeypatch.setattr(h.ring, "close", close)
    with pytest.raises(OSError, match="ambiguous"):
        h.host._shutdown()
    h.host._shutdown()
    assert h.host.ring is h.ring and h.ring.closes == 1
    assert h.statuses[-1][2]["ring_coverage"]["close_unresolved"] is True


def test_manager_retains_reader_fault_high_water_and_drains_both_outboxes(monkeypatch):
    from angerona.resilience import manager

    clock, calls, publications, receipts = [0.0], [], [], []
    owner = manager.ResilienceManager.__new__(manager.ResilienceManager)
    owner._reader, owner.ring_interval = None, 1.0
    owner._closed, owner._ring_unretired_reader = False, None
    owner._shutdown_lock = threading.RLock()
    owner._ring_retry_at, owner._ring_gap_observations, owner._ring_gap_reason = 0.0, 0, ""
    owner._ring_coverage = {"state": "unmeasured", "missed_frames_lower_bound": 0}
    owner.frames_ingested = owner.frames_rejected = 0
    reader = SimpleNamespace(authentication_failures=0)

    def read_batch(_limit):
        calls.append(clock[0])
        if len(calls) == 1:
            raise ipc_ring.FrameError("inert ring header error")
        return [{"seq": 10, "missed": 3}]

    reader.read_batch = read_batch
    admissions = []

    def attach(_path):
        admissions.append(clock[0])
        if len(admissions) == 1:
            raise ipc_ring.FrameError("inert admission error")
        return reader

    class Turns:
        def __init__(self):
            self.times = iter([0.0, 1.0, 29.0, 30.0, 31.0, 60.0])

        def is_set(self):
            return False

        def wait(self, _timeout):
            try:
                clock[0] = next(self.times)
                return False
            except StopIteration:
                return True

    class Outbox:
        def __init__(self, name):
            self.name = name

        def peek(self):
            return [{"id": self.name, "mac": self.name + "-original-MAC", "msg": self.name}]

        def ack(self, record):
            assert publications[-1][0] == self.name
            receipts.append(record)

    owner._stop = Turns()
    owner._peer_alerts, owner._native_peer_alerts = Outbox("python"), Outbox("native")
    owner._handle_frame = lambda frame: receipts.append(frame)

    def publish(_module, message, _level, details):
        publications.append((message, details))
        return True

    owner._publish = publish
    monkeypatch.setattr(manager, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(manager.ipc_ring, "ring_path", lambda _name: "inert-private-path")
    monkeypatch.setattr(manager.ipc_ring, "RingReader", attach)
    owner._ring_loop()
    assert admissions == [0.0, 30.0] and calls == [30.0, 60.0] and owner._reader is reader
    assert owner.frames_ingested == 1 and owner._ring_coverage["missed_frames_lower_bound"] == 3
    assert {record.get("id") for record in receipts if "id" in record} == {"python", "native"}
    peer_details = [details for message, details in publications if message in {"python", "native"}]
    assert all(details["response_authorized"] is False for details in peer_details)
    assert {details["peer_record_mac"] for details in peer_details} == {"python-original-MAC", "native-original-MAC"}
    gaps = [details for message, details in publications if "coverage is incomplete" in message]
    assert gaps and all(details["response_authorized"] is False for details in gaps)


@pytest.mark.parametrize("close_failure", [False, True])
def test_reader_admission_finishing_after_stop_retires_or_retains_exact_owner(monkeypatch, close_failure):
    from angerona.resilience import manager

    owner = manager.ResilienceManager.__new__(manager.ResilienceManager)
    owner._closed, owner._ring_unretired_reader, owner._reader = False, None, None
    owner._shutdown_lock, owner._stop = threading.RLock(), threading.Event()
    owner._ring_coverage = {}
    gaps, closes = [], []
    owner._record_ring_gap = lambda reason: gaps.append(reason)

    def close():
        closes.append(reader)
        if close_failure:
            raise OSError("inert ambiguous late mapping close")

    reader = SimpleNamespace(close=close)

    def attach(_path):
        owner._stop.set()
        owner._closed = True
        return reader

    monkeypatch.setattr(manager.ipc_ring, "ring_path", lambda _name: "inert-private-path")
    monkeypatch.setattr(manager.ipc_ring, "RingReader", attach)
    assert owner._admit_ring_reader() is False and owner._reader is None
    assert closes == [reader]
    assert owner._ring_unretired_reader is (reader if close_failure else None)
    assert bool(gaps) is close_failure
    if close_failure:
        assert owner._ring_coverage["close_unresolved"] is True
    with pytest.raises(ipc_ring.FrameError, match="closed"):
        owner._admit_ring_reader()
    assert closes == [reader]


def test_reader_header_regression_retains_high_water_across_failure(tmp_path):
    with pair(tmp_path) as (writer, reader):
        fill(writer, 2)
        assert [frame["seq"] for frame in reader.read_batch()] == [0, 1]
        struct.pack_into("<Q", writer._mm, 16, 0)
        rejected = bytes(writer._mm)
        with pytest.raises(ipc_ring.FrameError, match="header"):
            reader.read_batch()
        assert reader.next_sequence == 2 and bytes(writer._mm) == rejected
        # Reviewed fixture restoration; the product never resets these bytes.
        struct.pack_into("<Q", writer._mm, 16, 2)
        assert writer.write(b"fresh after retained-reader fault", sensor_id=7)
        assert [frame["seq"] for frame in reader.read_batch()] == [2]


@pytest.mark.parametrize("kind", [ipc_ring.RingWriter, ipc_ring.RingReader])
def test_unverified_initial_counter_cannot_establish_a_huge_cursor(tmp_path, kind):
    path = tmp_path / "initial-cursor.ring"
    with ipc_ring.RingWriter(path, SLOTS, SLOT_BYTES, key=KEY) as writer:
        fill(writer, 1)
        struct.pack_into("<Q", writer._mm, 16, (1 << 64) - 1)
        struct.pack_into("<Q", writer._mm, 24, (1 << 64) - 1)
    rejected = path.read_bytes()
    with pytest.raises(ipc_ring.FrameError):
        kind(path, SLOTS, SLOT_BYTES, key=KEY)
    assert path.read_bytes() == rejected
