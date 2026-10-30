"""Synthetic Windows tables and metadata only; never query or open a host PID."""
from __future__ import annotations

import ctypes
import importlib
import struct
import sys
from types import MappingProxyType, SimpleNamespace

import pytest

from angerona.telemetry import sensors
from angerona.telemetry import windows_process_births as births


BASE = 0x100000
TICKS = 116444736000000000 + 17_000_000_000_000_000
OWN_PID = 991


@pytest.fixture(autouse=True)
def no_native_calls(monkeypatch):
    def refused(*args, **kwargs):
        pytest.fail("a synthetic test attempted to load a native DLL")

    monkeypatch.setattr(ctypes, "WinDLL", refused, raising=False)
    monkeypatch.setattr(sensors, "_WINDOWS_PROCESS_MAP", True)
    monkeypatch.setattr(sensors, "_proc_cache", (0.0, None))
    monkeypatch.setattr(sensors, "_process_snapshot_provider", None)
    births._system_library.cache_clear()
    yield
    births._system_library.cache_clear()


def table(rows, *, base=BASE, name=b"", threads=0):
    """Construct the pinned AMD64 layout without native structures/pointers."""
    size = (256 + threads * 80 + len(name) + 7) & ~7
    data = bytearray(size * len(rows))
    for index, (pid, ticks) in enumerate(rows):
        offset = index * size
        struct.pack_into("<II", data, offset, size if index + 1 < len(rows) else 0, threads)
        struct.pack_into("<q", data, offset + 32, ticks)
        struct.pack_into("<QQ", data, offset + 80, pid, 4)
        if name:
            start = offset + 256 + threads * 80
            struct.pack_into("<HH", data, offset + 56, len(name), len(name))
            struct.pack_into("<Q", data, offset + 64, base + start)
            data[start:start + len(name)] = name
    return data


def parsed(data):
    return births.parse_births(data, len(data), BASE)


def set_returned(pointer, value):
    ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32)).contents.value = value


def query_tables(tables):
    calls = []

    def query(kind, buffer, capacity, returned):
        calls.append(capacity)
        assert kind == 5
        rows = tables[len(calls) - 1]
        data = table(rows, base=ctypes.addressof(buffer))
        assert len(data) <= capacity
        buffer[:len(data)] = data
        set_returned(returned, len(data))
        return 0

    return query, calls


def test_import_is_inert_even_when_dll_loading_is_refused():
    importlib.reload(births)


def test_filetime_conversion_preserves_fraction_and_float_collision():
    assert births.filetime_to_unix(116444736000000001).hex() == (1e-7).hex()
    assert births.filetime_to_unix(TICKS) == 1_700_000_000.0
    assert births.filetime_to_unix(TICKS + 1) == 1_700_000_000.0
    assert births.filetime_to_unix(0) is None


@pytest.mark.parametrize("ticks", [True, -1, "1", 1.0, 1 << 63, 116444736000000000])
def test_invalid_filetimes_are_not_wraparound_or_plausible_births(ticks):
    with pytest.raises(births.BirthObservationError):
        births.filetime_to_unix(ticks)


@pytest.mark.parametrize("value", [None, 0.0, 100.0])
def test_fast_cache_is_read_without_filling_or_mutating_it(value):
    process = SimpleNamespace(_create_time=value, _ident=(731, None))
    original = vars(process).copy()
    assert births.cached_fast_birth(process) == value
    assert vars(process) == original


@pytest.mark.parametrize("value", [True, -1, "100", float("nan"), float("inf"), 10 ** 1000])
def test_changed_fast_cache_shape_or_value_is_rejected(value):
    with pytest.raises(births.BirthObservationError):
        births.cached_fast_birth(SimpleNamespace(_create_time=value))
    with pytest.raises(births.BirthObservationError, match="fast-cache-shape"):
        births.cached_fast_birth(SimpleNamespace())


def test_parser_returns_detached_immutable_raw_ticks_and_ignores_name_content():
    # An unpaired UTF-16 surrogate is not decoded, much less used as exe custody.
    data = table([(731, TICKS), (0, 0)], name=b"\x00\xd8", threads=1)
    result = parsed(data)
    assert result == {731: TICKS, 0: 0}
    with pytest.raises(TypeError):
        result[731] = TICKS + 1
    struct.pack_into("<q", data, 32, TICKS + 2)
    assert result[731] == TICKS


@pytest.mark.parametrize("data", [None, [], memoryview(bytearray(512))[::2]])
def test_nonbyte_or_noncontiguous_buffers_have_typed_failure(data):
    with pytest.raises(births.BirthObservationError):
        births.parse_births(data, 256, BASE)


@pytest.mark.parametrize("offset", [1, 248, 257, 512, 0xFFFFFFF8])
def test_malformed_next_offsets_are_rejected(offset):
    data = table([(731, TICKS), (732, TICKS)])
    struct.pack_into("<I", data, 0, offset)
    with pytest.raises(births.BirthObservationError):
        parsed(data)


@pytest.mark.parametrize("returned", [0, 255, 257, True, -1, 16 * 1024 * 1024 + 1])
def test_invalid_returned_lengths_never_form_empty_healthy_maps(returned):
    with pytest.raises(births.BirthObservationError, match="buffer-range"):
        births.parse_births(table([(731, TICKS)]), returned, BASE)


@pytest.mark.parametrize("base", [0, -1, True, (1 << 64) - 1])
def test_invalid_native_buffer_addresses_are_rejected_as_integers(base):
    with pytest.raises(births.BirthObservationError, match="buffer-range"):
        births.parse_births(table([(731, TICKS)]), 256, base)


def test_thread_array_must_fit_its_own_record():
    data = table([(731, TICKS), (732, TICKS)])
    struct.pack_into("<I", data, 4, 1)
    with pytest.raises(births.BirthObservationError, match="thread-range"):
        parsed(data)


@pytest.mark.parametrize("field", [80, 88])
def test_pointer_sized_pids_must_fit_the_public_pid_width(field):
    data = table([(731, TICKS)])
    struct.pack_into("<Q", data, field, 1 << 32)
    with pytest.raises(births.BirthObservationError, match="pid-range"):
        parsed(data)


def test_duplicate_pids_and_excess_rows_are_not_silently_overwritten(monkeypatch):
    with pytest.raises(births.BirthObservationError, match="duplicate-pid"):
        parsed(table([(731, TICKS), (731, TICKS)]))
    monkeypatch.setattr(births, "_MAX_ROWS", 2)
    with pytest.raises(births.BirthObservationError, match="row-limit"):
        parsed(table([(731, TICKS), (732, TICKS), (733, TICKS)]))


@pytest.mark.parametrize("ticks", [-1, 1, 116444736000000000])
def test_invalid_native_birth_ticks_reject_the_table(ticks):
    with pytest.raises(births.BirthObservationError):
        parsed(table([(731, ticks)]))


@pytest.mark.parametrize("length,maximum,pointer", [
    (1, 2, BASE), (2, 3, BASE), (4, 2, BASE), (2, 2, 0),
    (2, 2, BASE - 2), (2, 2, BASE + 256), (2, 2, (1 << 64) - 1),
])
def test_unicode_ranges_are_bounded_without_dereferencing(length, maximum, pointer):
    data = table([(731, TICKS)])
    struct.pack_into("<HH", data, 56, length, maximum)
    struct.pack_into("<Q", data, 64, pointer)
    with pytest.raises(births.BirthObservationError):
        parsed(data)


def test_empty_name_pointer_is_never_followed():
    data = table([(731, TICKS)])
    struct.pack_into("<Q", data, 64, (1 << 64) - 1)
    assert parsed(data) == {731: TICKS}


def test_reader_executes_each_query_and_never_reuses_observed_data():
    query, calls = query_tables([
        [(OWN_PID, TICKS), (731, TICKS)],
        [(OWN_PID, TICKS), (731, TICKS + 20)],
    ])
    reader = births._WindowsBirthReader(query, witness=(OWN_PID, TICKS))
    assert reader.own_pid == OWN_PID
    with pytest.raises(AttributeError):
        reader.own_pid = 731
    first, second = reader.read(), reader.read()
    assert len(calls) == 2 and first is not second
    assert first[731] == TICKS and second[731] == TICKS + 20


@pytest.mark.parametrize("own_rows", [[], [(OWN_PID, TICKS + 1)], [(OWN_PID, 0)]])
def test_each_map_requires_exact_raw_self_witness_even_with_float_collision(own_rows):
    query, calls = query_tables([
        [(OWN_PID, TICKS), (731, TICKS)],
        [*own_rows, (731, TICKS)],
    ])
    reader = births._WindowsBirthReader(query, witness=(OWN_PID, TICKS))
    assert reader.read()[OWN_PID] == TICKS
    with pytest.raises(births.BirthObservationError, match="self-witness-mismatch"):
        reader.read()
    assert len(calls) == 2


def test_injected_query_without_witness_cannot_query_the_host():
    with pytest.raises(births.BirthObservationError, match="witness-required"):
        births._WindowsBirthReader(lambda *args: pytest.fail("query called"))


@pytest.mark.parametrize("status", [0xC0000022, 0x80000005, 1])
def test_nonzero_nonresize_status_is_explicit_loss_without_partial_parsing(status):
    calls = []

    def query(kind, buffer, capacity, returned):
        calls.append(1)
        set_returned(returned, 256)
        return status - (1 << 32) if status & 0x80000000 else status

    reader = births._WindowsBirthReader(query, witness=(OWN_PID, TICKS))
    with pytest.raises(births.BirthObservationError, match=f"query-status-{status:08x}"):
        reader.read()
    assert len(calls) == 1


@pytest.mark.parametrize("status", [0xC0000004, 0xC0000023])
def test_recognized_resize_status_retries_with_bounded_growth(monkeypatch, status):
    monkeypatch.setattr(births, "_INITIAL_BUFFER", 256)
    calls = []

    def query(kind, buffer, capacity, returned):
        calls.append(capacity)
        if len(calls) == 1:
            set_returned(returned, 512)
            return status
        data = table([(OWN_PID, TICKS), (731, TICKS)], base=ctypes.addressof(buffer))
        buffer[:len(data)] = data
        set_returned(returned, len(data))
        return 0

    assert births._WindowsBirthReader(query, witness=(OWN_PID, TICKS)).read()[731] == TICKS
    assert calls == [256, 512]


def test_resize_attempt_and_allocation_limits_are_finite(monkeypatch):
    monkeypatch.setattr(births, "_INITIAL_BUFFER", 256)
    calls = []

    def repeated(kind, buffer, capacity, returned):
        calls.append(capacity)
        return 0xC0000004

    with pytest.raises(births.BirthObservationError, match="query-attempt-limit"):
        births._WindowsBirthReader(repeated, witness=(OWN_PID, TICKS)).read()
    assert calls == [256, 512, 1024, 2048]

    def oversized(kind, buffer, capacity, returned):
        set_returned(returned, 16 * 1024 * 1024 + 1)
        return 0xC0000004

    with pytest.raises(births.BirthObservationError, match="buffer-limit"):
        births._WindowsBirthReader(oversized, witness=(OWN_PID, TICKS)).read()


@pytest.mark.parametrize("extra", [0, 1])
def test_success_requires_a_valid_actual_returned_length(extra):
    def query(kind, buffer, capacity, returned):
        set_returned(returned, capacity + 1 if extra else 0)
        return 0

    with pytest.raises(births.BirthObservationError, match="buffer-range"):
        births._WindowsBirthReader(query, witness=(OWN_PID, TICKS)).read()


def compatible_psutil():
    class Process:
        def as_dict(self):
            pass

        def _get_ident(self):
            pass

    class Backend:
        def create_time(self):
            pass

    def pids():
        pass

    def proc_times():
        pass

    Process.__module__ = Process.as_dict.__module__ = Process._get_ident.__module__ = "psutil"
    Backend.__module__ = Backend.create_time.__module__ = "psutil._pswindows"
    pids.__module__ = "psutil"
    proc_times.__module__ = "psutil_windows"
    return SimpleNamespace(
        __version__="7.2.2", WINDOWS=True, Process=Process, pids=pids,
        _psplatform=SimpleNamespace(__name__="psutil._pswindows", Process=Backend,
                                    cext=SimpleNamespace(version=722, proc_times=proc_times)),
    )


@pytest.mark.skipif(sys.platform != "win32", reason="reviewed Windows psutil metadata seam")
def test_installed_psutil_722_metadata_matches_the_reviewed_admission_contract():
    # Inspect module/function metadata only. In particular, do not call
    # create_reader(), Process(), pids() or any native query in this test.
    import psutil

    if psutil.__version__ != "7.2.2":
        pytest.skip("only the reviewed psutil 7.2.2 metadata contract is admitted")
    assert births._compatible_psutil(psutil)


@pytest.mark.parametrize("changed", ["version", "pids", "factory", "backend", "native-version"])
def test_unsupported_or_replaced_psutil_seam_never_reaches_native_admission(monkeypatch, changed):
    monkeypatch.setattr(sys, "platform", "win32")
    psutil = compatible_psutil()
    if changed == "version":
        psutil.__version__ = "7.2.3"
    elif changed == "pids":
        psutil.pids = lambda: []
    elif changed == "factory":
        psutil.Process = lambda pid: None
    elif changed == "backend":
        psutil._psplatform.Process = type("Other", (), {})
    else:
        psutil._psplatform.cext.version = 721
    monkeypatch.setattr(births, "_native_amd64", lambda: pytest.fail("native admission called"))
    assert births.create_reader(psutil) is None


def test_compatible_seam_still_requires_reviewed_native_architecture(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(births, "_native_amd64", lambda: False)
    assert births.create_reader(compatible_psutil()) is None
    sentinel = object()
    monkeypatch.setattr(births, "_native_amd64", lambda: True)
    monkeypatch.setattr(births, "_WindowsBirthReader", lambda: sentinel)
    assert births.create_reader(compatible_psutil()) is sentinel


def test_admitted_binding_failure_has_a_fixed_code_without_legacy_selection(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(births, "_native_amd64", lambda: True)

    def failed():
        raise OSError("private loader path must not be retained")

    monkeypatch.setattr(births, "_WindowsBirthReader", failed)
    with pytest.raises(births.BirthObservationError, match="^native-binding$"):
        births.create_reader(compatible_psutil())


def test_nonwindows_selection_never_reaches_native_admission(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(births, "_native_amd64", lambda: pytest.fail("architecture queried"))
    assert births.create_reader(compatible_psutil()) is None


@pytest.mark.parametrize("process_machine,native_machine,success,expected", [
    (0, 0x8664, 1, True), (0x014C, 0x8664, 1, False),
    (0x8664, 0xAA64, 1, False), (0, 0xAA64, 1, False), (0, 0x8664, 0, False),
])
def test_architecture_gate_uses_only_own_pseudo_handle(
    monkeypatch, process_machine, native_machine, success, expected,
):
    calls = []

    def current():
        return -1

    def architecture(handle, process, native):
        assert handle == -1
        calls.append(handle)
        ctypes.cast(process, ctypes.POINTER(ctypes.c_ushort)).contents.value = process_machine
        ctypes.cast(native, ctypes.POINTER(ctypes.c_ushort)).contents.value = native_machine
        return success

    kernel = SimpleNamespace(GetCurrentProcess=current, IsWow64Process2=architecture)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: kernel)
    assert births._native_amd64() is expected
    assert calls == [-1]


def test_32_bit_runtime_cannot_bind_native_adapter(monkeypatch):
    monkeypatch.setattr(ctypes, "sizeof", lambda value: 4)
    assert births._native_amd64() is False


def test_own_witness_keeps_all_filetime_bits_and_does_not_close_pseudo_handle(monkeypatch):
    def current():
        return -1

    def pid():
        return OWN_PID

    def times(handle, created, exited, kernel, user):
        assert handle == -1
        stamp = ctypes.cast(created, ctypes.POINTER(births._Filetime)).contents
        stamp.low, stamp.high = (TICKS + 1) & 0xFFFFFFFF, (TICKS + 1) >> 32
        return 1

    kernel = SimpleNamespace(GetCurrentProcess=current, GetCurrentProcessId=pid,
                             GetProcessTimes=times,
                             CloseHandle=lambda *args: pytest.fail("pseudo handle closed"))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: kernel)
    assert births._own_witness() == (OWN_PID, TICKS + 1)


def test_failed_own_witness_is_explicit_loss_without_native_error_text(monkeypatch):
    def current():
        return -1

    def pid():
        pytest.fail("failed GetProcessTimes must not proceed to identity publication")

    def times(*args):
        return 0

    kernel = SimpleNamespace(GetCurrentProcess=current, GetCurrentProcessId=pid, GetProcessTimes=times)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: kernel)
    with pytest.raises(births.BirthObservationError, match="^self-witness-query$"):
        births._own_witness()


def metadata(pid=731, **changes):
    return {"pid": pid, "name": "fixture.exe", "exe": "C:/fixture.exe", "username": "fixture",
            "cmdline": ["fixture.exe"], **changes}


def install_bulk(monkeypatch, rows=None, *, observations=None, after=None,
                 before_fast=None, after_fast=None, parents=None, pids=None, own_pid=731):
    rows = [metadata()] if rows is None else rows
    by_pid = {row["pid"]: row for row in rows}
    after = by_pid if after is None else after
    if observations is None:
        observed = {pid: TICKS for pid in by_pid}
        observed.setdefault(own_pid, TICKS)
        observations = [observed, observed]
    before_fast = {} if before_fast is None else before_fast
    after_fast = {} if after_fast is None else after_fast
    events, objects, opened = [], [], {}

    class Process:
        def __init__(self, pid):
            self.pid = pid
            opened[pid] = opened.get(pid, 0) + 1
            self.second = opened[pid] == 2
            self._create_time = (after_fast if self.second else before_fast).get(pid)
            objects.append(self)
            events.append(("open", pid))

        def as_dict(self, *, attrs, ad_value):
            assert ad_value is None and "create_time" not in attrs
            events.append(("read", self.pid, tuple(attrs)))
            source = after if self.second else by_pid
            value = source[self.pid]
            if isinstance(value, Exception):
                raise value
            return {field: value.get(field) for field in attrs}

        def create_time(self):
            pytest.fail("admitted inventory invoked a slow public birth read")

    class Reader:
        def __init__(self):
            self.calls = 0

        @property
        def own_pid(self):
            return own_pid

        def read(self):
            events.append(("bulk", self.calls + 1))
            result = observations[self.calls]
            self.calls += 1
            if isinstance(result, Exception):
                raise result
            return MappingProxyType(dict(result))

    def public_pids():
        events.append(("pids",))
        return list(by_pid) if pids is None else pids()

    def parent_map():
        events.append(("map",))
        return {pid: 4 for pid in by_pid} if parents is None else parents

    psutil = SimpleNamespace(Process=Process, pids=public_pids, _ppid_map=parent_map)
    reader = Reader()
    monkeypatch.setitem(sys.modules, "psutil", psutil)
    monkeypatch.setattr(births, "create_reader", lambda adapter: reader if adapter is psutil else None)
    return events, objects, reader


def test_bulk_births_bracket_all_rich_map_and_independent_second_image_reads(monkeypatch):
    events, objects, reader = install_bulk(monkeypatch, [metadata(732), metadata(731)])
    receipt = sensors.process_snapshot(max_age=0)
    rich = ("pid", "name", "exe", "username", "cmdline")
    verify = ("pid", "exe")
    assert events == [
        ("pids",), ("bulk", 1),
        ("open", 732), ("read", 732, rich), ("open", 731), ("read", 731, rich),
        ("map",), ("open", 732), ("read", 732, verify),
        ("open", 731), ("read", 731, verify), ("bulk", 2),
    ]
    assert len(objects) == len({id(process) for process in objects}) == 4
    assert reader.own_pid == 731 and reader.calls == 2 and receipt.complete and receipt.enumeration_complete
    assert [row["pid"] for row in receipt.processes] == [732, 731]
    assert receipt.enumerated == 2 and receipt.skipped == receipt.identity_incomplete == receipt.unreadable == 0
    assert all(row["create_time"] == 1_700_000_000.0 and row["ppid"] == 4
               and row["cmdline"] == ("fixture.exe",) for row in receipt.processes)
    assert all(process._create_time is None for process in objects)


def test_admitted_empty_pid_list_is_explicit_loss_without_queries_or_legacy_refresh(monkeypatch):
    events, objects, reader = install_bulk(monkeypatch, rows=[], observations=[])
    monkeypatch.setattr(sensors, "_collect_process_snapshot_legacy",
                        lambda: pytest.fail("admitted empty PID list used legacy refresh"))
    receipt = sensors.process_snapshot(max_age=0)
    assert events == [("pids",)] and not objects and reader.calls == 0
    assert receipt.processes == () and not receipt.complete and not receipt.enumeration_complete
    assert receipt.enumerated == receipt.skipped == receipt.unreadable == receipt.identity_incomplete == 0
    assert receipt.error == "Windows PID table unexpectedly empty"


def test_admitted_nonempty_pid_list_omitting_self_keeps_visible_rows_as_partial(monkeypatch):
    events, objects, reader = install_bulk(monkeypatch, [metadata(732)])
    monkeypatch.setattr(sensors, "_collect_process_snapshot_legacy",
                        lambda: pytest.fail("omitted-self table used legacy refresh"))
    receipt = sensors.process_snapshot(max_age=0)
    assert reader.own_pid == 731 and reader.calls == 2 and len(objects) == 2
    assert events.count(("pids",)) == events.count(("map",)) == 1
    assert [event for event in events if event[0] == "bulk"] == [("bulk", 1), ("bulk", 2)]
    assert [row["pid"] for row in receipt.processes] == [732]
    assert receipt.processes[0]["create_time"] == 1_700_000_000.0
    assert receipt.enumerated == 1 and receipt.skipped == receipt.unreadable == receipt.identity_incomplete == 0
    assert not receipt.complete and not receipt.enumeration_complete
    assert receipt.error == "Windows PID table omitted current worker"


@pytest.mark.parametrize("change", ["raw", "raw-float-collision", "fast-before", "fast-after", "image", "pid"])
def test_known_disagreements_cannot_stitch_a_row_or_parent_claim(monkeypatch, change):
    second_ticks = TICKS + (1 if change == "raw-float-collision" else 10_000_000)
    observations = [{731: TICKS, OWN_PID: TICKS},
                    {731: second_ticks if change.startswith("raw") else TICKS, OWN_PID: TICKS}]
    before_fast = {731: 1_700_000_001.0} if change == "fast-before" else {}
    after_fast = {731: 1_700_000_001.0} if change == "fast-after" else {}
    after = {731: metadata(**({"exe": "C:/new.exe"} if change == "image" else
                             {"pid": 999} if change == "pid" else {})), OWN_PID: metadata(OWN_PID)}
    install_bulk(monkeypatch, [metadata(), metadata(OWN_PID)], observations=observations, after=after,
                 before_fast=before_fast, after_fast=after_fast, own_pid=OWN_PID)
    receipt = sensors.process_snapshot(max_age=0)
    assert [row["pid"] for row in receipt.processes] == [OWN_PID]
    assert receipt.skipped == 1 and receipt.error
    assert not receipt.complete and not receipt.enumeration_complete


@pytest.mark.parametrize("observations", [[{}, {731: TICKS}], [{731: TICKS}, {}], [{731: 0}, {731: 0}]])
def test_missing_bulk_birth_never_promotes_a_successful_fast_cache(monkeypatch, observations):
    observations = [{**observed, OWN_PID: TICKS} for observed in observations]
    install_bulk(monkeypatch, [metadata(), metadata(OWN_PID)], observations=observations,
                 before_fast={731: 1_700_000_000.0}, after_fast={731: 1_700_000_000.0}, own_pid=OWN_PID)
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.enumeration_complete and not receipt.complete and receipt.identity_incomplete == 1
    assert receipt.skipped == 0 and receipt.processes[0]["create_time"] is None
    assert receipt.processes[0]["ppid"] is None


def test_lost_bulk_maps_cannot_mask_disagreeing_known_fast_births(monkeypatch):
    install_bulk(monkeypatch,
                 observations=[births.BirthObservationError("self-witness-mismatch")] * 2,
                 before_fast={731: 1_700_000_000.0}, after_fast={731: 1_700_000_001.0})
    receipt = sensors.process_snapshot(max_age=0)
    assert not receipt.processes and receipt.skipped == 1
    assert not receipt.complete and not receipt.enumeration_complete


@pytest.mark.parametrize("side", [0, 1])
def test_query_loss_preserves_metadata_as_unknown_without_legacy_refresh(monkeypatch, side):
    observations = [{731: TICKS}, {731: TICKS}]
    observations[side] = births.BirthObservationError("query-status-c0000022")
    events, _objects, reader = install_bulk(monkeypatch, observations=observations)
    monkeypatch.setattr(sensors, "_collect_process_snapshot_legacy",
                        lambda: pytest.fail("admitted failure used legacy refresh"))
    receipt = sensors.process_snapshot(max_age=0)
    assert reader.calls == 2 and events[-1] == ("bulk", 2)
    assert not receipt.complete and not receipt.enumeration_complete
    assert receipt.enumerated == 1 and receipt.skipped == 0 and receipt.identity_incomplete == 1
    assert "query-status-c0000022" in receipt.error
    assert receipt.processes[0]["create_time"] is None and receipt.processes[0]["ppid"] is None
    assert receipt.processes[0]["exe"] == "C:/fixture.exe"


@pytest.mark.parametrize("field", ["exe", "cmdline"])
@pytest.mark.parametrize("side", ["before", "after"])
def test_protected_metadata_stays_unknown_with_valid_bulk_births(monkeypatch, field, side):
    first, last = metadata(), metadata()
    (first if side == "before" else last)[field] = None
    install_bulk(monkeypatch, [first], after={731: last})
    receipt = sensors.process_snapshot(max_age=0)
    # The second pass reads image only: its unrelated cmdline is not evidence.
    if field == "cmdline" and side == "after":
        assert receipt.complete
    elif field == "cmdline":
        assert receipt.unreadable == 1 and receipt.processes[0]["cmdline"] is None
        assert not receipt.complete
    else:
        assert receipt.identity_incomplete == 1 and receipt.processes[0]["exe"] is None
        assert receipt.processes[0]["ppid"] is None and not receipt.complete


def test_denied_pid_zero_and_four_fallbacks_do_not_promote_native_births(monkeypatch):
    install_bulk(monkeypatch, [metadata(0), metadata(4), metadata(731)])
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.enumeration_complete and not receipt.complete and receipt.identity_incomplete == 2
    assert [row["create_time"] for row in receipt.processes] == [None, None, 1_700_000_000.0]
    assert [row["ppid"] for row in receipt.processes] == [None, None, 4]


def test_successful_pid_four_fast_birth_is_preserved_and_zero_fast_birth_is_not_promoted(monkeypatch):
    install_bulk(monkeypatch, [metadata(4), metadata(731)],
                 before_fast={4: 1_700_000_000.0, 731: 0.0},
                 after_fast={4: 1_700_000_000.0, 731: 0.0})
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.processes[0]["create_time"] == 1_700_000_000.0
    assert receipt.processes[0]["ppid"] == 4
    assert receipt.processes[1]["create_time"] is None and receipt.processes[1]["ppid"] is None


def test_bounded_public_pid_order_and_loss_counters_are_preserved(monkeypatch):
    monkeypatch.setattr(sensors, "_MAX_PROCESS_ROWS", 2)
    events, _objects, reader = install_bulk(monkeypatch, [metadata(733), metadata(731), metadata(732)])
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.enumerated == 3 and receipt.skipped == 1 and not receipt.enumeration_complete
    assert [row["pid"] for row in receipt.processes] == [733, 731]
    assert reader.calls == 2 and events.count(("map",)) == 1 and "bounded row limit" in receipt.error


def test_oversized_pid_list_does_not_preinspect_unbounded_members(monkeypatch):
    monkeypatch.setattr(sensors, "_MAX_PROCESS_ROWS", 2)

    class Unvisited:
        def __eq__(self, other):
            pytest.fail("oversized table membership prewalk reached an unretained row")

    events, objects, reader = install_bulk(
        monkeypatch, [metadata(733), metadata(731)], own_pid=OWN_PID,
        pids=lambda: [733, 731, Unvisited()],
    )
    receipt = sensors.process_snapshot(max_age=0)
    assert [row["pid"] for row in receipt.processes] == [733, 731]
    assert receipt.enumerated == 3 and receipt.skipped == 1 and len(objects) == 4
    assert reader.calls == 2 and events.count(("map",)) == 1
    assert not receipt.complete and not receipt.enumeration_complete
    assert receipt.error == "process inventory exceeded the bounded row limit"


@pytest.mark.parametrize("pids", [None, (731,), {731}])
def test_admitted_pid_table_requires_a_list_without_queries_or_legacy(monkeypatch, pids):
    events, objects, reader = install_bulk(monkeypatch, pids=lambda: pids)
    monkeypatch.setattr(sensors, "_collect_process_snapshot_legacy",
                        lambda: pytest.fail("malformed PID table used legacy refresh"))
    receipt = sensors.process_snapshot(max_age=0)
    assert events == [("pids",)] and not objects and reader.calls == 0
    assert receipt.processes == () and receipt.enumerated == receipt.skipped == 0
    assert not receipt.enumeration_complete and not receipt.complete
    assert receipt.error == "Windows PID table shape unavailable"


def test_admitted_pid_iterator_is_not_consumed_as_a_supported_table(monkeypatch):
    def pids():
        pytest.fail("unsupported PID iterator was consumed")
        yield 731

    events, objects, reader = install_bulk(monkeypatch, pids=pids)
    receipt = sensors.process_snapshot(max_age=0)
    assert events == [("pids",)] and not objects and reader.calls == 0
    assert not receipt.enumeration_complete and not receipt.complete
    assert receipt.error == "Windows PID table shape unavailable"


def test_second_process_exit_is_skipped_before_the_final_bulk_observation(monkeypatch):
    events, _objects, reader = install_bulk(monkeypatch, after={731: ProcessLookupError("fixture exit")})
    receipt = sensors.process_snapshot(max_age=0)
    assert not receipt.processes and receipt.skipped == 1 and not receipt.enumeration_complete
    assert reader.calls == 2 and events[-1] == ("bulk", 2)


def test_invalid_parent_map_keeps_metadata_but_cannot_claim_completeness(monkeypatch):
    install_bulk(monkeypatch, parents={731: True})
    receipt = sensors.process_snapshot(max_age=0)
    assert len(receipt.processes) == 1 and receipt.processes[0]["ppid"] is None
    assert not receipt.complete and not receipt.enumeration_complete
    assert "parent map unavailable" in receipt.error


def test_admitted_self_witness_failure_is_explicit_and_sanitized_without_legacy_scan(monkeypatch):
    monkeypatch.setitem(sys.modules, "psutil", SimpleNamespace())

    def failed(psutil):
        raise births.BirthObservationError("self-witness-query")

    monkeypatch.setattr(births, "create_reader", failed)
    monkeypatch.setattr(sensors, "_collect_process_snapshot_legacy",
                        lambda: pytest.fail("self-witness failure used legacy"))
    receipt = sensors.process_snapshot(max_age=0)
    assert not receipt.processes and receipt.enumerated == 0
    assert not receipt.complete and not receipt.enumeration_complete
    assert "self-witness-query" in receipt.error
    assert str(births.BirthObservationError("C:/private/error")) == "adapter-error"


def test_public_psutil_objects_never_invoke_denied_slow_birth_fallback_when_admitted(monkeypatch):
    import psutil

    objects, slow_calls = [], []

    class Backend:
        def __init__(self, pid):
            self.pid, self._name = pid, None
            objects.append(self)

        def create_time(self, fast_only=False, monotonic=False):
            if fast_only:
                raise psutil.AccessDenied(self.pid)
            if monotonic:
                return 1_700_000_000.0
            slow_calls.append(self.pid)
            pytest.fail("denied slow fallback invoked")

        def oneshot_enter(self):
            pass

        def oneshot_exit(self):
            pass

        def name(self):
            return "fixture.exe"

        def exe(self):
            return "C:/fixture.exe"

        def cmdline(self):
            return ["fixture.exe"]

    class Reader:
        calls = 0
        own_pid = 731

        def read(self):
            self.calls += 1
            return MappingProxyType({731: TICKS})

    reader = Reader()
    monkeypatch.setattr(psutil._psplatform, "Process", Backend)
    monkeypatch.setattr(psutil.Process, "username", lambda self: "fixture")
    monkeypatch.setattr(psutil, "pids", lambda: [731])
    monkeypatch.setattr(psutil, "_ppid_map", lambda: {731: 4}, raising=False)
    monkeypatch.setattr(births, "create_reader", lambda adapter: reader)
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.complete and receipt.processes[0]["create_time"] == 1_700_000_000.0
    assert not slow_calls and len(objects) == 2 and objects[0] is not objects[1]
    assert reader.calls == 2
