from __future__ import annotations

import json
import ctypes
import os
import struct
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.forensic_vault import read_vault
from angerona.core.windows_process_lease import ProcessObjectIdentity
from angerona.modules import forensics

TICKS = forensics._EPOCH + 100 * 10_000_000


def signed(module, **changes):
    bus = EventBus()
    bus.arm(BusAuthority(b"forensic-offline-authority-key-32!"))
    module.bind(bus)
    details = {"pid": 4242, "process_birth_ticks": str(TICKS), "process_create_time": 100.0,
               "active_attack": True, **changes}
    bus.publish(Event("Native Detection", "Observed active local evidence", Severity.HIGH, details=details))
    return bus.recent(1)[0]


class Native:
    def __init__(self):
        self.birth = TICKS
        self.image = r"D:\fixtures\sample.exe"
        self.exited = False
        self.opened = []
        self.closed = []
        self.reads = []
        self.socket_calls = 0

    def open(self, pid, rights, inherit):
        self.opened.append((pid, rights, inherit))
        return 901

    def identity(self, handle):
        assert handle == 901
        return ProcessObjectIdentity(4242, self.birth, self.image)

    def wait(self, handle, milliseconds):
        assert handle == 901 and milliseconds == 0
        return self.exited

    def is_system(self, _handle):
        return False

    def close(self, handle):
        self.closed.append(handle)

    def region(self, handle, address):
        return (0, 16, 0x1000, 4) if address == 0 else None

    def memory(self, handle, address, amount):
        self.reads.append((handle, address, amount))
        return b"SECRET-MEMORY\x00\x00\x00", True

    def socket_rows(self, pid, check):
        assert pid == 4242
        check()
        self.socket_calls += 1
        return [{"protocol": "tcp", "remote_ip": "192.0.2.1", "remote_port": 443}]


@pytest.mark.parametrize("details", [
    {}, {"create_time": None}, {"create_time": True}, {"create_time": float("nan")},
    {"create_time": float("inf")}, {"create_time": 0}, {"create_time": -1},
    {"process_create_time": "100"}, {"create_time": 100, "process_create_time": 101},
    {"process_birth_ticks": None}, {"process_birth_ticks": True},
    {"process_birth_ticks": str(TICKS), "native_birth_ticks": TICKS + 1},
    {"process_birth_ticks": str(TICKS), "create_time": 101},
])
def test_missing_nonfinite_bool_and_conflicting_identity_never_queries_current_pid(details, monkeypatch):
    import psutil
    monkeypatch.setattr(psutil, "Process", lambda *_a: pytest.fail("must not substitute the current PID generation"))
    with pytest.raises(ValueError):
        forensics._identity(4242, details)


def test_raw_identity_is_preserved_and_lossy_seconds_cannot_mint_ticks():
    assert forensics._identity(4242, {"process_birth_ticks": str(TICKS)}) == (4242, 100.0, TICKS)
    assert forensics._identity(4242, {"create_time": 100.0}) == (4242, 100.0, None)


def test_raw_birth_dedup_keeps_distinct_native_generations():
    module = forensics.ForensicsModule()
    assert module._capture_needed(4242, {"process_birth_ticks": str(TICKS)}, now=200)
    assert not module._capture_needed(4242, {"process_birth_ticks": str(TICKS)}, now=201)
    assert module._capture_needed(4242, {"process_birth_ticks": str(TICKS + 1)}, now=202)


def test_authenticated_original_admits_but_modified_and_seconds_only_hold():
    module = forensics.ForensicsModule()
    event = signed(module)
    assert module._admit(event) == (4242, 100.0, TICKS)
    with pytest.raises(ValueError):
        module._admit(replace(event, message="altered"))
    legacy = signed(module)
    details = dict(legacy.details)
    del details["process_birth_ticks"]
    module._bus.publish(Event("Native Detection", "Observed active local evidence", Severity.HIGH, details=details))
    with pytest.raises(ValueError, match="exact native process birth missing"):
        module._admit(module._bus.recent(1)[0])


@pytest.mark.parametrize("changes", [
    {"active_attack": False, "disposition": "observation"},
    {"node_origin": "other-host"}, {"raw_sensor_evidence": True},
    {"drill": True}, {"active_attack": False, "finding_kind": "exposure"},
])
def test_remote_advisory_raw_and_practice_sources_cannot_trigger_reads(changes):
    module = forensics.ForensicsModule()
    event = signed(module, **changes)
    with pytest.raises(ValueError):
        module._admit(event)


def test_unsigned_unarmed_or_stale_evidence_is_held():
    module = forensics.ForensicsModule()
    event = signed(module)
    with pytest.raises(ValueError):
        module._admit(replace(event, hmac_sig=""))
    stale = replace(event, ts=time.time() - 60)
    module._bus.publish(stale)
    with pytest.raises(ValueError):
        module._admit(module._bus.recent(1)[0])
    module.bind(EventBus())
    with pytest.raises(ValueError):
        module._admit(event)


def test_exact_native_handle_is_held_through_collectors_and_retired():
    native = Native()
    with forensics._CaptureHandle(4242, TICKS, 100, _native=native, _clock=lambda: 1) as retained:
        retained.check()
        assert retained.handle == 901
        assert native.closed == []
        assert not native.opened[0][1] & 0x0001  # no terminate right
        assert native.opened[0][1] & 0x0010
        assert native.opened[0][2] is False
    assert native.closed == [901]


@pytest.mark.parametrize("change", ["birth", "exit", "protected"])
def test_changed_exited_or_protected_native_process_is_refused_and_handle_closed(change):
    native = Native()
    if change == "birth":
        native.birth += 1
    elif change == "exit":
        native.exited = True
    else:
        native.image = r"C:\Windows\System32\lsass.exe"
    with pytest.raises(ValueError):
        forensics._CaptureHandle(4242, TICKS, 100, _native=native, _clock=lambda: 1)
    assert native.closed == [901] and not native.reads


def test_native_handle_deadline_and_identity_changes_hold_later_reads():
    native, clock = Native(), [1.0]
    with forensics._CaptureHandle(4242, TICKS, 10, _native=native, _clock=lambda: clock[0]) as retained:
        clock[0] = 11
        with pytest.raises(ValueError, match="deadline"):
            retained.check()
    assert native.closed == [901]


@pytest.mark.parametrize("clock,deadline", [
    (float("nan"), 10), (float("inf"), 10), (True, 10), (-1, 10),
    (1, float("inf")), (1, float("nan")), (1, True), (1, 1), (1, 0),
])
def test_capture_clock_and_deadline_refuse_before_process_open(clock, deadline):
    native = Native()
    with pytest.raises(ValueError, match="clock/deadline"):
        forensics._CaptureHandle(4242, TICKS, deadline, _native=native, _clock=lambda: clock)
    assert native.opened == [] and native.closed == []


@pytest.mark.parametrize("failure", ["false", "raises"])
def test_failed_native_close_is_retained_once_and_holds_only_future_capture(monkeypatch, failure):
    from angerona.core import forensic_vault as vault
    monkeypatch.setattr(vault, "_RETIREMENT_HOLDS", {})
    native = Native()
    calls = []
    def close(handle):
        calls.append(handle)
        if failure == "raises":
            raise OSError("fixture close uncertainty")
        return False
    native.close = close
    retained = forensics._CaptureHandle(4242, TICKS, 10, _native=native, _clock=lambda: 1)
    with pytest.raises(vault.ForensicVaultError, match="retirement unavailable"):
        retained.close()
    assert retained.handle == 901
    assert calls == [901]
    assert vault.retirement_snapshot()["capture_held"]
    assert vault.retirement_snapshot()["ambiguous_owners"] == 1
    with pytest.raises(vault.ForensicVaultError, match="remains unverified"):
        retained.close()
    assert calls == [901]  # an ambiguous numeric handle must never be retried
    with pytest.raises(ValueError, match="custody is closed"):
        retained.check()
    module = forensics.ForensicsModule()
    with pytest.raises(vault.ForensicVaultError, match="restart Angerona"):
        module._admit(signed(module))
    assert "normal shutdown" in module.forensic_capture_snapshot()["scope"]
    assert native.reads == [] and native.socket_calls == 0


def test_full_capture_writes_only_authenticated_ciphertext_with_mocked_reads(tmp_path, monkeypatch):
    module, native = forensics.ForensicsModule(), Native()
    event = signed(module)
    monkeypatch.setattr(forensics, "_evidence_root", lambda: tmp_path)
    original = forensics._CaptureHandle
    monkeypatch.setattr(forensics, "_CaptureHandle", lambda pid, ticks, deadline: original(pid, ticks, deadline, _native=native))
    result = module._capture(4242, expected_create_time=100.0, event=event)
    assert result["complete"] and result["encrypted"], result
    path = Path(result["path"])
    assert b"SECRET-MEMORY" not in path.read_bytes()
    assert b"192.0.2.1" not in path.read_bytes()
    assert list(path.parent.iterdir()) == [path]
    verified = read_vault(path)
    assert b"SECRET-MEMORY" in verified["records"]["memory"]
    assert json.loads(verified["records"]["sockets"])["remote_ip"] == "192.0.2.1"
    assert verified["receipt"]["capture"]["shell_history"]["collected"] is False
    assert verified["receipt"]["capture"]["source_event"]["hmac_sig"] == event.hmac_sig
    assert native.closed == [901] and native.socket_calls == 1


def test_late_directory_retirement_failure_never_returns_completed_capture(tmp_path, monkeypatch):
    from angerona.core import forensic_vault as vault
    monkeypatch.setattr(vault, "_RETIREMENT_HOLDS", {})
    module, native = forensics.ForensicsModule(), Native()
    event = signed(module)
    monkeypatch.setattr(forensics, "_evidence_root", lambda: tmp_path)
    original = forensics._CaptureHandle
    monkeypatch.setattr(forensics, "_CaptureHandle", lambda pid, ticks, deadline: original(pid, ticks, deadline, _native=native))
    class LateHold:
        def __enter__(self):
            self.pins = vault.DirectoryPins(tmp_path)
            self.pins.__enter__()
            return self
        def __exit__(self, *args):
            self.pins.__exit__(*args)  # real fixture handles are retired first
            vault.retain_retirement_hold(self, "directory")
            raise vault.ForensicVaultError("fixture directory retirement unavailable")
    monkeypatch.setattr(forensics, "DirectoryPins", lambda _path: LateHold())
    result = module._capture(4242, expected_create_time=100.0, event=event)
    assert not result["complete"] and result["encrypted"]
    assert result["forensic_retirement"]["capture_held"]
    assert Path(result["path"]).is_file()  # completed bytes remain available for independent review
    assert module.health == 45
    assert native.closed == [901]


def test_crypto_failure_holds_before_opening_suspect_and_preserves_originals(tmp_path, monkeypatch):
    from angerona.modules import hardware_crypto
    module = forensics.ForensicsModule()
    event = signed(module)
    original = tmp_path / "old-plaintext.txt"
    original.write_bytes(b"preserved-historical-evidence")
    monkeypatch.setattr(forensics, "_evidence_root", lambda: tmp_path)
    monkeypatch.setattr(hardware_crypto, "protect", lambda *_a: None)
    monkeypatch.setattr(forensics, "_CaptureHandle", lambda *_a: pytest.fail("crypto must verify before foreign process open"))
    result = module._capture(4242, expected_create_time=100.0, event=event)
    assert not result["complete"] and not result["encrypted"]
    assert original.read_bytes() == b"preserved-historical-evidence"
    assert not list(tmp_path.glob("Case_*/*.txt"))
    assert not list(tmp_path.glob("Case_*"))


def test_process_exit_during_read_preserves_partial_encrypted_receipt_not_false_completion(tmp_path, monkeypatch):
    module, native = forensics.ForensicsModule(), Native()
    event = signed(module)
    monkeypatch.setattr(forensics, "_evidence_root", lambda: tmp_path)
    original = forensics._CaptureHandle
    monkeypatch.setattr(forensics, "_CaptureHandle", lambda pid, ticks, deadline: original(pid, ticks, deadline, _native=native))
    def memory(*_args):
        native.exited = True
        return b"SECRET-MEMORY\0\0\0", True
    native.memory = memory
    result = module._capture(4242, expected_create_time=100.0, event=event)
    assert result["encrypted"] and not result["complete"]
    verified = read_vault(Path(result["path"]))
    receipt = verified["receipt"]["capture"]
    assert not receipt["complete"] and receipt["failure_type"] == "ValueError"
    assert receipt["memory"]["read_bytes"] is None
    assert "completion unavailable" in receipt["memory"]["reason"]
    assert verified["records"]["sockets"] == b""
    assert native.closed == [901] and not native.socket_calls


def test_socket_postcheck_rejects_reused_pid_before_writing_any_socket_data(monkeypatch):
    module, native = forensics.ForensicsModule(), Native()
    event = signed(module)
    def rows(_pid, _check):
        native.exited = True
        return [{"remote_ip": "192.0.2.1"}]
    native.socket_rows = rows
    output = []
    with forensics._CaptureHandle(4242, TICKS, 100, _native=native, _clock=lambda: 1) as retained:
        with pytest.raises(ValueError):
            module._audit_sockets(retained, SimpleNamespace(append=lambda *args: output.append(args)), event=event)
    assert output == []


def test_failed_memory_reads_still_consume_byte_budget(monkeypatch):
    module, native = forensics.ForensicsModule(), Native()
    event = signed(module)
    monkeypatch.setattr(forensics, "_MEMORY_READ_BUDGET", 8)
    native.region = lambda _h, address: (0, 1000, 0x1000, 4) if address == 0 else None
    native.memory = lambda *_a: (b"", False)
    with forensics._CaptureHandle(4242, TICKS, 100, _native=native, _clock=lambda: 1) as retained:
        receipt = module._dump_memory_strings(retained, SimpleNamespace(append=lambda *_a: None), event=event)
    assert not receipt["complete"]
    assert receipt["attempted_bytes"] == 8 and receipt["read_bytes"] == 0


def test_none_original_direct_capture_cannot_open_a_process(tmp_path, monkeypatch):
    module = forensics.ForensicsModule()
    monkeypatch.setattr(forensics, "_CaptureHandle", lambda *_a: pytest.fail("no original evidence"))
    result = module._capture(4242, expected_create_time=None)
    assert not result["complete"]


def test_system_owner_is_excluded_even_for_non_windows_path():
    native = Native()
    native.is_system = lambda _h: True
    with pytest.raises(ValueError, match="protected"):
        forensics._CaptureHandle(4242, TICKS, 100, _native=native, _clock=lambda: 1)
    assert native.closed == [901] and not native.reads


def test_native_socket_row_decoding_uses_owner_pid_network_ports_and_ipv6_scopes():
    port = lambda value: int.from_bytes(value.to_bytes(2, "big") + b"\0\0", "little")
    scope = lambda value: int.from_bytes(value.to_bytes(4, "big"), "little")
    ipv4 = int.from_bytes(bytes([192, 0, 2, 1]), "little")
    ipv6 = bytes.fromhex("20010db8000000000000000000000001")
    native = object.__new__(forensics._NativeCapture)
    def table(protocol):
        def read(buffer, size, _order, af, klass, _reserved):
            assert klass == (5 if protocol == "tcp" else 1)
            if af == 2:
                raw = struct.pack("<6I", 5, ipv4, port(1234), ipv4, port(443), 4242) if protocol == "tcp" else struct.pack("<3I", ipv4, port(53), 4242)
            else:
                raw = struct.pack("<16sII16sIIII", ipv6, scope(3), port(1234), ipv6, scope(5), port(443), 5, 4242) if protocol == "tcp" else struct.pack("<16sIII", ipv6, scope(3), port(53), 4242)
            raw = struct.pack("<I", 1) + raw
            size._obj.value = len(raw)
            if buffer is None:
                return 122
            ctypes.memmove(buffer, raw, len(raw))
            return 0
        return read
    native._iphlp = SimpleNamespace(GetExtendedTcpTable=table("tcp"), GetExtendedUdpTable=table("udp"))
    rows = native.socket_rows(4242, lambda: None)
    assert len(rows) == 4
    tcp6 = next(row for row in rows if row["protocol"] == "tcp" and row["family"] == "ipv6")
    assert tcp6["local_port"] == 1234 and tcp6["remote_port"] == 443
    assert tcp6["local_scope"] == 3 and tcp6["remote_scope"] == 5
    assert native.socket_rows(99, lambda: None) == []


def test_native_owner_and_retained_handle_only_for_our_inert_child(request):
    if os.name != "nt":
        pytest.skip("Windows native handle and token APIs")
    # This fixture never reads memory or host socket tables. It owns its child,
    # captures raw creation identity through a retained handle, and retires it.
    child = subprocess.Popen([sys._base_executable, "-I", "-c", "import sys; sys.stdin.buffer.read(1)"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    query = handle = None
    try:
        query = forensics._ProcessNative()
        handle = query.open(child.pid, 0x1000 | 0x00100000, False)
        identity = query.identity(handle)
        assert identity.pid == child.pid and identity.birth_ticks > forensics._EPOCH
        request.node.user_properties.extend([
            ("owned_child_pid", str(identity.pid)),
            ("owned_child_birth_ticks", str(identity.birth_ticks)),
            ("owned_child_image", identity.image),
        ])
        assert Path(identity.image).samefile(sys._base_executable)
        native = forensics._NativeCapture()
        owner_is_system = native.is_system(handle)
        assert type(owner_is_system) is bool
        request.node.user_properties.append(("owned_child_system_owner", str(owner_is_system)))
        # Hosted Python can live below a literal Windows directory or run as
        # SYSTEM. The production exclusion must still hold for our own child.
        protected = ("\\windows\\" in identity.image.casefold()
                     or "angerona" in identity.image.casefold()
                     or owner_is_system)
        if protected:
            with pytest.raises(ValueError, match="protected process is excluded"):
                forensics._CaptureHandle(child.pid, identity.birth_ticks, time.monotonic() + 5,
                                         _native=native)
        else:
            with forensics._CaptureHandle(child.pid, identity.birth_ticks, time.monotonic() + 5,
                                          _native=native) as retained:
                retained.check()
                assert retained.identity == identity
        assert query.identity(handle) == identity
        assert child.communicate(b"x", timeout=5) == (b"", b"")
        assert child.returncode == 0
        assert query.wait(handle, 0) is True and query.exit_code(handle) == 0
        request.node.user_properties.append(("owned_child_exit_code", "0"))
    finally:
        if child.poll() is None:
            child.kill()  # exact Popen-owned object, never a discovered PID
            child.wait(timeout=5)
        if handle is not None:
            assert query.close(handle) is not False
            request.node.user_properties.append(("owned_query_handle_closed", "True"))
