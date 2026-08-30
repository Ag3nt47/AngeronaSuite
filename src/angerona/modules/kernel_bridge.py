"""Kernel Sensor Bridge — G3-C.

Python user-mode interface to the AngeronaSensor.sys kernel driver.
Reads process-creation and image-load events from the kernel ring buffer
via DeviceIoControl and emits them on the Angerona bus.

Why a kernel driver?
  User-mode telemetry (ETW, win32evtlog, psutil) can be suppressed by a
  sophisticated attacker who patches ntdll!EtwEventWrite or modifies the
  userland call chain.  A kernel driver registered via
  PsSetCreateProcessNotifyRoutineEx receives callbacks at kernel IRQL before
  any user-mode code runs — it cannot be silenced from user space.

Prerequisite:
  AngeronaSensor.sys must be built (see kernel/AngeronaSensor/build.bat)
  and loaded:
      sc create AngeronaSensor type= kernel binPath= C:\\path\\AngeronaSensor.sys
      sc start  AngeronaSensor

  The driver creates \\\\.\\\\ AngeronaSensor which this bridge opens with
  DeviceIoControl.

Fallback:
  If the driver is not loaded (or not built yet), this module emits a one-time
  INFO notice and parks idle — it does NOT crash or degrade other modules.

IOCTL codes (must match AngeronaSensor.h):
  GET_VERSION   = 0x80002000
  GET_EVENTS    = 0x80002004
  CLEAR_EVENTS  = 0x80002008
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import struct
import time
from typing import Callable, Optional

from angerona.core.module_base import BaseModule, Severity

# ── IOCTL codes (CTL_CODE values from AngeronaSensor.h) ──────────────────────
IOCTL_GET_VERSION   = 0x80002000
IOCTL_GET_EVENTS    = 0x80002004
IOCTL_CLEAR_EVENTS  = 0x80002008

_DEVICE_PATH = r"\\.\AngeronaSensor"

# Event types (must match ANGERONA_EVENT_TYPE in header)
_EVT_PROCESS_CREATE = 1
_EVT_PROCESS_EXIT   = 2
_EVT_IMAGE_LOAD     = 3

_EVT_LABELS = {
    _EVT_PROCESS_CREATE: "Process Created (kernel)",
    _EVT_PROCESS_EXIT:   "Process Exit (kernel)",
    _EVT_IMAGE_LOAD:     "Image Load (kernel)",
}

# Struct layout: matches ANGERONA_EVENT (packed, no padding)
# Fields: EventType(4) Sequence(8) ProcessId(4) ParentProcessId(4) ThreadId(4)
#         Timestamp(8) ImagePathLen(4) ImagePath(520) CommandLineLen(4) CommandLine(520)
_EVENT_FMT  = "<IQIIIQI520sI520s"
_EVENT_SIZE = struct.calcsize(_EVENT_FMT)

_POLL_INTERVAL    = 1.0   # seconds between driver polls
_MAX_EVENTS_BATCH = 64    # events to drain per poll
_EXPECTED_VERSION = (2, 0, 0)
_EXPECTED_TAG = b"ANGRSENS"
_PROTOCOL_VERSION = 2
_CAP_PROCESS = 0x00000001
_CAP_IMAGE = 0x00000002
_CAP_SEQUENCE = 0x00000004
_CAP_LOSS = 0x00000008
_CAP_HEARTBEAT = 0x00000010
_REQUIRED_CAPABILITIES = (
    _CAP_PROCESS | _CAP_IMAGE | _CAP_SEQUENCE | _CAP_LOSS | _CAP_HEARTBEAT
)
_VERSION_FMT = "<III8sIIQQQQ"
_VERSION_SIZE = struct.calcsize(_VERSION_FMT)
_EVENTS_HEADER_FMT = "<IIQQQ"
_EVENTS_HEADER_SIZE = struct.calcsize(_EVENTS_HEADER_FMT)
_HANDSHAKE_INTERVAL = 10.0


def _kernel32():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.argtypes = [
        ctypes.wintypes.LPCWSTR,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.HANDLE,
    ]
    k32.CreateFileW.restype = ctypes.wintypes.HANDLE
    k32.DeviceIoControl.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.wintypes.DWORD),
        ctypes.c_void_p,
    ]
    k32.DeviceIoControl.restype = ctypes.wintypes.BOOL
    k32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    k32.CloseHandle.restype = ctypes.wintypes.BOOL
    return k32


def _open_device() -> Optional[ctypes.wintypes.HANDLE]:
    """Open a handle to the AngeronaSensor device. Returns None on failure."""
    try:
        k32 = _kernel32()
        handle = k32.CreateFileW(
            _DEVICE_PATH,
            0x80000000 | 0x40000000,   # GENERIC_READ | GENERIC_WRITE
            0,                          # no sharing
            None,
            3,                          # OPEN_EXISTING
            0,
            None,
        )
        if handle in {None, ctypes.c_void_p(-1).value}:
            return None
        return handle
    except Exception:
        return None


def _ioctl(handle: ctypes.wintypes.HANDLE, code: int,
           in_buf: Optional[bytes], out_size: int) -> Optional[bytes]:
    """Call DeviceIoControl and return output bytes, or None on error."""
    if handle is None or not 0 <= int(out_size) <= 16 * 1024 * 1024:
        return None
    k32 = _kernel32()
    out = (ctypes.c_ubyte * out_size)()
    input_buffer = ctypes.create_string_buffer(in_buf) if in_buf else None
    returned = ctypes.wintypes.DWORD(0)
    ok = k32.DeviceIoControl(
        handle,
        code,
        ctypes.cast(input_buffer, ctypes.c_void_p) if input_buffer else None,
        len(in_buf) if in_buf else 0,
        out,
        out_size,
        ctypes.byref(returned),
        None,
    )
    if not ok:
        return None
    return bytes(out[:returned.value])


def _close_device(handle: Optional[ctypes.wintypes.HANDLE]) -> None:
    if handle is None:
        return
    try:
        _kernel32().CloseHandle(handle)
    except Exception:
        pass


def _parse_event(data: bytes, offset: int) -> Optional[dict]:
    """Parse one ANGERONA_EVENT from *data* at *offset*."""
    if offset + _EVENT_SIZE > len(data):
        return None
    (
        evt_type, sequence, pid, ppid, tid, ts_filetime,
        img_len, img_raw,
        cmd_len, cmd_raw,
    ) = struct.unpack_from(_EVENT_FMT, data, offset)
    if (
        evt_type not in _EVT_LABELS
        or sequence < 1
        or img_len > 260
        or cmd_len > 260
    ):
        return None

    def decode_wstr(raw: bytes, length: int) -> str:
        return raw[:length * 2].decode("utf-16-le", errors="strict").rstrip("\x00")

    try:
        image = decode_wstr(img_raw, img_len)
        cmdline = decode_wstr(cmd_raw, cmd_len)
    except UnicodeDecodeError:
        return None

    # Convert FILETIME (100-ns since 1601) to Unix timestamp
    FILETIME_EPOCH_DIFF = 11644473600   # seconds between 1601 and 1970
    ts = ts_filetime / 1e7 - FILETIME_EPOCH_DIFF if ts_filetime else time.time()

    return {
        "event_type":    evt_type,
        "sequence":      sequence,
        "label":         _EVT_LABELS.get(evt_type, f"unknown({evt_type})"),
        "pid":           pid,
        "parent_pid":    ppid,
        "thread_id":     tid,
        "ts":            ts,
        "image":         image,
        "command_line":  cmdline,
    }


class KernelBridgeModule(BaseModule):
    CODE = "KRNL"
    NAME = "Kernel Sensor Bridge"
    name = "Kernel Sensor Bridge"
    version = "1.13.0"
    description = (
        "Reads process-creation and image-load events from the AngeronaSensor.sys "
        "kernel driver ring buffer via DeviceIoControl.  Provides tamper-resistant "
        "telemetry that cannot be suppressed from user space."
    )
    category = "Endpoint"

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def __init__(
        self,
        identity_verifier: Callable[[], tuple[bool, str]] | None = None,
    ) -> None:
        super().__init__()
        self._handle: Optional[ctypes.wintypes.HANDLE] = None
        self._identity_verifier = identity_verifier or (
            lambda: (
                False,
                "driver service/image signer, digest, and device ACL are not pinned",
            )
        )
        self._identity_verified = False
        self._identity_reason = "not assessed"
        self._protocol_ok = False
        self._instance_id: int | None = None
        self._last_sequence: int | None = None
        self._last_dropped = 0
        self._last_heartbeat = 0
        self._last_handshake_at = 0.0
        self._loss_observed = False
        self._transport_alerted = False

    def run(self) -> None:
        while not self.stopping:
            if self._handle is None:
                self._handle = _open_device()
                if self._handle is None:
                    self.set_health(30, "AngeronaSensor.sys device is unavailable")
                    self.sleep(30.0)
                    continue
                if not self._verify_version(announce=True):
                    self._transport_failure("driver protocol handshake failed")
                    self.sleep(5.0)
                    continue
                try:
                    verified, reason = self._identity_verifier()
                    self._identity_verified = verified is True
                    self._identity_reason = str(reason or "identity proof unavailable")[:500]
                except Exception as exc:
                    self._identity_verified = False
                    self._identity_reason = f"identity verifier failed: {exc}"[:500]
                self._transport_alerted = False
                self._update_health()
                self.emit(
                    "Kernel Sensor Bridge protocol connected.",
                    Severity.INFO,
                    protocol_version=_PROTOCOL_VERSION,
                    identity_verified=self._identity_verified,
                    identity_reason=self._identity_reason,
                    response_authorized=False,
                )
            if not self._drain():
                self._transport_failure("kernel event transport failed validation")
                self.sleep(5.0)
                continue
            self.sleep(_POLL_INTERVAL)

    def _verify_version(self, *, announce: bool = False) -> bool:
        out = _ioctl(self._handle, IOCTL_GET_VERSION, None, _VERSION_SIZE)
        if out is None or len(out) != _VERSION_SIZE:
            self._protocol_ok = False
            return False
        try:
            (
                major,
                minor,
                build,
                tag,
                protocol,
                capabilities,
                instance_id,
                write_sequence,
                dropped,
                heartbeat,
            ) = struct.unpack(_VERSION_FMT, out)
        except struct.error:
            self._protocol_ok = False
            return False
        if (
            (major, minor, build) != _EXPECTED_VERSION
            or tag != _EXPECTED_TAG
            or protocol != _PROTOCOL_VERSION
            or capabilities != _REQUIRED_CAPABILITIES
            or instance_id < 1
            or heartbeat < 1
            or dropped > write_sequence
        ):
            self._protocol_ok = False
            return False
        if self._instance_id == instance_id:
            if (
                heartbeat <= self._last_heartbeat
                or write_sequence < (self._last_sequence or 0)
                or dropped < self._last_dropped
            ):
                self._protocol_ok = False
                return False
        elif self._instance_id is not None:
            self.emit(
                "Kernel sensor generation changed; continuity restarted at a "
                "new authenticated protocol instance.",
                Severity.MEDIUM,
                previous_instance_omitted=True,
                current_instance_omitted=True,
                response_authorized=False,
            )
            self._last_sequence = None
            self._last_dropped = 0
        self._instance_id = instance_id
        self._last_heartbeat = heartbeat
        self._last_handshake_at = time.monotonic()
        self._protocol_ok = True
        if announce:
            self.emit(
                "AngeronaSensor.sys v2.0.0 exact protocol handshake passed.",
                Severity.INFO,
                driver_version="2.0.0",
                protocol_version=protocol,
                capabilities=capabilities,
            )
        return True

    def _drain(self) -> bool:
        if time.monotonic() - self._last_handshake_at >= _HANDSHAKE_INTERVAL:
            if not self._verify_version():
                return False
        out_size = _EVENTS_HEADER_SIZE + _MAX_EVENTS_BATCH * _EVENT_SIZE
        out = _ioctl(self._handle, IOCTL_GET_EVENTS, None, out_size)
        if out is None or len(out) < _EVENTS_HEADER_SIZE:
            return False
        try:
            count, protocol, instance_id, dropped, write_sequence = struct.unpack_from(
                _EVENTS_HEADER_FMT, out, 0
            )
        except struct.error:
            return False
        expected_size = _EVENTS_HEADER_SIZE + count * _EVENT_SIZE
        if (
            protocol != _PROTOCOL_VERSION
            or instance_id != self._instance_id
            or count > _MAX_EVENTS_BATCH
            or len(out) != expected_size
            or dropped < self._last_dropped
            or dropped > write_sequence
            or (self._last_sequence is not None and write_sequence < self._last_sequence)
        ):
            return False
        if dropped > self._last_dropped:
            loss = dropped - self._last_dropped
            self._loss_observed = True
            self.emit(
                "Kernel sensor ring reported overwritten telemetry.",
                Severity.HIGH,
                dropped_events=loss,
                cumulative_dropped_events=dropped,
                response_authorized=False,
            )
        self._last_dropped = dropped
        offset = _EVENTS_HEADER_SIZE
        for _ in range(count):
            evt = _parse_event(out, offset)
            if evt is None:
                return False
            offset += _EVENT_SIZE
            sequence = int(evt["sequence"])
            if self._last_sequence is not None and sequence != self._last_sequence + 1:
                self._loss_observed = True
                self.emit(
                    "Kernel sensor event sequence gap detected.",
                    Severity.HIGH,
                    expected_sequence=self._last_sequence + 1,
                    observed_sequence=sequence,
                    response_authorized=False,
                )
            self._last_sequence = sequence
            self._emit_event(evt)
        if count == 0 and self._last_sequence is not None and write_sequence > self._last_sequence:
            self._loss_observed = True
            self.emit(
                "Kernel sensor write sequence advanced without delivered events.",
                Severity.HIGH,
                expected_after=self._last_sequence,
                observed_write_sequence=write_sequence,
                response_authorized=False,
            )
        self._update_health()
        return True

    def _update_health(self) -> None:
        if not self._protocol_ok:
            self.set_health(20, "kernel sensor exact protocol/liveness is unverified")
        elif not self._identity_verified:
            self.set_health(
                60,
                "kernel protocol is live but driver service/image/ACL identity is "
                f"unverified: {self._identity_reason}",
            )
        elif self._loss_observed:
            self.set_health(70, "kernel telemetry loss or sequence gap was observed")
        else:
            self.set_health(100, "pinned driver identity and loss-aware protocol are live")

    def _transport_failure(self, reason: str) -> None:
        if not self._transport_alerted:
            self.emit(
                "Kernel Sensor Bridge transport is unavailable or incompatible.",
                Severity.MEDIUM,
                reason=reason,
                response_authorized=False,
            )
            self._transport_alerted = True
        _close_device(self._handle)
        self._handle = None
        self._protocol_ok = False
        self.set_health(20, reason)

    def _emit_event(self, evt: dict) -> None:
        etype = evt["event_type"]
        image = evt["image"].split("\\")[-1] if evt["image"] else "unknown"

        if etype == _EVT_PROCESS_CREATE:
            msg = (
                f"[Kernel] Process created: {image} (PID={evt['pid']}, "
                f"PPID={evt['parent_pid']}) cmd={evt['command_line'][:120]}"
            )
            sev = Severity.INFO
        elif etype == _EVT_PROCESS_EXIT:
            msg  = f"[Kernel] Process exited: PID={evt['pid']}"
            sev  = Severity.INFO
        elif etype == _EVT_IMAGE_LOAD:
            msg = f"[Kernel] Image loaded: {image} into PID={evt['pid']}"
            sev = Severity.INFO
        else:
            msg  = f"[Kernel] Unknown event type {etype}"
            sev  = Severity.LOW

        self.emit(msg, sev,
                  pid=evt["pid"],
                  parent_pid=evt["parent_pid"],
                  image=evt["image"],
                  command_line=evt["command_line"],
                  label=evt["label"],
                  kernel_ts=evt["ts"],
                  kernel_sequence=evt["sequence"],
                  kernel_identity_verified=self._identity_verified,
                  source="kernel",
                  response_authorized=False)

    def self_test(self) -> tuple[bool, str]:
        if self._handle is None:
            return False, "AngeronaSensor.sys driver not loaded"
        if not self._verify_version():
            return False, "exact kernel protocol handshake failed"
        if not self._identity_verified:
            return False, f"kernel protocol live; identity incomplete: {self._identity_reason}"
        return True, "exact protocol, liveness, and driver identity verified"

    def stop(self) -> None:
        super().stop()
        if self._handle is not None:
            _close_device(self._handle)
            self._handle = None
        self._protocol_ok = False
        self._update_health()


def register() -> KernelBridgeModule:
    return KernelBridgeModule()
