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
from typing import Optional

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
# Fields: EventType(4) ProcessId(4) ParentProcessId(4) ThreadId(4)
#         Timestamp(8) ImagePathLen(4) ImagePath(520) CommandLineLen(4) CommandLine(520)
_EVENT_FMT  = "<IIIIQI260sI260s"
_EVENT_SIZE = struct.calcsize(_EVENT_FMT)

_POLL_INTERVAL    = 1.0   # seconds between driver polls
_MAX_EVENTS_BATCH = 64    # events to drain per poll


def _open_device() -> Optional[ctypes.wintypes.HANDLE]:
    """Open a handle to the AngeronaSensor device. Returns None on failure."""
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = k32.CreateFileW(
            _DEVICE_PATH,
            0x80000000 | 0x40000000,   # GENERIC_READ | GENERIC_WRITE
            0,                          # no sharing
            None,
            3,                          # OPEN_EXISTING
            0,
            None,
        )
        if handle == ctypes.wintypes.HANDLE(-1).value:
            return None
        return handle
    except Exception:
        return None


def _ioctl(handle: ctypes.wintypes.HANDLE, code: int,
           in_buf: Optional[bytes], out_size: int) -> Optional[bytes]:
    """Call DeviceIoControl and return output bytes, or None on error."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    out  = (ctypes.c_byte * out_size)()
    returned = ctypes.wintypes.DWORD(0)
    ok = k32.DeviceIoControl(
        handle,
        code,
        ctypes.c_char_p(in_buf) if in_buf else None,
        len(in_buf) if in_buf else 0,
        out,
        out_size,
        ctypes.byref(returned),
        None,
    )
    if not ok:
        return None
    return bytes(out[:returned.value])


def _parse_event(data: bytes, offset: int) -> Optional[dict]:
    """Parse one ANGERONA_EVENT from *data* at *offset*."""
    if offset + _EVENT_SIZE > len(data):
        return None
    (
        evt_type, pid, ppid, tid, ts_filetime,
        img_len, img_raw,
        cmd_len, cmd_raw,
    ) = struct.unpack_from(_EVENT_FMT, data, offset)

    def decode_wstr(raw: bytes, length: int) -> str:
        chars = min(length, 260)
        return raw[:chars * 2].decode("utf-16-le", errors="replace").rstrip("\x00")

    image   = decode_wstr(img_raw, img_len)
    cmdline = decode_wstr(cmd_raw, cmd_len)

    # Convert FILETIME (100-ns since 1601) to Unix timestamp
    FILETIME_EPOCH_DIFF = 11644473600   # seconds between 1601 and 1970
    ts = ts_filetime / 1e7 - FILETIME_EPOCH_DIFF if ts_filetime else time.time()

    return {
        "event_type":    evt_type,
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

    def __init__(self) -> None:
        super().__init__()
        self._handle: Optional[ctypes.wintypes.HANDLE] = None

    def run(self) -> None:
        self._handle = _open_device()
        if self._handle is None:
            self.set_health(50, "AngeronaSensor.sys not loaded")
            self.emit(
                "Kernel Sensor Bridge: AngeronaSensor.sys driver not loaded. "
                "Build the driver (kernel/AngeronaSensor/build.bat) and run "
                "'sc start AngeronaSensor' to enable kernel-level telemetry. "
                "Idling — other modules still provide user-mode coverage.",
                Severity.INFO,
                driver_loaded=False,
            )
            while not self.stopping:
                self.sleep(30.0)
                self._handle = _open_device()
                if self._handle is not None:
                    self.emit(
                        "Kernel Sensor Bridge: AngeronaSensor.sys detected — activating.",
                        Severity.INFO,
                    )
                    break
            if self._handle is None:
                return

        self._verify_version()
        self.set_health(100, "")
        self.emit("Kernel Sensor Bridge active — kernel callbacks connected.", Severity.INFO)

        while not self.stopping:
            self._drain()
            self.sleep(_POLL_INTERVAL)

    def _verify_version(self) -> None:
        out = _ioctl(self._handle, IOCTL_GET_VERSION, None, 16)
        if out and len(out) >= 16:
            major, minor, build = struct.unpack_from("<III", out, 0)
            tag = out[12:20].rstrip(b"\x00").decode("ascii", errors="replace")
            self.emit(
                f"AngeronaSensor.sys v{major}.{minor}.{build} ({tag}) loaded.",
                Severity.INFO,
                driver_version=f"{major}.{minor}.{build}",
            )

    def _drain(self) -> None:
        # Output buffer: 4-byte count header + N events
        out_size = 4 + _MAX_EVENTS_BATCH * _EVENT_SIZE
        out = _ioctl(self._handle, IOCTL_GET_EVENTS, None, out_size)
        if not out or len(out) < 4:
            return

        count = struct.unpack_from("<I", out, 0)[0]
        offset = 4
        for _ in range(min(count, _MAX_EVENTS_BATCH)):
            evt = _parse_event(out, offset)
            if evt is None:
                break
            offset += _EVENT_SIZE
            self._emit_event(evt)

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
                  source="kernel")

    def self_test(self) -> tuple[bool, str]:
        if self._handle is None:
            return False, "AngeronaSensor.sys driver not loaded"
        out = _ioctl(self._handle, IOCTL_GET_VERSION, None, 16)
        if out:
            return True, "DeviceIoControl responsive"
        return False, "DeviceIoControl returned no data"

    def stop(self) -> None:
        super().stop()
        if self._handle is not None:
            try:
                ctypes.WinDLL("kernel32").CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None


def register() -> KernelBridgeModule:
    return KernelBridgeModule()
