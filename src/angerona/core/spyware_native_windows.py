"""Read fixed Windows launch settings for explicit local spyware review."""
from __future__ import annotations

import ctypes
import re
import sys
import time


_CURRENT_VERSION = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
_IFEO = _CURRENT_VERSION + r"\Image File Execution Options"
_SILENT_EXIT = _CURRENT_VERSION + r"\SilentProcessExit"
_DEBUGGER_SOURCE = "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-details"
_SILENT_EXIT_SOURCE = "https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit"
_IMAGE_KEY = re.compile(r"[a-z0-9][a-z0-9 _().+-]{0,127}", re.IGNORECASE | re.ASCII)
_GLOBAL_FLAG = re.compile(r"0[xX][0-9a-fA-F]{1,8}")
_MONITOR_SILENT_EXIT = 0x200
_LAUNCH_MONITOR = 0x1
_MAX_IMAGES_PER_SOURCE = 256
_MAX_VALUE_BYTES = 4096
_COLLECTION_SECONDS = 3.0
_MISSING = object()


class _ReadGap(Exception):
    """An allowlisted coverage reason, with no host-specific text."""


class _Registry:
    def __init__(self, winreg, query):
        self.winreg = winreg
        self.query = query
        self.buffer = ctypes.create_string_buffer(_MAX_VALUE_BYTES)
        self.views = (("32", winreg.KEY_WOW64_32KEY), ("64", winreg.KEY_WOW64_64KEY))

    def open(self, parent, name, view, *, enumerate_keys=False):
        access = self.winreg.KEY_QUERY_VALUE
        if enumerate_keys:
            access |= self.winreg.KEY_ENUMERATE_SUB_KEYS
        return self.winreg.OpenKey(parent, name, 0, access | view)

    def info(self, key):
        return self.winreg.QueryInfoKey(key)

    def name(self, key, index):
        return self.winreg.EnumKey(key, index)

    def value(self, key, name):
        kind = ctypes.c_uint32()
        size = ctypes.c_uint32(_MAX_VALUE_BYTES)
        status = self.query(int(key), name, None, ctypes.byref(kind), self.buffer, ctypes.byref(size))
        if status == 2:  # ERROR_FILE_NOT_FOUND
            return _MISSING
        if status == 5:  # ERROR_ACCESS_DENIED
            raise _ReadGap("access-denied")
        if status == 234 or size.value > _MAX_VALUE_BYTES:  # ERROR_MORE_DATA
            raise _ReadGap("value-size-limit")
        if status:
            raise _ReadGap("value-unavailable")
        raw = self.buffer.raw[:size.value]
        if kind.value == self.winreg.REG_DWORD and len(raw) == 4:
            return int.from_bytes(raw, "little")
        if kind.value == self.winreg.REG_SZ and len(raw) >= 2 and len(raw) % 2 == 0 and raw.endswith(b"\0\0"):
            try:
                value = raw.decode("utf-16-le", errors="strict")[:-1]
            except UnicodeError as exc:
                raise _ReadGap("invalid-value") from exc
            if "\0" not in value:
                return value
        raise _ReadGap("invalid-value")


def _windows_registry():
    import winreg

    query = ctypes.WinDLL("advapi32", use_last_error=True).RegQueryValueExW
    dword_pointer = ctypes.POINTER(ctypes.c_uint32)
    query.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p,
                      dword_pointer, ctypes.c_void_p, dword_pointer)
    query.restype = ctypes.c_int32
    return _Registry(winreg, query)


def _stable_values(registry, key, *names):
    before = registry.info(key)
    values = tuple(registry.value(key, name) for name in names)
    if registry.info(key) != before:
        raise _ReadGap("key-changed")
    return values


def _dword(value):
    if value is _MISSING:
        return 0
    if type(value) is int:
        return value
    raise _ReadGap("unexpected-value-type")


def _flag(value):
    # GFlags uses hexadecimal flags. Do not guess the base of bare text.
    if type(value) is str and _GLOBAL_FLAG.fullmatch(value):
        return int(value, 16)
    return _dword(value)


def _configured_text(value):
    if value is _MISSING:
        return False
    if type(value) is not str:
        raise _ReadGap("unexpected-value-type")
    return bool(value.strip())


def _debugger(registry, root, view, image):
    with registry.open(root, image, view) as key:
        use_filter, debugger = _stable_values(registry, key, "UseFilter", "Debugger")
    if _dword(use_filter):
        raise _ReadGap("path-filter-not-evaluated")
    return "configured" if _configured_text(debugger) else "not-configured"


def _silent_monitor(registry, root, view, image):
    with registry.open(root, image, view) as key:
        before = registry.info(key)
        mode = registry.value(key, "ReportingMode")
        if not _dword(mode) & _LAUNCH_MONITOR:
            if registry.info(key) != before:
                raise _ReadGap("key-changed")
            return "reporting-without-launch" if mode is not _MISSING else "not-configured"
        hive = registry.winreg.HKEY_LOCAL_MACHINE
        try:
            ifeo = registry.open(hive, _IFEO + "\\" + image, view)
        except FileNotFoundError:
            if registry.info(key) != before:
                raise _ReadGap("key-changed")
            return "image-flag-not-enabled"
        with ifeo:
            flag_before = registry.info(ifeo)
            flag = registry.value(ifeo, "GlobalFlag")
            use_filter = registry.value(ifeo, "UseFilter")
            if _dword(use_filter):
                raise _ReadGap("path-filter-not-evaluated")
            enabled = bool(_flag(flag) & _MONITOR_SILENT_EXIT)
            monitor = registry.value(key, "MonitorProcess") if enabled else _MISSING
            if registry.info(ifeo) != flag_before or registry.info(key) != before:
                raise _ReadGap("key-changed")
        if not enabled:
            return "image-flag-not-enabled"
        if monitor is _MISSING:
            (global_monitor,) = _stable_values(registry, root, "MonitorProcess")
            raise _ReadGap("global-monitor-not-evaluated" if _configured_text(global_monitor)
                           else "monitor-value-unavailable")
        if not _configured_text(monitor):
            raise _ReadGap("monitor-value-unavailable")
        return "configured"


def _error_code(error):
    if isinstance(error, _ReadGap):
        return error.args[0]
    if isinstance(error, PermissionError) or getattr(error, "winerror", None) == 5:
        return "access-denied"
    return "key-changed" if isinstance(error, FileNotFoundError) else "registry-unavailable"


def _walk_source(registry, path, view, inspect, stop):
    coverage = {"state": "completed", "checked": 0, "skipped": 0, "key_present": None,
                "configuration_counts": {}, "gaps": {}}
    rows = []

    def gap(reason):
        gaps = coverage["gaps"]
        gaps[reason] = gaps.get(reason, 0) + 1
        coverage["skipped"] += 1
        coverage["state"] = "partial" if coverage["key_present"] is True else "unavailable"

    if reason := stop():
        gap(reason)
        return coverage, rows
    try:
        root = registry.open(registry.winreg.HKEY_LOCAL_MACHINE, path, view, enumerate_keys=True)
    except FileNotFoundError:
        coverage["key_present"] = False
        return coverage, rows
    except OSError as exc:
        gap(_error_code(exc))
        return coverage, rows
    try:
        with root:
            coverage["key_present"] = True
            start = registry.info(root)
            count = start[0]
            if count > _MAX_IMAGES_PER_SOURCE:
                gap("image-entry-limit")
            seen = set()
            for index in range(min(count, _MAX_IMAGES_PER_SOURCE)):
                if reason := stop():
                    gap(reason)
                    break
                try:
                    image = registry.name(root, index)
                    if (type(image) is not str or len(image) > 128 or not _IMAGE_KEY.fullmatch(image)
                            or image.endswith((" ", "."))):
                        raise _ReadGap("unsupported-image-name")
                    identity = image.lower()
                    if identity in seen:
                        raise _ReadGap("key-changed")
                    seen.add(identity)
                    result = inspect(registry, root, view, image)
                    counts = coverage["configuration_counts"]
                    counts[result] = counts.get(result, 0) + 1
                    coverage["checked"] += 1
                    if result == "configured":
                        rows.append(identity)
                except (_ReadGap, OSError) as exc:
                    gap(_error_code(exc))
            if reason := stop():
                if reason not in coverage["gaps"]:
                    gap(reason)
            elif registry.info(root) != start:
                gap("key-changed")
    except OSError as exc:
        gap(_error_code(exc))
    return coverage, rows


def _collect(registry, cancelled, clock):
    deadline = clock() + _COLLECTION_SECONDS
    sources, findings = {}, {}

    def stop():
        if cancelled():
            return "cancelled"
        return "time-limit" if clock() >= deadline else ""

    for mechanism, path, inspect, source, summary in (
        ("ifeo-debugger", _IFEO, _debugger, _DEBUGGER_SOURCE,
         "Windows records a debugger setting for this image name."),
        ("silent-process-exit-monitor", _SILENT_EXIT, _silent_monitor, _SILENT_EXIT_SOURCE,
         "Windows records a monitor launch setting for this image name when a qualifying silent exit occurs."),
    ):
        for label, view in registry.views:
            coverage, images = _walk_source(registry, path, view, inspect, stop)
            sources[f"{mechanism}-{label}"] = coverage
            for image in images:
                finding = findings.setdefault((mechanism, image), {
                    "classification": "advisory", "evidence_type": mechanism, "summary": summary,
                    "source": source, "image_name": image, "registry_views": [],
                    "execution_observed": False, "response_authorized": False,
                })
                finding["registry_views"].append(label)
    states = {coverage["state"] for coverage in sources.values()}
    state = "completed" if states == {"completed"} else "unavailable" if states == {"unavailable"} else "partial"
    return {"state": state, "checked": sum(item["checked"] for item in sources.values()),
            "skipped": sum(item["skipped"] for item in sources.values()),
            "sources": sources, "findings": list(findings.values())}


def scan_windows_launch_configuration(*, cancelled):
    """Inspect configuration only; cancellation and the deadline apply between native calls."""
    if sys.platform != "win32":
        return {"state": "unavailable", "checked": 0, "skipped": 1, "sources": {},
                "reason": "windows-only", "findings": []}
    if cancelled():
        return {"state": "unavailable", "checked": 0, "skipped": 1, "sources": {},
                "reason": "cancelled", "findings": []}
    try:
        registry = _windows_registry()
    except (ImportError, AttributeError, OSError):
        return {"state": "unavailable", "checked": 0, "skipped": 1, "sources": {},
                "reason": "registry-unavailable", "findings": []}
    return _collect(registry, cancelled, time.monotonic)
