"""Private stdlib-only dispatcher for one pinned optional scanner process.

This entry is handled before the dashboard, configuration or sensors import.
It accepts no arbitrary script, command, password or execution adapter.
"""
from __future__ import annotations

from contextlib import ExitStack
import builtins
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import threading


ENGINE_SHA256 = "075b2a0ac20f285fa4385d6b6c5cda2cedd410364c4f4686db3c1b8b033265d3"
ENGINE_BYTES = 968987
_UUID = re.compile(r"[0-9a-f]{32}")
_TOKEN = re.compile(r"[0-9a-f]{64}")


def _plain(path: Path, *, missing=False):
    cursor = path
    while cursor != cursor.parent:
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            if not missing:
                raise
        else:
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Redirected curated-worker path")
        cursor = cursor.parent


def _read(path: Path, limit):
    _plain(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise ValueError("Invalid curated-worker input file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        held = os.fstat(stream.fileno())
        if (held.st_dev, held.st_ino, held.st_size) != (info.st_dev, info.st_ino, info.st_size):
            raise ValueError("Curated-worker input changed")
        raw = stream.read(limit + 1)
    if len(raw) != info.st_size:
        raise ValueError("Curated-worker input exceeded its bound")
    return raw


def _birth(pid):
    if os.name != "nt":
        return ""
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (w.DWORD, w.BOOL, w.DWORD)
    kernel.OpenProcess.restype = w.HANDLE
    kernel.GetProcessTimes.argtypes = (w.HANDLE, *([ctypes.POINTER(w.FILETIME)] * 4))
    kernel.CloseHandle.argtypes = (w.HANDLE,)
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        raise ValueError("Curated-worker parent generation unavailable")
    try:
        values = [w.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *(ctypes.byref(v) for v in values)):
            raise ValueError("Curated-worker native generation unavailable")
        return str(values[0].dwHighDateTime << 32 | values[0].dwLowDateTime)
    finally:
        kernel.CloseHandle(handle)


def _user_only():
    if os.name == "nt":
        from ctypes import wintypes as w
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel.GetCurrentProcess.restype = w.HANDLE
        kernel.CloseHandle.argtypes = (w.HANDLE,)
        advapi.OpenProcessToken.argtypes = (w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE))
        advapi.GetTokenInformation.argtypes = (w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD))
        token, elevation, size = w.HANDLE(), w.DWORD(), w.DWORD()
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise PermissionError("Curated-worker token could not be verified")
        try:
            if not advapi.GetTokenInformation(token, 20, ctypes.byref(elevation), ctypes.sizeof(elevation), ctypes.byref(size)):
                raise PermissionError("Curated-worker elevation could not be verified")
        finally:
            kernel.CloseHandle(token)
        if elevation.value:
            raise PermissionError("Curated workers require an ordinary-user token")
    elif os.geteuid() == 0:
        raise PermissionError("Curated workers cannot run as root")


def _request(path: Path, handshake: dict):
    if (not path.is_absolute() or path.name != "request.json" or not _UUID.fullmatch(path.parent.name)
            or path.parent.parent.name != "jobs" or str(path).startswith(("\\\\", "//"))):
        raise ValueError("Unknown curated-worker request location")
    root, job = path.parent.parent.parent, path.parent
    from angerona.core.startup_recovery import private_directory, private_repair_file
    for directory in (root, root / "jobs", job, job / "scratch"):
        _plain(directory)
        if not private_directory(directory, create=False):
            raise PermissionError("Curated-worker storage is not private")
    if not private_repair_file(path):
        raise PermissionError("Curated-worker request is not private")
    request_raw = _read(path, 64 * 1024)
    if hashlib.sha256(request_raw).hexdigest() != handshake.get("request_sha256"):
        raise ValueError("Curated-worker request bytes changed")
    document = json.loads(request_raw)
    if (type(document) is not dict or document.get("schema") != 1 or document.get("job_id") != job.name
            or document.get("version") != "0.1.10" or document.get("engine_sha256") != ENGINE_SHA256
            or not _TOKEN.fullmatch(str(document.get("nonce", "")))
            or document.get("nonce") != handshake.get("nonce")
            or document.get("parent_pid") != os.getppid()
            or handshake.get("pid") != os.getpid()):
        raise ValueError("Curated-worker request does not match its owned launch")
    if os.name == "nt" and (document.get("parent_birth") != _birth(os.getppid()) or handshake.get("birth") != _birth(os.getpid())):
        raise ValueError("Curated-worker process generation changed")
    engine = root / "engines" / "0.1.10" / "engine.py"
    raw = _read(engine, ENGINE_BYTES)
    if len(raw) != ENGINE_BYTES or hashlib.sha256(raw).hexdigest() != ENGINE_SHA256:
        raise ValueError("Curated-worker engine pin mismatch")
    if not private_repair_file(engine):
        raise PermissionError("Curated-worker engine is not private")
    limits = document.get("limits", {})
    if type(limits) is not dict or type(limits.get("working_bytes")) is not int or not 64 * 1024**2 <= limits["working_bytes"] <= 1024**3:
        raise ValueError("Curated-worker working limit is invalid")
    return document, root, job, engine, raw


def _arguments(document, job):
    kind = document.get("kind")
    if kind == "describe":
        return ["--describe", "--no-pause"]
    if kind != "scan":
        raise ValueError("Unknown curated-worker operation")
    request = document.get("request")
    if type(request) is not dict:
        raise ValueError("Missing curated-worker scan request")
    mode = request.get("mode")
    targets, indicators = request.get("targets", []), request.get("iocs", [])
    if mode not in {"default", "full", "targeted", "browser"}:
        raise ValueError("Unknown curated-worker scan mode")
    for paths in (targets, indicators):
        if type(paths) is not list or len(paths) > 16:
            raise ValueError("Too many curated-worker inputs")
        for value in paths:
            if (type(value) is not str or len(value) > 4096 or "\x00" in value
                    or not Path(value).is_absolute() or value.startswith(("\\\\", "//"))):
                raise ValueError("Curated-worker accepts local absolute evidence only")
            if os.name == "nt":
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.GetDriveTypeW.argtypes = (ctypes.c_wchar_p,)
                if kernel.GetDriveTypeW(Path(value).anchor) != 3:
                    raise ValueError("Curated-worker input is not on a fixed local drive")
            _plain(Path(value))
    phone = request.get("phone", False)
    if type(phone) is not bool:
        raise ValueError("Invalid curated-worker phone switch")
    args = ["--no-menu", "--no-pause", "--no-banner", "--scan-type", mode,
            "--indicator-cache", str(job / "cache"), "--no-feeds"]
    if phone:
        ios = request.get("ios_input")
        if len(targets) != 1 or mode != "default" or ios not in {"backup", "filesystem", "sysdiagnose"}:
            raise ValueError("Invalid curated-worker phone input")
        args += ["--phone", targets[0], "--ios-input", ios]
    else:
        if bool(targets) != (mode == "targeted"):
            raise ValueError("Invalid curated-worker selected scope")
        for value in targets:
            args += ["--target", value]
    for value in indicators:
        args += ["--iocs", value]
    for key, flag in (("quick", "--quick"), ("preview", "--preview"), ("extended_windows", "--extended-windows")):
        value = request.get(key, False)
        if type(value) is not bool:
            raise ValueError("Invalid curated-worker switch")
        if value:
            if key == "quick" and mode == "targeted":
                raise ValueError("Quick selected-target mode is unsupported")
            args.append(flag)
    if not request.get("preview"):
        args += ["--json", str(job / "report.json"), "--report", str(job / "report.txt"), "--share-json", str(job / "summary.json")]
    return args


def _posix_limits(request, limits):
    """Per-process inherited resource limits; CPU rate isolation is separate."""
    import resource
    memory = request.get("max_memory_mib")
    priority = request.get("priority")
    if type(memory) is not int or not 128 <= memory <= 2048 or priority not in {"normal", "above-normal", "high"}:
        raise ValueError("Invalid curated-worker resource request")
    values = [(resource.RLIMIT_FSIZE, limits["working_bytes"]), (resource.RLIMIT_NOFILE, 256),
              (resource.RLIMIT_CPU, min(900, max(1, int(limits.get("cpu_seconds", 300)))))]
    if sys.platform.startswith("linux"):
        values.append((resource.RLIMIT_AS, memory * 1024**2))
    for name, value in values:
        _soft, hard = resource.getrlimit(name)
        cap = value if hard == resource.RLIM_INFINITY else min(hard, value)
        resource.setrlimit(name, (cap, cap))
    # An ordinary user may lack permission to increase CPU scheduling priority.
    # Keep that a resource-policy gap; do not request elevation.
    if priority != "normal":
        try:
            os.nice(-10 if priority == "high" else -5)
        except OSError:
            pass


class _BoundedWriter:
    def __init__(self, real, budget, path):
        self.real, self.budget, self.path = real, budget, path

    def __getattr__(self, name):
        return getattr(self.real, name)

    def write(self, value):
        amount = len(value) if isinstance(value, (bytes, bytearray, memoryview)) else len(value.encode(self.real.encoding or "utf-8", "replace")) * 2
        self.budget.reserve(amount, self.path)
        return self.real.write(value)

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def truncate(self, size=None):
        size = self.real.tell() if size is None else size
        self.budget.reserve(max(0, size - os.fstat(self.real.fileno()).st_size), self.path)
        return self.real.truncate(size)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.real.close()


class _WriteBudget:
    """Conservative Python-writer allowance, not an OS filesystem quota."""
    def __init__(self, job, allowance, retained_allowance=None):
        self.job = job
        self.remaining = allowance - 4 * 1024**2  # Parent's two bounded log sinks.
        self.original_open, self.original_io_open = builtins.open, io.open
        self.original_os_open, self.original_os_write = os.open, os.write
        self.original_ftruncate = os.ftruncate
        self.original_replace, self.original_rename = os.replace, os.rename
        self.descriptors = {}
        self.lock = threading.Lock()
        self.written = {}
        # Reserve both parent log streams, launch request and final receipt.
        self.retained_limit = max(0, (retained_allowance if retained_allowance is not None else allowance) - 4 * 1024**2 - 384 * 1024)
        self.published_outputs = {}

    def file_limit(self, path):
        if path.parent == self.job:
            return {"report.json": 8 * 1024**2, "report.txt": 8 * 1024**2,
                    "summary.json": 1024**2}.get(path.name)
        return None

    def destination(self, value):
        if isinstance(value, int):
            if value not in self.descriptors:
                raise OSError("Unowned curated write descriptor")
            return self.descriptors[value]
        path = Path(os.path.abspath(os.fspath(value)))
        if not path.is_relative_to(self.job) or path == self.job:
            raise OSError("Curated writes must remain in their private job")
        _plain(path, missing=True)
        return path

    def reserve(self, amount, path):
        path = self.destination(path)
        with self.lock:
            if type(amount) is not int or amount < 0 or amount > self.remaining:
                raise OSError("Curated working-write allowance reached; coverage is incomplete")
            limit = self.file_limit(path)
            used = self.written.get(path, 0)
            if limit is not None and used + amount > limit:
                raise OSError("Curated report output allowance reached; coverage is incomplete")
            if limit is not None:
                others = sum(size for name, size in self.published_outputs.items() if name != path)
                if others + used + amount > self.retained_limit:
                    raise OSError("Curated aggregate report allowance reached; coverage is incomplete")
            if shutil.disk_usage(self.job).free - amount < 2 * 1024**3:
                raise OSError("Curated scan reserve reached; coverage is incomplete")
            self.remaining -= amount
            self.written[path] = used + amount
            if limit is not None:
                self.published_outputs[path] = used + amount

    def open(self, filename, mode="r", *args, **kwargs):
        writing = any(flag in mode for flag in "wax+") if isinstance(mode, str) else False
        if writing:
            path = self.destination(filename)
            real = self.original_open(filename, mode, *args, **kwargs)
            self.descriptors[real.fileno()] = path
            return _BoundedWriter(real, self, path)
        return self.original_open(filename, mode, *args, **kwargs)

    def io_open(self, filename, mode="r", *args, **kwargs):
        writing = any(flag in mode for flag in "wax+") if isinstance(mode, str) else False
        if writing:
            path = self.destination(filename)
            real = self.original_io_open(filename, mode, *args, **kwargs)
            self.descriptors[real.fileno()] = path
            return _BoundedWriter(real, self, path)
        return self.original_io_open(filename, mode, *args, **kwargs)

    def os_open(self, filename, flags, *args, **kwargs):
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        path = self.destination(filename) if writing else None
        descriptor = self.original_os_open(filename, flags, *args, **kwargs)
        if path is not None:
            self.descriptors[descriptor] = path
        return descriptor

    def os_write(self, descriptor, data):
        path = self.destination(descriptor)
        self.reserve(len(data), path)
        return self.original_os_write(descriptor, data)

    def ftruncate(self, descriptor, length):
        path = self.destination(descriptor)
        self.reserve(max(0, length - os.fstat(descriptor).st_size), path)
        return self.original_ftruncate(descriptor, length)

    def replace(self, src, dst, *args, **kwargs):
        source, target = self.destination(src), self.destination(dst)
        limit = self.file_limit(target)
        if limit is not None:
            size = source.stat().st_size
            if size > limit or sum(value for name, value in self.published_outputs.items() if name != target) + size > self.retained_limit:
                raise OSError("Curated atomic report output exceeds its bound")
            self.published_outputs[target] = size
        return self.original_replace(src, dst, *args, **kwargs)

    def rename(self, src, dst, *args, **kwargs):
        source, target = self.destination(src), self.destination(dst)
        limit = self.file_limit(target)
        if limit is not None:
            size = source.stat().st_size
            if size > limit or sum(value for name, value in self.published_outputs.items() if name != target) + size > self.retained_limit:
                raise OSError("Curated atomic report output exceeds its bound")
            self.published_outputs[target] = size
        return self.original_rename(src, dst, *args, **kwargs)

    def copy(self, src, dst, *, follow_symlinks=True):
        source = Path(src)
        _plain(source)
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OSError("Curated snapshot source is not a regular single-link file")
        target = Path(dst) / source.name if Path(dst).is_dir() else Path(dst)
        self.destination(target)
        if before.st_size > self.remaining:
            raise OSError("Curated snapshot exceeds the remaining working allowance")
        with self.original_open(source, "rb") as reader, self.open(target, "xb") as writer:
            read = 0
            while True:
                chunk = reader.read(64 * 1024)
                if not chunk:
                    break
                read += len(chunk)
                if read > before.st_size:
                    raise OSError("Curated snapshot source grew during its bounded copy")
                writer.write(chunk)
        after = source.lstat()
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise OSError("Curated snapshot source changed during its copy")
        return os.fspath(target)

    def install(self):
        builtins.open, io.open = self.open, self.io_open
        os.open, os.write, os.ftruncate = self.os_open, self.os_write, self.ftruncate
        os.replace, os.rename = self.replace, self.rename
        shutil.copy2 = self.copy
        shutil.copyfile = self.copy


def _pipe_streams():
    """Windowed frozen children can have None Python standard streams."""
    if os.name != "nt":
        return
    import msvcrt
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.GetStdHandle.argtypes = (w.DWORD,)
    kernel.GetStdHandle.restype = w.HANDLE
    kernel.GetFileType.argtypes = (w.HANDLE,)
    kernel.DuplicateHandle.argtypes = (w.HANDLE, w.HANDLE, w.HANDLE, ctypes.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD)
    kernel.CloseHandle.argtypes = (w.HANDLE,)
    for name, identifier, mode in (("stdin", -10, "rb"), ("stdout", -11, "wb"), ("stderr", -12, "wb")):
        if getattr(sys, name, None) is not None:
            continue
        original = kernel.GetStdHandle(identifier & 0xffffffff)
        if not original or kernel.GetFileType(original) != 3:
            raise ValueError("Curated-worker private standard pipe unavailable")
        duplicate = w.HANDLE()
        current = kernel.GetCurrentProcess()
        if not kernel.DuplicateHandle(current, original, current, ctypes.byref(duplicate), 0, False, 2):
            raise ValueError("Curated-worker standard pipe could not be retained")
        try:
            fd = msvcrt.open_osfhandle(duplicate.value, os.O_RDONLY if mode == "rb" else os.O_WRONLY)
        except BaseException:
            kernel.CloseHandle(duplicate)
            raise
        raw = os.fdopen(fd, mode, buffering=0)
        setattr(sys, name, io.TextIOWrapper(raw, encoding="utf-8", errors="backslashreplace", write_through=mode != "rb"))


def main(argv=None) -> int:
    arguments = sys.argv[1:] if argv is None else list(argv)
    try:
        if len(arguments) != 1:
            raise ValueError("Expected one private curated-worker request")
        _pipe_streams()
        _user_only()
        handshake_raw = sys.stdin.buffer.readline(4097)
        if len(handshake_raw) > 4096 or not handshake_raw.endswith(b"\n"):
            raise ValueError("Invalid curated-worker launch handshake")
        handshake = json.loads(handshake_raw)
        if type(handshake) is not dict:
            raise ValueError("Invalid curated-worker launch identity")
        document, root, job, engine, source = _request(Path(arguments[0]), handshake)
        args = _arguments(document, job)
        if os.name != "nt":
            _posix_limits(document.get("request", {}), document["limits"])
        # Only first-party plain-directory guards are imported. No GUI,
        # configuration, manager or security engine is initialized here.
        from angerona.core.source_sandbox import _hold_plain_directories
        with ExitStack() as stack:
            stack.enter_context(_hold_plain_directories(root, job, engine.parent))
            for name in ("TEMP", "TMP", "TMPDIR"):
                if Path(os.environ.get(name, "")) != job / "scratch":
                    raise ValueError("Curated-worker temporary routing changed")
            retained = document["limits"].get("retained_bytes")
            if type(retained) is not int or not 5 * 1024**2 <= retained <= 256 * 1024**2:
                raise ValueError("Curated retained-output allowance is invalid")
            budget = _WriteBudget(job, document["limits"]["working_bytes"], retained)
            budget.install()
            sys.argv = [str(engine), *args]
            namespace = {"__name__": "__main__", "__file__": str(engine), "__package__": None}
            exec(compile(source, str(engine), "exec"), namespace)
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1
    except (OSError, ValueError, TypeError, KeyError, PermissionError) as exc:
        print("Curated scanner held: " + type(exc).__name__, file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
