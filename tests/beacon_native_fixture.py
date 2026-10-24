"""Test-only direct beacon children and retained-object retirement receipts.

No descendant discovery, PID-reopened mutation, external transport or live
stderr read. Run only under the suite's bounded owned native supervisor.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import queue
import secrets
import stat
import subprocess
import sys
import sysconfig
import threading
import time
from types import SimpleNamespace

_MAX_FRAME = 16384
_MAX_FILE = 64 * 1024 * 1024
_WINDOWS_SITE_DIRS = ("win32", "win32/lib", "Pythonwin")
_DIAGNOSTIC_FLAGS = frozenset({
    "settings_absolute", "config_authorized", "settings_authorized",
    "identity_alive", "identity_gone", "identity_reused", "identity_unknown",
    "receipt_shape", "native_verified", "runtime_verified", "exit_available",
    "reader_retired", "observer_retained", "sticky_unavailable",
    "streams_closed", "process_handle_closed", "observer_closed",
    "generation_verified", "wait_signalled", "native_exit_verified",
})


def _exception_kind(error):
    if error is None:
        return "None"
    if type(error) is _FixtureFailure:
        return error.diagnostic["exception_type"]
    if type(error) is subprocess.TimeoutExpired:
        return "TimeoutExpired"
    names = {AssertionError: "AssertionError", OSError: "OSError",
        BrokenPipeError: "BrokenPipeError", TimeoutError: "TimeoutError",
        ValueError: "ValueError", TypeError: "TypeError", RuntimeError: "RuntimeError",
        AttributeError: "AttributeError", ImportError: "ImportError",
        ModuleNotFoundError: "ModuleNotFoundError", FileNotFoundError: "FileNotFoundError",
        PermissionError: "PermissionError", EOFError: "EOFError"}
    return names.get(type(error), "OtherError")


def _diagnostic(stage, error=None, **flags):
    assert stage in {"bootstrap", "admission", "terminal", "retire"}
    assert set(flags) <= _DIAGNOSTIC_FLAGS and all(type(value) is bool for value in flags.values())
    result = {"stage": stage, "exception_type": _exception_kind(error), **flags}
    assert len(json.dumps(result, sort_keys=True)) <= 2048
    return result


class _FixtureFailure(AssertionError):
    def __init__(self, stage, error=None, **flags):
        self.diagnostic = _diagnostic(stage, error, **flags)
        super().__init__(json.dumps(self.diagnostic, sort_keys=True))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _plain(path, *, directory=False):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise AssertionError("native fixture path traverses an alias")
    assert (path.is_dir() if directory else path.is_file())
    return path


def _fingerprint(path):
    path = _plain(path)
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and 0 < before.st_size <= _MAX_FILE
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        held = os.fstat(stream.fileno())
        total = 0
        while True:
            raw = stream.read(65536)
            if not raw:
                break
            total += len(raw)
            assert total <= _MAX_FILE
            digest.update(raw)
        after = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    assert identity(before) == identity(held) == identity(after) == identity(path.lstat())
    assert total == before.st_size
    return {"path": str(path), "sha256": digest.hexdigest()}


def _windows():
    kernel = ctypes.WinDLL("kernel32", winmode=0x800)
    signatures = {
        "GetModuleFileNameW": ([wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD], wintypes.DWORD),
        "GetCurrentProcess": ([], wintypes.HANDLE),
        "GetProcessId": ([wintypes.HANDLE], wintypes.DWORD),
        "GetProcessTimes": ([wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME)], wintypes.BOOL),
        "QueryFullProcessImageNameW": ([wintypes.HANDLE, wintypes.DWORD,
            wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
        "DuplicateHandle": ([wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
            ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL,
            wintypes.DWORD], wintypes.BOOL),
        "WaitForSingleObject": ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
        "GetExitCodeProcess": ([wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
        "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(kernel, name)
        function.argtypes, function.restype = arguments, result
    return kernel


def _native_generation(kernel, handle):
    created, exited, system, user = (wintypes.FILETIME() for _ in range(4))
    assert kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                  ctypes.byref(system), ctypes.byref(user))
    pid = int(kernel.GetProcessId(handle))
    raw = (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
    assert pid > 0 and raw > 0
    return {"pid": pid, "birth_raw": str(raw)}


def _native_identity(kernel, handle):
    generation = _native_generation(kernel, handle)
    image = ctypes.create_unicode_buffer(32768)
    length = wintypes.DWORD(len(image))
    assert kernel.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(length))
    return {**generation, "image": os.path.normcase(os.path.abspath(image.value))}


def _physical_image():
    if os.name == "nt":
        kernel = _windows()
        path = _plain(_native_identity(kernel, kernel.GetCurrentProcess())["image"])
        with path.open("rb") as stream:
            header = stream.read(64)
            assert len(header) == 64 and header[:2] == b"MZ"
            offset = int.from_bytes(header[60:64], "little")
            assert 64 <= offset <= 1024 * 1024
            stream.seek(offset)
            assert stream.read(4) == b"PE\0\0", "current image is not a Windows PE"
        return path
    return _plain(Path(sys.executable).resolve(strict=True))


def runtime(beacon):
    image = _physical_image()
    source = _plain(Path(beacon.__file__))
    helper = _plain(__file__)
    site = _plain(sysconfig.get_path("purelib"), directory=True)
    return {"image": _fingerprint(image), "source": _fingerprint(source),
            "helper": _fingerprint(helper), "source_root": str(source.parents[2]),
            "site": str(site), "windows_runtime": _site_runtime(site)}


def _site_runtime(site):
    if os.name != "nt":
        return {}
    site = _plain(site, directory=True)
    return {name: str(_plain(site / name, directory=True))
            for name in (*_WINDOWS_SITE_DIRS, "pywin32_system32")}


def _validate_runtime(contract):
    for field in ("image", "source", "helper"):
        assert _fingerprint(contract[field]["path"]) == contract[field]
    site = _plain(contract["site"], directory=True)
    _plain(contract["source_root"], directory=True)
    assert type(contract["windows_runtime"]) is dict
    assert contract["windows_runtime"] == _site_runtime(site)


def _runtime_preamble(contract):
    _validate_runtime(contract)
    paths = [contract["source_root"], contract["site"]]
    windows = contract["windows_runtime"]
    if os.name == "nt":
        paths.extend(windows[name] for name in _WINDOWS_SITE_DIRS)
    preamble = ("import os,sys,runpy;"
        f"sys.path[:0]={paths!r};_beacon_fixture_dll_paths=[];")
    if os.name == "nt":
        preamble += ("_beacon_fixture_dll_paths.append(os.add_dll_directory("
            f"{windows['pywin32_system32']!r}));")
    return preamble


def _receipt(contract, key, nonce):
    if os.name == "nt":
        kernel = _windows()
        native = _native_identity(kernel, kernel.GetCurrentProcess())
    else:
        native = {"pid": os.getpid(), "birth_raw": None,
                  "image": os.path.normcase(str(_physical_image()))}
    _validate_runtime(contract)
    body = {"nonce": nonce, "native": native, "runtime": contract}
    return {"body": body, "mac": hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()}


def _write_receipt(path, receipt):
    raw = _canonical(receipt)
    assert len(raw) <= _MAX_FRAME
    path = Path(path)
    partial = path.with_name(path.name + ".partial")
    with partial.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.link(partial, path)  # Atomic, non-replacing admission receipt.
    finally:
        partial.unlink()


def _read_receipt(path, deadline):
    while not Path(path).exists():
        assert time.monotonic() < deadline, "bounded child admission did not complete"
        time.sleep(0.01)
    with Path(path).open("rb") as stream:
        raw = stream.read(_MAX_FRAME + 1)
    assert 0 < len(raw) <= _MAX_FRAME
    return json.loads(raw)


class OwnedChild:
    def __init__(self, process, *, reader):
        self.process = process
        self.identity = None
        self.observer = None
        self.kernel = None
        self.reader = None
        self.other_readers = []
        self.frames = queue.Queue(maxsize=8)
        self.proof = None
        self._native_required = os.name == "nt"
        self._terminal_proof = None
        self._proof_unavailable = False
        # Register this object in the caller before pin(), which can fail.
        if reader:
            self.reader = threading.Thread(target=self._read,
                name="BeaconFixture-stdout", daemon=True)

    def pin(self):
        if os.name == "nt":
            self.kernel = _windows()
            current = self.kernel.GetCurrentProcess()
            duplicate = wintypes.HANDLE()
            assert self.kernel.DuplicateHandle(current, self.process._handle, current,
                ctypes.byref(duplicate), 0x00101000, False, 0)
            self.observer = int(duplicate.value)
            self.identity = _native_identity(self.kernel, self.observer)
            assert self.identity["pid"] == self.process.pid
        if self.reader is not None:
            self.reader.start()

    def _read(self):
        try:
            while True:
                raw = self.process.stdout.readline(_MAX_FRAME + 1)
                if not raw:
                    return
                assert len(raw) <= _MAX_FRAME and raw.endswith(b"\n")
                self.frames.put_nowait(raw)
        except Exception:
            try:
                self.frames.put_nowait(b"")
            except queue.Full:
                pass

    def next_frame(self, deadline):
        raw = self.frames.get(timeout=max(0.01, deadline - time.monotonic()))
        assert raw, "owned child stdout ended before admission"
        return json.loads(raw)

    def admit(self, receipt, contract, key, nonce):
        flags = {"receipt_shape": False, "native_verified": False, "runtime_verified": False}
        try:
            assert type(receipt) is dict and set(receipt) == {"body", "mac"}
            body = receipt["body"]
            assert type(body) is dict and set(body) == {"nonce", "native", "runtime"}
            flags["receipt_shape"] = True
            assert hmac.compare_digest(receipt["mac"],
                hmac.new(key, _canonical(body), hashlib.sha256).hexdigest())
            assert body["nonce"] == nonce and body["runtime"] == contract
            native = body["native"]
            assert type(native) is dict and set(native) == {"pid", "birth_raw", "image"}
            assert type(native["pid"]) is int
            assert native["pid"] == self.process.pid, "redirector is not the admitted interpreter"
            assert native["image"] == os.path.normcase(os.path.abspath(contract["image"]["path"]))
            if self.identity is not None:
                assert native == self.identity
            flags["native_verified"] = True
            _validate_runtime(contract)
            flags["runtime_verified"] = True
        except Exception as exc:
            if type(receipt) is dict and type(receipt.get("diagnostic")) is dict:
                for name in _DIAGNOSTIC_FLAGS:
                    value = receipt["diagnostic"].get(name)
                    if name not in flags and type(value) is bool:
                        flags[name] = value
            raise _FixtureFailure("admission", exc, **flags) from None

    def wait(self, deadline):
        code = None
        generation_verified = wait_signalled = native_exit_verified = False
        try:
            code = self.process.wait(timeout=max(0.01, deadline - time.monotonic()))
            assert type(code) is int and self.process.poll() == self.process.returncode == code
            assert not self._proof_unavailable
            if self._native_required:
                if self._terminal_proof is None:
                    assert self.observer is not None and self.identity is not None
                    generation = _native_generation(self.kernel, self.observer)
                    assert generation == {name: self.identity[name] for name in ("pid", "birth_raw")}
                    generation_verified = True
                    assert self.kernel.WaitForSingleObject(self.observer, 0) == 0
                    wait_signalled = True
                    native_code = wintypes.DWORD()
                    assert self.kernel.GetExitCodeProcess(self.observer, ctypes.byref(native_code))
                    assert int(native_code.value) == code
                    native_exit_verified = True
                    self._terminal_proof = {"identity": dict(self.identity), "exit_code": code}
                assert self._terminal_proof == {"identity": self.identity, "exit_code": code}
            return code
        except Exception as exc:
            raise _FixtureFailure("terminal", exc, exit_available=type(code) is int,
                observer_retained=self.observer is not None,
                sticky_unavailable=self._proof_unavailable,
                generation_verified=generation_verified, wait_signalled=wait_signalled,
                native_exit_verified=native_exit_verified) from None

    def retire(self, deadline):
        self.proof = None
        errors = []
        code = None
        terminal_verified = False
        terminal_flags = {}
        try:
            if self.process.poll() is None:
                self.process.kill()  # Original Popen object only; no PID reopen.
        except Exception as exc:
            errors.append(exc)
        try:
            code = self.wait(deadline)
            terminal_verified = True
        except Exception as exc:
            errors.append(exc)
            code = self.process.returncode
            if type(exc) is _FixtureFailure:
                terminal_flags = {name: exc.diagnostic[name] for name in
                    ("generation_verified", "wait_signalled", "native_exit_verified")}
        readers = [self.reader, *self.other_readers]
        for reader in readers:
            if reader is not None and reader.is_alive():
                try:
                    reader.join(timeout=max(0.0, deadline - time.monotonic()))
                except Exception as exc:
                    errors.append(exc)
        reader_retired = all(reader is None or not reader.is_alive() for reader in readers)
        native_verified = terminal_verified and (
            not self._native_required or self._terminal_proof is not None)
        if type(code) is int and reader_retired:
            # Resource cleanup is not proof. Once an unverified lease is closed,
            # retain a sticky failure so cached Popen status can never green a retry.
            if not native_verified:
                self._proof_unavailable = True
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                try:
                    if stream is not None and not stream.closed:
                        stream.close()
                    assert stream is None or stream.closed
                except Exception as exc:
                    errors.append(exc)
            if os.name == "nt":
                try:
                    if not self.process._handle.closed:
                        self.process._handle.Close()
                    assert self.process._handle.closed
                except Exception as exc:
                    errors.append(exc)
            if self.observer is not None:
                try:
                    assert self.kernel.CloseHandle(self.observer)
                    self.observer = None
                except Exception as exc:
                    errors.append(exc)
        if (type(code) is not int or not reader_retired or errors
                or not native_verified or self._proof_unavailable):
            raise _FixtureFailure("retire", errors[0] if errors else None,
                exit_available=type(code) is int, reader_retired=reader_retired,
                native_verified=native_verified, observer_retained=self.observer is not None,
                sticky_unavailable=self._proof_unavailable,
                streams_closed=all(stream is None or stream.closed for stream in
                    (self.process.stdin, self.process.stdout, self.process.stderr)),
                observer_closed=self.observer is None,
                process_handle_closed=os.name != "nt" or self.process._handle.closed,
                **terminal_flags) from None
        self.proof = {"owned_wait_exit": code, "reader_retired": True,
                      "streams_closed": True, "observer_closed": True,
                      "native_terminal_verified": self._native_required}



class OwnedChildren:
    def __init__(self, beacon):
        self.contract = runtime(beacon)
        self.key = secrets.token_bytes(32)
        self.nonce = secrets.token_hex(16)
        self.children = []
        self.raw_processes = []
        self.physical_adaptations = []
        self.descriptors = set()

    def command(self, role):
        contract = self.contract
        bootstrap = (_runtime_preamble(contract) +
            f"runpy.run_path({contract['helper']['path']!r},run_name='__main__')")
        return [contract["image"]["path"], "-I", "-B", "-c", bootstrap, role]

    def launch(self, command, *, reader=False, **kwargs):
        _validate_runtime(self.contract)
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        process = subprocess.Popen(command, **kwargs)
        self.raw_processes.append(process)
        child = OwnedChild(process, reader=reader)
        self.children.append(child)
        child.pin()
        if child.identity is not None:
            assert child.identity["image"] == os.path.normcase(
                os.path.abspath(self.contract["image"]["path"]))
        return child

    def close(self):
        errors = []
        for descriptor in tuple(self.descriptors):
            try:
                os.close(descriptor)
            except OSError as exc:
                errors.append({"exception_type": _exception_kind(exc)})
            self.descriptors.discard(descriptor)
        deadline = time.monotonic() + 5.0
        for child in self.children:
            try:
                child.retire(deadline)
            except Exception as exc:
                errors.append(exc.diagnostic if type(exc) is _FixtureFailure
                              else {"exception_type": _exception_kind(exc)})
        for process in self.raw_processes:
            if any(child.process is process for child in self.children):
                continue
            # Popen succeeded but construction of its wrapper failed.
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
                if os.name == "nt" and not process._handle.closed:
                    process._handle.Close()
            except Exception as exc:
                errors.append({"exception_type": _exception_kind(exc)})
        assert not errors, "owned beacon cleanup unresolved: " + json.dumps(
            {"errors": errors[:8], "additional_errors": len(errors) > 8}, sort_keys=True)

    def production_launcher(self, receipt_path):
        def launch(command, **kwargs):
            source = self.contract["source_root"]
            original = (f"import sys;sys.path.insert(0,{source!r});"
                        "from angerona.core.spyware_beacon import watch_main;"
                        "raise SystemExit(watch_main())")
            assert command == [self.contract["image"]["path"], "-I", "-c", original]
            expected = {"stdin", "stdout", "stderr", "close_fds", "env"}
            expected.add("creationflags" if os.name == "nt" else "start_new_session")
            assert set(kwargs) == expected
            assert kwargs["stdin"] == subprocess.PIPE and kwargs["stdout"] == subprocess.PIPE
            assert kwargs["stderr"] == subprocess.DEVNULL and kwargs["close_fds"] is True
            assert type(kwargs["env"]) is dict and all(
                type(key) is str and type(value) is str for key, value in kwargs["env"].items())
            if os.name == "nt":
                assert kwargs["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)
            else:
                assert kwargs["start_new_session"] is True
            self.physical_adaptations.append({"physical_image": self.contract["image"],
                "explicit_source_and_site": True, "unmodified_production_launcher": False})
            bootstrap = (_runtime_preamble(self.contract) +
                f"h=runpy.run_path({self.contract['helper']['path']!r});"
                "h['_production_entry']();" + original)
            command = [command[0], "-I", "-B", "-c", bootstrap]
            child = self.launch(command, reader=False, **kwargs)
            startup = {"runtime": self.contract, "key": self.key.hex(),
                       "nonce": self.nonce, "receipt": str(receipt_path)}
            raw = _canonical(startup)
            assert len(raw) <= _MAX_FRAME
            child.process.stdin.write(raw + b"\n")
            child.process.stdin.flush()
            receipt = _read_receipt(receipt_path, time.monotonic() + 4.0)
            child.admit(receipt, self.contract, self.key, self.nonce)
            child.process.stdin.write(b"ADMIT\n")
            child.process.stdin.flush()
            return child.process
        return launch


class BeaconCase(OwnedChildren):
    def __init__(self, beacon, initial, output, receipt_path):
        super().__init__(beacon)
        self.initial, self.output, self.receipt_path = initial, output, receipt_path
        self.engine = self.watcher = None
        self.engine_pid = None

    def start(self):
        read_fd, write_fd = os.pipe()
        self.descriptors.update((read_fd, write_fd))
        deadline = time.monotonic() + 8.0
        self.engine = self.launch(self.command("engine"), stdin=subprocess.PIPE,
            stdout=write_fd, stderr=subprocess.DEVNULL, close_fds=True)
        os.close(write_fd)
        self.descriptors.remove(write_fd)
        setup = {"runtime": self.contract, "key": self.key.hex(), "nonce": self.nonce,
                 "receipt": str(self.receipt_path), "initial": self.initial,
                 "output": str(self.output)}
        raw = _canonical(setup)
        assert len(raw) <= _MAX_FRAME
        self.engine.process.stdin.write(raw + b"\n")
        self.engine.process.stdin.flush()
        receipt = _read_receipt(self.receipt_path, deadline)
        self.engine.admit(receipt, self.contract, self.key, self.nonce)
        self.engine_pid = self.engine.process.pid
        self.watcher = self.launch(self.command("watcher"), reader=True, stdin=read_fd,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
        os.close(read_fd)
        self.descriptors.remove(read_fd)
        self.engine.process.stdin.write(b"go\n")
        self.engine.process.stdin.flush()
        self.watcher.admit(self.watcher.next_frame(deadline), self.contract, self.key, self.nonce)
        return self

    def normal_stop(self):
        self.engine.process.stdin.write(b"stop\n")
        self.engine.process.stdin.flush()
        deadline = time.monotonic() + 5.0
        assert self.engine.wait(deadline) == 0
        assert self.watcher.wait(deadline) == 0
        final = self.watcher.next_frame(deadline)
        assert final == {"result": "normal_stop", "reader_retired": True}


def _production_entry():
    setup = json.loads(sys.stdin.buffer.readline(_MAX_FRAME + 1))
    _write_receipt(setup["receipt"], _receipt(setup["runtime"],
        bytes.fromhex(setup["key"]), setup["nonce"]))
    assert sys.stdin.buffer.readline(32) == b"ADMIT\n"


def _child_main():
    from angerona.core import spyware_beacon as beacon
    if sys.argv[1] == "engine":
        import psutil
        setup = json.loads(sys.stdin.buffer.readline(_MAX_FRAME + 1))
        key = bytes.fromhex(setup["key"])
        _write_receipt(setup["receipt"], _receipt(setup["runtime"], key, setup["nonce"]))
        assert sys.stdin.buffer.readline(32) == b"go\n"
        initial = setup["initial"]
        initial["pid"] = os.getpid()
        initial["birth"] = psutil.Process(os.getpid()).create_time()
        envelope = {"setup": setup, "initial": initial}
        raw = _canonical(envelope)
        assert len(raw) <= _MAX_FRAME
        sys.stdout.buffer.write(raw + b"\n")
        sys.stdout.buffer.write(beacon._canonical(beacon._wrap(
            {"run": initial["run"], "seq": 1, "kind": "heartbeat"},
            bytes.fromhex(initial["key"]))) + b"\n")
        sys.stdout.buffer.flush()
        if sys.stdin.buffer.readline(32) == b"stop\n":
            sys.stdout.buffer.write(beacon._canonical(beacon._wrap(
                {"run": initial["run"], "seq": 2, "kind": "stop"},
                bytes.fromhex(initial["key"]))) + b"\n")
            sys.stdout.buffer.flush()
        return
    envelope = json.loads(sys.stdin.buffer.readline(_MAX_FRAME + 1))
    setup, initial = envelope["setup"], envelope["initial"]
    key = bytes.fromhex(setup["key"])
    def ready():
        print(_canonical(_receipt(setup["runtime"], key, setup["nonce"])).decode("ascii"), flush=True)
    def sender(event):
        with Path(setup["output"]).open("x", encoding="utf-8") as stream:
            json.dump(event, stream)
    facts = {"settings_absolute": Path(initial["settings"]).is_absolute(),
             "config_authorized": beacon._authorized(SimpleNamespace(**initial["config"]))}
    def authority(path, config):
        result = beacon._settings_authorized(path, config)
        facts["settings_authorized"] = result is True
        return result
    def identity(pid, birth):
        result = beacon._identity_state(pid, birth)
        for value in ("alive", "gone", "reused", "unknown"):
            facts["identity_" + value] = result == value
        return result
    result = beacon._watch_loop(sys.stdin.buffer, initial, sender=sender,
        authority_probe=authority, identity_probe=identity,
        destination_probe=lambda *_: True, on_ready=ready,
        heartbeat_timeout=2.0, poll_seconds=0.02)
    retired = not any(thread.name == "SpywareBeacon-pipe-read" and thread.is_alive()
                      for thread in threading.enumerate())
    final = {"result": result, "reader_retired": retired}
    if result in {"invalid_bootstrap", "unverified_bootstrap"}:
        final["diagnostic"] = _diagnostic("bootstrap", **facts)
    print(json.dumps(final), flush=True)
    if not retired:
        raise SystemExit(3)


if __name__ == "__main__":
    _child_main()
