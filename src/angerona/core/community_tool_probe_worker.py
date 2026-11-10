"""Fixed YARA-X data probe in an owned, resource-limited ordinary-user child.

This is process/resource isolation, not an OS sandbox. No Python, upstream
commands, prerequisites, plugins, include files or modules are executed.
"""
from __future__ import annotations

import base64
import hashlib
from itertools import islice
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import uuid
import stat

from angerona.core.github_tool_catalog import _bounded_read, _require_unprivileged
from angerona.core.source_sandbox import _atomic_bytes_write, _ensure_directory, _hold_plain_directories
from angerona.core.file_lease import ExclusiveFileLease

MAX_REQUEST = 2 * 1024 * 1024
MAX_OUTPUT = 256 * 1024
MAX_SOURCE = 64 * 1024
MAX_PAYLOAD = 512 * 1024
_HELD = {}
_HELD_LOCK = threading.Lock()
_DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_RETAINED_PROBES = 8
MAX_RETAINED_BYTES = 8 * 1024 * 1024


def _request(sources, samples):
    if not isinstance(sources, list) or not 0 < len(sources) <= 32 or not isinstance(samples, list) or not 0 < len(samples) <= 4:
        raise ValueError("Choose 1–32 rule members and 1–4 explicit sample buffers.")
    rows, total = [], 0
    seen = set()
    for source in sources:
        if not isinstance(source, dict) or set(source) != {"path", "text"} or not isinstance(source["path"], str) or not 0 < len(source["path"]) <= 256 or not isinstance(source["text"], str):
            raise ValueError("Invalid closed YARA source input.")
        if source["path"] in seen:
            raise ValueError("YARA source paths must be distinct within a probe.")
        seen.add(source["path"])
        content = source["text"].encode("utf-8")
        total += len(content)
        if total > MAX_SOURCE or not content or re.search(r"\b(?:include|import)\b", source["text"]):
            raise ValueError("YARA probes permit at most 64 KiB of include/import-free source.")
        rows.append(dict(source, sha256=hashlib.sha256(content).hexdigest()))
    payloads = []
    for sample in samples:
        if type(sample) is not bytes or len(sample) > MAX_PAYLOAD:
            raise ValueError("Explicit sample buffers must be bytes up to 512 KiB each.")
        payloads.append(dict(base64=base64.b64encode(sample).decode("ascii"), sha256=hashlib.sha256(sample).hexdigest()))
    raw = json.dumps(dict(schema=1, sources=rows, samples=payloads), ensure_ascii=True).encode()
    if len(raw) > MAX_REQUEST:
        raise ValueError("YARA probe request exceeded its transport budget.")
    return raw


def source_namespace(path):
    """Same stable source namespace used by the managed runtime compiler."""
    if not isinstance(path, str) or not 0 < len(path) <= 256:
        raise ValueError("Invalid bounded YARA source path.")
    return "community_" + hashlib.sha256(path.encode("utf-8")).hexdigest()


def probe_custody_released():
    """Memory-only shutdown evidence; a failed native close stays a hold."""
    with _HELD_LOCK:
        return not bool(_HELD)


def _windows_limits(child):
    import win32job
    handle = child._job._handle  # newly launched, exclusively owned local Job.
    info = win32job.QueryInformationJobObject(handle, win32job.JobObjectExtendedLimitInformation)
    info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_JOB_MEMORY | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    info["BasicLimitInformation"]["ActiveProcessLimit"] = 4  # venv redirector + actual worker.
    info["JobMemoryLimit"] = 512 * 1024 * 1024
    win32job.SetInformationJobObject(handle, win32job.JobObjectExtendedLimitInformation, info)
    # pywin32 does not expose information class 15 on every supported build.
    import ctypes
    class Rate(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_uint32), ("rate", ctypes.c_uint32)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.SetInformationJobObject.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
    rate = Rate(1 | 4, 3000)
    if not kernel.SetInformationJobObject(int(handle), 15, ctypes.byref(rate), ctypes.sizeof(rate)):
        raise ctypes.WinError(ctypes.get_last_error())


def _validate_windows_admission(limits, cpu_flags, cpu_rate):
    """Closed native facts from the calling worker's immediate Job."""
    import win32job
    required = (win32job.JOB_OBJECT_LIMIT_JOB_MEMORY | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
    basic = limits.get("BasicLimitInformation") if type(limits) is dict else None
    if (type(basic) is not dict or type(basic.get("LimitFlags")) is not int
            or basic["LimitFlags"] & required != required
            or basic["LimitFlags"] & (win32job.JOB_OBJECT_LIMIT_BREAKAWAY_OK | win32job.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
            or type(basic.get("ActiveProcessLimit")) is not int or not 0 < basic["ActiveProcessLimit"] <= 4
            or type(limits.get("JobMemoryLimit")) is not int or not 0 < limits["JobMemoryLimit"] <= 512 * 1024 * 1024
            or type(cpu_flags) is not int or cpu_flags != (1 | 4)
            or type(cpu_rate) is not int or not 0 < cpu_rate <= 3000):
        raise ValueError("The worker's actual Windows Job has not admitted the required resource/lifetime limits.")


def _probe_job_name(root):
    name = Path(root).name
    if not re.fullmatch(r"[0-9a-f]{32}", name):
        raise ValueError("Invalid private YARA probe Job identity.")
    return "Local\\Angerona.YaraProbe." + name


def _verify_windows_worker_limits(root):
    """Query the actual parent-owned outer Job, including venv children.

    A scratch file is only an ordering signal. It cannot substitute for these
    OS-enforced memory/process/lifetime/CPU facts before native compilation.
    CPython's venv redirector may add its own inner Job; its presence does not
    replace or weaken the outer Job's inherited resource restrictions.
    """
    import ctypes
    import win32api
    import win32job
    handle = win32job.OpenJobObject(win32job.JOB_OBJECT_QUERY, False, _probe_job_name(root))
    try:
        if not win32job.IsProcessInJob(win32api.GetCurrentProcess(), handle):
            raise ValueError("The calling worker is not a member of its resource-admission Job.")
        limits = win32job.QueryInformationJobObject(handle, win32job.JobObjectExtendedLimitInformation)
        class Rate(ctypes.Structure):
            _fields_ = [("flags", ctypes.c_uint32), ("rate", ctypes.c_uint32)]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.QueryInformationJobObject.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                                    ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))
        kernel.QueryInformationJobObject.restype = ctypes.c_int
        rate, returned = Rate(), ctypes.c_uint32()
        if not kernel.QueryInformationJobObject(int(handle), 15, ctypes.byref(rate), ctypes.sizeof(rate), ctypes.byref(returned)):
            raise ctypes.WinError(ctypes.get_last_error())
        if returned.value != ctypes.sizeof(rate):
            raise ValueError("The worker's actual Windows Job CPU limit query was incomplete.")
        _validate_windows_admission(limits, int(rate.flags), int(rate.rate))
    finally:
        # Query custody must be released before compiling. Never retry a numeric
        # handle after an ambiguous native close; process exit releases it.
        handle.Close()


def _install_posix_worker_limits():
    import resource
    memory, cpu = 512 * 1024 * 1024, 10
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    for name, maximum in ((resource.RLIMIT_AS, memory), (resource.RLIMIT_CPU, cpu)):
        observed = resource.getrlimit(name)
        if (type(observed) is not tuple or len(observed) != 2
                or any(type(value) is not int or not 0 < value <= maximum for value in observed)):
            raise ValueError("The worker's actual POSIX resource limits were not established.")


def _probe_argv(request, digest):
    """Fixed internal dispatch shared by source and packaged executables."""
    image = str(Path(sys.executable).absolute())
    suffix = ["--community-tool-probe", "--request", str(request), "--sha256", digest]
    return [image, *suffix] if getattr(sys, "frozen", False) else [image, "-I", "-B", "-m", "angerona", *suffix]


def _admit_spool(root):
    """Inventory only this known spool and one bounded level of UUID children."""
    with _hold_plain_directories(root):
        entries = list(islice(root.iterdir(), MAX_RETAINED_PROBES+2))
        if len(entries) > MAX_RETAINED_PROBES + 1:
            raise ValueError("YARA probe diagnostics reached their retained-directory limit; review them before another probe.")
        total = retained = 0
        for path in entries:
            info = path.lstat()
            if path.name == "probe.lock":
                if not stat.S_ISREG(info.st_mode) or info.st_size > 4096 or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise ValueError("YARA probe lock identity requires review.")
                continue
            if not re.fullmatch(r"[0-9a-f]{32}", path.name) or not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Unknown YARA probe storage was preserved for review.")
            retained += 1
            with _hold_plain_directories(path):
                children = list(islice(path.iterdir(), 5))
                if len(children) > 4:
                    raise ValueError("YARA probe diagnostics exceed their file-count budget.")
                for child in children:
                    current = child.lstat()
                    if not stat.S_ISREG(current.st_mode) or stat.S_ISLNK(current.st_mode) or current.st_nlink != 1 or getattr(current, "st_file_attributes", 0) & 0x400:
                        raise ValueError("Redirected YARA probe diagnostics were preserved for review.")
                    total += current.st_size
            if total + MAX_REQUEST + MAX_OUTPUT + 5 > MAX_RETAINED_BYTES:
                raise ValueError("YARA probe diagnostics reached their 8 MiB byte budget; existing files were preserved.")
        if retained >= MAX_RETAINED_PROBES:
            raise ValueError("YARA probe diagnostics reached their retained-directory limit; review them before another probe.")


def run_yara_probe(root, sources, samples, operation, progress=None):
    """Admit bounded owned scratch before the fixed child can be launched."""
    _require_unprivileged()
    operation.check()
    _request(sources, samples)
    root = Path(root).absolute()
    _ensure_directory(root)
    with _hold_plain_directories(root), ExclusiveFileLease(root / "probe.lock"):
        _admit_spool(root)
        return _run_admitted_probe(root, sources, samples, operation, progress)


def _run_admitted_probe(root, sources, samples, operation, progress=None):
    """Background only; actual launch/exit and tree retirement precede results."""
    _require_unprivileged()
    operation.check()
    raw = _request(sources, samples)
    root = Path(root).absolute()
    key = str(root).casefold()
    with _HELD_LOCK:
        if key in _HELD:
            raise ValueError("An earlier YARA worker's native retirement is unproven; this adapter remains held.")
    _ensure_directory(root)
    job = root / uuid.uuid4().hex
    _ensure_directory(job)
    job_identity = (job.stat().st_dev, job.stat().st_ino)
    request = job / "request.json"
    _atomic_bytes_write(request, raw, root=job, private=True)
    digest = hashlib.sha256(raw).hexdigest()
    from angerona.core.privilege import sanitized_child_environment
    environment = sanitized_child_environment(source={})
    environment.update(TEMP=str(job), TMP=str(job), TMPDIR=str(job), HOME=str(job), USERPROFILE=str(job),
                       APPDATA=str(job), LOCALAPPDATA=str(job), ANGERONA_DATA=str(job), ANGERONA_BLACKBOX_ENABLED="0")
    argv = _probe_argv(request, digest)
    deadline = min(operation.deadline, time.monotonic() + 15)
    child = None
    retired = False
    result = None
    cleanup = {"request.json": digest, "ready": hashlib.sha256(b"ready").hexdigest()}
    try:
        if os.name == "nt":
            from angerona.core.windows_child_job import launch_windows_child
            child = launch_windows_child(argv, environment, cwd=str(job), deadline=deadline,
                                         check_cancelled=operation.check, kill_on_close=True,
                                         job_name=_probe_job_name(job))
            _windows_limits(child)
        else:
            child = subprocess.Popen(argv, cwd=job, env=environment, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        _atomic_bytes_write(job / "ready", b"ready", root=job, private=True)
        while child.poll() is None:
            operation.check()
            if time.monotonic() >= deadline:
                raise TimeoutError("YARA compile/scan worker exceeded its 15-second wall budget.")
            if progress is not None:
                progress(dict(phase="yara-worker", percent=None, message="Compiling reviewed data and scanning explicit buffers"))
            operation.cancelled.wait(.05)
        code = child.wait(timeout=1)
        if os.name == "nt":
            child.wait_tree(timeout=2)
        retired = True
        if code != 0:
            raise ValueError("YARA worker failed or reached a resource limit; no complete scan verdict was accepted.")
        content = _bounded_read(job / "result.json", job, MAX_OUTPUT)
        cleanup["result.json"] = hashlib.sha256(content).hexdigest()
        result = json.loads(content)
        if not isinstance(result, dict) or set(result) != {"schema", "request_sha256", "state", "matches", "message", "response_authority", "source_namespaces"} or result["schema"] != 1 or result["request_sha256"] != digest or result["response_authority"] is not False or result["state"] not in {"completed", "unavailable", "invalid"} or not isinstance(result["matches"], list) or len(result["matches"]) > 128 or result["source_namespaces"] != {source_namespace(row["path"]): row["path"] for row in sources}:
            raise ValueError("YARA worker returned an invalid bounded result envelope.")
        operation.check()
        isolation = ("Owned process, 15-second wall timeout, 512 MiB memory; Windows Job CPU cap 30%. Not an OS sandbox."
                     if os.name == "nt" else
                     "Owned process, 15-second wall timeout, 512 MiB address-space and 10-second CPU limits. Not an OS sandbox.")
        return dict(result, worker_retired=True, isolation=isolation)
    finally:
        if child is not None:
            try:
                if not retired:
                    child.kill()
                    child.wait(timeout=2)
                    if os.name == "nt":
                        child.wait_tree(timeout=2)
                    retired = True
                if os.name == "nt":
                    child.close()
            except BaseException:
                with _HELD_LOCK:
                    _HELD[key] = dict(child=child, directory=job)
                retired = False
                raise
        if retired or child is None:
            # Only exact unchanged files created by this operation are disposable.
            # Changed/unknown files remain for review; never recurse over a path.
            with _hold_plain_directories(job):
                for name, expected in cleanup.items():
                    path = job / name
                    try:
                        content = _bounded_read(path, job, MAX_REQUEST)
                    except FileNotFoundError:
                        continue
                    if hashlib.sha256(content).hexdigest() == expected:
                        path.unlink()
            with _hold_plain_directories(root):
                if (job.lstat().st_dev, job.lstat().st_ino) == job_identity:
                    try:
                        job.rmdir()
                    except OSError:
                        pass


def _worker(request, expected):
    _require_unprivileged()
    request = Path(request).absolute()
    root = request.parent
    if request.name != "request.json" or not _DIGEST.fullmatch(expected):
        raise ValueError("Invalid probe request identity.")
    raw = _bounded_read(request, root, MAX_REQUEST)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("Probe request changed before launch.")
    document = json.loads(raw)
    if not isinstance(document, dict) or set(document) != {"schema", "sources", "samples"} or document["schema"] != 1:
        raise ValueError("Invalid probe request schema.")
    # Revalidate the closed source/sample request before any native compilation.
    sources = [{"path": row["path"], "text": row["text"]} for row in document["sources"]]
    samples = [base64.b64decode(row["base64"], validate=True) for row in document["samples"]]
    if _request(sources, samples) != raw:
        raise ValueError("Probe source/sample digest failed validation.")
    deadline = time.monotonic() + 5
    while not (root / "ready").exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("Parent resource admission was not completed.")
        time.sleep(.02)
    if _bounded_read(root / "ready", root, 5) != b"ready":
        raise ValueError("Invalid resource admission marker.")
    if os.name == "nt":
        _verify_windows_worker_limits(root)
    else:
        _install_posix_worker_limits()
    result = dict(schema=1, request_sha256=expected, state="unavailable", matches=[], message="", response_authority=False,
                  source_namespaces={source_namespace(row["path"]): row["path"] for row in sources})
    compiler = rules = scanner = scan = None
    try:
        import yara_x
    except ImportError:
        result["message"] = "Existing pinned YARA-X engine is unavailable; nothing was installed."
    else:
        try:
            compiler = yara_x.Compiler()
            compiler.enable_includes(False)
            for row in sources:
                compiler.new_namespace(source_namespace(row["path"]))
                compiler.add_source(row["text"], origin=row["path"])
            rules = compiler.build()
            compiler = None
            scanner = yara_x.Scanner(rules)
            scanner.set_timeout(2)
            scanner.max_matches_per_pattern(16)
            matches = []
            for index, sample in enumerate(samples):
                scan = scanner.scan(sample)
                identifiers = [str(rule.identifier)[:128] for rule in scan.matching_rules]
                if len(identifiers) > 128:
                    raise ValueError("Rule match count exceeded its output budget.")
                matches.append(dict(sample=index, rules=identifiers))
                scan = None
            result.update(state="completed", matches=matches, message="Reviewed data scanned explicit buffers; no host files were enumerated.")
        except Exception as exc:
            # Native objects never escape their owning worker or traceback.
            result.update(state="invalid", message="YARA compilation/scan failed: " + type(exc).__name__)
        finally:
            scan = scanner = rules = compiler = None
    content = json.dumps(result, ensure_ascii=True, allow_nan=False).encode()
    if len(content) > MAX_OUTPUT:
        raise ValueError("Probe output exceeded its budget.")
    _atomic_bytes_write(root / "result.json", content, root=root, private=True)


def worker_main(argv):
    """Only the enrolled --community-tool-probe application entry calls this."""
    if not isinstance(argv, list) or len(argv) != 4 or argv[0] != "--request" or argv[2] != "--sha256" or any(not isinstance(value, str) for value in argv):
        return 2
    try:
        _worker(argv[1], argv[3])
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(worker_main(sys.argv[1:]))
