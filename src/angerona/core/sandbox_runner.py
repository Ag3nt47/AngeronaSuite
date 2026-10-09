"""Bounded subprocess runner for Sandbox Editor module self-tests.

The runner is deliberately Qt-free so its fail-safe boundary can be tested in
minimal environments. It never imports or invokes the selected module in the
live Angerona process.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from angerona.resilience._selftest_environment import (
    _assign_windows_kill_job, _bounded_process_output, _remove_owned_temp,
    _resume_windows_process, _stop_process_custody,
)

SELF_TEST_TIMEOUT_SECONDS = 30.0
_RESULT_MARKER = "ANGERONA_SANDBOX_RESULT="
_HARNESS = r"""
import contextlib
import importlib
import io
import json
import os
import secrets
import sys
import traceback

bootstrap_root, source_root, module_name, class_name, expected_name = sys.argv[1:6]
sys.path.insert(0, bootstrap_root)
from angerona.resilience._selftest_environment import _apply_posix_child_limits
_apply_posix_child_limits()
expected = os.environ.pop("ANGERONA_SELFTEST_CHILD_TOKEN", "")
supplied = sys.stdin.readline(129).strip()
if len(expected) != 64 or not secrets.compare_digest(expected, supplied):
    raise SystemExit(2)
sys.path.insert(0, source_root)

class BoundedCapture(io.TextIOBase):
    def __init__(self):
        self.parts = []
        self.remaining = 1600
        self.truncated = False

    def write(self, value):
        value = str(value)
        if self.remaining and value:
            self.parts.append(value[:self.remaining])
        self.truncated |= len(value) > self.remaining
        self.remaining = max(0, self.remaining - len(value))
        return len(value)

    def getvalue(self):
        return "".join(self.parts)

buf = BoundedCapture()
passed = False
try:
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        module = importlib.import_module(module_name)
        cls = getattr(module, class_name)
        instance = cls()
        if str(getattr(instance, "name", "")) != expected_name:
            raise RuntimeError("module identity changed before isolated test")
        result = instance.self_test()
    if isinstance(result, tuple):
        passed = bool(result[0])
        detail = str(result[1]) if len(result) > 1 else ""
    else:
        passed = bool(result)
        detail = ""
    if detail:
        buf.write("\n[self_test detail] " + detail)
except BaseException:
    buf.write("\n" + traceback.format_exc())
    passed = False
if buf.truncated:
    passed = False
    output = "OUTPUT LIMIT: isolated self_test output exceeded its bound.\n" + buf.getvalue()
else:
    output = buf.getvalue().strip() or "(no output)"
print("ANGERONA_SANDBOX_RESULT=" + json.dumps({
    "passed": passed,
    "output": output,
}, ensure_ascii=True))
"""


def _sandbox_environment(data_root: str) -> dict[str, str]:
    """Return a minimal child environment with production integrations disabled."""
    from angerona.core.privilege import sanitized_child_environment

    env = sanitized_child_environment(source={})
    env.update({
        "ANGERONA_DATA": data_root,
        "ANGERONA_OFFLINE": "1",
        "ANGERONA_EXTERNAL_MODULES": "0",
        "ANGERONA_REMOTE_BRIDGE": "0",
        "ANGERONA_MOBILE_ENABLED": "0",
        "ANGERONA_CLOUD_ENABLED": "0",
        "HOME": data_root,
        "USERPROFILE": data_root,
        "TEMP": data_root,
        "TMP": data_root,
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    return env


def run_isolated_self_test(
    module_name: str,
    class_name: str,
    expected_name: str,
    *,
    timeout: float = SELF_TEST_TIMEOUT_SECONDS,
    source_root: Path | None = None,
) -> tuple[bool, str]:
    """Run one freshly-instantiated module test outside the Angerona process."""
    timeout = float(timeout)
    if not 0 < timeout <= 60:
        raise ValueError("self-test timeout must be positive and at most 60 seconds")
    if bool(getattr(sys, "frozen", False)):
        return False, "isolated source self_test is unavailable in this packaged runtime"
    bootstrap_root = Path(__file__).resolve().parents[2]
    source_root = Path(source_root or bootstrap_root).resolve()
    root = Path(tempfile.mkdtemp(prefix="angerona-sandbox-")).resolve(strict=True)
    created = root.lstat()
    proc = None
    windows_job = None
    try:
        token = secrets.token_hex(32)
        environment = _sandbox_environment(str(root))
        environment["ANGERONA_SELFTEST_CHILD_TOKEN"] = token
        kwargs = dict(
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=environment, cwd=str(root), close_fds=True, bufsize=0,
        )
        if os.name == "nt":
            kwargs["creationflags"] = (
                getattr(subprocess, "CREATE_NO_WINDOW", 0)
                | getattr(subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
            )
        else:
            kwargs["start_new_session"] = True
        command = [
            sys.executable, "-I", "-c", _HARNESS,
            str(bootstrap_root), str(source_root), module_name, class_name, expected_name,
        ]
        proc = subprocess.Popen(command, **kwargs)
        if os.name == "nt":
            windows_job = _assign_windows_kill_job(proc)
            _resume_windows_process(proc)
        state, raw = _bounded_process_output(proc, token, timeout)
        if state == "timeout":
            return False, f"TIMEOUT: isolated self_test exceeded {timeout:.1f}s and was terminated."
        if state == "overflow":
            return False, "OUTPUT LIMIT: isolated self_test output exceeded its bound."
        if state != "complete":
            return False, "isolated self_test output custody failed closed."
        stdout = raw.decode("utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"isolated self_test process custody failed: {type(exc).__name__}"
    finally:
        _stop_process_custody(proc, windows_job)
        _remove_owned_temp(root, created)

    payload = None
    for line in reversed(stdout.splitlines()):
        if line.startswith(_RESULT_MARKER):
            try:
                payload = json.loads(line[len(_RESULT_MARKER):])
            except json.JSONDecodeError:
                payload = None
            break
    if proc.returncode != 0 or not isinstance(payload, dict):
        detail = (stdout or "child returned no structured result").strip()
        return False, f"isolated self_test failed (exit {proc.returncode}):\n{detail[:8000]}"
    return bool(payload.get("passed")), str(payload.get("output", "(no output)"))[:16000]
