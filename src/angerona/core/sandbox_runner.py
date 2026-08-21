"""Bounded subprocess runner for Sandbox Editor module self-tests.

The runner is deliberately Qt-free so its fail-safe boundary can be tested in
minimal environments. It never imports or invokes the selected module in the
live Angerona process.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SELF_TEST_TIMEOUT_SECONDS = 30.0
_RESULT_MARKER = "ANGERONA_SANDBOX_RESULT="
_HARNESS = r"""
import contextlib
import importlib
import io
import json
import sys
import traceback

source_root, module_name, class_name, expected_name = sys.argv[1:5]
sys.path.insert(0, source_root)
buf = io.StringIO()
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
print("ANGERONA_SANDBOX_RESULT=" + json.dumps({
    "passed": passed,
    "output": buf.getvalue().strip() or "(no output)",
}, ensure_ascii=True))
"""


def _sandbox_environment(data_root: str) -> dict[str, str]:
    """Return a minimal child environment with production integrations disabled."""
    keep = (
        "COMSPEC", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER", "SYSTEMDRIVE", "SYSTEMROOT", "WINDIR",
    )
    env = {key: os.environ[key] for key in keep if key in os.environ}
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


def _terminate_process_tree(proc: subprocess.Popen) -> None:
    """Best-effort termination without a shell; timeout remains fail-closed."""
    if proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5, check=False,
            )
        except Exception:
            proc.kill()
    else:
        proc.kill()


def run_isolated_self_test(
    module_name: str,
    class_name: str,
    expected_name: str,
    *,
    timeout: float = SELF_TEST_TIMEOUT_SECONDS,
    source_root: Path | None = None,
) -> tuple[bool, str]:
    """Run one freshly-instantiated module test outside the Angerona process."""
    if timeout <= 0:
        raise ValueError("self-test timeout must be positive")
    source_root = source_root or Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="angerona-sandbox-") as temp_root:
        creationflags = 0
        if os.name == "nt":
            creationflags = (getattr(subprocess, "CREATE_NO_WINDOW", 0)
                             | getattr(subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0)
                             | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        command = [
            sys.executable, "-I", "-c", _HARNESS,
            str(source_root), module_name, class_name, expected_name,
        ]
        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=_sandbox_environment(temp_root), creationflags=creationflags,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(proc)
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
            return False, f"TIMEOUT: isolated self_test exceeded {timeout:.1f}s and was terminated."

    payload = None
    for line in reversed(stdout.splitlines()):
        if line.startswith(_RESULT_MARKER):
            try:
                payload = json.loads(line[len(_RESULT_MARKER):])
            except json.JSONDecodeError:
                payload = None
            break
    if proc.returncode != 0 or not isinstance(payload, dict):
        detail = (stderr or stdout or "child returned no structured result").strip()
        return False, f"isolated self_test failed (exit {proc.returncode}):\n{detail[:8000]}"
    return bool(payload.get("passed")), str(payload.get("output", "(no output)"))[:16000]
