"""Pure PowerShell invocation predicates over supplied rows; no process lookup/action."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from angerona.core.privilege import trusted_powershell_path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "angerona_process_owner.ps1"
# The only child is this constant loader. The loaded file defines path/token
# predicates only; every process row and parent snapshot is caller-supplied.
LOADER = (
    "$ErrorActionPreference='Stop'; "
    ". $env:ANGERONA_OWNER_TEST_SCRIPT; "
    "$request=ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd()); "
    "$results=@($request.cases | ForEach-Object { "
    "[pscustomobject]@{id=$_.id; owned=[bool](Test-AngeronaProcessOwnership "
    "-Process $_.process -Root $request.root -ProcessSnapshot @($_.snapshot))} }); "
    "ConvertTo-Json -InputObject $results -Compress"
)
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell predicate contract")


def test_closed_python_prefixes_preserve_exact_module_and_parent_ownership():
    fixture_root = r"D:\Angerona Ownership Fixture"
    suite = fixture_root + r"\venv\Scripts\pythonw.exe"
    base = r"D:\Unrelated Python Fixture\pythonw.exe"
    script = fixture_root + r"\blackbox_recorder.py"
    cases = []

    def row(executable, arguments, *, pid=20, parent=10, born="2026-01-01T00:00:01Z"):
        return {"ExecutablePath": executable,
                "CommandLine": subprocess.list2cmdline([executable, *arguments]),
                "ProcessId": pid, "ParentProcessId": parent, "CreationDate": born}

    def case(identifier, process, expected, snapshot=()):
        cases.append({"id": identifier, "process": process,
                      "snapshot": list(snapshot), "expected": expected})

    for module in ("angerona", "angerona.startup", "angerona.resilience.scanner",
                   "angerona.resilience.status_ui", "angerona.resilience.watchdog"):
        case("isolated:" + module, row(suite, ["-I", "-m", module]), True)
        case("legacy:" + module, row(suite, ["-m", module]), True)

    prefixed = ["-I", "-B", "-X", r"pycache_prefix=D:\Private Fixture\cache",
                "-W", "ignore", "-m", "angerona.resilience.scanner"]
    case("cache-prefix", row(suite, prefixed), True)
    parent = row(suite, prefixed, pid=10, parent=1, born="2026-01-01T00:00:00Z")
    child = row(base, prefixed)
    case("redirected-base", child, True, [parent])
    case("base-no-parent", child, False)
    case("base-parent-other-module", child, False, [row(
        suite, ["-I", "-m", "angerona.resilience.watchdog"], pid=10)])
    case("base-parent-other-prefix", child, False, [row(
        suite, prefixed[1:], pid=10)])
    case("base-parent-other-installation", child, False, [dict(
        parent, ExecutablePath=r"D:\Different Suite\venv\Scripts\pythonw.exe")])
    case("base-parent-newer", child, False, [dict(parent, CreationDate="2026-01-01T00:00:02Z")])
    case("base-parent-missing-birth", child, False, [dict(parent, CreationDate=None)])
    case("base-child-missing-birth", dict(child, CreationDate=None), False, [parent])
    case("base-parent-invalid-birth", child, False, [dict(parent, CreationDate="invalid-date")])
    case("base-duplicate-parent", child, False, [parent, dict(parent)])
    case("base-parent-wrong-pid", child, False, [dict(parent, ProcessId=11)])
    case("base-self-parent", dict(child, ParentProcessId=20), False, [dict(parent, ProcessId=20)])

    for identifier, arguments in (
        ("unrelated-module", ["-I", "-m", "pytest"]),
        ("module-case", ["-I", "-m", "angerona.resilience.Watchdog"]),
        ("missing-module", ["-I", "-m"]),
        ("missing-X", ["-I", "-X"]),
        ("missing-W", ["-W"]),
        ("empty-X", ["-X", "", "-m", "angerona"]),
        ("unknown-prefix", ["--unknown", "-m", "angerona"]),
        ("interactive-prefix", ["-i", "-m", "angerona"]),
        ("code-is-not-script", ["-c", script]),
        ("code-is-not-module", ["-c", "angerona", "-m", "angerona"]),
        ("code-after-cache-prefix", ["-X", "utf8", "-c", script]),
        ("stdin", ["-", script]),
        ("end-options", ["--", script]),
        ("options-consume-script-text", ["-W", script]),
        ("excess-prefixes", [*(["-I"] * 17), "-m", "angerona"]),
        ("relative-script", ["-I", "blackbox_recorder.py"]),
        ("unrelated-script", ["-I", r"D:\Other Fixture\blackbox_recorder.py"]),
        ("unknown-prefix-script", ["--unknown", script]),
    ):
        case(identifier, row(suite, arguments), False)
    case("bounded-prefixes", row(suite, [*(["-I"] * 16), "-m", "angerona"]), True)
    case("canonical-script", row(suite, ["-I", script]), True)
    case("canonical-system-python-script", row(base, ["-B", script]), True)
    case("non-python-script", row(r"D:\Fixture\notepad.exe", [script]), False)
    case("non-python-module", row(r"D:\Fixture\tool.exe", ["-I", "-m", "angerona"]), False)
    case("empty-command", dict(child, CommandLine=""), False, [parent])
    case("missing-image", dict(child, ExecutablePath=None), False, [parent])

    request = {"root": fixture_root,
               "cases": [{key: value for key, value in item.items() if key != "expected"}
                         for item in cases]}
    environment = dict(os.environ, ANGERONA_OWNER_TEST_SCRIPT=str(SCRIPT))
    result = subprocess.run(
        [str(trusted_powershell_path()), "-NoProfile", "-NonInteractive", "-Command", LOADER],
        input=json.dumps(request), capture_output=True, text=True, env=environment,
        timeout=30, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, result.stderr
    actual = json.loads(result.stdout.lstrip("\ufeff"))
    assert len(actual) == len(cases)
    assert [value["id"] for value in actual] == [value["id"] for value in cases]
    for observed, expected in zip(actual, cases, strict=True):
        assert type(observed["owned"]) is bool
        assert observed["owned"] is expected["expected"], expected["id"]
