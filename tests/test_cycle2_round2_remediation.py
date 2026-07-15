from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import replace
from pathlib import Path

from angerona.connectors.research import Research
from angerona.connectors.research_fetchers import register_research_tool
from angerona.core.assistant import Assistant, Tool, ToolKind
from angerona.shark.red_team import RedTeamEngine
from angerona.shark.shark_attack import SharkAttackEngine


ROOT = Path(__file__).resolve().parents[1]


def _stop_during_jitter(engine, start, waiting: threading.Event) -> float:
    assert start()
    assert waiting.wait(2.0), "drill never entered its interruptible jitter"
    began = time.monotonic()
    engine.stop_and_clean()
    worker = engine._thread
    if worker is not None:
        worker.join(1.0)
    return time.monotonic() - began


def test_stop_cancels_both_drills_before_later_side_effects(tmp_path: Path) -> None:
    red_waiting = threading.Event()
    red_events: list[str] = []

    def on_red(message: str) -> None:
        red_events.append(message)
        if "Waiting" in message:
            red_waiting.set()

    red_dir = tmp_path / "red"
    red = RedTeamEngine(tmp_path / "red-data", documents_dir=red_dir, on_event=on_red)
    red_elapsed = _stop_during_jitter(
        red, lambda: red.start(jitter_range=(5.0, 5.0), noise_chance=0.0), red_waiting)
    assert red_elapsed < 1.0 and not red.is_running and not red._thread.is_alive()
    assert red.steps == [] and not list(red_dir.glob("_redteam_*"))
    assert not any("Attack complete" in message for message in red_events)

    shark_waiting = threading.Event()
    shark_events: list[str] = []
    completed: list[object] = []

    def on_shark(message: str) -> None:
        shark_events.append(message)
        if "Waiting" in message:
            shark_waiting.set()

    shark_dir = tmp_path / "shark"
    shark = SharkAttackEngine(
        tmp_path / "shark-data", downloads_dir=shark_dir,
        documents_dir=shark_dir, on_event=on_shark,
        on_complete=lambda steps: completed.append(steps),
    )
    shark_elapsed = _stop_during_jitter(
        shark, lambda: shark.start(jitter_range=(5.0, 5.0), noise_chance=0.0), shark_waiting)
    assert shark_elapsed < 1.0 and not shark.is_running and not shark._thread.is_alive()
    assert shark.steps == [] and completed == []
    assert not any("Attack complete" in message for message in shark_events)
    assert not any(path.suffix in {".txt", ".zip", ".sys"} for path in shark_dir.glob("*"))


def test_aria_confirmation_binds_callback_kind_preview_and_arguments() -> None:
    calls: list[tuple[str, object]] = []
    aria = Assistant(enabled=True)

    def original(payload):
        calls.append(("original", payload))
        return payload

    aria.register("act", ToolKind.WRITE, original,
                  preview=lambda payload: f"Act on {payload['items'][0]}")
    mutable = {"items": ["reviewed"]}
    staged = aria.invoke("act", mutable)
    mutable["items"][0] = "mutated"
    assert aria.confirm(staged.confirm_token).ok
    assert calls == [("original", {"items": ["reviewed"]})]
    assert not aria.confirm(staged.confirm_token).ok, "confirmation must be single-use"

    replaced = aria.invoke("act", {"items": ["safe"]})
    aria.register("act", ToolKind.WRITE, lambda payload: calls.append(("replacement", payload)))
    assert not aria.confirm(replaced.confirm_token).ok and len(calls) == 1

    direct = aria.invoke("act", {"items": ["safe"]})
    current = aria._tools["act"]
    aria._tools["act"] = Tool("act", ToolKind.READ, current.fn,
                               current.description, current.preview, current.version)
    assert not aria.confirm(direct.confirm_token).ok and len(calls) == 1

    aria.register("act", ToolKind.WRITE, original)
    expired = aria.invoke("act", {"items": ["old"]})
    aria._pending[expired.confirm_token] = replace(
        aria._pending[expired.confirm_token], staged_at=time.time() - 10_000)
    assert not aria.confirm(expired.confirm_token).ok and len(calls) == 1

    disabled = aria.invoke("act", {"items": ["disabled"]})
    aria.enabled = False
    aria.enabled = True
    assert not aria.confirm(disabled.confirm_token).ok and len(calls) == 1


def test_aria_releases_abandoned_confirmations_after_ttl() -> None:
    aria = Assistant(enabled=True)
    aria.register("act", ToolKind.WRITE, lambda payload: payload)
    old_tokens = []
    for value in range(100):
        staged = aria.invoke("act", {"value": value, "items": [1, 2, 3]})
        old_tokens.append(staged.confirm_token)
        aria._pending[staged.confirm_token] = replace(
            aria._pending[staged.confirm_token], staged_at=time.time() - 10_000)

    current = aria.invoke("act", {"value": "current"})
    assert aria.pending() == [current.confirm_token]
    assert not any(token in aria._pending for token in old_tokens)


def test_research_read_has_zero_egress_and_browser_open_requires_confirmation() -> None:
    opened: list[str] = []
    aria = Assistant(enabled=True)
    register_research_tool(
        aria, Research(enabled=True, fetch=lambda _url: (_ for _ in ()).throw(
            AssertionError("READ must not use an injected fetcher"))),
        open_in_browser=True, opener=lambda url: opened.append(url) or True,
    )
    result = aria.invoke("research", "8.8.8.8")
    assert result.ok and not result.needs_confirmation and not opened
    action = aria.invoke("open_research_sources", "8.8.8.8")
    assert action.ok and action.needs_confirmation and not opened
    assert "Open 2 vetted" in action.text and "8.8...8.8" in action.text
    assert aria.confirm(action.confirm_token).ok and len(opened) == 2


def test_shutdown_ownership_predicate_is_boundary_and_entrypoint_aware() -> None:
    powershell = shutil.which("powershell")
    if powershell is None:
        raise AssertionError("PowerShell is required for the Windows shutdown predicate")
    helper = ROOT / "tools" / "angerona_process_owner.ps1"
    root = str(ROOT)
    valid_script = str(ROOT / "src" / "angerona" / "__main__.py")
    repo_readme = str(ROOT / "README.md")
    suite_python = str(ROOT / "venv" / "Scripts" / "python.exe")
    sibling_python = str(ROOT) + "-copy\\venv\\Scripts\\python.exe"
    command = f"""
. '{helper}'
$root = '{root}'
$cases = @(
  @{{ Name='suite'; P=[pscustomobject]@{{ ExecutablePath='{suite_python}'; CommandLine='"{suite_python}" -m angerona'; ProcessId=10 }} }},
  @{{ Name='script'; P=[pscustomobject]@{{ ExecutablePath='C:\\Python\\python.exe'; CommandLine='python.exe -u "{valid_script}"'; ProcessId=11 }} }},
  @{{ Name='sibling'; P=[pscustomobject]@{{ ExecutablePath='{sibling_python}'; CommandLine='"{sibling_python}" -m angerona'; ProcessId=12 }} }},
  @{{ Name='reader'; P=[pscustomobject]@{{ ExecutablePath='C:\\Python\\python.exe'; CommandLine='python.exe "C:\\work\\notebook.py" "{repo_readme}"'; ProcessId=13 }} }},
  @{{ Name='mixed'; P=[pscustomobject]@{{ ExecutablePath='{suite_python.upper()}'; CommandLine='python.exe'; ProcessId=14 }} }},
  @{{ Name='reused'; P=[pscustomobject]@{{ ExecutablePath='C:\\Windows\\System32\\notepad.exe'; CommandLine='notepad.exe'; ProcessId=10 }} }}
)
$cases | ForEach-Object {{ [pscustomobject]@{{ Name=$_.Name; Owned=(Test-AngeronaProcessOwnership -Process $_.P -Root $root) }} }} | ConvertTo-Json -Compress
"""
    proc = subprocess.run(
        [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        cwd=ROOT, text=True, capture_output=True, timeout=20, check=True,
    )
    results = {item["Name"]: item["Owned"] for item in json.loads(proc.stdout)}
    assert results == {
        "suite": True, "script": True, "sibling": False,
        "reader": False, "mixed": True, "reused": False,
    }


if __name__ == "__main__":
    checks = []
    with tempfile.TemporaryDirectory() as td:
        checks.append(("drill cancellation", lambda: test_stop_cancels_both_drills_before_later_side_effects(Path(td))))
        for name, check in checks + [
            ("ARIA action binding", test_aria_confirmation_binds_callback_kind_preview_and_arguments),
            ("ARIA pending TTL cleanup", test_aria_releases_abandoned_confirmations_after_ttl),
            ("research confirmation", test_research_read_has_zero_egress_and_browser_open_requires_confirmation),
            ("shutdown ownership", test_shutdown_ownership_predicate_is_boundary_and_entrypoint_aware),
        ]:
            check()
            print(f"PASS - {name}")
