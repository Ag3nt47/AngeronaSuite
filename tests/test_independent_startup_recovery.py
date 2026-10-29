"""Standalone recovery survives application failures and treats reports as data."""
from __future__ import annotations

import importlib.util
import base64
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "angerona_recovery.py"
SPEC = importlib.util.spec_from_file_location("independent_recovery_under_test", SCRIPT)
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)


@pytest.fixture
def report(tmp_path):
    log = tmp_path / "startup-supervisor.jsonl"
    log.write_text('phase=dependencies exit=82\n', encoding="utf-8")
    path = tmp_path / "startup-status.json"
    document = dict(schema=1, phase="dependencies", outcome="needs-recovery",
                    message="An exact dependency mismatch was detected.",
                    protection_status="inactive", log_path=str(log),
                    attempts=[dict(strategy="normal", outcome="failed", exit_code=82,
                                   detail="Expected one reviewed dependency version.")])
    path.write_text(json.dumps(document), encoding="utf-8")
    return path, log, document


@pytest.fixture
def windows_report(report):
    """Use the production reader's known checkout scratch scope on every host.

    pytest's default temporary directory lives outside that scope on hosted
    Windows. Keep the real path restriction instead of widening it for tests.
    The repository fixture supplies an independently owned root per test.
    """
    directory = Path(os.environ["ANGERONA_DATA"]) / "recovery-reader"
    assert directory.absolute().is_relative_to(ROOT / ".tmp")
    directory.mkdir(parents=True, exist_ok=False)
    _, source_log, source_document = report
    log = directory / source_log.name
    log.write_bytes(source_log.read_bytes())
    document = dict(source_document, log_path=str(log))
    path = directory / "startup-status.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path, log, document


def test_report_is_display_data_and_does_not_claim_protection(report):
    path, _, _ = report
    model = recovery.load_model(path)
    assert model["report_valid"] and model["protection_status"] == "inactive"
    assert model["attempts"][0]["exit_code"] == 82
    text = recovery.display_text(model)
    assert "Protection is not verified" in text and "needs-recovery" in text


def test_active_claim_from_report_cannot_verify_security(report):
    path, _, document = report
    document["protection_status"] = "active"
    path.write_text(json.dumps(document))
    model = recovery.load_model(path)
    assert model["protection_status"] == "unknown"
    assert "Protection is not verified" in recovery.display_text(model)


def test_missing_log_remains_a_visible_gap(report):
    path, log, _ = report
    log.unlink()
    model = recovery.load_model(path)
    assert model["report_valid"]
    assert "missing" in model["log_state"]
    assert "missing" in recovery.log_text(model["log_path"])


@pytest.mark.parametrize("payload", [
    b'{"schema":1,"schema":1}', b'{"schema":true}', b'{"schema":2}', b'not JSON',
    b'{"schema":1,"attempts":"wrong"}', b'{"schema":1,"attempts":["wrong"]}',
    b"x" * (recovery.MAX_STATUS_BYTES + 1),
], ids=["duplicate", "boolean-schema", "unknown-schema", "non-json", "bad-list", "bad-row", "oversized"])
def test_invalid_status_still_has_a_recovery_model_and_can_request_retry(tmp_path, payload):
    path = tmp_path / "status.json"
    path.write_bytes(payload)
    model = recovery.load_model(path)
    assert not model["report_valid"] and model["outcome"] == "report-unavailable"
    called = []
    assert recovery.main(["--status-file", str(path)], show=lambda value: called.append(value) or 10) == 10
    assert called and not called[0]["report_valid"]


def test_missing_report_does_not_prevent_recovery_ui(tmp_path):
    path = tmp_path / "missing.json"
    assert recovery.main(["--status-file", str(path)], show=lambda model: recovery.CLOSE) == 0


def test_bounded_report_rows_and_secret_redaction(report):
    path, _, document = report
    document["message"] = "password=private Bearer abcdefghijklmnop sk-secretlongvalue"
    # Keep the physical report within its independent input byte cap.
    document["attempts"] = [dict(strategy="x" * 300, outcome="failed", exit_code=82,
                                  detail="api_key=credential " + "z" * 700)] * 45
    path.write_text(json.dumps(document))
    model = recovery.load_model(path)
    assert model["report_valid"]
    assert len(model["attempts"]) == 32 and model["omitted_attempts"] == 13
    text = recovery.display_text(model)
    for secret in ("private", "abcdefghijklmnop", "sk-secretlongvalue", "credential"):
        assert secret not in text
    assert "[redacted]" in text


def test_log_view_is_bounded_and_redacts_credentials(report):
    _, log, _ = report
    log.write_bytes(b"a" * (recovery.MAX_LOG_BYTES + 100) + b"\npassword=private\n")
    text = recovery.log_text(str(log))
    assert "Earlier diagnostic text omitted" in text
    assert "private" not in text and "[redacted]" in text
    assert len(text) <= recovery.MAX_LOG_BYTES + 100


def test_report_cannot_select_a_file_outside_the_cli_log_root(report, tmp_path):
    path, _, document = report
    other = tmp_path.parent / (tmp_path.name + "-outside.log")
    other.write_text("must not read")
    document["log_path"] = str(other)
    path.write_text(json.dumps(document))
    model = recovery.load_model(path)
    assert model["log_path"] == ""
    assert "outside" in model["log_state"]


def test_explicit_log_root_can_select_another_owned_diagnostic_directory(report, tmp_path):
    path, _, document = report
    directory = tmp_path / "logs"
    directory.mkdir()
    selected = directory / "preflight.log"
    selected.write_text("diagnostic text")
    document["log_path"] = str(selected)
    path.write_text(json.dumps(document))
    model = recovery.load_model(path, log_root=directory)
    assert model["log_path"] == str(selected)


def test_hardlinked_report_is_rejected_without_reading_it(report, tmp_path):
    path, _, _ = report
    os.link(path, tmp_path / "linked.json")
    assert not recovery.load_model(path)["report_valid"]


def test_hardlinked_log_is_unavailable_and_cannot_be_opened_from_model(report, tmp_path):
    path, log, _ = report
    os.link(log, tmp_path / "linked.log")
    model = recovery.load_model(path)
    assert model["report_valid"] and model["log_path"] == ""
    assert "unsafe" in model["log_state"]


def test_untrusted_surrogate_text_is_safe_to_display(report):
    path, _, document = report
    document["message"] = "Untrusted surrogate \ud800 text"
    document["log_path"] = "C:/bad\ud800.log"
    path.write_text(json.dumps(document))
    model = recovery.load_model(path)
    assert "\ud800" not in recovery.display_text(model)
    assert "\ufffd" in model["message"]


@pytest.mark.parametrize("action,expected", [("Retry safe recovery", 10), ("Close", 0)])
def test_tk_buttons_only_return_parent_owned_actions(report, action, expected):
    path, _, _ = report
    buttons = []
    class Widget:
        def __init__(self, *_args, **options):
            self.options = options
        def pack(self, **_options):
            pass
        def title(self, _title):
            pass
        def geometry(self, _geometry):
            pass
        def insert(self, *_args):
            pass
        def configure(self, **_options):
            pass
        def protocol(self, *_args):
            pass
        def destroy(self):
            self.closed = True
    class Window(Widget):
        def mainloop(self):
            next(button for button in buttons if button.options["text"] == action).options["command"]()
    class Button(Widget):
        def __init__(self, *args, **options):
            super().__init__(*args, **options)
            buttons.append(self)
    from types import SimpleNamespace
    fake = SimpleNamespace(Tk=Window, Label=Widget, Text=Widget, Frame=Widget, Button=Button)
    assert recovery.show_window(recovery.load_model(path), tk_module=fake) == expected


@pytest.mark.parametrize("which", ["status", "log"])
def test_redirected_file_is_rejected(report, tmp_path, which):
    path, log, _ = report
    target = path if which == "status" else log
    original = target.with_name("original" + target.suffix)
    target.rename(original)
    try:
        target.symlink_to(original)
    except OSError:
        pytest.skip("Host does not permit test symbolic links")
    model = recovery.load_model(path)
    if which == "status":
        assert not model["report_valid"]
    else:
        assert model["log_path"] == "" and "unsafe" in model["log_state"]


def test_only_retry_and_close_codes_are_emitted(report, capsys):
    path, _, _ = report
    for requested, expected in ((0, 0), (10, 10), (82, 11)):
        assert recovery.main(["--status-file", str(path)], show=lambda _model: requested) == expected
    def failed(_model):
        raise ImportError("Tk unavailable; password=private")
    assert recovery.main(["--status-file", str(path)], show=failed) == 11
    payload = json.loads(capsys.readouterr().err)
    assert payload["exception_type"] == "ImportError"
    assert "private" not in payload["message"]


def test_standalone_subprocess_ignores_broken_application_and_never_executes_report(report, tmp_path):
    path, _, document = report
    broken = tmp_path / "angerona"
    broken.mkdir()
    (broken / "__init__.py").write_text("def broken(\n")
    marker = tmp_path / "executed"
    document["message"] = "__import__('pathlib').Path(" + repr(str(marker)) + ").touch()"
    document["command"] = "should never execute"
    path.write_text(json.dumps(document))
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(tmp_path)
    isolated = """import importlib.abc, runpy, sys
class BrokenApplication(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'angerona' or fullname.startswith('angerona.'):
            raise SyntaxError('Application code is broken')
sys.meta_path.insert(0, BrokenApplication())
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name='__main__')
"""
    result = subprocess.run([sys.executable, "-I", "-c", isolated, str(SCRIPT),
                             "--status-file", str(path), "--headless"],
                            cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=20,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert result.returncode == 0, result.stderr
    model = json.loads(result.stdout)
    assert model["report_valid"] and "__import__" in model["message"]
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows retained file handle sharing")
def test_windows_reader_holds_file_against_writes_and_renames(report, monkeypatch):
    path, _, _ = report
    original = recovery.os.read
    witnessed = []
    def read(descriptor, count):
        with pytest.raises(OSError):
            with path.open("wb"):
                pass
        with pytest.raises(OSError):
            path.rename(path.with_name("replaced.json"))
        witnessed.append(True)
        return original(descriptor, count)
    monkeypatch.setattr(recovery.os, "read", read)
    assert recovery.load_model(path)["report_valid"]
    assert witnessed


@pytest.mark.skipif(os.name != "nt", reason="Independent Windows PowerShell recovery")
def test_windows_powershell_recovery_reads_valid_status_without_python(windows_report):
    path, _, _ = windows_report
    shell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    script = ROOT / "tools/Show-AngeronaStartupRecovery.ps1"
    result = subprocess.run([str(shell), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script),
                             "-StatusFile", str(path), "-Headless"], cwd=ROOT,
                            capture_output=True, text=True, timeout=30,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr + result.stdout
    model = json.loads(result.stdout)
    assert model["report_valid"] and model["phase"] == "dependencies"
    assert model["protection_status"] == "unknown"


@pytest.mark.skipif(os.name != "nt", reason="Independent Windows PowerShell recovery")
def test_windows_powershell_fallback_preserves_literal_message_when_report_missing(tmp_path):
    shell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    script = ROOT / "tools/Show-AngeronaStartupRecovery.ps1"
    result = subprocess.run([str(shell), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script),
                             "-StatusFile", str(tmp_path / "missing.json"), "-Message",
                             "A source syntax error prevented normal startup", "-Headless"],
                            cwd=ROOT, capture_output=True, text=True, timeout=30,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 11
    model = json.loads(result.stdout)
    assert not model["report_valid"] and "source syntax error" in model["message"]


@pytest.mark.skipif(os.name != "nt", reason="Independent Windows PowerShell recovery")
def test_windows_powershell_fallback_rejects_hardlinked_status(windows_report):
    path, _, _ = windows_report
    os.link(path, path.with_name("another.json"))
    shell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([str(shell), "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                             str(ROOT / "tools/Show-AngeronaStartupRecovery.ps1"), "-StatusFile", str(path), "-Headless"],
                            cwd=ROOT, capture_output=True, text=True, timeout=30,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 11
    assert not json.loads(result.stdout)["report_valid"]


def _native_recovery_functions():
    """Load declarations only; never execute the launcher's script entry point."""
    script = str(ROOT / "tools/Show-AngeronaStartupRecovery.ps1").replace("'", "''")
    return f"""
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile('{script}', [ref]$tokens, [ref]$errors)
if ($errors.Count) {{ throw ($errors | Out-String) }}
foreach ($definition in $ast.FindAll({{ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst]
}}, $false)) {{ . ([scriptblock]::Create($definition.Extent.Text)) }}
$fixedRoot = '{str(ROOT).replace(chr(39), chr(39) * 2)}'
$localRuntime = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Angerona'
$ownedScratch = Join-Path $fixedRoot '.tmp'
$statusLimit = 64KB; $logLimit = 128KB
$Message = ''; $LogRoot = ''
"""


def _run_native_harness(body, *, timeout=40):
    shell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    encoded = base64.b64encode((_native_recovery_functions() + body).encode("utf-16-le")).decode("ascii")
    return subprocess.run([str(shell), "-NoLogo", "-NoProfile", "-NonInteractive", "-STA",
                           "-EncodedCommand", encoded], cwd=ROOT, capture_output=True,
                          text=True, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows startup dashboard state")
def test_native_startup_dashboard_requires_current_run_and_real_dashboard(windows_report):
    path, _, document = windows_report
    document.update(run_id="a" * 32, supervisor_pid=123,
                    supervisor_creation_filetime="134377029371751523")
    path.write_text(json.dumps(document), encoding="utf-8")
    literal = str(path).replace("'", "''")
    result = _run_native_harness(f"""
$StatusFile = '{literal}'
$StartupRunId = '{'a' * 32}'; $SupervisorPid = 123
$SupervisorCreationFileTime = 134377029371751523L
$model = Get-RecoveryModel
$states = @()
foreach ($case in @(
    @('startup', 'checking', '{'a' * 32}', 123),
    @('recovery', 'needs-attention', '{'a' * 32}', 123),
    @('dashboard', 'verified', '{'a' * 32}', 123),
    @('preflight', 'verified', '{'a' * 32}', 123),
    @('dashboard', 'verified', '{'b' * 32}', 123),
    @('dashboard', 'verified', '{'a' * 32}', 124),
    @('startup', 'operator-stopped', '{'a' * 32}', 123),
    @('unexpected', 'unrecognized', '{'a' * 32}', 123),
    @('recovery', 'custody-held', '{'a' * 32}', 123)
)) {{
    $model.phase = $case[0]; $model.outcome = $case[1]
    $model.run_id = $case[2]; $model.supervisor_pid = $case[3]
    $states += Get-StartupDashboardState $model
}}
$states | ConvertTo-Json -Depth 5 -Compress
""")
    assert result.returncode == 0, result.stderr + result.stdout
    states = json.loads(result.stdout)
    assert [state["state"] for state in states] == [
        "checking", "held", "ready", "held", "waiting", "waiting", "stopped", "waiting", "held"]
    assert states[0]["close_code"] == 1223 and not states[0]["can_retry"]
    assert states[1]["can_retry"] and states[1]["close_code"] == 0
    assert not states[3]["dashboard_ready"]
    assert not states[6]["can_retry"]
    assert not states[-1]["can_retry"] and states[-1]["close_code"] == 0
    assert all(not state["dashboard_ready"] for i, state in enumerate(states) if i != 2)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows startup dashboard paint")
def test_native_startup_dashboard_paints_before_status_read_and_closes_on_ready(windows_report):
    path, _, document = windows_report
    receipt = path.with_name("startup-shell-painted.json")
    receipt.write_bytes(b"")
    path.write_text("not JSON; never execute this diagnostic", encoding="utf-8")
    literal = str(path).replace("'", "''")
    receipt_literal = str(receipt).replace("'", "''")
    result = _run_native_harness(f"""
$StatusFile = '{literal}'; $PaintReceiptFile = '{receipt_literal}'
$StartupRunId = '{'c' * 32}'; $SupervisorPid = $PID
$SupervisorCreationFileTime = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc()
$script:ReadsAfterPaint = 0
$originalModelReader = ${{function:Get-RecoveryModel}}
function Get-RecoveryModel {{
    param([string]$RawText, [switch]$FromMemory, [switch]$DeferLogValidation)
    if (!(Test-Path -LiteralPath $PaintReceiptFile) -or
        (Get-Item -LiteralPath $PaintReceiptFile).Length -eq 0) {{ throw 'Report read before paint receipt.' }}
    $script:ReadsAfterPaint++
    & $originalModelReader @PSBoundParameters
}}
Add-Type -AssemblyName System.Windows.Forms
$fixtureTimer = [Windows.Forms.Timer]::new(); $fixtureTimer.Interval = 100
$fixtureTimer.Add_Tick({{
    if (!(Test-Path -LiteralPath $PaintReceiptFile) -or
        (Get-Item -LiteralPath $PaintReceiptFile).Length -eq 0) {{ return }}
    if ($script:ReadsAfterPaint -eq 0) {{ return }}
    $fixtureTimer.Stop()
    $status = @{{schema=1; phase='dashboard'; outcome='verified'; message='Fixture ready receipt only.'
        run_id=$StartupRunId; supervisor_pid=$SupervisorPid
        supervisor_creation_filetime=[string]$SupervisorCreationFileTime; attempts=@()}}
    [IO.File]::WriteAllText($StatusFile, ($status | ConvertTo-Json -Compress))
}})
$fixtureTimer.Start()
$watchdog = [Windows.Forms.Timer]::new(); $watchdog.Interval = 12000
$watchdog.Add_Tick({{ throw 'Native fixture did not reach its terminal state.' }})
$watchdog.Start()
try {{ $code = Show-StartupDashboard }}
finally {{ $fixtureTimer.Stop(); $fixtureTimer.Dispose(); $watchdog.Stop(); $watchdog.Dispose() }}
@{{exit_code=$code; reads_after_paint=$script:ReadsAfterPaint}} | ConvertTo-Json -Compress
""")
    assert result.returncode == 0, result.stderr + result.stdout
    observed = json.loads(result.stdout)
    assert observed["exit_code"] == 0 and observed["reads_after_paint"] >= 2
    painted = json.loads(receipt.read_text(encoding="utf-8-sig"))
    assert painted["schema"] == 1 and painted["run_id"] == "c" * 32
    assert painted["shell_pid"] > 0 and int(painted["shell_creation_filetime"]) > 0
    assert receipt.stat().st_size <= 1024


@pytest.mark.skipif(os.name != "nt", reason="Native Windows startup dashboard controls")
@pytest.mark.parametrize("action,outcome,expected", [
    ("StartupRetry", "needs-recovery", 10),
    ("StartupClose", "needs-recovery", 0),
    ("StartupClose", "checking", 1223),
])
def test_native_startup_dashboard_controls_do_not_launch_code(windows_report, action, outcome, expected):
    path, _, document = windows_report
    receipt = path.with_name("startup-shell-painted.json")
    receipt.write_bytes(b"")
    literal = str(path).replace("'", "''")
    receipt_literal = str(receipt).replace("'", "''")
    sentinel = path.with_name("diagnostic-must-not-run.txt")
    document.update(run_id="d" * 32, outcome=outcome,
                    message=f"[IO.File]::WriteAllText('{sentinel}', 'executed')")
    path.write_text(json.dumps(document), encoding="utf-8")
    result = _run_native_harness(f"""
$StatusFile = '{literal}'; $PaintReceiptFile = '{receipt_literal}'
$StartupRunId = '{'d' * 32}'; $SupervisorPid = $PID
$SupervisorCreationFileTime = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc()
$document = ConvertFrom-Json ([IO.File]::ReadAllText($StatusFile))
$document | Add-Member supervisor_pid $SupervisorPid
$document | Add-Member supervisor_creation_filetime ([string]$SupervisorCreationFileTime)
[IO.File]::WriteAllText($StatusFile, ($document | ConvertTo-Json -Depth 5 -Compress))
Add-Type -AssemblyName System.Windows.Forms
$fixtureTimer = [Windows.Forms.Timer]::new(); $fixtureTimer.Interval = 100
$fixtureTimer.Add_Tick({{
    foreach ($window in [Windows.Forms.Application]::OpenForms) {{
        if ($window.Name -ne 'AngeronaStartupDashboard' -or
            $window.Tag.State -ne '{'checking' if outcome == 'checking' else 'held'}') {{ continue }}
        $buttons = $window.Controls.Find('{action}', $true)
        if ($buttons.Count -eq 1 -and $buttons[0].Enabled) {{
            $fixtureTimer.Stop(); $buttons[0].PerformClick(); break
        }}
    }}
}})
$fixtureTimer.Start()
try {{ $code = Show-StartupDashboard }}
finally {{ $fixtureTimer.Stop(); $fixtureTimer.Dispose() }}
@{{exit_code=$code}} | ConvertTo-Json -Compress
""")
    assert result.returncode == 0, result.stderr + result.stdout
    assert json.loads(result.stdout)["exit_code"] == expected
    assert not sentinel.exists()


@pytest.mark.skipif(os.name != "nt", reason="Native Windows startup receipt identity")
def test_native_startup_receipt_rejects_aliases_without_overwriting(windows_report):
    path, _, _ = windows_report
    receipt = path.with_name("startup-shell-painted.json")
    receipt.write_text("original fixture", encoding="utf-8")
    os.link(receipt, path.with_name("receipt-alias.json"))
    literal = str(receipt).replace("'", "''")
    result = _run_native_harness(f"""
Initialize-RecoveryReader
$refused = $false
try {{ [AngeronaRecoveryReadV1]::WritePaintReceipt('{literal}', '{{}}', $localRuntime, $ownedScratch) }}
catch {{ $refused = $true }}
@{{refused=$refused}} | ConvertTo-Json -Compress
""")
    assert result.returncode == 0, result.stderr + result.stdout
    assert json.loads(result.stdout)["refused"]
    assert receipt.read_text(encoding="utf-8") == "original fixture"
