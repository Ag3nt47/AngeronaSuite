"""Compile the independent package entry and probe only inert native children."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
WINDOWS = Path(os.environ.get("SystemRoot", r"C:\Windows"))
FRAMEWORK = WINDOWS / "Microsoft.NET/Framework64/v4.0.30319"
CSC = FRAMEWORK / "csc.exe"
POWERSHELL = WINDOWS / "System32/WindowsPowerShell/v1.0/powershell.exe"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="OS .NET Framework native package entry")


def compile_source(source: str, output: Path, *, main=None):
    path = output.with_suffix(".cs")
    path.write_text(source, encoding="utf-8")
    args = [str(CSC), "/nologo", "/noconfig", "/nostdlib+", "/target:exe", "/platform:x64", f"/out:{output}"]
    args += [f"/reference:{FRAMEWORK / name}" for name in (
        "mscorlib.dll", "System.dll", "System.Core.dll", "System.Windows.Forms.dll", "System.Drawing.dll")]
    if main:
        args.append("/main:" + main)
    result = subprocess.run([*args, str(path)], cwd=output.parent, capture_output=True, text=True, timeout=45, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture
def payload(tmp_path):
    root = tmp_path / "installation"
    root.mkdir()
    helper = root / "AngeronaStartup.exe"
    compile_source(r"""
using System;
using System.IO;
using System.Threading;
internal static class FixtureStartup {
    internal static int Main(string[] args) {
        File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"helper-receipt.txt"),args.Length==0?"inert helper":String.Join(" ",args));
        Thread.Sleep(800);return 0;
    }
}
""", helper)
    environment = dict(os.environ, PSModulePath="", TEMP=str(tmp_path), TMP=str(tmp_path))
    result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                             str(ROOT / "tools/build_packaged_safe_start.ps1"), "-PayloadRoot", str(root)],
                            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (root / "AngeronaSafeStart.exe").is_file()
    assert not list(root.glob(".safe-start-build.*"))
    return root


def verify(root):
    return subprocess.run([str(root / "AngeronaSafeStart.exe"), "--verify-bootstrap"], cwd=root,
                          capture_output=True, text=True, timeout=20, check=False)


def test_built_native_entry_verifies_pinned_helper_without_launching_it(payload):
    result = verify(payload)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "no application was launched" in result.stdout
    assert not (payload / "helper-receipt.txt").exists()


@pytest.mark.parametrize("missing", [False, True])
def test_corrupt_or_missing_frozen_helper_is_detected_before_python_or_ui(payload, missing):
    helper = payload / "AngeronaStartup.exe"
    if missing:
        helper.unlink()
    else:
        helper.write_bytes(b"corrupt helper fixture")
    result = verify(payload)
    assert result.returncode == 1
    assert ("windows-error-2" if missing else "helper-digest-mismatch") in result.stderr
    assert not (payload / "helper-receipt.txt").exists()


def test_hardlinked_helper_is_held_without_altering_the_other_name(payload, tmp_path):
    helper = payload / "AngeronaStartup.exe"
    alias = tmp_path / "other-file.exe"
    os.link(helper, alias)
    before = alias.read_bytes()
    result = verify(payload)
    assert result.returncode == 1 and "helper-path-not-plain" in result.stderr
    assert alias.read_bytes() == before


def harness(payload, tmp_path, body):
    source = (ROOT / "tools/packaged_safe_start.cs").read_text(encoding="utf-8")
    pin = hashlib.sha256((payload / "AngeronaStartup.exe").read_bytes()).hexdigest()
    source = source.replace("__STARTUP_SHA256__", pin)
    source += "\nnamespace Angerona.SafeStart { internal static class TestHarness { internal static int Main(string[] args) {\n"
    source += "string root=args[0];\n" + body + "\nreturn 0; } } }\n"
    target = tmp_path / "NativeHarness.exe"
    compile_source(source, target, main="Angerona.SafeStart.TestHarness")
    result = subprocess.run([str(target), str(payload)], cwd=tmp_path, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_verified_helper_bytes_and_ancestry_remain_excluded_until_lease_release(payload, tmp_path):
    harness(payload, tmp_path, r"""
string image=Path.Combine(root,"AngeronaStartup.exe");
using(var bound=new BoundHelper(root,Program.HelperSha256)) {
    bool denied=false;
    try {using(var write=File.Open(image,FileMode.Open,FileAccess.Write,FileShare.ReadWrite)) { }} catch(IOException) {denied=true;}
    if(!denied)throw new Exception("Pinned helper was writable.");
    denied=false;
    try {Directory.Move(root,root+".renamed");}catch(IOException){denied=true;}
    if(!denied)throw new Exception("Pinned helper ancestry could move.");
    bound.AssertBound();
}
using(var write=File.Open(image,FileMode.Open,FileAccess.Write,FileShare.ReadWrite)) { }
Directory.Move(root,root+".renamed");Directory.Move(root+".renamed",root);
""")


def test_timeout_keeps_the_exact_native_child_alive_then_observes_its_exit(payload, tmp_path):
    harness(payload, tmp_path, r"""
using(var bound=new BoundHelper(root,Program.HelperSha256))
using(var child=new OwnedStartup(bound)) {
    if(child.Pid==0 || child.CreationFileTime<=0 || child.StartFailure!=null)throw new Exception("Native child identity unavailable.");
    uint pid=child.Pid;long birth=child.CreationFileTime;
    if(StartupDeadline.Inspect(child,TimeSpan.FromSeconds(180))!=StartupState.TimedOut)throw new Exception("Deadline did not hold readiness.");
    if(child.Exited || child.Pid!=pid || child.CreationFileTime!=birth)throw new Exception("Timeout disturbed the owned child generation.");
    if(!child.WaitExited(10000))throw new Exception("Inert native child did not retire.");
    if(child.ExitCode!=0 || StartupDeadline.Inspect(child,TimeSpan.Zero)!=StartupState.Ready)throw new Exception("Exited helper readiness status was lost.");
    bound.AssertBound();
}
""")
    assert (payload / "helper-receipt.txt").read_text(encoding="utf-8-sig") == "inert helper"


def test_native_automatic_start_forwards_only_the_fixed_inhibition_flag(payload, tmp_path):
    harness(payload, tmp_path, r"""
Program.AutomaticStart=true;
using(var bound=new BoundHelper(root,Program.HelperSha256))
using(var child=new OwnedStartup(bound)) {
    if(!child.WaitExited(10000) || child.ExitCode!=0)throw new Exception("Inert automatic helper did not retire.");
}
""")
    assert (payload / "helper-receipt.txt").read_text(encoding="utf-8-sig") == "--automatic-start"


def test_msix_and_prepared_payload_require_the_independent_entry_before_signing():
    template = (ROOT / "installer/msix/AppxManifest.xml.in").read_text()
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    assert 'Executable="AngeronaSafeStart.exe"' in template
    assert workflow.index("build_packaged_safe_start.ps1") < workflow.index("name: Prepare unsigned payload")
    assert "AngeronaSafeStart.exe\" --verify-bootstrap" in workflow
    assert workflow.index("& $safeStart --verify-bootstrap") < workflow.index("& $makeAppx pack")
    assert "Final MSIX stage helper bytes no longer match the SafeStart pin" in workflow
    assert "finalize-release-authority:" in workflow and "authority is not provisioned" in workflow


@pytest.mark.parametrize("cancel_before_start", [False, True])
def test_close_cancels_unstarted_attempt_but_preserves_committed_native_child(payload, tmp_path, cancel_before_start):
    harness(payload, tmp_path, r"""
using(var bound=new BoundHelper(root,Program.HelperSha256)) {
    var admission=new StartupAdmission();
    bool before=__BEFORE__;
    if(before)admission.Cancel();
    using(var child=admission.TryStart(bound)) {
        if(before){if(child!=null)throw new Exception("Cancelled admission launched a helper.");}
        else {
            admission.Cancel();
            if(child==null || child.Exited)throw new Exception("Close disturbed the already committed child.");
            if(admission.TryStart(bound)!=null)throw new Exception("Close admitted a second engine.");
            if(!child.WaitExited(10000))throw new Exception("Preserved inert helper did not retire.");
        }
    }
}
""".replace("__BEFORE__", str(cancel_before_start).lower()))
    assert (payload / "helper-receipt.txt").exists() is not cancel_before_start
