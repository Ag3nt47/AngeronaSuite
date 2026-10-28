"""Pinned recovery-bundle proofs using inert files and an injected blob transport."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bundle_manifest", ROOT / "tools/build_startup_recovery_manifest.py")
assert SPEC and SPEC.loader
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\WindowsPowerShell\v1.0\powershell.exe"


def fixture_root(tmp_path: Path, overrides=None):
    root = tmp_path / "installation"
    for relative in BUILDER.FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((overrides or {}).get(relative, ("# Inert reviewed fixture: " + relative + "\n").encode()))
    (root / BUILDER.VERIFIER).write_bytes((ROOT / BUILDER.VERIFIER).read_bytes())
    raw, pins = BUILDER.build_manifest(root)
    path = root / BUILDER.MANIFEST
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)
    blobs = {BUILDER.git_blob(raw): raw}
    for relative in BUILDER.FILES:
        data = BUILDER.read_plain(root, relative)
        blobs[BUILDER.git_blob(data)] = data
    transport = tmp_path / "blobs.json"
    import base64
    transport.write_text(json.dumps({key: base64.b64encode(value).decode() for key, value in blobs.items()}))
    return root, pins, transport


def test_builder_is_deterministic_and_checkout_newline_independent(tmp_path):
    root, pins, _ = fixture_root(tmp_path)
    expected, _ = BUILDER.build_manifest(root)
    for relative in (*BUILDER.FILES, BUILDER.VERIFIER):
        path = root / relative
        path.write_bytes(b"\xef\xbb\xbf" + BUILDER.canonical_text(path.read_bytes()).replace(b"\n", b"\r\n"))
    actual, actual_pins = BUILDER.build_manifest(root)
    assert actual == expected and actual_pins == pins
    document = json.loads(actual)
    assert [entry["path"] for entry in document["files"]] == list(BUILDER.FILES)
    assert BUILDER.VERIFIER not in BUILDER.FILES and BUILDER.MANIFEST not in BUILDER.FILES
    assert "start-angerona.bat" not in BUILDER.FILES
    assert pins["manifest_blob_sha1"] == hashlib.sha1(b"blob " + str(len(actual)).encode() + b"\0" + actual).hexdigest()


@pytest.mark.parametrize("raw", [b"bad\rtext", b"bad\0text", b"\xff"])
def test_builder_rejects_noncanonical_text(raw):
    with pytest.raises((ValueError, UnicodeError)):
        BUILDER.canonical_text(raw)


def test_builder_refuses_hardlinked_source_and_output(tmp_path):
    root, _, _ = fixture_root(tmp_path)
    original = root / BUILDER.FILES[0]
    os.link(original, tmp_path / "other-link")
    with pytest.raises(ValueError, match="single-link"):
        BUILDER.build_manifest(root)
    original.unlink()
    original.write_text("# replacement\n")
    destination = root / BUILDER.MANIFEST
    os.link(destination, tmp_path / "output-link")
    with pytest.raises(ValueError, match="single-link"):
        BUILDER.main(["--root", str(root)])


LIBRARY = r"""
$ErrorActionPreference='Stop'
$root=$env:BUNDLE_TEST_INSTALL
$pins=Get-Content -LiteralPath $env:BUNDLE_TEST_PINS -Raw|ConvertFrom-Json
. (Join-Path $root 'tools\verify_startup_recovery_bundle.ps1') -Root $root -ManifestSha256 $pins.manifest_sha256 -ManifestBlobSha1 $pins.manifest_blob_sha1
function Get-BundleStateRoot { return (Join-Path $env:BUNDLE_TEST_SCRATCH 'private-state') }
function Get-BundleDataRoot { return (Join-Path $env:BUNDLE_TEST_SCRATCH 'private-source-data') }
function Assert-BundleRoot([string]$Path) { Assert-BundlePlainPath $Path }
function Get-BundleFreeBytes([string]$Path) { return [long]100GB }
$script:fetches=0
$script:transport=Get-Content -LiteralPath $env:BUNDLE_TEST_BLOBS -Raw|ConvertFrom-Json
function Get-BundleBlob([string]$Sha1,[int]$Maximum) {
    $script:fetches++
    $property=$script:transport.PSObject.Properties[$Sha1]
    if(!$property) { throw 'Fixture has no such reviewed blob.' }
    return ,([Convert]::FromBase64String($property.Value))
}
function Invoke-FixtureBundle {
    param([switch]$CheckOnly,[switch]$Offline,[switch]$RunSupervisor,[switch]$SetupOnly,[string]$Verifier=$pins.verifier_sha256)
    return Invoke-StartupRecoveryBundle -Root $root -ManifestSha256 $pins.manifest_sha256 -ManifestBlobSha1 $pins.manifest_blob_sha1 -ExpectedVerifierSha256 $Verifier -CheckOnly:$CheckOnly -Offline:$Offline -RunSupervisor:$RunSupervisor -SetupOnly:$SetupOnly
}
"""


def run_fixture(tmp_path, root, pins, transport, script):
    pinfile = tmp_path / "pins.json"
    pinfile.write_text(json.dumps(pins))
    scriptfile = tmp_path / "bundle-fixture.ps1"
    scriptfile.write_text(LIBRARY + script, encoding="utf-8")
    environment = dict(os.environ, BUNDLE_TEST_INSTALL=str(root), BUNDLE_TEST_PINS=str(pinfile),
                       BUNDLE_TEST_REPOSITORY=str(ROOT), BUNDLE_TEST_SCRATCH=str(tmp_path),
                       BUNDLE_TEST_BLOBS=str(transport), TEMP=str(tmp_path), TMP=str(tmp_path))
    result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(scriptfile)],
                            cwd=ROOT, env=environment, text=True, capture_output=True, timeout=60, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


WINDOWS = pytest.mark.skipif(os.name != "nt", reason="Native Windows recovery file bindings")


@WINDOWS
def test_intact_bundle_works_offline_without_network(tmp_path):
    root, pins, transport = fixture_root(tmp_path)
    path = root / BUILDER.FILES[0]
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    run_fixture(tmp_path, root, pins, transport, r"""
$result=Invoke-FixtureBundle -Offline
if($result.outcome -ne 'verified' -or $script:fetches -ne 0 -or $result.protection_status -ne 'not-attested') { throw 'Offline intact verification failed.' }
""")


@WINDOWS
@pytest.mark.parametrize("missing", [False, True])
def test_changed_or_missing_helper_restores_exact_blob_and_preserves_original(tmp_path, missing):
    root, pins, transport = fixture_root(tmp_path)
    path = root / BUILDER.FILES[0]
    expected = path.read_bytes()
    if missing:
        path.unlink()
    else:
        path.write_bytes(b"# operator edit\r\n")
        path.chmod(0o444)
    userdata = root / "runtime-data/private-key.json"
    userdata.parent.mkdir()
    userdata.write_text("untouched private fixture")
    run_fixture(tmp_path, root, pins, transport, r"""
$result=Invoke-FixtureBundle
if($result.outcome -ne 'repaired' -or $script:fetches -ne 1 -or $result.restored_files.Count -ne 1) { throw 'Exact repair did not finish.' }
""")
    assert path.read_bytes() == expected
    copies = list((tmp_path / "private-state").glob("q-*.bin"))
    assert [item.read_bytes() for item in copies] == ([] if missing else [b"# operator edit\r\n"])
    assert userdata.read_text() == "untouched private fixture"


@WINDOWS
def test_check_only_and_offline_failure_preserve_changed_file(tmp_path):
    root, pins, transport = fixture_root(tmp_path)
    path = root / BUILDER.FILES[0]
    path.write_text("# edited\n")
    run_fixture(tmp_path, root, pins, transport, r"""
$result=Invoke-FixtureBundle -CheckOnly
if($result.outcome -ne 'changed' -or $script:fetches) { throw 'CheckOnly fetched or wrote payload.' }
try { Invoke-FixtureBundle -Offline;throw 'Offline repair unexpectedly succeeded.' } catch {
    if($_.Exception.Message -notlike '*offline repair is held*') { throw }
}
$report=Get-Content -LiteralPath (Join-Path (Get-BundleStateRoot) 'report.json') -Raw|ConvertFrom-Json
if($report.outcome -ne 'held') { throw 'Failure report was not retained.' }
""")
    assert path.read_text() == "# edited\n"


@WINDOWS
@pytest.mark.parametrize("attack", ["traversal", "duplicate", "unknown"])
def test_invalid_pinned_manifest_cannot_expand_operational_scope(tmp_path, attack):
    root, pins, transport = fixture_root(tmp_path)
    manifest_path = root / BUILDER.MANIFEST
    document = json.loads(manifest_path.read_bytes())
    if attack == "traversal":
        document["files"][0]["path"] = "../private.txt"
    elif attack == "duplicate":
        document["files"][1] = document["files"][0]
    else:
        document["files"][0]["authority"] = "unrecognized"
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    manifest_path.write_bytes(raw)
    pins["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    pins["manifest_blob_sha1"] = BUILDER.git_blob(raw)
    run_fixture(tmp_path, root, pins, transport, r"""
try { Invoke-FixtureBundle;throw 'Unsafe manifest accepted.' } catch {
    if($_.Exception.Message -notmatch 'Recovery manifest') { throw }
}
if($script:fetches) { throw 'Unsafe manifest reached transport.' }
""")


@WINDOWS
def test_bad_payload_or_changed_verifier_cannot_mutate_recovery_files(tmp_path):
    root, pins, transport = fixture_root(tmp_path)
    path = root / BUILDER.FILES[0]
    path.write_text("# edited\n")
    run_fixture(tmp_path, root, pins, transport, r"""
try { Invoke-FixtureBundle -Verifier ('0'*64);throw 'Changed verifier accepted.' } catch {
    if($_.Exception.Message -notlike '*Verifier body differs*') { throw }
}
if($script:fetches) { throw 'Untrusted verifier reached transport.' }
function Get-BundleBlob { return ,([Text.Encoding]::UTF8.GetBytes('bad payload')) }
try { Invoke-FixtureBundle;throw 'Bad payload accepted.' } catch {
    if($_.Exception.Message -notlike '*payload bytes did not verify*') { throw }
}
""")
    assert path.read_text() == "# edited\n"
    assert not list((tmp_path / "private-state").glob("q-*.bin"))


@WINDOWS
def test_concurrent_editor_change_after_discovery_is_preserved(tmp_path):
    root, pins, transport = fixture_root(tmp_path)
    path = root / BUILDER.FILES[0]
    path.write_text("# first edit\n")
    run_fixture(tmp_path, root, pins, transport, r"""
function Get-BundleBlob([string]$Sha1,[int]$Maximum) {
    [IO.File]::WriteAllText((Join-Path $root 'Repair-Angerona-Python.ps1'),'# concurrent editor')
    return ,([Convert]::FromBase64String($script:transport.PSObject.Properties[$Sha1].Value))
}
try { Invoke-FixtureBundle;throw 'Editor update overwritten.' } catch {
    if($_.Exception.Message -notlike '*changed after discovery*') { throw }
}
""")
    assert path.read_text() == "# concurrent editor"


@WINDOWS
def test_drive_reserve_blocks_repair_without_fetch_or_eviction(tmp_path):
    root, pins, transport = fixture_root(tmp_path)
    path = root / BUILDER.FILES[0]
    path.write_text("# edited\n")
    run_fixture(tmp_path, root, pins, transport, r"""
function Get-BundleFreeBytes([string]$Path) { return [long]1GB }
try { Invoke-FixtureBundle;throw 'Low-space repair accepted.' } catch {
    if($_.Exception.Message -notlike '*2 GiB reserve*') { throw }
}
if($script:fetches) { throw 'Low-space repair reached transport.' }
""")
    assert path.read_text() == "# edited\n"


@WINDOWS
def test_missing_manifest_is_fetched_only_by_its_exact_independent_blob_pin(tmp_path):
    root, pins, transport = fixture_root(tmp_path)
    manifest_path = root / BUILDER.MANIFEST
    expected = manifest_path.read_bytes()
    manifest_path.unlink()
    run_fixture(tmp_path, root, pins, transport, r"""
$result=Invoke-FixtureBundle
if($result.outcome -ne 'repaired' -or $script:fetches -ne 1 -or $result.restored_files[0] -ne 'assets/startup-recovery-manifest.json') { throw 'Pinned manifest repair failed.' }
""")
    assert manifest_path.read_bytes() == expected


@WINDOWS
def test_full_quarantine_holds_without_deleting_existing_originals(tmp_path):
    root, pins, transport = fixture_root(tmp_path)
    path = root / BUILDER.FILES[0]
    path.write_text("# edited\n")
    run_fixture(tmp_path, root, pins, transport, r"""
$result=Invoke-FixtureBundle -CheckOnly
$state=Get-BundleStateRoot
for($i=0;$i -lt 258;$i++) { [IO.File]::WriteAllBytes((Join-Path $state ('q-'+$i.ToString('x32')+'.json')),([byte[]]@(123,125))) }
try { Invoke-FixtureBundle;throw 'Full quarantine accepted.' } catch {
    if($_.Exception.Message -notlike '*capacity requires review*') { throw }
}
if($script:fetches -or @(Get-ChildItem -LiteralPath $state -Filter 'q-*.json').Count -ne 258) { throw 'Capacity hold fetched or evicted originals.' }
""")
    assert path.read_text() == "# edited\n"


@WINDOWS
def test_operational_hardlink_holds_without_rewriting_alias(tmp_path):
    root, pins, transport = fixture_root(tmp_path)
    path = root / BUILDER.FILES[0]
    alias = tmp_path / "other-owner-file"
    os.link(path, alias)
    before = path.read_bytes()
    run_fixture(tmp_path, root, pins, transport, r"""
try { Invoke-FixtureBundle;throw 'Hardlink accepted.' } catch {
    if($_.Exception.Message -notmatch 'linked|single-link') { throw }
}
if($script:fetches) { throw 'Hardlink reached transport.' }
""")
    assert alias.read_bytes() == before


@WINDOWS
@pytest.mark.parametrize("bad", [False, True])
def test_actual_blob_decoder_verifies_metadata_length_and_git_identity(tmp_path, bad):
    root, pins, transport = fixture_root(tmp_path)
    raw = b"inert blob\n"
    import base64
    response = dict(sha=BUILDER.git_blob(raw), encoding="base64", size=len(raw),
                    content=base64.b64encode(raw if not bad else b"altered blob").decode())
    response_path = tmp_path / "response.json"
    response_path.write_text(json.dumps(response))
    run_fixture(tmp_path, root, pins, transport, r"""
$tokens=$null;$issues=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'tools\verify_startup_recovery_bundle.ps1'),[ref]$tokens,[ref]$issues)
$definition=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-BundleBlob'},$true)
Invoke-Expression $definition.Extent.Text
$script:responseBytes=[IO.File]::ReadAllBytes((Join-Path $env:BUNDLE_TEST_SCRATCH 'response.json'))
function New-BundleBlobRequest([string]$Sha1) {
    $response=[pscustomobject]@{StatusCode=200;ContentLength=$script:responseBytes.Length}
    $response|Add-Member ScriptMethod GetResponseStream { return [IO.MemoryStream]::new($script:responseBytes,$false) }
    $response|Add-Member ScriptMethod Dispose { }
    $request=[pscustomobject]@{response=$response}
    $request|Add-Member ScriptMethod GetResponse { return $this.response }
    return $request
}
$document=[Text.Encoding]::UTF8.GetString($script:responseBytes)|ConvertFrom-Json
try { $actual=Get-BundleBlob $document.sha 100;$accepted=$true } catch {
    if($_.Exception.Message -notlike '*Git blob bytes did not verify*') { throw };$accepted=$false
}
if($accepted -ne (('__BAD__') -eq 'False')) { throw 'Blob decoder accepted bad bytes or rejected valid identity.' }
""".replace("__BAD__", str(bad)))


@WINDOWS
@pytest.mark.parametrize("lock", ["repair", "helper", "core"])
def test_active_mutation_lock_blocks_repairs_before_any_network_or_writes(tmp_path, lock):
    root, pins, transport = fixture_root(tmp_path)
    path = root / BUILDER.FILES[0]
    path.write_text("# edited\n")
    run_fixture(tmp_path, root, pins, transport, r"""
$all=Enter-BundleMutationLocks $root
Close-BundleMutationLocks $all
$lockPaths=@((Join-Path $root '.tmp\repair-wheels\startup-repair.lock'),
    (Join-Path (Get-BundleDataRoot) 'startup-helper.lock'),(Join-Path (Get-BundleDataRoot) 'angerona.instance.lock'))
$index=@{repair=0;helper=1;core=2}['__LOCK__']
$busy=Open-BundleMutationLock $lockPaths[$index] -PermitReadOnlyPrincipals:($index -eq 0)
try {
    try { Invoke-FixtureBundle;throw 'Live mutation lock ignored.' } catch {
        if($_.Exception.Message -notlike '*Recovery mutation is held*') { throw }
    }
    if($script:fetches) { throw 'Contended mutation reached transport.' }
} finally { Close-BundleMutationLocks @($busy) }
$all=Enter-BundleMutationLocks $root
Close-BundleMutationLocks $all
""".replace("__LOCK__", lock))
    assert path.read_text() == "# edited\n"


@WINDOWS
def test_supervisor_runs_only_under_retained_verified_reads_after_mutation_locks_release(tmp_path):
    root, pins, transport = fixture_root(tmp_path)
    run_fixture(tmp_path, root, pins, transport, r"""
function Invoke-BundleVerifiedSupervisor([string]$Root,[switch]$SetupOnly) {
    if(!$SetupOnly) { throw 'SetupOnly argument was lost.' }
    $mutations=Enter-BundleMutationLocks $Root
    Close-BundleMutationLocks $mutations
    foreach($relative in @('tools\Invoke-AngeronaSourceStartup.ps1','src\angerona\startup.py','assets\startup-recovery-manifest.json','tools\verify_startup_recovery_bundle.ps1')) {
        $blocked=$false
        try { $write=[IO.File]::Open((Join-Path $Root $relative),'Open','Write','ReadWrite');$write.Dispose() } catch { $blocked=$true }
        if(!$blocked) { throw 'Verified file was writable during supervisor execution.' }
    }
    return 7
}
$result=Invoke-FixtureBundle -RunSupervisor -SetupOnly
if($result.supervisor_exit_code -ne 7) { throw 'Supervisor exit code was lost.' }
$write=[IO.File]::Open((Join-Path $root 'src\angerona\startup.py'),'Open','Write','ReadWrite');$write.Dispose()
""")


@WINDOWS
def test_same_size_python_restore_avoids_failed_timestamp_bytecode(tmp_path):
    import py_compile
    import time
    relative = "src/angerona/startup.py"
    root, pins, transport = fixture_root(tmp_path, {relative: b"VALUE = 'good'\n"})
    path = root / relative
    path.write_bytes(b"VALUE = 'evil'\n")
    old_second = int(time.time())
    os.utime(path, (old_second, old_second))
    py_compile.compile(str(path), doraise=True)
    run_fixture(tmp_path, root, pins, transport, r"""
$result=Invoke-FixtureBundle
if($result.outcome -ne 'repaired') { throw 'Python source restore did not finish.' }
""")
    assert int(path.stat().st_mtime) != old_second
    spec = importlib.util.spec_from_file_location("bundle_cache_fixture", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.VALUE == "good"


@WINDOWS
@pytest.mark.parametrize("changed", [False, True])
def test_check_only_supervisor_preserves_disabled_recovery_and_holds_if_changed(tmp_path, changed):
    root, pins, transport = fixture_root(tmp_path)
    if changed:
        (root / BUILDER.FILES[0]).write_text("# edited\n")
    run_fixture(tmp_path, root, pins, transport, r"""
$script:launched=$false
function Invoke-BundleVerifiedSupervisor([string]$Root,[switch]$SetupOnly) {
    $script:launched=$true
    $blocked=$false
    try { $write=[IO.File]::Open((Join-Path $Root 'src\angerona\startup.py'),'Open','Write','ReadWrite');$write.Dispose() } catch { $blocked=$true }
    if(!$blocked) { throw 'CheckOnly supervisor lost retained read authority.' }
    return 0
}
$result=Invoke-FixtureBundle -CheckOnly -Offline -RunSupervisor
if($script:fetches -or $script:launched -eq (('__CHANGED__') -eq 'True')) { throw 'Disabled recovery fetched or executed changed files.' }
if(Test-Path -LiteralPath (Join-Path $root '.tmp\repair-wheels\startup-repair.lock')) { throw 'CheckOnly acquired mutation locks.' }
""".replace("__CHANGED__", str(changed)))


@WINDOWS
def test_check_only_never_fetches_an_untrusted_manifest(tmp_path):
    root, pins, transport = fixture_root(tmp_path)
    (root / BUILDER.MANIFEST).write_text("{}")
    run_fixture(tmp_path, root, pins, transport, r"""
try { Invoke-FixtureBundle -CheckOnly -RunSupervisor;throw 'Unknown manifest executed.' } catch {
    if($_.Exception.Message -notlike '*CheckOnly cannot fetch*') { throw }
}
if($script:fetches) { throw 'CheckOnly fetched a manifest.' }
""")
