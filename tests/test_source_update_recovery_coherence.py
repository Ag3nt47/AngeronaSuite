"""Real merged source/backup bytes and the original offline recovery verifier.

The activation fixture models only its declared Git/process observations. No
candidate generator or application is executed; CheckOnly uses the existing
verifier fixture and a scheduling-only supervisor callback after retained reads.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import zipfile

import pytest

from test_source_update_activation import (
    activation as activation, composition as composition, context as context,
    inert_child_factory as inert_child_factory, inert_owner as inert_owner,
    _BASE, _FIRST, _SECOND, _approve, _archive, _encoded, _json, _operation,
    _plan, _protected_unchanged, _run, _sha, _stage, _write,
)
from test_startup_recovery_bundle import run_fixture
from angerona.core import source_activation as api
from angerona.core import source_activation_storage as storage
from angerona.core.startup_recovery import (
    RECOVERY_BATCH_PATH, RECOVERY_MANIFEST_PATH, RECOVERY_VERIFIER_PATH,
    derive_recovery_coherent_tree, mask_recovery_batch_pins,
    verify_recovery_coherence,
)
from angerona.updater import source_stage

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native source recovery/activation custody")
CONTROL = "tools/Invoke-AngeronaSourceStartup.ps1"
LOCAL_CONTROL = b"# PRIVATE-FIXTURE local control comment\n"
LOCAL_BATCH = b"rem PRIVATE-FIXTURE local batch comment\r\n"
LOCAL_PROJECT = b'\n[tool.angerona_local_fixture]\nchoice = "keep"\n'


def _tree(sample):
    paths = set(sample.git.inventory())
    applied = api.applied_source_base(sample.root, sample.state)
    if applied is not None:
        paths.update(applied["effective_paths"])
    return source_stage.snapshot_local(sample.root, tuple(sorted(paths)))


def _source_state(sample):
    return {name: (raw, (sample.root / name).stat().st_ino) for name, raw in _tree(sample).items()}


def _files(path):
    return {item.relative_to(path).as_posix(): (item.read_bytes(), item.stat().st_ino)
            for item in path.rglob("*") if item.is_file()}


def _offline_check_only(sample, directory):
    directory.mkdir()
    batch = (sample.root / RECOVERY_BATCH_PATH).read_bytes()
    pins = {}
    for field, size, key in (("manifestSha", 64, "manifest_sha256"),
                             ("manifestBlob", 40, "manifest_blob_sha1"),
                             ("verifierSha", 64, "verifier_sha256"),
                             ("verifierBlob", 40, "verifier_blob_sha1")):
        matches = re.findall(rb"(?m)^\$" + field.encode() + rb"='([0-9a-f]{" + str(size).encode() + rb"})'\r?$", batch)
        assert len(matches) == 1
        pins[key] = matches[0].decode("ascii")
    # No build_manifest call: feed the actual installed four batch pins to the
    # actual verifier. This empty transport must never be consulted.
    transport = directory / "no-blobs.json"
    transport.write_text("{}", encoding="utf-8")
    before = _source_state(sample)
    run_fixture(directory, sample.root, pins, transport, r'''
$script:gateReached=$false
function Invoke-BundleVerifiedSupervisor([string]$Root,[switch]$SetupOnly) {
    # Scheduling seam only; no application is launched by this test. The
    # original verifier must already retain the actual verified source reads.
    $write=$null;$blocked=$false
    try{$write=[IO.File]::Open((Join-Path $Root 'src\angerona\startup.py'),'Open','Write','ReadWrite')}
    catch{$blocked=$true}
    finally{if($write){$write.Dispose()}}
    if(!$blocked){throw 'Later startup gate lost verified retained source reads.'}
    $script:gateReached=$true
    return 0
}
$result=Invoke-FixtureBundle -CheckOnly -Offline -RunSupervisor -SetupOnly
if($result.outcome -cne 'verified' -or !$script:gateReached -or $script:fetches -ne 0 -or
    @($result.changed_files).Count -ne 0 -or @($result.restored_files).Count -ne 0){
    throw 'Merged recovery closure did not pass the later offline CheckOnly gate.'
}
''')
    assert _source_state(sample) == before
    _protected_unchanged(sample)


def _version(raw, value):
    from angerona.core import _source_tomli
    previous = _source_tomli.loads(raw.decode("utf-8-sig"))["project"]["version"]
    old = ('version = "' + previous + '"').encode()
    assert raw.count(old) == 1
    return raw.replace(old, ('version = "' + value + '"').encode(), 1)


def test_local_operational_pyproject_and_nonpin_batch_bytes_survive_two_updates_and_later_startup_gate(
    activation, tmp_path,
):
    sample = activation
    _write(sample.root / CONTROL, LOCAL_CONTROL + sample.base[CONTROL])
    _write(sample.root / "pyproject.toml", sample.base["pyproject.toml"] + LOCAL_PROJECT)
    _write(sample.root / RECOVERY_BATCH_PATH, LOCAL_BATCH + sample.base[RECOVERY_BATCH_PATH])
    # A syntactically valid candidate generator is a tripwire, never a tool to
    # import/execute. The original pure helper must derive the pins itself.
    tripwire = (b"from pathlib import Path\n"
                b"Path(__file__).with_name('candidate-generator-executed').write_text('forbidden')\n"
                b"raise RuntimeError('Candidate generator must never execute')\n")
    first = dict(sample.first)
    first[CONTROL] += b"\n# upstream first control comment\n"
    first["pyproject.toml"] = _version(first["pyproject.toml"], "99.1.0")
    first["tools/build_startup_recovery_manifest.py"] = tripwire
    first, _ = derive_recovery_coherent_tree(first)
    second = dict(first, **{"feature.py": b"value=3\n", "new_upstream.py": b"new=3\n"})
    second[CONTROL] += b"# upstream second control comment\n"
    second["pyproject.toml"] = _version(second["pyproject.toml"], "99.2.0")
    second, _ = derive_recovery_coherent_tree(second)
    sample.archives[_FIRST], sample.archives[_SECOND] = _archive(first, _FIRST), _archive(second, _SECOND)
    for index, target in enumerate((_FIRST, _SECOND), 1):
        plan = _plan(sample, target)
        body = _json(_operation(sample, plan) / "plan.json")
        stage = sample.state / "stages" / body["stage_id"]
        report = source_stage.validate_source_candidate(stage, body["manifest_sha256"])
        assert report["static_checks"] == "passed" and report["activation"] == "held"
        assert report["recovery_coherence"]["state"] == "verified"
        assert report["recovery_coherence"]["candidate_code_executed"] is False
        assert not sample.app._shutdown_requested.is_set()
        request = _approve(sample, plan)
        assert _run(sample, plan, request)["status"] == "committed"
        installed = _tree(sample)
        proof = verify_recovery_coherence(installed)
        assert proof["candidate_code_executed"] is False
        assert installed[CONTROL].startswith(LOCAL_CONTROL)
        assert b"upstream first control comment" in installed[CONTROL]
        if target == _SECOND:
            assert b"upstream second control comment" in installed[CONTROL]
        assert installed["pyproject.toml"].endswith(LOCAL_PROJECT)
        assert mask_recovery_batch_pins(installed[RECOVERY_BATCH_PATH]).startswith(LOCAL_BATCH)
        assert installed["custom.py"] == b"my_local_preference=True\n"
        assert installed["tools/build_startup_recovery_manifest.py"] == tripwire
        assert not (sample.root / "tools/candidate-generator-executed").exists()
        assert not (sample.state / "activation-pending.json").exists()
        _protected_unchanged(sample)
        _offline_check_only(sample, tmp_path / ("later-check-only-" + str(index)))


def _resolved_control_plan(sample):
    original = sample.base[CONTROL]
    base = dict(sample.base)
    base[CONTROL] = b"# control choice = base\n" + original
    base, _ = derive_recovery_coherent_tree(base)
    sample.base = base
    sample.archives[_BASE] = _archive(base, _BASE)
    for name, raw in base.items():
        _write(sample.root / name, raw)
    chosen = b"# control choice = user\n" + original
    _write(sample.root / CONTROL, chosen)
    first = dict(sample.first)
    first[CONTROL] = b"# control choice = upstream\n" + original
    first, _ = derive_recovery_coherent_tree(first)
    second = dict(first, **{"feature.py": b"value=3\n", "new_upstream.py": b"new=3\n"})
    second, _ = derive_recovery_coherent_tree(second)
    sample.archives[_FIRST], sample.archives[_SECOND] = _archive(first, _FIRST), _archive(second, _SECOND)
    staged = _stage(sample)
    assert staged.status == "conflicts" and staged.conflicts == (CONTROL,)
    stage = sample.state / "stages" / staged.stage_id
    manifest_raw = (stage / "manifest.json").read_bytes()
    with pytest.raises(api.SourceActivationError, match="Resolve every source conflict"):
        api.prepare_source_activation(sample.root, sample.state, staged.stage_id, staged.manifest_sha256)
    assert not (sample.state / "activation-request.json").exists()
    assert not sample.app._shutdown_requested.is_set()
    assert (sample.root / CONTROL).read_bytes() == chosen
    source_stage.resolve_source_conflict(stage, staged.manifest_sha256, CONTROL, "user")
    assert (stage / "manifest.json").read_bytes() == manifest_raw
    report = source_stage.validate_source_candidate(stage, staged.manifest_sha256)
    assert report["static_checks"] == "passed" and report["activation"] == "held"
    assert report["recovery_coherence"]["state"] == "verified"
    assert report["recovery_coherence"]["candidate_code_executed"] is False
    plan = api.prepare_source_activation(sample.root, sample.state, staged.stage_id, staged.manifest_sha256)
    body = _json(_operation(sample, plan) / "plan.json")
    assert (stage / "candidate" / CONTROL).read_bytes() == chosen
    assert _sha((stage / "candidate" / RECOVERY_MANIFEST_PATH).read_bytes()) != body["after"][RECOVERY_MANIFEST_PATH]["sha256"]
    return staged, stage, plan, chosen


@pytest.mark.parametrize("tamper", ["raw-candidate", "resolution"])
def test_resolved_raw_stage_and_resolution_are_authenticated_again_before_approval(activation, tamper):
    sample = activation
    _staged, stage, plan, chosen = _resolved_control_plan(sample)
    if tamper == "raw-candidate":
        _write(stage / "candidate" / CONTROL, chosen + b"# unauthorized post-review edit\n")
    else:
        resolution = _json(stage / "resolutions.json")
        row = next(row for row in _json(stage / "manifest.json")["files"] if row["path"] == CONTROL)
        resolution["files"][CONTROL]["choice"] = "upstream"
        resolution["files"][CONTROL]["sha256"] = row["upstream"]
        _write(stage / "resolutions.json", _encoded(resolution))
        _write(stage / "candidate" / CONTROL, source_stage._read_blob(stage, row["upstream"]))
    before = _source_state(sample)
    with pytest.raises((api.SourceActivationError, source_stage.SourceStageError)):
        _approve(sample, plan)
    assert not sample.app._shutdown_requested.is_set()
    assert not (sample.state / "activation-request.json").exists()
    assert not (sample.state / "activation-pending.json").exists()
    assert _source_state(sample) == before
    _protected_unchanged(sample)


@pytest.mark.parametrize("shape", ["manifest-extra", "batch-expression", "verifier-scope"])
def test_unsupported_recovery_profile_holds_staging_before_stop_or_checkout_effect(activation, shape):
    sample = activation
    incoming = dict(sample.first)
    if shape == "manifest-extra":
        value = json.loads(incoming[RECOVERY_MANIFEST_PATH])
        value["unknown-authority"] = True
        incoming[RECOVERY_MANIFEST_PATH] = _encoded(value) + b"\n"
    elif shape == "batch-expression":
        incoming[RECOVERY_BATCH_PATH], count = re.subn(
            rb"(?m)^\$manifestSha='([0-9a-f]{64})'", rb"$manifestSha=('\1')",
            incoming[RECOVERY_BATCH_PATH], count=1)
        assert count == 1
    else:
        incoming[RECOVERY_VERIFIER_PATH] = incoming[RECOVERY_VERIFIER_PATH].replace(
            b"'Repair-Angerona-Python.ps1'", b"'unrecognized-helper.ps1'", 1)
        assert incoming[RECOVERY_VERIFIER_PATH] != sample.first[RECOVERY_VERIFIER_PATH]
    sample.archives[_FIRST] = _archive(incoming, _FIRST)
    before = _source_state(sample)
    if shape == "verifier-scope":
        with pytest.raises(source_stage.SourceStageError):
            _stage(sample)
    else:
        staged = _stage(sample)
        expected = RECOVERY_MANIFEST_PATH if shape == "manifest-extra" else RECOVERY_BATCH_PATH
        assert staged.status == "conflicts" and staged.conflicts == (expected,)
        with pytest.raises(api.SourceActivationError, match="Resolve every source conflict"):
            api.prepare_source_activation(sample.root, sample.state, staged.stage_id, staged.manifest_sha256)
    assert _source_state(sample) == before
    assert not sample.app._shutdown_requested.is_set()
    assert not (sample.state / "activation-request.json").exists()
    assert not (sample.state / "activation-pending.json").exists()
    _protected_unchanged(sample)


def _completed_control_pair(sample):
    _staged, stage, first, chosen = _resolved_control_plan(sample)
    first_operation = _operation(sample, first)
    assert _run(sample, first, _approve(sample, first))["status"] == "committed"
    assert (sample.root / CONTROL).read_bytes() == chosen
    second = _plan(sample, _SECOND)
    assert _run(sample, second, _approve(sample, second))["status"] == "committed"
    assert (sample.root / CONTROL).read_bytes() == chosen
    verify_recovery_coherence(_tree(sample))
    review = storage.review_source_update_storage(sample.root, sample.state)
    rows = {row["activation_id"]: row for row in review["operations"]}
    assert rows[first["activation_id"]]["protected"] is False
    assert rows[first["activation_id"]]["export_allowed"] is True
    assert rows[first["activation_id"]]["delete_requires_confirmation"] is True
    assert rows[second["activation_id"]]["protected"] is True
    _protected_unchanged(sample)
    return first, first_operation, stage, second, chosen


def test_completed_backup_after_resolved_control_conflict_exports_and_deletes_without_touching_current_lineage(
    activation,
):
    sample = activation
    first, operation, stage, second, chosen = _completed_control_pair(sample)
    current = _source_state(sample)
    lineage = (sample.state / "applied-base.json").read_bytes()
    second_before = _files(_operation(sample, second))
    compact_before = {path.name: (path.read_bytes(), path.stat().st_ino)
                      for path in operation.iterdir() if path.is_file()}
    raw_control = (stage / "candidate" / CONTROL).read_bytes()
    raw_manifest = (stage / "candidate" / RECOVERY_MANIFEST_PATH).read_bytes()
    assert raw_control == chosen
    assert raw_manifest != (sample.root / RECOVERY_MANIFEST_PATH).read_bytes()
    review = storage.review_source_update_storage(sample.root, sample.state)
    exported = storage.export_source_update_backup(sample.root, sample.state, first["activation_id"],
                                                  review["review_sha256"], accepted=True)
    assert exported["status"] == "exported"
    archive_path = Path(exported["path"])
    assert hashlib.sha256(archive_path.read_bytes()).hexdigest() == exported["zip_sha256"]
    with zipfile.ZipFile(archive_path) as archive:
        contents = archive.namelist()
        control_member = [name for name in contents if name.endswith("/candidate/" + CONTROL)]
        manifest_member = [name for name in contents if name.endswith("/candidate/" + RECOVERY_MANIFEST_PATH)]
        assert len(control_member) == len(manifest_member) == 1
        assert archive.read(control_member[0]) == raw_control
        assert archive.read(manifest_member[0]) == raw_manifest
        verified = json.loads(archive.read("verified-manifest.json"))
        assert verified["files"][control_member[0]]["sha256"] == _sha(raw_control)
    fresh = storage.review_source_update_storage(sample.root, sample.state)
    result = storage.delete_source_update_backup(sample.root, sample.state, first["activation_id"],
        fresh["review_sha256"], accepted=True, permanent=True)
    assert result["status"] == "deleted"
    assert result["deleted_files"] > 0 and result["deleted_bytes"] > 0
    assert not stage.exists()
    # Payload retirement preserves the original compact audit/lineage records.
    # Requiring the operation directory to vanish would erase those originals.
    assert {path.name for path in operation.iterdir()} == set(compact_before) | {"backup-retired.json"}
    for name, original in compact_before.items():
        path = operation / name
        assert (path.read_bytes(), path.stat().st_ino) == original
    retired = _json(operation / "backup-retired.json")
    assert retired["activation_id"] == first["activation_id"]
    assert retired["compact_metadata_preserved"] is True
    assert retired["consent_receipt"] == result["receipt_id"]
    assert retired["deleted_files"] == result["deleted_files"]
    assert retired["deleted_bytes"] == result["deleted_bytes"]
    after = storage.review_source_update_storage(sample.root, sample.state)
    row = next(item for item in after["operations"] if item["activation_id"] == first["activation_id"])
    assert row["status"] == "retired-payload" and row["export_allowed"] is False
    assert _source_state(sample) == current
    assert (sample.state / "applied-base.json").read_bytes() == lineage
    assert _files(_operation(sample, second)) == second_before
    assert archive_path.is_file() and hashlib.sha256(archive_path.read_bytes()).hexdigest() == exported["zip_sha256"]
    _protected_unchanged(sample)


@pytest.mark.parametrize("tamper", ["raw-candidate", "resolution"])
def test_old_backup_raw_stage_tamper_holds_fresh_review_export_and_delete_without_effect(activation, tamper):
    sample = activation
    first, operation, stage, second, chosen = _completed_control_pair(sample)
    if tamper == "raw-candidate":
        _write(stage / "candidate" / CONTROL, chosen + b"# unauthorized retained-stage edit\n")
    else:
        resolution = _json(stage / "resolutions.json")
        resolution["files"][CONTROL]["sha256"] = "0" * 64
        _write(stage / "resolutions.json", _encoded(resolution))
    current, lineage = _source_state(sample), (sample.state / "applied-base.json").read_bytes()
    retained = (_files(operation), _files(stage), _files(_operation(sample, second)))
    # Re-review AFTER tampering: refusal must not be merely a stale UI hash.
    review = storage.review_source_update_storage(sample.root, sample.state)
    for action in ("export", "delete"):
        with pytest.raises(storage.SourceActivationStorageHeld):
            if action == "export":
                storage.export_source_update_backup(sample.root, sample.state, first["activation_id"],
                    review["review_sha256"], accepted=True)
            else:
                storage.delete_source_update_backup(sample.root, sample.state, first["activation_id"],
                    review["review_sha256"], accepted=True, permanent=True)
    assert (_files(operation), _files(stage), _files(_operation(sample, second))) == retained
    assert _source_state(sample) == current
    assert (sample.state / "applied-base.json").read_bytes() == lineage
    assert not (sample.state / "exports").exists()
    _protected_unchanged(sample)
