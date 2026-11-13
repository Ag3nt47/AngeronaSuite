"""Inert PW04 proofs; never fetch, publish, restore source or execute the batch."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tools import build_startup_recovery_manifest as builder
from tools import publish_github_update as publisher

ROOT = Path(__file__).resolve().parents[1]


def _reviewed_tree(root: Path) -> tuple[bytes, dict[str, str]]:
    for name in (*builder.FILES, builder.VERIFIER):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(("# inert reviewed fixture: " + name + "\n").encode())
    (root / builder.VERIFIER).write_text(
        "# inert verifier scope fixture\n$script:BundleFiles=@(\n" +
        "\n".join("    '" + name + "'" + ("," if index + 1 < len(builder.FILES) else "")
                  for index, name in enumerate(builder.FILES)) + "\n)\n", encoding="ascii")
    (root / "src/angerona/core/startup_recovery.py").write_text(
        "RECOVERY_COHERENCE_FILES = " + repr(builder.FILES) + "\n", encoding="ascii")
    raw, pins = builder.build_manifest(root)
    target = root / builder.MANIFEST
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    (root / builder.BATCH).write_text("\n".join(
        f"\u0024{name}='{pins[key]}'" for name, key in builder.BATCH_PINS.items()) + "\n", encoding="ascii")
    return raw, pins


def test_check_binds_manifest_verifier_and_all_four_literal_batch_pins(tmp_path, capsys):
    _raw, pins = _reviewed_tree(tmp_path)
    before = {tmp_path / name: (tmp_path / name).read_bytes()
              for name in (*builder.FILES, builder.VERIFIER, builder.MANIFEST, builder.BATCH)}
    assert builder.check_recovery_bundle(tmp_path) == pins
    assert builder.main(["--root", str(tmp_path), "--check"]) == 0
    assert json.loads(capsys.readouterr().out) == pins
    assert all(path.read_bytes() == raw for path, raw in before.items())


@pytest.mark.parametrize("name", tuple(builder.BATCH_PINS))
def test_check_refuses_each_stale_launcher_pin_without_rewriting_it(tmp_path, name):
    _raw, pins = _reviewed_tree(tmp_path)
    batch = tmp_path / builder.BATCH
    original = batch.read_text()
    old = pins[builder.BATCH_PINS[name]]
    changed = ("0" if old[0] != "0" else "1") + old[1:]
    batch.write_text(original.replace(old, changed), encoding="ascii")
    before = batch.read_bytes()
    with pytest.raises(ValueError, match="launcher pin " + name):
        builder.check_recovery_bundle(tmp_path)
    assert batch.read_bytes() == before


@pytest.mark.parametrize("assignment", ["\u0024manifestSha='short'", "\u0024ManifestSha='duplicate'",
                                        '\u0024manifestSha="ambiguous"'])
def test_check_refuses_duplicate_case_aliased_or_nonliteral_pin_assignments(tmp_path, assignment):
    _reviewed_tree(tmp_path)
    batch = tmp_path / builder.BATCH
    batch.write_text(batch.read_text() + assignment + "\n", encoding="ascii")
    with pytest.raises(ValueError, match="launcher pin manifestSha"):
        builder.check_recovery_bundle(tmp_path)


@pytest.mark.parametrize("member", [builder.FILES[0], builder.VERIFIER, builder.MANIFEST])
def test_changed_reviewed_member_cannot_pass_offline_gate(tmp_path, member):
    _reviewed_tree(tmp_path)
    with (tmp_path / member).open("ab") as stream:
        stream.write(b"# changed\n")
    reason = "launcher pin verifierSha" if member == builder.VERIFIER else "manifest differs"
    with pytest.raises(ValueError, match=reason):
        builder.check_recovery_bundle(tmp_path)


def test_windows_newlines_and_bom_do_not_make_literal_pins_stale(tmp_path):
    _raw, pins = _reviewed_tree(tmp_path)
    for name in (*builder.FILES, builder.VERIFIER, builder.MANIFEST, builder.BATCH):
        path = tmp_path / name
        path.write_bytes(b"\xef\xbb\xbf" + builder.canonical_text(path.read_bytes()).replace(b"\n", b"\r\n"))
    assert builder.check_recovery_bundle(tmp_path) == pins


def test_publisher_denies_stale_pins_before_any_network_operation(tmp_path, monkeypatch):
    _reviewed_tree(tmp_path)
    monkeypatch.setattr(publisher, "_assert_local_snapshot", lambda *_: None)
    monkeypatch.setattr(publisher, "_assert_origin_configuration", lambda *_: None)
    batch = tmp_path / builder.BATCH
    batch.write_text(batch.read_text() + "\u0024manifestSha='stale'\n", encoding="ascii")
    operations = []
    with pytest.raises(publisher.PublicationError, match="recovery-bundle publication precondition"):
        publisher._guarded_network_operation(tmp_path, "a" * 40, object(), lambda: operations.append("network"))
    assert operations == []


def test_publisher_rechecks_recovery_bytes_after_network_boundary(tmp_path, monkeypatch):
    _reviewed_tree(tmp_path)
    monkeypatch.setattr(publisher, "_assert_local_snapshot", lambda *_: None)
    monkeypatch.setattr(publisher, "_assert_origin_configuration", lambda *_: None)
    operations = []

    def mutate():
        operations.append("inert operation")
        batch = tmp_path / builder.BATCH
        batch.write_text(batch.read_text() + "\u0024verifierBlob='stale'\n", encoding="ascii")

    with pytest.raises(publisher.PublicationError, match="recovery-bundle publication precondition"):
        publisher._guarded_network_operation(tmp_path, "a" * 40, object(), mutate)
    assert operations == ["inert operation"]


def test_ci_runs_offline_recovery_gate_before_public_asset_network_check():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["public-readme"]["steps"]
    checks = [index for index, step in enumerate(steps)
              if step.get("run") == "python tools/build_startup_recovery_manifest.py --check"]
    network = next(index for index, step in enumerate(steps)
                   if step.get("name") == "Verify exact images served from public main")
    assert len(checks) == 1 and checks[0] < network


@pytest.mark.parametrize("fault", ["missing", "extra", "duplicate-assignment", "nonliteral"])
def test_check_refuses_verifier_scope_drift_before_publication(tmp_path, fault):
    _reviewed_tree(tmp_path)
    verifier = tmp_path / builder.VERIFIER
    text = verifier.read_text()
    if fault == "missing":
        text = text.replace("    '" + builder.FILES[0] + "',\n", "")
    elif fault == "extra":
        text = text.replace("\n)\n", "\n    'unreviewed.py'\n)\n")
    elif fault == "duplicate-assignment":
        text += "$script:bundlefiles=@()\n"
    else:
        text = text.replace("    '" + builder.FILES[0] + "',", "    (Get-Content untrusted),")
    verifier.write_text(text)
    with pytest.raises(ValueError, match="verifier scope"):
        builder.check_recovery_bundle(tmp_path)


@pytest.mark.parametrize("fault", ["missing", "extra", "duplicate-assignment", "dynamic"])
def test_check_refuses_application_profile_drift_without_executing_source(tmp_path, fault):
    _reviewed_tree(tmp_path)
    application = tmp_path / "src/angerona/core/startup_recovery.py"
    if fault == "missing":
        text = "RECOVERY_COHERENCE_FILES = " + repr(builder.FILES[1:])
    elif fault == "extra":
        text = "RECOVERY_COHERENCE_FILES = " + repr((*builder.FILES, "unreviewed.py"))
    elif fault == "duplicate-assignment":
        text = application.read_text() + "RECOVERY_COHERENCE_FILES = ()"
    else:
        text = "RECOVERY_COHERENCE_FILES = tuple(open('unreviewed.py'))"
    text += "\nraise RuntimeError('application source must never execute in this check')\n"
    application.write_text(text, encoding="ascii")
    before = application.read_bytes()
    with pytest.raises(ValueError, match="application scope"):
        builder.check_recovery_bundle(tmp_path)
    assert application.read_bytes() == before
