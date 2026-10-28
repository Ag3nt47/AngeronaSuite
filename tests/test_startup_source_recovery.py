"""Source-only recovery preserves edits and never borrows runtime authority."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import py_compile
from types import SimpleNamespace
import zipfile

import pytest


SPEC = importlib.util.spec_from_file_location("source_recovery_under_test", Path(__file__).resolve().parents[1] / "tools/startup_source_recovery.py")
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)


@pytest.fixture
def store(tmp_path, monkeypatch):
    root = tmp_path / "checkout"
    (root / "src/angerona").mkdir(parents=True)
    (root / "src/srt").mkdir()
    (root / ".git").mkdir()
    (root / ".git/config").write_text('[remote "origin"]\nurl = ' + recovery.CANONICAL + '\n')
    (root / ".git/HEAD").write_text("a" * 40 + "\n")
    (root / "src/angerona/__init__.py").write_bytes(b"# first party\n")
    (root / "src/angerona/app.py").write_bytes(b"VERSION = 'ready'\n")
    (root / "src/angerona/resilience").mkdir()
    (root / recovery.STOP_CONTRACT_SOURCE).write_bytes(b"OPERATOR_STOP_CONTRACT_VERSION = 1\n")
    (root / "src/srt/__init__.py").write_bytes(b"# local compatibility\n")
    (root / "settings.json").write_bytes(b"preserve settings")
    (root / "external_modules").mkdir()
    (root / "external_modules/plugin.py").write_bytes(b"preserve external")
    monkeypatch.setattr(recovery, "SCRIPT_ROOT", root)
    monkeypatch.setattr(recovery.shutil, "disk_usage", lambda _path: SimpleNamespace(free=100 * 1024**3))
    return recovery.RecoveryStore(root, tmp_path / "startup-recovery")


def modify(store, data=b"def broken(\n"):
    (store.root / "src/angerona/app.py").write_bytes(data)


def capture_ready(store):
    expected = recovery.digest(recovery.inventory(store.root))
    return store.snapshot(ready_observed=True, expected_source_digest=expected)


def test_empty_recovery_cache_is_not_source_recovery_input(store):
    assert not (store.root / "shadow_cache").exists()
    result = capture_ready(store)
    assert result["outcome"] == "snapshot-recorded"
    assert not (store.root / "shadow_cache").exists()


def test_snapshot_requires_parent_readiness_and_uses_two_bounded_slots(store):
    with pytest.raises(recovery.Held, match="dashboard-ready"):
        store.snapshot()
    capture_ready(store)
    assert capture_ready(store)["snapshot_reused"]
    modify(store, b"VERSION = 'second-ready'\n")
    capture_ready(store)
    modify(store, b"VERSION = 'third-ready'\n")
    with pytest.raises(recovery.Held, match="Two ready snapshots"):
        capture_ready(store)
    assert len(list(store.state.glob("ready-*.zip"))) == 2


@pytest.mark.parametrize("declaration", [
    b"OPERATOR_STOP_CONTRACT_VERSION = 0\n",
    b"OPERATOR_STOP_CONTRACT_VERSION = True\n",
    b"OPERATOR_STOP_CONTRACT_VERSION = '1'\n",
    b"OPERATOR_STOP_CONTRACT_VERSION = 1 + 0\n",
    b"OPERATOR_STOP_CONTRACT_VERSION = 1\nOPERATOR_STOP_CONTRACT_VERSION = 1\n",
])
def test_legacy_or_ambiguous_stop_contract_cannot_be_labeled_ready(store, declaration):
    (store.root / recovery.STOP_CONTRACT_SOURCE).write_bytes(declaration)
    before = recovery.inventory(store.root)
    with pytest.raises(recovery.Held, match="STOP lifecycle contract"):
        capture_ready(store)
    assert recovery.inventory(store.root) == before
    assert not list(store.state.glob("ready-*.zip"))


@pytest.mark.parametrize("strategy", ["last-ready", "github-head", "github-parent"])
def test_legacy_candidate_cannot_undo_stop_fix_and_failed_edits_stay_preserved(store, monkeypatch, strategy):
    legacy = recovery.inventory(store.root)
    legacy.pop(recovery.STOP_CONTRACT_SOURCE)
    entry = store.archive(legacy, "ready")
    store.write("index.json", dict(schema=1, ready=[entry], failed=None))
    modify(store)
    failed = recovery.inventory(store.root)
    monkeypatch.setattr(recovery, "github_candidate", lambda *_args: (legacy, "b" * 40))
    with pytest.raises(recovery.Held, match="STOP lifecycle contract"):
        store.recover(strategy, exclusive_startup=True)
    assert recovery.inventory(store.root) == failed
    assert store.unarchive(store.load("index.json")["failed"]) == failed
    assert not (store.state / "transaction.pending.json").exists()


def test_deferred_legacy_edits_require_stop_contract_repair_before_publication(store):
    capture_ready(store)
    modify(store)
    (store.root / recovery.STOP_CONTRACT_SOURCE).write_bytes(b"OPERATOR_STOP_CONTRACT_VERSION = 0\n")
    failed = recovery.inventory(store.root)
    report = store.recover("last-ready", exclusive_startup=True)
    working = recovery.inventory(store.root)
    with pytest.raises(recovery.Held, match="STOP lifecycle contract"):
        store.decision("restore-edits", expected_id=report["report_id"])
    assert not (store.state / "edits.pending.json").exists()
    # A deferred request written by an older helper must also be held on upgrade.
    store.write("edits.pending.json", dict(schema=1, report_id=report["report_id"],
                candidate=store.load("index.json")["failed"]["id"], working_digest=report["working_digest"]))
    with pytest.raises(recovery.Held, match="STOP lifecycle contract"):
        store.apply_pending(exclusive_startup=True)
    assert recovery.inventory(store.root) == working
    assert store.unarchive(store.load("index.json")["failed"]) == failed
    assert (store.state / "edits.pending.json").exists()


def test_stop_contract_inspection_never_executes_candidate_python():
    recovery.require_stop_contract({
        recovery.STOP_CONTRACT_SOURCE:
            b"OPERATOR_STOP_CONTRACT_VERSION: int = 1\nraise AssertionError('untrusted source must never execute')\n"
    })


def test_recover_preserves_complete_failed_code_before_restoring_only_source(store):
    ready = recovery.inventory(store.root)
    capture_ready(store)
    modify(store)
    added = store.root / "src/angerona/new_edit.py"
    added.write_bytes(b"personal_edit = 1\n")
    failed = recovery.inventory(store.root)
    with pytest.raises(recovery.Held, match="startup lease"):
        store.recover("last-ready")
    result = store.recover("last-ready", exclusive_startup=True, failure_detail="SyntaxError: bad application code")
    assert result["changed"] and result["pending_decision"]
    assert recovery.inventory(store.root) == ready
    assert store.unarchive(store.load("index.json")["failed"]) == failed
    assert (store.root / "settings.json").read_bytes() == b"preserve settings"
    assert (store.root / "external_modules/plugin.py").read_bytes() == b"preserve external"
    assert (store.root / ".git/HEAD").read_text().strip() == "a" * 40
    assert not (store.state / "transaction.pending.json").exists()


def test_missing_ready_snapshot_preserves_failure_and_allows_bound_next_strategy(store, monkeypatch):
    initial = recovery.inventory(store.root)
    with pytest.raises(recovery.Held, match="No genuinely ready"):
        store.recover("last-ready", exclusive_startup=True)
    report = store.report()
    assert report["report_id"] and not report["changed"]
    target = dict(initial, **{"src/angerona/app.py": b"VERSION = 'canonical'\n"})
    monkeypatch.setattr(recovery, "github_candidate", lambda *_args: (target, "b" * 40))
    with pytest.raises(recovery.Held, match="Another recovery"):
        store.recover("github-head", exclusive_startup=True, expected_id="c" * 32)
    result = store.recover("github-head", exclusive_startup=True, expected_id=report["report_id"])
    assert result["report_id"] == report["report_id"] and result["strategy"] == "github-head"
    assert len(list(store.state.glob("failed-*.zip"))) == 1
    assert store.unarchive(store.load("index.json")["failed"]) == initial


def test_choosing_edits_is_deferred_and_identity_bound(store):
    capture_ready(store)
    modify(store)
    failed = recovery.inventory(store.root)
    report = store.recover("last-ready", exclusive_startup=True)
    working = recovery.inventory(store.root)
    with pytest.raises(recovery.Held, match="displayed report"):
        store.decision("restore-edits", expected_id="f" * 32)
    store.decision("restore-edits", expected_id=report["report_id"])
    assert recovery.inventory(store.root) == working
    with pytest.raises(recovery.Held, match="Exclusive"):
        store.apply_pending()
    result = store.apply_pending(exclusive_startup=True)
    assert result["strategy"] == "restore-edits"
    assert recovery.inventory(store.root) == failed
    assert not (store.state / "edits.pending.json").exists()


def test_keep_working_preserves_original_edits_without_hot_source_writes(store):
    capture_ready(store)
    modify(store)
    report = store.recover("last-ready", exclusive_startup=True)
    working = recovery.inventory(store.root)
    store.decision("keep-working", expected_id=report["report_id"])
    assert recovery.inventory(store.root) == working
    assert store.load("index.json")["failed"]
    assert not store.report()["pending_decision"]


def test_resolved_keep_working_capture_can_rotate_for_the_next_failure(store):
    capture_ready(store)
    modify(store, b"first broken edit\n")
    first = store.recover("last-ready", exclusive_startup=True)
    prior = store.load("index.json")["failed"]
    store.decision("keep-working", expected_id=first["report_id"])
    assert (store.state / prior["file"]).exists()  # Keep originals through the decision.
    modify(store, b"second broken edit\n")
    second = store.recover("last-ready", exclusive_startup=True)
    assert second["report_id"] != first["report_id"]
    assert second["resolved_capture_rotated"] == prior["id"]
    assert len(list(store.state.glob("failed-*.zip"))) == 1
    assert store.unarchive(store.load("index.json")["failed"])["src/angerona/app.py"] == b"second broken edit\n"


def test_unreviewed_failure_is_never_replaced_by_later_edits(store):
    capture_ready(store)
    modify(store, b"first broken edit\n")
    first = store.recover("last-ready", exclusive_startup=True)
    prior = store.load("index.json")["failed"]
    modify(store, b"new unreviewed editor work\n")
    with pytest.raises(recovery.Held, match="editor change"):
        store.recover("last-ready", exclusive_startup=True, expected_id=first["report_id"])
    assert (store.state / prior["file"]).exists()
    assert len(list(store.state.glob("failed-*.zip"))) == 1
    assert (store.root / "src/angerona/app.py").read_bytes() == b"new unreviewed editor work\n"


def test_deferred_restore_refuses_new_editor_changes(store):
    capture_ready(store)
    modify(store)
    report = store.recover("last-ready", exclusive_startup=True)
    store.decision("restore-edits", expected_id=report["report_id"])
    modify(store, b"VERSION = 'new-editor-work'\n")
    with pytest.raises(recovery.Held, match="Working source changed"):
        store.apply_pending(exclusive_startup=True)
    assert (store.root / "src/angerona/app.py").read_bytes() == b"VERSION = 'new-editor-work'\n"


def test_interrupted_publication_preserves_originals_and_blocks_unknown_next_work(store, monkeypatch):
    capture_ready(store)
    modify(store)
    failed = recovery.inventory(store.root)
    original = recovery.FileLease.rename
    def fail_new(held, target):
        if held.path.suffix == ".tmp":
            raise OSError("injected publication failure")
        return original(held, target)
    monkeypatch.setattr(recovery.FileLease, "rename", fail_new)
    with pytest.raises(OSError):
        store.recover("last-ready", exclusive_startup=True)
    assert (store.state / "transaction.pending.json").exists()
    assert store.unarchive(store.load("index.json")["failed"]) == failed
    assert list((store.root / "src/angerona").glob(".angerona-recovery-*.old"))
    with pytest.raises(recovery.Held, match="interrupted"):
        store.recover("last-ready", exclusive_startup=True)


def test_low_space_never_captures_or_changes_source(store, monkeypatch):
    initial = recovery.inventory(store.root)
    monkeypatch.setattr(recovery.shutil, "disk_usage", lambda _path: SimpleNamespace(free=recovery.MIN_FREE))
    with pytest.raises(recovery.Held, match="free-space reserve"):
        capture_ready(store)
    with pytest.raises(recovery.Held, match="free-space reserve"):
        store.recover("last-ready", exclusive_startup=True)
    assert recovery.inventory(store.root) == initial
    assert not list(store.state.glob("*.zip"))


def test_unindexed_preserved_capture_causes_capacity_hold_instead_of_more_data(store):
    source = recovery.inventory(store.root)
    store.archive(source, "failed")
    with pytest.raises(recovery.Held, match="capacity is full"):
        store.recover("last-ready", exclusive_startup=True)
    assert len(list(store.state.glob("failed-*.zip"))) == 1


def test_changed_archive_is_never_restored(store):
    capture_ready(store)
    index = store.load("index.json")
    (store.state / index["ready"][0]["file"]).write_bytes(b"changed")
    modify(store)
    failed = recovery.inventory(store.root)
    with pytest.raises(recovery.Held, match="capture bytes changed"):
        store.recover("last-ready", exclusive_startup=True)
    assert recovery.inventory(store.root) == failed


def test_hardlinked_source_is_refused(store, tmp_path):
    original = store.root / "src/angerona/app.py"
    os.link(original, tmp_path / "outside.py")
    with pytest.raises(recovery.Held, match="single-link"):
        capture_ready(store)


def test_canonical_origin_and_fixed_checkout_are_required(store, monkeypatch):
    (store.root / ".git/config").write_text('[remote "origin"]\nurl=https://example.invalid/repo.git\n')
    with pytest.raises(recovery.Held, match="canonical"):
        recovery.RecoveryStore(store.root, store.state)


def fake_github(files, *, tree_override=None, zip_override=None):
    head, parent, tree = "a" * 40, "b" * 40, "c" * 40
    rows = [dict(path=name, type="blob", mode="100644", size=len(data), sha=recovery.blob_sha(data))
            for name, data in files.items()]
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as target:
        for name, data in files.items():
            target.writestr("AngeronaSuite-" + head + "/" + name, data)
    calls = []
    def transport(url, limit):
        calls.append(url)
        if "/commits/" in url:
            revision = url.rsplit("/", 1)[1]
            return json.dumps(dict(sha=revision, tree=dict(sha=tree), parents=[dict(sha=parent)])).encode()
        if "/trees/" in url:
            value = dict(sha=tree, truncated=False, tree=rows)
            if tree_override:
                value.update(tree_override)
            return json.dumps(value).encode()
        return zip_override if zip_override is not None else archive.getvalue()
    return transport, calls


def test_github_candidate_is_exact_commit_tree_and_blob_checked(store):
    expected = recovery.inventory(store.root)
    transport, calls = fake_github(expected)
    actual, revision = recovery.github_candidate(store.root, "github-head", transport)
    assert actual == expected and revision == "a" * 40
    assert all(url.startswith((recovery.API, recovery.CODELOAD)) for url in calls)


def test_truncated_github_tree_is_never_used(store):
    transport, _ = fake_github(recovery.inventory(store.root), tree_override=dict(truncated=True))
    with pytest.raises(recovery.Held, match="incomplete"):
        recovery.github_candidate(store.root, "github-head", transport)


def test_github_blob_mismatch_is_held_before_any_publication(store):
    expected = recovery.inventory(store.root)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as target:
        for name in expected:
            target.writestr("AngeronaSuite-" + "a" * 40 + "/" + name, b"wrong")
    transport, _ = fake_github(expected, zip_override=archive.getvalue())
    with pytest.raises(recovery.Held, match="changed|verify"):
        recovery.github_candidate(store.root, "github-head", transport)
    assert recovery.inventory(store.root) == expected


def test_no_pending_summary_has_the_complete_parent_contract(store):
    result = store.apply_pending(exclusive_startup=True)
    assert result["outcome"] == "no-pending-edits"
    for name in ("report_id", "changed_files", "changed_file_count", "actions", "action_summary", "pending_decision"):
        assert name in result


def test_held_cli_retains_report_id_for_the_next_bound_strategy(store, capsys):
    result = recovery.main(["--root", str(store.root), "--state-root", str(store.state),
                            "--action", "recover", "--strategy", "last-ready", "--exclusive-startup"])
    assert result == 1
    data = json.loads(capsys.readouterr().out)
    assert recovery._ID.fullmatch(data["report_id"])
    assert data["pending_decision"]


def test_concurrent_source_creation_is_not_overwritten(store, monkeypatch):
    capture_ready(store)
    modify(store)
    original = recovery.FileLease.rename
    def editor_new_file(held, target):
        if held.path.suffix == ".tmp":
            target.write_bytes(b"concurrent editor work\n")
        return original(held, target)
    monkeypatch.setattr(recovery.FileLease, "rename", editor_new_file)
    with pytest.raises(recovery.Held, match="concurrent source"):
        store.recover("last-ready", exclusive_startup=True)
    assert (store.root / "src/angerona/app.py").read_bytes() == b"concurrent editor work\n"
    assert (store.state / "transaction.pending.json").exists()
    assert store.unarchive(store.load("index.json")["failed"])["src/angerona/app.py"] == b"def broken(\n"


@pytest.mark.skipif(os.name != "nt", reason="Windows exact-handle source rename")
def test_readonly_failed_source_is_preserved_and_can_be_replaced(store):
    capture_ready(store)
    modify(store)
    path = store.root / "src/angerona/app.py"
    path.chmod(0o400)
    try:
        result = store.recover("last-ready", exclusive_startup=True)
        assert result["changed"]
        assert path.read_bytes() == b"VERSION = 'ready'\n"
        assert store.unarchive(store.load("index.json")["failed"])["src/angerona/app.py"] == b"def broken(\n"
    finally:
        if path.exists():
            path.chmod(0o600)


def test_unresolved_metadata_publication_blocks_further_growth(store):
    (store.state / (".state-" + "a" * 32 + ".tmp")).write_bytes(b"interrupted metadata")
    with pytest.raises(recovery.Held, match="metadata publication"):
        with store.locked():
            capture_ready(store)
    assert not list(store.state.glob("*.zip"))


def test_file_byte_bound_refuses_capture_before_any_restoration(store, monkeypatch):
    monkeypatch.setattr(recovery, "MAX_FILE", 4)
    with pytest.raises(recovery.Held, match="byte limit"):
        capture_ready(store)
    assert not list(store.state.glob("*.zip"))


def test_packed_head_resolution_is_exact_and_does_not_execute_git(store):
    (store.root / ".git/HEAD").write_text("ref: refs/heads/test\n")
    (store.root / ".git/packed-refs").write_text("# pack-refs\n" + "b" * 40 + " refs/heads/test\n")
    assert recovery.local_head(store.root) == "b" * 40


def test_unrelated_source_tree_data_is_not_recovery_content(store):
    path = store.root / "src/angerona/notes.txt"
    path.write_bytes(b"not application code")
    before = recovery.inventory(store.root)
    assert not any(name.endswith("notes.txt") for name in before)
    capture_ready(store)
    modify(store)
    store.recover("last-ready", exclusive_startup=True)
    assert path.read_bytes() == b"not application code"


def test_same_size_rollback_does_not_reuse_failed_timestamp_bytecode(store):
    path = store.root / "src/angerona/app.py"
    good, bad = b"VALUE = 'good'\n", b"VALUE = 'evil'\n"
    assert len(good) == len(bad)
    path.write_bytes(good)
    capture_ready(store)
    path.write_bytes(bad)
    py_compile.compile(str(path), doraise=True)
    before_second = int(path.stat().st_mtime)
    store.recover("last-ready", exclusive_startup=True)
    assert int(path.stat().st_mtime) != before_second
    spec = importlib.util.spec_from_file_location("recovered_bytecode_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.VALUE == "good"


def test_post_import_editor_change_cannot_become_a_ready_snapshot(store):
    expected = recovery.digest(recovery.inventory(store.root))
    modify(store, b"unexecuted editor code\n")
    with pytest.raises(recovery.Held, match="pre-launch fingerprint"):
        store.snapshot(ready_observed=True, expected_source_digest=expected)
    assert not list(store.state.glob("ready-*.zip"))


def interrupt_before_first_new_source(store, monkeypatch):
    capture_ready(store)
    modify(store)
    original = recovery.FileLease.rename
    def fail_new(held, target):
        if held.path.suffix == ".tmp":
            raise OSError("controlled first-file interruption")
        return original(held, target)
    monkeypatch.setattr(recovery.FileLease, "rename", fail_new)
    with pytest.raises(OSError):
        store.recover("last-ready", exclusive_startup=True)
    monkeypatch.setattr(recovery.FileLease, "rename", original)
    return store.load("transaction.pending.json")


def test_own_interrupted_first_file_can_restore_complete_originals(store, monkeypatch):
    interrupted = interrupt_before_first_new_source(store, monkeypatch)
    result = store.apply_pending(exclusive_startup=True)
    assert result["outcome"] == "own-interruption-reconciled"
    assert not result["launch_held"]
    assert (store.root / "src/angerona/app.py").read_bytes() == b"def broken(\n"
    assert not (store.state / "transaction.pending.json").exists()
    assert store.load("transaction.interrupted.json")["pending"] == interrupted


def test_own_interruption_never_overwrites_new_editor_source(store, monkeypatch):
    interrupt_before_first_new_source(store, monkeypatch)
    modify(store, b"new editor work after interruption\n")
    with pytest.raises(recovery.Held, match="editor changes"):
        store.apply_pending(exclusive_startup=True)
    assert (store.root / "src/angerona/app.py").read_bytes() == b"new editor work after interruption\n"
    assert (store.state / "transaction.pending.json").exists()


def test_own_interruption_refuses_editor_deletion_of_an_unprocessed_changed_file(store, monkeypatch):
    later = store.root / "src/angerona/z_later.py"
    later.write_bytes(b"READY = True\n")
    capture_ready(store)
    modify(store)
    later.write_bytes(b"BROKEN = True\n")
    original = recovery.FileLease.rename
    def fail_first_new(held, target):
        if held.path.suffix == ".tmp":
            raise OSError("first file interrupted before later file processing")
        return original(held, target)
    monkeypatch.setattr(recovery.FileLease, "rename", fail_first_new)
    with pytest.raises(OSError):
        store.recover("last-ready", exclusive_startup=True)
    monkeypatch.setattr(recovery.FileLease, "rename", original)
    later.unlink()  # Independent editor change after the owned interruption.
    with pytest.raises(recovery.Held, match="editor deleted"):
        store.apply_pending(exclusive_startup=True)
    assert not later.exists()
    assert (store.state / "transaction.pending.json").exists()


def test_own_interruption_refuses_editor_deletion_of_a_completed_addition(store, monkeypatch):
    addition = store.root / "src/angerona/a_added.py"
    addition.write_bytes(b"READY_MODULE = True\n")
    capture_ready(store)
    addition.unlink()
    modify(store)
    original = recovery.FileLease.rename
    def fail_later(held, target):
        if held.path.suffix == ".tmp" and target.name == "app.py":
            raise OSError("later publication interrupted")
        return original(held, target)
    monkeypatch.setattr(recovery.FileLease, "rename", fail_later)
    with pytest.raises(OSError):
        store.recover("last-ready", exclusive_startup=True)
    monkeypatch.setattr(recovery.FileLease, "rename", original)
    assert addition.exists()
    addition.unlink()
    with pytest.raises(recovery.Held, match="editor deleted"):
        store.apply_pending(exclusive_startup=True)
    assert not addition.exists()
    assert (store.state / "transaction.pending.json").exists()


def test_reconciliation_never_drops_pending_marker_before_new_journal_is_durable(store, monkeypatch):
    interrupted = interrupt_before_first_new_source(store, monkeypatch)
    original = store.write
    def fail_next_pending(name, value):
        if name == "transaction.pending.json" and value["id"] != interrupted["id"]:
            raise OSError("injected new-journal failure")
        return original(name, value)
    monkeypatch.setattr(store, "write", fail_next_pending)
    with pytest.raises(OSError):
        store.apply_pending(exclusive_startup=True)
    assert store.load("transaction.pending.json")["id"] == interrupted["id"]
    monkeypatch.setattr(store, "write", original)
    assert store.apply_pending(exclusive_startup=True)["outcome"] == "own-interruption-reconciled"


def test_unknown_pending_cli_is_an_explicit_engine_launch_hold(store, capsys):
    store.write("transaction.pending.json", dict(schema=1, unknown=True))
    code = recovery.main(["--root", str(store.root), "--state-root", str(store.state),
                          "--action", "apply-pending", "--exclusive-startup"])
    result = json.loads(capsys.readouterr().out)
    assert code == 1 and result["launch_held"] is True
    assert result["reason_code"] == "source-transaction-unresolved"


def test_canonical_parent_candidate_is_bound_to_exact_local_head(store):
    expected = recovery.inventory(store.root)
    original, calls = fake_github(expected)
    def transport(url, limit):
        if url == recovery.CODELOAD + "b" * 40:
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w") as target:
                for name, data in expected.items():
                    target.writestr("AngeronaSuite-" + "b" * 40 + "/" + name, data)
            return archive.getvalue()
        return original(url, limit)
    actual, revision = recovery.github_candidate(store.root, "github-parent", transport)
    assert actual == expected and revision == "b" * 40
    assert recovery.API + "commits/" + "a" * 40 in calls
    assert recovery.API + "commits/" + "b" * 40 in calls


def test_inspect_missing_state_creates_nothing(store, tmp_path):
    missing = tmp_path / "absent-parent" / "startup-recovery"
    result = recovery.inspect_state(store.root, missing)
    assert result["launch_held"] is False
    assert not missing.exists()


def test_state_namespace_cannot_overwrite_a_key_or_evidence_directory(store, tmp_path):
    selected = tmp_path / "security-state"
    selected.mkdir()
    protected = selected / "index.json"
    protected.write_bytes(b"original protected metadata")
    with pytest.raises(recovery.Held, match="dedicated startup-recovery"):
        recovery.RecoveryStore(store.root, selected)
    assert protected.read_bytes() == b"original protected metadata"


def test_oversized_private_report_cannot_flood_supervisor_output(store, capsys):
    (store.state / "report.json").write_text(json.dumps(dict(message="x" * 100000)))
    code = recovery.main(["--root", str(store.root), "--state-root", str(store.state), "--action", "inspect"])
    output = capsys.readouterr().out
    assert code == 1 and len(output.encode()) < recovery.MAX_REPORT
    assert json.loads(output)["launch_held"] is True


def test_inspect_pending_is_readonly_and_never_reconciles_or_applies_edits(store):
    store.write("transaction.pending.json", dict(schema=1, unknown=True))
    store.write("edits.pending.json", dict(schema=1, user_choice="pending"))
    before = {path.name: path.read_bytes() for path in store.state.iterdir()}
    source = recovery.inventory(store.root)
    result = recovery.inspect_state(store.root, store.state)
    assert result["launch_held"] is True
    assert result["reason_code"] == "source-transaction-unresolved"
    assert {path.name: path.read_bytes() for path in store.state.iterdir()} == before
    assert recovery.inventory(store.root) == source


def test_operational_bootstrap_source_is_never_snapshot_or_rollback_content(store):
    for relative in recovery.OPERATIONAL_SOURCE:
        path = store.root / relative
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(b"preserve operational bundle\n")
    assert all(not recovery.allowed(relative) for relative in recovery.OPERATIONAL_SOURCE)
    capture_ready(store)
    for relative in recovery.OPERATIONAL_SOURCE:
        (store.root / relative).write_bytes(b"new independently verified operational bundle\n")
    modify(store)
    store.recover("last-ready", exclusive_startup=True)
    assert all((store.root / relative).read_bytes() == b"new independently verified operational bundle\n"
               for relative in recovery.OPERATIONAL_SOURCE)
