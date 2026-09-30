"""A vanished leaf may trigger one bounded retry, never partial scan credit."""
import hashlib
import os
import pytest

from angerona.modules import file_integrity


@pytest.mark.parametrize("vanishes", [True, False])
def test_small_snapshot_retries_only_confirmed_leaf_disappearance(tmp_path, monkeypatch, vanishes):
    leaf = tmp_path / "moving.txt"
    survivor = tmp_path / "survivor.txt"
    leaf.write_bytes(b"inert moving object")
    survivor.write_bytes(b"inert stable object")
    monkeypatch.setattr(file_integrity, "watch_roots", lambda: [str(tmp_path)])
    module = file_integrity.FileIntegrityModule()
    original = module._stat
    failed = False

    def stat_once(path):
        nonlocal failed
        if path == str(leaf) and not failed:
            failed = True
            if vanishes:
                leaf.unlink()
            return None
        return original(path)

    monkeypatch.setattr(module, "_stat", stat_once)
    snapshot = module._scan()
    assert failed
    assert str(survivor) in snapshot
    assert module._scan_generation == (2 if vanishes else 1)
    assert module._last_scan_receipt["complete"] is vanishes
    context = module._claim_scan_evaluation(snapshot)
    assert context is not None
    assert context["receipt"]["complete"] is vanishes


def test_churn_retry_is_single_and_cancelable(tmp_path, monkeypatch):
    monkeypatch.setattr(file_integrity, "watch_roots", lambda: [str(tmp_path)])
    module = file_integrity.FileIntegrityModule()
    snapshots = []

    def incomplete():
        module._scan_work.transient_leaf_disappearances = 1
        module._last_scan_receipt = {
            "error_count": 1,
            "files_visited": 1, "content_bytes_hashed": 10,
            "complete": False,
        }
        snapshots.append({})
        return snapshots[-1]

    monkeypatch.setattr(module, "_scan_snapshot", incomplete)
    assert module._scan() is snapshots[1]
    assert len(snapshots) == 2
    module.generation_stop_event().set()
    snapshots.clear()
    assert module._scan() is snapshots[0]
    assert len(snapshots) == 1


@pytest.mark.skipif(os.name != "nt", reason="Windows delete-capable custody")
def test_fim_reads_stable_marker_while_response_holds_delete_access(tmp_path):
    from angerona.shark.shark_attack import SharkAttackEngine
    marker = tmp_path / "held-marker.txt"
    descriptor = SharkAttackEngine._open_new_artifact(marker)
    body = b"inert marker under exact response custody"
    try:
        os.write(descriptor, body)
        os.fsync(descriptor)
        module = file_integrity.FileIntegrityModule()
        assert module._stat(str(marker)) is not None
        assert module._hash(str(marker)) == hashlib.sha256(body).hexdigest()
    finally:
        os.close(descriptor)
