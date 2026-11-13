"""PW26 fake enumeration/stat/hash coverage; no host FIM reads or authority loads."""
from __future__ import annotations

import os
import stat
from types import SimpleNamespace

import pytest

from angerona.modules import file_integrity as fim


OLD, NEW = "a" * 64, "b" * 64


def harness(monkeypatch, tmp_path, *, roots=("a-user", "z-protected")):
    names = [os.path.abspath(str(tmp_path / name)) for name in roots]
    files = {root: [] for root in names}
    digests, tokens, sizes = {}, {}, {}
    denied, unsafe, hash_calls, walks, notices = set(), set(), [], [], []
    clock = [100.0]

    class Path:
        def __init__(self, value):
            self.value = os.fspath(value)

        def __str__(self):
            return self.value

        def __fspath__(self):
            return self.value

        def __truediv__(self, name):
            return Path(os.path.join(self.value, name))

        def is_dir(self):
            return self.value in files and self.value not in unsafe

        def is_symlink(self):
            return False

    def walk(root, *, followlinks, onerror):
        root = os.fspath(root)
        assert followlinks is False
        walks.append(root)
        for directory, filenames in files[root]:
            yield directory, [], list(filenames)

    def info(path):
        path = os.fspath(path)
        return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=sizes.get(path, 1),
                               st_file_attributes=0)

    monkeypatch.setattr(fim, "watch_roots", lambda: list(names))
    monkeypatch.setattr(fim, "Path", Path)
    monkeypatch.setattr(fim, "os", SimpleNamespace(
        path=os.path, walk=walk, lstat=info, name=os.name, environ=os.environ))
    monkeypatch.setattr(fim, "time", SimpleNamespace(
        monotonic=lambda: clock[0], monotonic_ns=lambda: int(clock[0] * 1_000_000_000)))
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "_is_reparse_point", lambda _path: False)
    module = fim.FileIntegrityModule()
    monkeypatch.setattr(module, "emit", lambda message, severity, **details:
                        notices.append((message, severity, details)))
    monkeypatch.setattr(module, "background_checkpoint", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(module, "_is_high_value", lambda _path: False)
    monkeypatch.setattr(module, "_baseline_key", lambda:
                        pytest.fail("baseline authority queried by fake scan"))

    def identity(path):
        if path in denied:
            return None
        return (1, sum(map(ord, path)), sizes.get(path, 1), 123, tokens.get(path, 1))

    def content(path):
        hash_calls.append(path)
        module._report_scan_work(bytes_read=sizes.get(path, 1))
        return digests[path]

    monkeypatch.setattr(module, "_stat", identity)
    monkeypatch.setattr(module, "_hash", content)

    def add(root_index, filename, *, digest=NEW, token=2, size=1):
        root = names[root_index]
        path = os.path.join(root, filename)
        files[root] = [(root, [*([name for _dir, row in files[root] for name in row]), filename])]
        digests[path], tokens[path], sizes[path] = digest, token, size
        return path

    return SimpleNamespace(module=module, roots=names, files=files, add=add, denied=denied,
        unsafe=unsafe, hashes=hash_calls, notices=notices, walks=walks, clock=clock,
        digests=digests, tokens=tokens, sizes=sizes, content=content)


def changes(h):
    return [(message, details.get("path")) for message, _severity, details in h.notices
            if details.get("path")]


def test_error_in_user_root_cannot_suppress_covered_root_changes_or_adoption(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path)
    bad = h.add(0, "denied.bin")
    healthy = h.add(1, "policy.bin")
    absent = os.path.join(h.roots[1], "removed.bin")
    h.denied.add(bad)
    h.module._baseline = {bad: OLD, healthy: OLD, absent: OLD}
    current = h.module._scan()
    assert current._fim_receipt["complete"] is False
    assert current._fim_receipt["covered_roots"] == [h.roots[1]]
    h.module._evaluate_snapshot(current, adopt_covered=True)
    assert h.module._baseline == {bad: OLD, healthy: NEW}
    assert any("modified" in message and path == healthy for message, path in changes(h))
    assert any("deleted" in message and path == absent for message, path in changes(h))
    assert not any(path == bad for _message, path in changes(h))
    h.module._record_scan_outcome()
    h.module._set_coverage_health()
    assert h.module.health <= 35
    coverage = [details for _message, _severity, details in h.notices if details.get("blocked_roots")]
    assert coverage[0]["blocked_roots"][0]["blocking_object"] == bad
    assert coverage[0]["response_authorized"] is False
    with pytest.raises(RuntimeError, match="incomplete"):
        h.module.approve_current_baseline(approved=True)


def test_incomplete_root_never_adopts_successful_prefix_or_infers_deletion(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path)
    prefix = h.add(0, "observed-new.bin")
    denied = h.add(0, "denied.bin")
    old_missing = os.path.join(h.roots[0], "unmeasured-old.bin")
    protected = h.add(1, "protected.bin")
    h.denied.add(denied)
    h.module._baseline = {prefix: OLD, denied: OLD, old_missing: OLD, protected: OLD}
    h.module._evaluate_snapshot(h.module._scan(), adopt_covered=True)
    assert h.module._baseline == {prefix: OLD, denied: OLD, old_missing: OLD, protected: NEW}
    assert not any(path.startswith(h.roots[0]) for _message, path in changes(h))


@pytest.mark.parametrize("budget", ["files", "content"])
def test_root_budget_share_preserves_later_root_opportunity_and_total_caps(monkeypatch, tmp_path, budget):
    h = harness(monkeypatch, tmp_path)
    if budget == "files":
        monkeypatch.setattr(fim, "_MAX_SCAN_FILES", 4)
        for index in range(3):
            h.add(0, f"churn-{index}.bin")
    else:
        monkeypatch.setattr(fim, "_MAX_SCAN_CONTENT_BYTES", 4)
        h.add(0, "large.bin", size=3)
    protected = h.add(1, "policy.bin")
    retained = os.path.join(h.roots[0], "prior-policy.bin")
    h.module._baseline = {retained: OLD, protected: OLD}
    current = h.module._scan()
    assert current._fim_receipt["complete"] is False
    assert current._fim_receipt["covered_roots"] == [h.roots[1]]
    assert current._fim_receipt["files_visited"] <= fim._MAX_SCAN_FILES
    assert current._fim_receipt["content_bytes_hashed"] <= fim._MAX_SCAN_CONTENT_BYTES
    h.module._evaluate_snapshot(current, adopt_covered=True)
    assert h.module._baseline[retained] == OLD and h.module._baseline[protected] == NEW
    assert h.walks == h.roots


def test_global_deadline_marks_later_roots_unmeasured_without_admission(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path)
    slow = h.add(0, "slow.bin")
    later = h.add(1, "later.bin")
    h.module._baseline = {slow: OLD, later: OLD}

    def late_hash(path):
        digest = h.content(path)
        h.clock[0] += fim._MAX_SCAN_SECONDS + 1
        return digest

    monkeypatch.setattr(h.module, "_hash", late_hash)
    current = h.module._scan()
    assert current._fim_receipt["complete"] is False
    assert current._fim_receipt["covered_roots"] == []
    assert h.walks == [h.roots[0]] and h.hashes == [slow]
    assert "not measured" in current._fim_receipt["root_coverage"][1]["reason"]
    h.module._evaluate_snapshot(current, adopt_covered=True)
    assert h.module._baseline == {slow: OLD, later: OLD} and not changes(h)


def test_unadopted_stat_cache_cannot_borrow_old_baseline_digest(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path)
    denied = h.add(0, "denied.bin")
    changed = h.add(1, "changed.bin", token=2)
    h.denied.add(denied)
    h.module._baseline = {changed: OLD}
    first = h.module._scan()
    assert first[changed] == NEW
    assert h.module._baseline[changed] == OLD  # No evaluation/adoption yet.
    second = h.module._scan()
    assert second[changed] == NEW and h.hashes == [changed, changed]
    assert second._fim_receipt["hashes_reused"] == 0
    h.module._evaluate_snapshot(second, adopt_covered=True)
    assert h.module._baseline[changed] == NEW
    third = h.module._scan()
    assert third[changed] == NEW and h.hashes == [changed, changed]
    assert third._fim_receipt["hashes_reused"] == 1


def test_most_specific_incomplete_root_preserves_nested_baseline(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path, roots=("watched", "watched/nested"))
    parent = h.add(0, "parent.bin")
    nested = h.add(1, "nested.bin")
    h.files[h.roots[0]].append((h.roots[1], ["nested.bin"]))
    h.unsafe.add(h.roots[1])
    h.module._baseline = {parent: OLD, nested: OLD}
    current = h.module._scan()
    assert nested in current and current._fim_receipt["covered_roots"] == [h.roots[0]]
    h.module._evaluate_snapshot(current, adopt_covered=True)
    assert h.module._baseline == {parent: NEW, nested: OLD}
    assert changes(h) == [("Watched file modified: " + parent, parent)]


def test_mutable_coverage_flags_cannot_admit_an_incomplete_root(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path)
    prefix = h.add(0, "prefix.bin")
    denied = h.add(0, "denied.bin")
    healthy = h.add(1, "healthy.bin")
    h.denied.add(denied)
    h.module._baseline = {prefix: OLD, denied: OLD, healthy: OLD}
    current = h.module._scan()
    current._fim_receipt["covered_roots"][:] = h.roots
    current._fim_receipt["complete"] = True
    h.module._last_scan_receipt["covered_roots"][:] = h.roots
    h.module._last_scan_receipt["complete"] = True
    h.module._evaluate_snapshot(current, adopt_covered=True)
    assert h.module._baseline == {prefix: OLD, denied: OLD, healthy: NEW}
    assert all(path == healthy for _message, path in changes(h))


def test_legacy_mapping_and_retained_flags_cannot_grant_partial_adoption(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path)
    target = h.add(1, "policy.bin")
    h.module._baseline = {target: OLD}
    h.module._last_scan_receipt = {"complete": False, "covered_roots": [h.roots[1]]}
    h.module._evaluate_snapshot({target: NEW}, adopt_covered=True)
    assert h.module._baseline == {target: OLD} and not changes(h)


def test_run_invalidates_both_prior_generation_caches(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path, roots=("watched",))
    target = h.add(0, "policy.bin", token=1)
    h.module._stat_cache[target] = h.module._stat(target)
    h.module._stat_cache_digests[target] = OLD
    monkeypatch.setattr(h.module, "_load_approved_baseline", lambda: ({target: OLD}, set()))
    monkeypatch.setattr(h.module, "_publish_assurance_receipts", lambda: None)
    monkeypatch.setattr(h.module, "_list_driver_names", lambda: set())
    monkeypatch.setattr(h.module, "sleep", lambda _seconds: h.module.stop())
    h.module.run()
    assert h.hashes == [target] and h.module._baseline[target] == NEW
    assert any("modified" in message and path == target for message, path in changes(h))


def test_identical_coverage_notices_are_bounded_and_count_opportunities(monkeypatch, tmp_path):
    h = harness(monkeypatch, tmp_path)
    denied = h.add(0, "denied.bin")
    h.denied.add(denied)
    h.module._scan()
    for _index in range(100):
        h.module._record_scan_outcome()
    coverage = [details for _message, _severity, details in h.notices if details.get("blocked_roots")]
    assert len(coverage) == 1
    h.clock[0] += 901
    h.module._record_scan_outcome()
    coverage = [details for _message, _severity, details in h.notices if details.get("blocked_roots")]
    assert len(coverage) == 2 and coverage[-1]["suppressed_observations"] == 99
    assert coverage[-1]["response_authorized"] is False
    assert "opportunities" in coverage[-1]["count_unit"]


@pytest.mark.parametrize("size,root_limit,total_limit,complete", [
    (4, 2, 3, False), (4, 100, 3, False), (2, 2, 3, True),
], ids=["root-limit", "global-limit", "exact-complete-size"])
def test_hash_chunk_reads_respect_one_actual_byte_budget(monkeypatch, size, root_limit, total_limit, complete):
    module = fim.FileIntegrityModule()
    reads, closes = [], []
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=size, st_file_attributes=0,
                           st_dev=1, st_ino=2, st_mtime_ns=123)

    class Handle:
        position = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            closes.append(True)

        def fileno(self):
            return 4242

        def read(self, limit):
            reads.append(limit)
            count = min(limit, size - self.position)
            self.position += count
            return b"x" * count

    monkeypatch.setattr(fim, "os", SimpleNamespace(
        lstat=lambda _path: info, fstat=lambda _fd: info, fdopen=lambda *_args: Handle()))
    monkeypatch.setattr(fim, "time", SimpleNamespace(monotonic=lambda: 100.0))
    monkeypatch.setattr(fim, "_open_read_descriptor", lambda _path: 4242)
    monkeypatch.setattr(fim, "_MAX_SCAN_CONTENT_BYTES", total_limit)
    monkeypatch.setattr(module, "_handle_change_token", lambda _fd: 1)
    monkeypatch.setattr(module, "_handle_usn", lambda _fd: None)
    monkeypatch.setattr(module, "background_checkpoint", lambda *_args, **_kwargs: True)
    module._scan_work.stop_event = module.generation_stop_event()
    module._scan_work.progress = {"bytes": 0, "files": 0, "next_report": 101.0}
    module._scan_work.root_byte_limit = root_limit
    module._scan_work.deadline = 400.0
    digest = module._hash_once("inert-private-file")
    assert bool(digest) is complete
    assert reads == [min(65536, root_limit, total_limit)] and closes == [True]
    assert module._scan_work.progress["bytes"] == min(size, root_limit, total_limit)
