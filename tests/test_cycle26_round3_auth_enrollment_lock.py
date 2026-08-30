from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading

import pytest

import angerona.core.windows_auth_extensions as auth_extensions
from angerona.core.privilege import sanitized_child_environment
from angerona.core.windows_auth_extensions import (
    AuthExtensionBaselineStore,
    BaselineEnrollmentError,
    BaselineIntegrityError,
)
from angerona.modules.authentication_extension_guard import (
    AuthenticationExtensionIntegrityGuardModule,
)


MASTER_KEY = b"A" * 32
REVIEW_REASON = "Reviewed every fixed authentication extension surface"
TRUSTED_SLOT_NAME = ".angerona-windows-auth-extensions.trusted-slot.json"


def _snapshot(marker: str = "a"):
    return AuthenticationExtensionIntegrityGuardModule._selftest_snapshot(marker * 64)


def _baseline_path(data_root: Path) -> Path:
    return data_root / "baselines" / "windows_auth_extensions.json"


def _store(data_root: Path) -> AuthExtensionBaselineStore:
    return AuthExtensionBaselineStore(
        _baseline_path(data_root),
        data_root=data_root,
        master_key=MASTER_KEY,
        clock=lambda: 1000.0,
        freshness_cap_seconds=900,
    )


def _enroll(store: AuthExtensionBaselineStore, *, marker: str = "a") -> None:
    store.establish_trusted(
        _snapshot(marker),
        operator="local-reviewer",
        reason=REVIEW_REASON,
        approved=True,
    )


def _provisional(data_root: Path) -> AuthExtensionBaselineStore:
    store = _store(data_root)
    assert store.observe(_snapshot()).status == "provisional"
    return store


def _lock_path(data_root: Path) -> Path:
    return data_root / ".angerona-windows-auth-extensions.enrollment.lock"


def test_legacy_stale_pid_and_malformed_metadata_do_not_claim_authority(
    tmp_path: Path,
) -> None:
    store = _provisional(tmp_path)
    lock_path = _lock_path(tmp_path)
    lock_path.write_bytes(b"999999\nmalformed-owner-metadata")

    _enroll(store)

    assert store.observe(_snapshot()).status == "stable"
    assert lock_path.read_bytes() == b"\x00"


def test_crashed_owner_releases_kernel_lock_and_later_enrollment_succeeds(
    tmp_path: Path,
) -> None:
    store = _provisional(tmp_path)
    source_root = Path(__file__).resolve().parents[1] / "src"
    child = (
        "import os,sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "from pathlib import Path;"
        "from angerona.core.windows_auth_extensions import AuthExtensionBaselineStore;"
        "r=Path(sys.argv[2]);p=r/'baselines'/'windows_auth_extensions.json';"
        "s=AuthExtensionBaselineStore(p,data_root=r,master_key=b'A'*32,"
        "clock=lambda:1000.0,freshness_cap_seconds=900);"
        "c=s._exclusive_transition();c.__enter__();"
        "print('LOCKED',flush=True);os._exit(23)"
    )
    process = subprocess.run(
        [sys.executable, "-I", "-c", child, str(source_root), str(tmp_path)],
        cwd=source_root,
        env=sanitized_child_environment(source={}),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=15,
        check=False,
    )

    assert process.returncode == 23
    expected_output = b"LOCKED\r\n" if os.name == "nt" else b"LOCKED\n"
    assert process.stdout == expected_output
    assert _lock_path(tmp_path).is_file()
    _enroll(store)
    assert store.observe(_snapshot()).status == "stable"


def test_live_owner_excludes_a_concurrent_enroller_and_releases_cleanly(
    tmp_path: Path,
) -> None:
    first = _provisional(tmp_path)
    second = _store(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    failures: list[BaseException] = []
    original_replace = first._replace_provisional

    def held_replace(body, signature):
        entered.set()
        if not release.wait(10):
            raise TimeoutError("test did not release enrollment owner")
        return original_replace(body, signature)

    first._replace_provisional = held_replace  # type: ignore[method-assign]

    def enroll_first() -> None:
        try:
            _enroll(first)
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    worker = threading.Thread(target=enroll_first, daemon=True)
    worker.start()
    assert entered.wait(10)
    try:
        with pytest.raises(BaselineEnrollmentError, match="another baseline enrollment"):
            _enroll(second)
    finally:
        release.set()
        worker.join(10)

    assert not worker.is_alive()
    assert failures == []
    assert first.observe(_snapshot()).status == "stable"


def test_lock_aliases_and_non_regular_objects_fail_closed(tmp_path: Path) -> None:
    store = _provisional(tmp_path)
    lock_path = _lock_path(tmp_path)
    target = tmp_path / "unrelated.lock"
    target.write_bytes(b"not-authority")

    try:
        os.link(target, lock_path)
    except OSError as exc:
        pytest.skip(f"hard-link fixture unavailable: {exc}")
    with pytest.raises(BaselineEnrollmentError, match="unique regular file"):
        _enroll(store)
    assert store.observe(_snapshot()).status == "provisional"

    lock_path.unlink()
    lock_path.mkdir()
    with pytest.raises(BaselineEnrollmentError, match="lock"):
        _enroll(store)
    assert store.observe(_snapshot()).status == "provisional"


def test_symlink_or_reparse_lock_is_never_followed(tmp_path: Path) -> None:
    store = _provisional(tmp_path)
    lock_path = _lock_path(tmp_path)
    target = tmp_path / "outside.lock"
    target.write_bytes(b"outside")
    try:
        lock_path.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink/reparse fixture unavailable: {exc}")

    with pytest.raises(BaselineEnrollmentError, match="link-backed"):
        _enroll(store)
    assert target.read_bytes() == b"outside"
    assert store.observe(_snapshot()).status == "provisional"


def test_exception_releases_lock_without_deleting_rendezvous(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(RuntimeError, match="inert failure"):
        with store._exclusive_transition():
            raise RuntimeError("inert failure")

    assert _lock_path(tmp_path).read_bytes() == b"\x00"
    with store._exclusive_transition():
        assert _lock_path(tmp_path).is_file()


def test_hard_linked_baseline_aliases_cannot_fork_trusted_enrollment(
    tmp_path: Path,
) -> None:
    path = _provisional(tmp_path).path
    alias = tmp_path / "alias.json"
    try:
        os.link(path, alias)
    except OSError as exc:
        pytest.skip(f"hard-link fixture unavailable: {exc}")

    barrier = threading.Barrier(2)
    successes: list[str] = []
    failures: list[BaseException] = []

    def attempt(label: str) -> None:
        store = _store(tmp_path)
        barrier.wait(10)
        try:
            _enroll(store)
            successes.append(label)
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    workers = [
        threading.Thread(target=attempt, args=(label,), daemon=True)
        for label in ("first", "second")
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(10)

    assert all(not worker.is_alive() for worker in workers)
    assert successes == []
    assert len(failures) == 2
    assert all(isinstance(exc, BaselineEnrollmentError) for exc in failures)
    assert b'"state":"provisional"' in path.read_bytes()
    assert os.path.samefile(path, alias)
    rejected = _store(tmp_path).observe(_snapshot(), initialize_provisional=False)
    assert rejected.status == "tampered"
    assert "unique regular file" in rejected.reason


def test_symlink_or_reparse_baseline_alias_is_rejected_before_enrollment(
    tmp_path: Path,
) -> None:
    target = _provisional(tmp_path / "source-root").path
    target_root = tmp_path / "target-root"
    alias = _baseline_path(target_root)
    alias.parent.mkdir(parents=True)
    try:
        alias.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink/reparse fixture unavailable: {exc}")

    with pytest.raises(BaselineIntegrityError, match="canonical fixed-local"):
        _store(target_root)


@pytest.mark.parametrize(
    "relative_path",
    (
        Path("windows_auth_extensions.json"),
        Path("baselines") / "alternate.json",
        Path("alternate") / "windows_auth_extensions.json",
    ),
)
def test_alternate_relative_slots_are_rejected_at_construction(
    tmp_path: Path, relative_path: Path
) -> None:
    candidate = tmp_path / relative_path

    with pytest.raises(BaselineIntegrityError, match="canonical fixed-local"):
        AuthExtensionBaselineStore(
            candidate,
            data_root=tmp_path,
            master_key=MASTER_KEY,
            freshness_cap_seconds=900,
        )

    assert not candidate.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX rendezvous replacement schedule")
def test_posix_rendezvous_unlink_recreate_cannot_split_root_authority(
    tmp_path: Path,
) -> None:
    first = _store(tmp_path)
    second = _store(tmp_path)
    lock_path = _lock_path(tmp_path)

    with pytest.raises(BaselineEnrollmentError, match="custody changed"):
        with first._exclusive_transition():
            lock_path.unlink()
            lock_path.write_bytes(b"replacement")
            with pytest.raises(BaselineEnrollmentError, match="another baseline enrollment"):
                with second._exclusive_transition():
                    pytest.fail("replacement rendezvous must not convey authority")


def test_root_rename_or_replacement_cannot_survive_enrollment_custody(
    tmp_path: Path,
) -> None:
    root = tmp_path / "protected-root"
    root.mkdir()
    store = _store(root)
    moved = tmp_path / "moved-root"

    if os.name == "nt":
        with store._exclusive_transition():
            with pytest.raises(OSError):
                root.rename(moved)
        assert root.is_dir()
        return

    with pytest.raises(BaselineEnrollmentError, match="custody changed"):
        with store._exclusive_transition():
            root.rename(moved)
            root.mkdir()
    root.rmdir()
    (moved / ".angerona-windows-auth-extensions.enrollment.lock").unlink()
    moved.rename(root)


def test_baseline_parent_rename_or_replacement_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "protected-root"
    parent = root / "baselines"
    parent.mkdir(parents=True)
    store = _store(root)
    moved = root / "moved-baselines"

    if os.name == "nt":
        renamed = False
        try:
            with store._exclusive_transition():
                try:
                    parent.rename(moved)
                except OSError:
                    pass
                else:
                    renamed = True
        except BaselineEnrollmentError as exc:
            assert renamed
            assert "custody" in str(exc)
            moved.rename(parent)
        else:
            assert not renamed
            assert parent.is_dir()
        if moved.exists():
            moved.rename(parent)
        return

    with pytest.raises(BaselineEnrollmentError, match="custody changed"):
        with store._exclusive_transition():
            parent.rename(moved)
            parent.mkdir()
    parent.rmdir()
    moved.rename(parent)


def test_authenticated_bytes_are_not_portable_to_another_logical_slot(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source-root"
    source_store = _provisional(source_root)
    _enroll(source_store)
    copied_root = tmp_path / "copied-root"
    alias = _baseline_path(copied_root)
    alias.parent.mkdir(parents=True)
    alias.write_bytes(source_store.path.read_bytes())

    copied = _store(copied_root)
    comparison = copied.observe(_snapshot(), initialize_provisional=False)

    assert source_store.observe(_snapshot()).status == "stable"
    assert comparison.status == "tampered"
    assert "logical_slot" in comparison.reason or "logical slot" in comparison.reason
    with pytest.raises(BaselineEnrollmentError, match="authenticated for enrollment"):
        _enroll(copied)


def test_hard_link_injected_at_atomic_replace_is_detected_and_not_trusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _baseline_path(tmp_path)
    alias = tmp_path / "late-alias.json"
    store = _provisional(tmp_path)
    original_replace = auth_extensions._replace_baseline_file

    def linked_replace(temporary, destination, *, parent_descriptor):
        os.link(destination, alias)
        return original_replace(
            temporary,
            destination,
            parent_descriptor=parent_descriptor,
        )

    monkeypatch.setattr(auth_extensions, "_replace_baseline_file", linked_replace)
    with pytest.raises(BaselineEnrollmentError, match="aliased or ambiguous"):
        _enroll(store)

    assert not path.exists()
    assert b'"state":"provisional"' in alias.read_bytes()
    with pytest.raises(BaselineIntegrityError, match="canonical fixed-local"):
        AuthExtensionBaselineStore(
            alias,
            data_root=tmp_path,
            master_key=MASTER_KEY,
            freshness_cap_seconds=900,
        )


@pytest.mark.skipif(os.name != "nt", reason="ReplaceFileW reconciliation is Windows-only")
def test_windows_1175_retries_only_after_exact_unchanged_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _provisional(tmp_path)
    original_replace = auth_extensions._replace_baseline_file
    calls = 0

    def fail_once(temporary, destination, *, parent_descriptor):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError(1175, "simulated unable-to-remove-replaced")
        return original_replace(
            temporary,
            destination,
            parent_descriptor=parent_descriptor,
        )

    monkeypatch.setattr(auth_extensions, "_replace_baseline_file", fail_once)
    _enroll(store)

    assert calls == 2
    assert store.observe(_snapshot()).status == "stable"
    assert not tuple(store.path.parent.glob(f".{store.path.name}.tmp-*"))


@pytest.mark.skipif(os.name != "nt", reason="ReplaceFileW reconciliation is Windows-only")
def test_windows_1175_accepts_only_an_exact_already_promoted_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _provisional(tmp_path)
    original_replace = auth_extensions._replace_baseline_file
    calls = 0

    def false_after_promotion(temporary, destination, *, parent_descriptor):
        nonlocal calls
        calls += 1
        original_replace(
            temporary,
            destination,
            parent_descriptor=parent_descriptor,
        )
        raise OSError(1175, "simulated false result after exact promotion")

    monkeypatch.setattr(
        auth_extensions,
        "_replace_baseline_file",
        false_after_promotion,
    )
    _enroll(store)

    assert calls == 1
    assert store.observe(_snapshot()).status == "stable"


@pytest.mark.skipif(os.name != "nt", reason="ReplaceFileW reconciliation is Windows-only")
def test_windows_1175_fails_closed_when_temporary_content_is_ambiguous(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _provisional(tmp_path)
    calls = 0

    def corrupt_then_fail(temporary, destination, *, parent_descriptor):
        nonlocal calls
        del destination, parent_descriptor
        calls += 1
        temporary.write_bytes(temporary.read_bytes() + b"corrupt")
        raise OSError(1175, "simulated ambiguous replacement state")

    monkeypatch.setattr(auth_extensions, "_replace_baseline_file", corrupt_then_fail)
    with pytest.raises(BaselineEnrollmentError, match="ambiguous result"):
        _enroll(store)

    assert calls == 1
    assert store.observe(_snapshot(), initialize_provisional=False).status == "provisional"
    assert not tuple(store.path.parent.glob(f".{store.path.name}.tmp-*"))


@pytest.mark.skipif(os.name != "nt", reason="ReplaceFileW reconciliation is Windows-only")
def test_windows_1175_exact_unchanged_state_has_a_bounded_retry_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _provisional(tmp_path)
    calls = 0

    def always_unavailable(temporary, destination, *, parent_descriptor):
        nonlocal calls
        del temporary, destination, parent_descriptor
        calls += 1
        raise OSError(1175, "simulated persistent unable-to-remove-replaced")

    monkeypatch.setattr(auth_extensions, "_replace_baseline_file", always_unavailable)
    with pytest.raises(BaselineEnrollmentError, match="bounded retries"):
        _enroll(store)

    assert calls == len(auth_extensions._WINDOWS_REPLACE_RETRY_DELAYS) + 1
    assert store.observe(_snapshot(), initialize_provisional=False).status == "provisional"
    assert not tuple(store.path.parent.glob(f".{store.path.name}.tmp-*"))


@pytest.mark.skipif(os.name != "nt", reason="ReplaceFileW reconciliation is Windows-only")
def test_windows_non_1175_replace_error_is_never_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _provisional(tmp_path)
    calls = 0

    def access_denied(temporary, destination, *, parent_descriptor):
        nonlocal calls
        del temporary, destination, parent_descriptor
        calls += 1
        raise OSError(5, "simulated access denial")

    monkeypatch.setattr(auth_extensions, "_replace_baseline_file", access_denied)
    with pytest.raises(OSError) as captured:
        _enroll(store)

    assert captured.value.errno == 5
    assert calls == 1
    assert store.observe(_snapshot(), initialize_provisional=False).status == "provisional"


def test_registry_loss_replay_cannot_reopen_slot_selection(tmp_path: Path) -> None:
    root = tmp_path / "protected-root"
    store = _store(root)
    _enroll(store)
    registry = root / TRUSTED_SLOT_NAME
    saved_authentic_registry = registry.read_bytes()

    registry.unlink()
    assert store.observe(_snapshot(), initialize_provisional=False).status == "tampered"

    alternate = root / "baselines" / "alternate.json"
    with pytest.raises(BaselineIntegrityError, match="canonical fixed-local"):
        AuthExtensionBaselineStore(
            alternate,
            data_root=root,
            master_key=MASTER_KEY,
            freshness_cap_seconds=900,
        )
    assert not alternate.exists()

    with pytest.raises(BaselineEnrollmentError, match="differs from reviewed evidence"):
        _enroll(store, marker="b")
    assert not registry.exists()

    _enroll(store)
    assert store.observe(_snapshot()).status == "stable"

    registry.unlink()
    registry.write_bytes(saved_authentic_registry)
    assert store.observe(_snapshot()).status == "stable"
    assert store.observe(_snapshot("b")).status == "drift"
    assert not alternate.exists()


def test_normalized_same_slot_matches_but_moved_root_does_not(tmp_path: Path) -> None:
    root = tmp_path / "protected-root"
    normalized = AuthExtensionBaselineStore(
        root
        / "baselines"
        / "normalized-away"
        / ".."
        / "windows_auth_extensions.json",
        data_root=root,
        master_key=MASTER_KEY,
        clock=lambda: 1000.0,
        freshness_cap_seconds=900,
    )
    canonical = _store(root)
    assert normalized.path == canonical.path
    assert normalized._logical_slot_token == canonical._logical_slot_token
    _enroll(normalized)

    copied = tmp_path / "copied-root"
    shutil.copytree(root, copied)
    copied_store = _store(copied)
    copied_comparison = copied_store.observe(_snapshot(), initialize_provisional=False)
    assert copied_comparison.status == "tampered"
    assert "logical_slot" in copied_comparison.reason or "logical slot" in copied_comparison.reason

    moved = tmp_path / "moved-root"
    root.rename(moved)
    moved_store = _store(moved)
    comparison = moved_store.observe(_snapshot(), initialize_provisional=False)
    assert comparison.status == "tampered"
    assert "logical_slot" in comparison.reason or "logical slot" in comparison.reason


def test_same_slot_explicit_reenrollment_recovers_interrupted_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _provisional(tmp_path)

    with monkeypatch.context() as patch:
        patch.setattr(
            store,
            "_commit_trusted_slot",
            lambda: (_ for _ in ()).throw(OSError("injected registration interruption")),
        )
        with pytest.raises(OSError, match="injected registration interruption"):
            _enroll(store)

    assert store.observe(_snapshot(), initialize_provisional=False).status == "tampered"
    _enroll(store)
    assert store.observe(_snapshot()).status == "stable"
