"""The ordinary-user source domain cannot become installed STOP authority."""
from __future__ import annotations

import dataclasses
import json
import shutil

import pytest

from angerona.resilience import source_stop as stop


@pytest.fixture
def source(tmp_path, monkeypatch):
    storage, root = tmp_path / "SourceData", tmp_path / "source"
    storage.mkdir()
    root.mkdir()
    core = stop._Identity("S-1-5-21-11-22-33-1001", 2, 101, 134000000000000001,
                          str(tmp_path / "python.exe"))
    state = {"identity": core}
    monkeypatch.setattr(stop, "_effective_identity", lambda: state["identity"])
    monkeypatch.setattr(stop, "_source_root", lambda: root)
    return storage, root, core, state


def _context(source):
    context = stop.create_source_session(source[0])
    assert context is not None
    return context


def _directory(source, context):
    return stop._namespace(context._scope()) / context.epoch


def _namespace(source):
    return stop._namespace(stop._scope(source[0], source[2]))


def _peer(source, context):
    storage, _root, core, state = source
    peer = dataclasses.replace(core, pid=202, birth=core.birth + 1)
    state["identity"] = peer
    result = stop.join_source_session(storage, context.epoch, role="peer")
    assert result is not None
    state["identity"] = core
    return peer, result


def test_source_stop_is_immutable_scoped_and_idempotent(source):
    context = _context(source)
    assert len(context.epoch) == 32
    assert not context.is_stop_requested()
    result = context.request_stop("dashboard STOP")
    assert context.is_stop_requested()
    assert result["purpose"] == "stop"
    assert result["issuer"] == stop._identity_record(source[2])
    assert result["owner"] == source[2].owner
    assert result["session"] == source[2].session
    assert result["storage"] == stop._canonical_path(source[0])
    assert result["source"] == stop._canonical_path(source[1])
    assert context.request_stop("second click") == result
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.epoch = "f" * 32


def test_stop_persists_after_issuer_exit_without_pid_lookup(source):
    context = _context(source)
    peer_identity, peer = _peer(source, context)
    context.request_stop()
    # The reader is now the only current identity. No probe of issuer PID 101
    # may be necessary to authenticate its retained intentional-stop command.
    source[3]["identity"] = peer_identity
    assert peer.is_stop_requested()
    joined = stop.join_source_session(source[0], context.epoch, role="peer")
    assert joined is not None and joined.is_stop_requested()


def test_new_explicit_launch_does_not_clear_old_peers_stop(source):
    old = _context(source)
    peer_identity, peer = _peer(source, old)
    old.request_stop()
    new = _context(source)
    assert new.epoch != old.epoch
    assert not new.is_stop_requested()
    assert old.is_stop_requested()
    assert (_directory(source, old) / "stop.json").is_file()
    source[3]["identity"] = peer_identity
    assert peer.is_stop_requested()
    automatic_old = stop.join_source_session(source[0], old.epoch, role="peer")
    assert automatic_old is not None and automatic_old.is_stop_requested()
    automatic_current = stop.join_source_session(source[0], role="peer")
    assert automatic_current is not None and automatic_current.epoch == new.epoch
    assert not automatic_current.is_stop_requested()


def test_automatic_join_never_rotates_or_removes_stop(source):
    context = _context(source)
    context.request_stop()
    pointer = _namespace(source) / "current.json"
    before = pointer.read_bytes()
    joined = stop.join_source_session(source[0])
    assert joined is not None and joined.epoch == context.epoch
    assert joined.is_stop_requested()
    assert pointer.read_bytes() == before


def test_explicit_missing_epoch_never_retargets_current(source):
    context = _context(source)
    unknown = "0" * 32 if context.epoch != "0" * 32 else "1" * 32
    assert stop.join_source_session(source[0], unknown) is None


@pytest.mark.parametrize("epoch", ["", "../current.json", "A" * 32, "0" * 33,
                                  1, True, [], {}])
def test_invalid_explicit_epoch_is_rejected(source, epoch):
    _context(source)
    assert stop.join_source_session(source[0], epoch) is None


def test_missing_join_is_read_only_and_environment_does_not_choose_root(source, monkeypatch):
    monkeypatch.setenv(stop.SOURCE_SESSION_ENV, "a" * 32)
    assert stop.join_source_session(source[0]) is None
    assert list(source[0].iterdir()) == []


def test_only_core_context_can_issue(source):
    context = _context(source)
    peer_identity, peer = _peer(source, context)
    source[3]["identity"] = peer_identity
    with pytest.raises(PermissionError):
        peer.request_stop()
    assert not (_directory(source, context) / "stop.json").exists()


@pytest.mark.parametrize("field,value", [("pid", 102), ("birth", 134000000000000999),
                                        ("owner", "S-1-5-21-11-22-33-1002"),
                                        ("session", 3)])
def test_context_cannot_be_reused_by_another_identity(source, field, value):
    context = _context(source)
    context.request_stop()
    source[3]["identity"] = dataclasses.replace(source[2], **{field: value})
    assert not context.is_stop_requested()
    with pytest.raises(PermissionError):
        context.request_stop()
    if field in {"owner", "session"}:
        assert stop.join_source_session(source[0], context.epoch) is None


def test_consumer_image_is_bound(source):
    context = _context(source)
    context.request_stop()
    source[3]["identity"] = dataclasses.replace(
        source[2], image=str(source[0] / "different-python.exe"))
    assert not context.is_stop_requested()
    with pytest.raises(PermissionError):
        context.request_stop()


def test_loaded_source_root_is_bound(source, tmp_path, monkeypatch):
    context = _context(source)
    context.request_stop()
    other = tmp_path / "other-source"
    other.mkdir()
    monkeypatch.setattr(stop, "_source_root", lambda: other)
    assert not context.is_stop_requested()
    assert stop.join_source_session(source[0], context.epoch) is None


def test_storage_copy_cannot_replay_stop_at_another_root(source, tmp_path):
    context = _context(source)
    context.request_stop()
    destination = tmp_path / "other-storage"
    shutil.copytree(source[0], destination)
    assert stop.join_source_session(destination, context.epoch) is None


@pytest.mark.parametrize("field,value", [("reason", "forged"), ("purpose", "current"),
                                        ("schema", True), ("session", True),
                                        ("epoch", "0" * 32),
                                        ("issuer", {"pid": 1, "birth": 1, "image": "relative"})])
def test_modified_stop_is_rejected_and_preserved(source, field, value):
    context = _context(source)
    command = context.request_stop()
    command[field] = value
    path = _directory(source, context) / "stop.json"
    raw = json.dumps(command).encode()
    path.write_bytes(raw)
    assert not context.is_stop_requested()
    with pytest.raises(ValueError):
        context.request_stop()
    assert path.read_bytes() == raw


def test_same_key_wrong_domain_is_rejected(source):
    context = _context(source)
    command = context.request_stop()
    body = {key: value for key, value in command.items() if key != "sig"}
    wrong = {**body, "purpose": "current"}
    # Even a MAC using the same coordination key is purpose/domain-bound.
    command["sig"] = stop._signed(wrong, context._key)["sig"]
    path = _directory(source, context) / "stop.json"
    path.write_bytes(stop._encode(command))
    assert not context.is_stop_requested()


@pytest.mark.parametrize("raw", [b"", b"{", b"[]", b'{"epoch":"a","epoch":"b"}',
                               b'{"schema":NaN}', b"x" * (stop._MAX_RECORD + 1)])
def test_malformed_command_never_stops_or_gets_overwritten(source, raw):
    context = _context(source)
    path = _directory(source, context) / "stop.json"
    path.write_bytes(raw)
    assert not context.is_stop_requested()
    with pytest.raises((ValueError, UnicodeError)):
        context.request_stop()
    assert path.read_bytes() == raw


@pytest.mark.parametrize("leaf,raw", [("key", b"bad-key"), ("session.json", b"{}")])
def test_corrupt_session_never_rotates_key_or_replaces_original(source, leaf, raw):
    context = _context(source)
    path = _directory(source, context) / leaf
    path.write_bytes(raw)
    assert stop.join_source_session(source[0], context.epoch) is None
    assert stop.create_source_session(source[0]) is None
    assert path.read_bytes() == raw


def test_corrupt_current_pointer_is_preserved_but_exact_old_context_still_works(source):
    context = _context(source)
    pointer = _namespace(source) / "current.json"
    pointer.write_bytes(b"{corrupt original")
    assert stop.join_source_session(source[0]) is None
    assert stop.create_source_session(source[0]) is None
    assert pointer.read_bytes() == b"{corrupt original"
    assert stop.join_source_session(source[0], context.epoch) is not None
    context.request_stop()
    assert context.is_stop_requested()


def test_unadmitted_privileged_or_packaged_context_does_not_read_or_write(source, monkeypatch):
    context = _context(source)
    context.request_stop()
    source[3]["identity"] = None
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Unadmitted consumer touched source authority")
    monkeypatch.setattr(stop, "_read_bytes", forbidden)
    monkeypatch.setattr(stop, "_scope", forbidden)
    assert not stop.source_runtime_admitted()
    assert stop.join_source_session(source[0], context.epoch) is None
    assert stop.create_source_session(source[0]) is None
    assert not context.is_stop_requested()
    with pytest.raises(PermissionError):
        context.request_stop()


def test_ordinary_runtime_classification_does_not_need_session_storage(source, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Runtime classification touched authority files")
    monkeypatch.setattr(stop, "_read_bytes", forbidden)
    monkeypatch.setattr(stop, "_scope", forbidden)
    assert stop.source_runtime_admitted()


def test_actual_frozen_admission_refuses_before_native_imports(monkeypatch):
    monkeypatch.setattr(stop.sys, "frozen", True, raising=False)
    assert stop._effective_identity() is None


def test_bounded_session_budget_preserves_old_stop_and_does_not_cleanup(source, monkeypatch):
    monkeypatch.setattr(stop, "_MAX_SESSIONS", 2)
    first = _context(source)
    first.request_stop()
    second = _context(source)
    namespace = _namespace(source)
    before = {path.relative_to(namespace): path.read_bytes()
              for path in namespace.rglob("*") if path.is_file()}
    assert stop.create_source_session(source[0]) is None
    after = {path.relative_to(namespace): path.read_bytes()
             for path in namespace.rglob("*") if path.is_file()}
    assert before == after
    assert first.is_stop_requested()
    assert not second.is_stop_requested()


@pytest.mark.parametrize("reason", ["", "\x00", "line\nbreak", "x" * 257, None, 1])
def test_reason_is_bounded_without_coercion(source, reason):
    context = _context(source)
    with pytest.raises(ValueError):
        context.request_stop(reason)
    assert not (_directory(source, context) / "stop.json").exists()


def test_source_protocol_does_not_consult_or_mutate_administrative_authority(source, monkeypatch):
    from angerona.resilience import control_authority, shutdown_token
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Source coordination crossed the installed authority domain")
    monkeypatch.setattr(control_authority, "provisioned", forbidden)
    monkeypatch.setattr(control_authority, "request_elevated", forbidden)
    monkeypatch.setattr(shutdown_token, "request_operator_stop", forbidden)
    context = _context(source)
    context.request_stop()
    joined = stop.join_source_session(source[0], context.epoch)
    assert joined is not None and joined.is_stop_requested()


def test_fresh_explicit_launch_stops_previous_valid_family_before_pointer_advances(source):
    old = _context(source)
    peer_identity, old_peer = _peer(source, old)
    assert old_peer.epoch == old.epoch
    assert not old.is_stop_requested()
    new = _context(source)
    assert new.epoch != old.epoch
    source[3]["identity"] = peer_identity
    assert old_peer.is_stop_requested()
    assert not old_peer.respawn_allowed()


@pytest.mark.parametrize("leaf,raw", [("key", b"bad"), ("session.json", b"{}")])
def test_session_corruption_holds_respawn_without_becoming_stop_intent(source, leaf, raw):
    context = _context(source)
    assert context.admission_current() and context.respawn_allowed()
    (_directory(source, context) / leaf).write_bytes(raw)
    assert not context.admission_current()
    assert not context.is_stop_requested()
    assert not context.respawn_allowed()


def test_missing_session_metadata_holds_captured_peer_respawn(source):
    context = _context(source)
    (_directory(source, context) / "session.json").unlink()
    assert not context.admission_current()
    assert not context.is_stop_requested()
    assert not context.respawn_allowed()


@pytest.mark.parametrize("leaf", ["stop.json", "retired.json"])
def test_corrupt_command_or_retirement_holds_respawn_without_forging_intent(source, leaf):
    context = _context(source)
    path = _directory(source, context) / leaf
    path.write_bytes(b"unknown original")
    assert context.admission_current()
    assert not context.is_stop_requested()
    assert not context.respawn_allowed()
    assert path.read_bytes() == b"unknown original"


def test_clean_retirement_requires_valid_stop_and_core_role(source):
    context = _context(source)
    with pytest.raises(FileNotFoundError):
        context.mark_retired()
    context.request_stop()
    marker = context.mark_retired()
    assert marker["purpose"] == "retired"
    assert marker["issuer"] == stop._identity_record(source[2])
    assert context.mark_retired() == marker
    assert not context.respawn_allowed()
    peer_identity, peer = _peer(source, context)
    source[3]["identity"] = peer_identity
    with pytest.raises(PermissionError):
        peer.mark_retired()


def test_clean_stop_launch_cycles_reclaim_beyond_session_limit(source, monkeypatch):
    monkeypatch.setattr(stop, "_MAX_SESSIONS", 4)
    monkeypatch.setattr(stop, "_RETAIN_CLOSED", 1)
    exited = set()
    monkeypatch.setattr(stop, "_closing_core_exited",
                        lambda issuer: (issuer["pid"], issuer["birth"]) in exited)
    first = None
    for number in range(14):
        identity = dataclasses.replace(source[2], pid=1000 + number,
                                       birth=source[2].birth + number)
        source[3]["identity"] = identity
        current = _context(source)
        first = first or current
        assert current.respawn_allowed()
        current.request_stop()
        current.mark_retired()
        exited.add((identity.pid, identity.birth))
    namespace = _namespace(source)
    assert len(stop._epoch_names(namespace)) <= 3
    source[3]["identity"] = first._identity
    assert not first.admission_current()
    assert not first.respawn_allowed()


@pytest.mark.parametrize("proof", [None, False])
def test_unknown_or_live_closing_core_is_never_pruned(source, monkeypatch, proof):
    monkeypatch.setattr(stop, "_MAX_SESSIONS", 2)
    monkeypatch.setattr(stop, "_RETAIN_CLOSED", 0)
    monkeypatch.setattr(stop, "_closing_core_exited", lambda _issuer: proof)
    first = _context(source)
    first.request_stop()
    first.mark_retired()
    _context(source)
    original = {p.name: p.read_bytes() for p in _directory(source, first).iterdir()}
    assert stop.create_source_session(source[0]) is None
    assert {p.name: p.read_bytes() for p in _directory(source, first).iterdir()} == original


@pytest.mark.parametrize("failure", ["wrong-scope", "wrong-mac", "missing-stop",
                                    "corrupt-session", "unknown-file"])
def test_uncertain_closed_epoch_is_never_reclaimed(source, monkeypatch, failure):
    monkeypatch.setattr(stop, "_MAX_SESSIONS", 2)
    monkeypatch.setattr(stop, "_RETAIN_CLOSED", 0)
    monkeypatch.setattr(stop, "_closing_core_exited", lambda _issuer: True)
    first = _context(source)
    first.request_stop()
    first.mark_retired()
    _context(source)
    directory = _directory(source, first)
    marker_path = directory / "retired.json"
    if failure == "wrong-scope":
        marker = json.loads(marker_path.read_bytes())
        marker["session"] += 1
        body = {key: value for key, value in marker.items() if key != "sig"}
        marker_path.write_bytes(stop._encode(stop._signed(body, first._key)))
    elif failure == "wrong-mac":
        marker = json.loads(marker_path.read_bytes())
        marker["sig"] = "0" * 64
        marker_path.write_bytes(stop._encode(marker))
    elif failure == "missing-stop":
        (directory / "stop.json").unlink()
    elif failure == "corrupt-session":
        (directory / "session.json").write_bytes(b"{}")
    else:
        (directory / "unknown.txt").write_bytes(b"preserve me")
    original = {p.name: p.read_bytes() for p in directory.iterdir()}
    assert stop.create_source_session(source[0]) is None
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == original


def _scope_snapshot(context):
    namespace = stop._namespace(context._scope())
    directory = namespace / context.epoch
    return {"current.json": (namespace / "current.json").read_bytes(),
            **{context.epoch + "/" + path.name: path.read_bytes()
               for path in directory.iterdir()}}


@pytest.mark.parametrize("field,value", [("session", 19),
                                        ("owner", "S-1-5-21-11-22-33-1002")])
def test_new_native_scope_can_launch_without_modifying_old_scope(source, field, value):
    original = _context(source)
    peer_identity, old_peer = _peer(source, original)
    original.request_stop()
    before = _scope_snapshot(original)
    new_identity = dataclasses.replace(source[2], pid=303, birth=source[2].birth + 2,
                                       **{field: value})
    source[3]["identity"] = new_identity
    fresh = stop.create_source_session(source[0])
    assert fresh is not None and fresh.respawn_allowed()
    assert fresh.epoch != original.epoch
    assert stop._namespace(fresh._scope()) != stop._namespace(original._scope())
    assert _scope_snapshot(original) == before
    assert stop.join_source_session(source[0], original.epoch, role="peer") is None
    current = stop.join_source_session(source[0], role="peer")
    assert current is not None and current.epoch == fresh.epoch
    source[3]["identity"] = peer_identity
    assert old_peer.is_stop_requested() and not old_peer.respawn_allowed()
    assert _scope_snapshot(original) == before


def test_new_loaded_source_root_gets_its_own_pointer_without_touching_old(source, tmp_path, monkeypatch):
    original = _context(source)
    peer_identity, old_peer = _peer(source, original)
    original.request_stop()
    before = _scope_snapshot(original)
    replacement_root = tmp_path / "relocated-source"
    replacement_root.mkdir()
    monkeypatch.setattr(stop, "_source_root", lambda: replacement_root)
    source[3]["identity"] = dataclasses.replace(source[2], pid=303, birth=source[2].birth + 2)
    fresh = stop.create_source_session(source[0])
    assert fresh is not None and fresh.respawn_allowed()
    namespace = stop._namespace(fresh._scope())
    assert len(namespace.name) == 64 and all(char in "0123456789abcdef" for char in namespace.name)
    assert namespace.parent == source[0] / "ipc" / stop._DIRECTORY
    assert _scope_snapshot(original) == before
    assert stop.join_source_session(source[0], original.epoch, role="peer") is None
    monkeypatch.setattr(stop, "_source_root", lambda: source[1])
    source[3]["identity"] = peer_identity
    assert old_peer.is_stop_requested() and not old_peer.respawn_allowed()
    assert _scope_snapshot(original) == before


def test_new_configured_storage_gets_its_own_scope_without_mutating_original(source, tmp_path):
    original = _context(source)
    original.request_stop()
    before = _scope_snapshot(original)
    replacement_storage = tmp_path / "new-SourceData"
    replacement_storage.mkdir()
    fresh = stop.create_source_session(replacement_storage)
    assert fresh is not None and fresh.respawn_allowed()
    assert fresh._scope()["storage"] != original._scope()["storage"]
    assert stop._namespace(fresh._scope()).name != stop._namespace(original._scope()).name
    assert stop.join_source_session(replacement_storage, original.epoch) is None
    assert original.is_stop_requested()
    assert _scope_snapshot(original) == before


@pytest.mark.parametrize("transition", ["native-session", "source-root"])
def test_unstopped_old_scope_cannot_respawn_after_new_scope_then_new_core_stop(source, tmp_path, monkeypatch, transition):
    old = _context(source)
    peer_identity, old_peer = _peer(source, old)
    before = _scope_snapshot(old)
    assert not old.is_stop_requested() and old.respawn_allowed()
    new_identity = dataclasses.replace(source[2], pid=303, birth=source[2].birth + 2)
    if transition == "native-session":
        new_identity = dataclasses.replace(new_identity, session=19)
    else:
        relocated = tmp_path / "replacement-source"
        relocated.mkdir()
        source[1].rmdir()  # Verification must not need the old source directory.
        monkeypatch.setattr(stop, "_source_root", lambda: relocated)
    source[3]["identity"] = new_identity
    fresh = stop.create_source_session(source[0])
    assert fresh is not None and fresh.respawn_allowed()
    fresh.request_stop()
    assert fresh.is_stop_requested() and not fresh.respawn_allowed()
    source[3]["identity"] = peer_identity
    monkeypatch.setattr(stop, "_source_root", lambda: source[1])
    assert not old_peer.is_stop_requested(), "Supersession must not forge operator STOP intent"
    assert old_peer.is_superseded(), "Only verified newer same-user scope permits self-retirement"
    assert not old_peer.respawn_allowed()
    assert _scope_snapshot(old) == before
    assert not (_directory(source, old) / "stop.json").exists()


@pytest.mark.parametrize("raw", [b"{}", b"unsigned original", b"", b"x" * (stop._MAX_RECORD + 1)])
def test_corrupt_latest_holds_respawn_without_supersession_or_replacement(source, raw):
    context = _context(source)
    latest = stop._latest_path(context._scope())
    latest.write_bytes(raw)
    before = _scope_snapshot(context)
    assert not context.respawn_allowed()
    assert not context.is_superseded()
    assert not context.is_stop_requested()
    assert stop.create_source_session(source[0]) is None
    assert latest.read_bytes() == raw and _scope_snapshot(context) == before


def test_missing_latest_holds_initialized_scope_without_forging_supersession(source):
    context = _context(source)
    stop._latest_path(context._scope()).unlink()
    before = _scope_snapshot(context)
    assert not context.respawn_allowed()
    assert not context.is_superseded() and not context.is_stop_requested()
    assert stop.create_source_session(source[0]) is None
    assert _scope_snapshot(context) == before


def test_latest_fence_mac_is_purpose_bound_and_does_not_authorize_self_exit_when_forged(source):
    context = _context(source)
    path = stop._latest_path(context._scope())
    record = json.loads(path.read_bytes())
    wrong = {key: value for key, value in record.items() if key != "sig"}
    wrong["purpose"] = "current"
    record["sig"] = stop._signed(wrong, context._key)["sig"]
    path.write_bytes(stop._encode(record))
    assert not context.respawn_allowed()
    assert not context.is_superseded() and not context.is_stop_requested()
    assert stop.create_source_session(source[0]) is None


def test_different_native_sid_cannot_adopt_or_supersede_another_users_scope(source):
    first = _context(source)
    first_latest = stop._latest_path(first._scope()).read_bytes()
    other_identity = dataclasses.replace(source[2], owner="S-1-5-21-11-22-33-1002",
                                         pid=303, birth=source[2].birth + 2)
    source[3]["identity"] = other_identity
    other = stop.create_source_session(source[0])
    assert other is not None and other.respawn_allowed()
    assert stop.join_source_session(source[0], first.epoch) is None
    assert stop._latest_path(first._scope()) != stop._latest_path(other._scope())
    stop._latest_path(other._scope()).write_bytes(first_latest)
    assert not other.respawn_allowed() and not other.is_superseded()
    assert stop.create_source_session(source[0]) is None
    source[3]["identity"] = source[2]
    assert first.respawn_allowed() and not first.is_superseded()
    assert stop._latest_path(first._scope()).read_bytes() == first_latest


def test_latest_record_storage_path_never_redirects_epoch_key_lookup(source, tmp_path, monkeypatch):
    context = _context(source)
    path = stop._latest_path(context._scope())
    record = json.loads(path.read_bytes())
    record["storage"] = str(tmp_path / "foreign-storage")
    body = {key: value for key, value in record.items() if key != "sig"}
    path.write_bytes(stop._encode(stop._signed(body, context._key)))
    actual_read = stop._read_bytes
    reads = []
    def trusted_read(target, *args, **kwargs):
        reads.append(target)
        assert target.is_relative_to(source[0])
        return actual_read(target, *args, **kwargs)
    monkeypatch.setattr(stop, "_read_bytes", trusted_read)
    assert not context.is_superseded()
    assert stop.create_source_session(source[0]) is None
    assert reads and all(target.is_relative_to(source[0]) for target in reads)


def test_retention_preserves_key_referenced_by_valid_latest_until_fence_advances(source, monkeypatch):
    monkeypatch.setattr(stop, "_RETAIN_CLOSED", 0)
    monkeypatch.setattr(stop, "_closing_core_exited", lambda _issuer: True)
    first = _context(source)
    first_latest_path = stop._latest_path(first._scope())
    first_latest = first_latest_path.read_bytes()
    first.request_stop()
    first.mark_retired()
    second = _context(source)
    # Model a retained pre-publication latest fence while the per-scope pointer
    # already names a newer epoch. Its key must not be pruned before commit.
    first_latest_path.write_bytes(first_latest)
    before = {path.name: path.read_bytes() for path in _directory(source, first).iterdir()}
    third = _context(source)
    assert third.epoch not in {first.epoch, second.epoch}
    assert {path.name: path.read_bytes() for path in _directory(source, first).iterdir()} == before
    assert (_directory(source, first) / "key").is_file()
    latest, _fingerprint = stop._latest_transition_state(third._scope())
    assert latest is not None and latest["epoch"] == third.epoch
