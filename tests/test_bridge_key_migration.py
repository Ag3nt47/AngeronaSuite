from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from angerona.core import data_paths, secure_store
from angerona.modules import remote_bridge as bridge


KEY = "a1" * 32
OTHER = "22" * 32
NAME = "ANGERONA_BRIDGE_KEY"


@pytest.fixture
def isolated_store(monkeypatch, tmp_path):
    """No live OS credential store, listener, or host key is accessed."""
    state = {"values": {}, "writes": [], "locked": 0, "reads": 0}
    monkeypatch.delenv(NAME, raising=False)
    monkeypatch.setattr(data_paths, "data_dir", lambda: tmp_path)

    @contextmanager
    def transaction(root):
        assert root == tmp_path
        state["locked"] += 1
        try:
            yield
        finally:
            state["locked"] -= 1

    def read(names, root, *, strict):
        assert strict is True and root == tmp_path and state["locked"] == 1
        assert names == (NAME,)
        state["reads"] += 1
        if state.get("read_error") or (state.get("readback_error") and state["reads"] > 1):
            raise RuntimeError("inert locked store")
        if state.get("readback_mismatch") and state["reads"] > 1:
            return {NAME: OTHER}
        return dict(state["values"])

    def write(updates, root):
        assert root == tmp_path and state["locked"] == 1
        if state.get("write_error"):
            raise RuntimeError("inert failed write")
        state["writes"].append(dict(updates))
        state["values"].update(updates)
        return tmp_path / "inert-store"

    monkeypatch.setattr(secure_store, "secret_transaction", transaction)
    monkeypatch.setattr(secure_store, "read_secret_values", read)
    monkeypatch.setattr(secure_store, "write_secret_map", write)
    state["legacy"] = tmp_path / "bridge.key"
    return state


def test_bridge_migrates_only_after_protected_readback_and_removes_plaintext(isolated_store):
    state = isolated_store
    state["legacy"].write_text(KEY + "\n", encoding="ascii")
    assert bridge._shared_key() == bytes.fromhex(KEY)
    assert state["values"] == {NAME: KEY}
    assert state["writes"] == [{NAME: KEY}]
    assert not state["legacy"].exists()
    assert state["locked"] == 0


@pytest.mark.parametrize("failure", ["read_error", "write_error", "readback_mismatch", "readback_error"])
def test_bridge_never_uses_plaintext_when_protected_migration_fails(isolated_store, failure):
    state = isolated_store
    state["legacy"].write_text(KEY, encoding="ascii")
    state[failure] = True
    assert bridge._shared_key() is None
    assert state["legacy"].read_text() == KEY
    if failure == "read_error":
        assert not state["writes"]
    assert state["locked"] == 0


def test_bridge_unlink_failure_holds_key_and_can_finish_later(isolated_store, monkeypatch):
    state = isolated_store
    state["legacy"].write_text(KEY, encoding="ascii")
    original = Path.unlink
    def refuse(path, *args, **kwargs):
        if path == state["legacy"]:
            raise PermissionError("inert legacy lock")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", refuse)
    assert bridge._shared_key() is None
    assert state["values"] == {NAME: KEY}
    assert state["legacy"].exists()
    monkeypatch.setattr(Path, "unlink", original)
    assert bridge._shared_key() == bytes.fromhex(KEY)
    assert len(state["writes"]) == 1
    assert not state["legacy"].exists()


def test_bridge_protected_rotation_cannot_fall_back_to_stale_plaintext(isolated_store):
    state = isolated_store
    state["values"][NAME] = OTHER
    state["legacy"].write_text(KEY, encoding="ascii")
    assert bridge._shared_key() is None
    assert state["values"] == {NAME: OTHER}
    assert not state["writes"]
    assert state["legacy"].read_text() == KEY


def test_bridge_finishes_identical_legacy_residue_without_replacing_key(isolated_store):
    state = isolated_store
    state["values"][NAME] = KEY
    state["legacy"].write_text(KEY.upper(), encoding="ascii")
    assert bridge._shared_key() == bytes.fromhex(KEY)
    assert not state["writes"]
    assert not state["legacy"].exists()


@pytest.mark.parametrize("value", ["", "broken", "00" * 31])
def test_bridge_invalid_existing_protected_key_is_not_replaced(isolated_store, value):
    state = isolated_store
    state["values"][NAME] = value
    state["legacy"].write_text(KEY, encoding="ascii")
    assert bridge._shared_key() is None
    assert state["values"] == {NAME: value}
    assert not state["writes"]
    assert state["legacy"].exists()


@pytest.mark.parametrize("value", ["garbage", "11" * 31, "11" * 2049],
                         ids=["non-hex", "short", "oversized"])
def test_bridge_invalid_or_oversized_legacy_key_never_enters_store(isolated_store, value):
    state = isolated_store
    state["legacy"].write_text(value, encoding="ascii")
    assert bridge._shared_key() is None
    assert not state["writes"]
    assert state["legacy"].read_text() == value


def test_bridge_alias_legacy_key_is_refused_without_modifying_either_name(isolated_store):
    import os
    state = isolated_store
    source = state["legacy"].with_name("original.key")
    source.write_text(KEY, encoding="ascii")
    os.link(source, state["legacy"])
    assert bridge._shared_key() is None
    assert not state["writes"]
    assert source.read_text() == state["legacy"].read_text() == KEY


def test_bridge_changed_legacy_identity_is_preserved_and_key_held(isolated_store, monkeypatch):
    state = isolated_store
    state["legacy"].write_text(KEY, encoding="ascii")
    original = secure_store._legacy_source_identity
    calls = []
    def changed(path):
        calls.append(path)
        result = original(path)
        if len(calls) >= 3:
            return None
        return result
    monkeypatch.setattr(secure_store, "_legacy_source_identity", changed)
    assert bridge._shared_key() is None
    assert state["legacy"].exists()


def test_bridge_explicit_strong_key_does_not_touch_os_store(isolated_store, monkeypatch):
    state = isolated_store
    state["read_error"] = True
    monkeypatch.setenv(NAME, KEY)
    assert bridge._shared_key() == bytes.fromhex(KEY)
    assert state["reads"] == 0
    assert state["locked"] == 0


def test_bridge_held_reason_does_not_log_credential_or_exception_text(isolated_store, caplog):
    state = isolated_store
    state["legacy"].write_text(KEY, encoding="ascii")
    state["write_error"] = True
    assert bridge._shared_key() is None
    assert "protected_storage_or_migration_unavailable" in caplog.text
    assert KEY not in caplog.text
    assert "inert failed write" not in caplog.text


def test_bridge_existing_key_with_no_legacy_is_read_only(isolated_store):
    state = isolated_store
    state["values"][NAME] = KEY
    assert bridge._shared_key() == bytes.fromhex(KEY)
    assert not state["writes"]


@pytest.mark.parametrize("value", ["short", "00" * 31, "00" * 2049],
                         ids=["non-hex", "short", "oversized"])
def test_bridge_invalid_explicit_key_never_falls_back_to_store(isolated_store, monkeypatch, value):
    state = isolated_store
    state["values"][NAME] = KEY
    state["legacy"].write_text(KEY, encoding="ascii")
    monkeypatch.setenv(NAME, value)
    assert bridge._shared_key() is None
    assert state["reads"] == 0
    assert not state["writes"]
    assert state["legacy"].exists()


def test_bridge_non_ascii_legacy_key_is_preserved(isolated_store):
    state = isolated_store
    state["legacy"].write_bytes(b"\xff" * 64)
    assert bridge._shared_key() is None
    assert not state["writes"]
    assert state["legacy"].read_bytes() == b"\xff" * 64


@pytest.mark.parametrize("mode", ["SENDER", "RECEIVER"])
def test_bridge_held_migration_cannot_enter_either_network_loop(isolated_store, monkeypatch, mode):
    state = isolated_store
    state["legacy"].write_text(KEY, encoding="ascii")
    state["write_error"] = True
    monkeypatch.setenv("ANGERONA_BRIDGE_MODE", mode)
    module = bridge.RemoteBridge()
    assert module._key is None
    opened = []
    monkeypatch.setattr(module, "_run_sender", lambda: opened.append("sender"))
    monkeypatch.setattr(module, "_run_receiver", lambda: opened.append("receiver"))
    monkeypatch.setattr(module, "emit", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "sleep", lambda seconds: module.stop())
    module.run()
    assert opened == []
    assert module.health == 40


@pytest.mark.parametrize("mode", ["", "DISABLED", "unrecognized"])
def test_disabled_bridge_discovery_does_not_acquire_credentials(isolated_store, monkeypatch, mode):
    state = isolated_store
    state["read_error"] = True
    monkeypatch.setenv("ANGERONA_BRIDGE_MODE", mode)
    module = bridge.RemoteBridge()
    assert module._key is None
    assert state["reads"] == 0
    assert not state["writes"]
    assert state["locked"] == 0


@pytest.fixture
def inert_legacy_metadata(monkeypatch):
    """Exercise exact stat semantics without real descriptors, stores or sockets."""
    import os
    from types import SimpleNamespace

    named = dict(st_dev=7, st_ino=11, st_size=len(KEY), st_mtime_ns=100,
                 st_ctime_ns=200, st_birthtime_ns=200, st_nlink=1)
    held = dict(named, st_ctime_ns=300)
    identity = tuple(named[name] for name in
                     ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))
    state = {"named": named, "held": [dict(held), dict(held)],
             "path_identities": [identity, identity], "opens": 0, "reads": 0,
             "stats": 0, "path_checks": 0, "closed": False, "identity": identity}

    class LegacyPath:
        def lstat(self):
            return SimpleNamespace(**state["named"])

    path = LegacyPath()
    state["path"] = path

    class LegacyStream:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            state["closed"] = True

        def fileno(self):
            return 42

        def read(self, limit):
            assert limit == bridge._MAX_KEY_TEXT + 1
            state["reads"] += 1
            return KEY.encode("ascii")

    def source_identity(candidate):
        assert candidate is path
        index = state["path_checks"]
        state["path_checks"] += 1
        return state["path_identities"][index]

    def open_source(candidate, flags):
        assert candidate is path
        assert flags == (os.O_RDONLY | getattr(os, "O_BINARY", 0)
                         | getattr(os, "O_NOFOLLOW", 0))
        state["opens"] += 1
        return 42

    def fdopen_source(descriptor, mode):
        assert descriptor == 42 and mode == "rb"
        return LegacyStream()

    def descriptor_stat(descriptor):
        assert descriptor == 42
        index = state["stats"]
        state["stats"] += 1
        return SimpleNamespace(**state["held"][index])

    # Replace this module's os reference, not shared os.fstat or Path.lstat.
    isolated_os = SimpleNamespace(**vars(os))
    isolated_os.name = "nt"
    isolated_os.open = open_source
    isolated_os.fdopen = fdopen_source
    isolated_os.fstat = descriptor_stat
    monkeypatch.setattr(bridge, "os", isolated_os)
    monkeypatch.setattr(secure_store, "_legacy_source_identity", source_identity)
    state["os"] = isolated_os
    return state


def test_bridge_legacy_read_accepts_stable_windows_birth_with_different_change_time(
        inert_legacy_metadata):
    state = inert_legacy_metadata
    assert state["named"]["st_ctime_ns"] != state["held"][0]["st_ctime_ns"]
    assert bridge._read_legacy_bridge_key(state["path"]) == (KEY, state["identity"])
    assert state["opens"] == state["reads"] == 1
    assert state["stats"] == state["path_checks"] == 2
    assert state["closed"] is True


@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size", "st_mtime_ns",
                                   "st_birthtime_ns"],
                         ids=["device", "inode", "size", "mtime", "birth"])
def test_bridge_legacy_read_refuses_cross_api_identity_mismatch(inert_legacy_metadata, field):
    state = inert_legacy_metadata
    state["held"][0][field] += 1
    with pytest.raises(ValueError, match="legacy key identity changed"):
        bridge._read_legacy_bridge_key(state["path"])
    assert state["opens"] == state["stats"] == 1
    assert state["reads"] == 0
    assert state["closed"] is True


@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size", "st_mtime_ns",
                                   "st_birthtime_ns", "st_ctime_ns"],
                         ids=["device", "inode", "size", "mtime", "birth", "native-change"])
def test_bridge_legacy_read_refuses_any_held_descriptor_change(inert_legacy_metadata, field):
    state = inert_legacy_metadata
    state["held"][1][field] += 1
    with pytest.raises(ValueError, match="legacy key changed during read"):
        bridge._read_legacy_bridge_key(state["path"])
    assert state["opens"] == state["reads"] == 1
    assert state["stats"] == 2
    assert state["closed"] is True


def test_bridge_legacy_read_refuses_named_metadata_change_before_open(inert_legacy_metadata):
    state = inert_legacy_metadata
    state["named"]["st_ctime_ns"] += 1
    with pytest.raises(ValueError, match="legacy key named identity changed"):
        bridge._read_legacy_bridge_key(state["path"])
    assert state["opens"] == state["stats"] == state["reads"] == 0


def test_bridge_legacy_read_refuses_named_identity_change_after_read(inert_legacy_metadata):
    state = inert_legacy_metadata
    changed = list(state["identity"])
    changed[-1] += 1
    state["path_identities"][1] = tuple(changed)
    with pytest.raises(ValueError, match="legacy key changed during read"):
        bridge._read_legacy_bridge_key(state["path"])
    assert state["opens"] == state["reads"] == 1
    assert state["stats"] == state["path_checks"] == 2
    assert state["closed"] is True


def test_bridge_legacy_read_keeps_posix_change_time_binding(inert_legacy_metadata):
    state = inert_legacy_metadata
    state["os"].name = "posix"
    with pytest.raises(ValueError, match="legacy key identity changed"):
        bridge._read_legacy_bridge_key(state["path"])
    assert state["reads"] == 0
    assert state["closed"] is True


def test_bridge_legacy_read_supports_older_windows_matching_ctime(inert_legacy_metadata):
    state = inert_legacy_metadata
    del state["named"]["st_birthtime_ns"]
    for info in state["held"]:
        del info["st_birthtime_ns"]
        info["st_ctime_ns"] = state["named"]["st_ctime_ns"]
    assert bridge._read_legacy_bridge_key(state["path"]) == (KEY, state["identity"])
    assert state["opens"] == state["reads"] == 1
    assert state["stats"] == state["path_checks"] == 2
    assert state["closed"] is True
