"""Legacy deception safety using an in-memory Windows native facade only."""
from __future__ import annotations

from contextlib import contextmanager
import sys
import threading
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import deception_io as io
from angerona.modules import deception


class Missing(Exception):
    pass


class Handle:
    def __init__(self, path=None, node=None):
        self.path, self.node, self.closed = path, node, False
        self.close_calls = 0


class MemoryApi:
    def __init__(self, documents):
        self.documents_path = documents
        self.files, self.directories, self.handles = {}, {}, []
        self.writes, self.hides, self.creates, self.mkdirs = [], [], [], []
        self.documents_calls = 0
        self.facts = dict(sid="S-1-5-21-1", elevated=False, integrity=8192,
                          impersonated=False, identity=("token", "auth", "modified"))
        self.fact_steps = []
        self.token_failure = False
        self.reparse = set()
        self.denied_directory = None
        self.close_failure = None
        self.missing_directories = set()
        self.on_info = None
        self.before_create = None
        self.attribute_writers = []

    def own(self, path=None, node=None):
        handle = Handle(path, node)
        self.handles.append(handle)
        return handle

    def token(self, resources):
        if self.token_failure:
            raise io.CanaryHeld("Token query is unavailable")
        handle = self.own()
        resources.append(io._Owned(handle, self.close))
        facts = self.fact_steps.pop(0) if self.fact_steps else self.facts
        if facts.get("impersonated"):
            raise io.CanaryHeld("Impersonating thread held")
        return resources[-1], dict(facts)

    def documents(self, token):
        assert not token.closed
        self.documents_calls += 1
        return self.documents_path

    def directory(self, path):
        if path == self.denied_directory:
            raise io.CanaryHeld("Existing directory data-writer conflicts with denied sharing")
        if path in self.missing_directories:
            raise Missing()
        node = self.directories.setdefault(path, self.node(directory=True))
        return self.own(path, node)

    def mkdir(self, path, sid):
        self.mkdirs.append((path, sid))
        self.missing_directories.discard(path)
        self.directories[path] = self.node(directory=True)

    def attribute_writer(self, path):
        # FILE_WRITE_ATTRIBUTES is explicitly outside sharing checks. This
        # competitor is allowed even while an ordinary read-share lease exists.
        self.attribute_writers.append(path)
        return SimpleNamespace(path=path, write_attributes=True)

    def leaf(self, path, sid, *, create):
        if create:
            if self.before_create is not None:
                path = self.before_create(path)
            if path in self.files:
                raise FileExistsError()
            self.files[path] = self.node()
            self.creates.append(path)
        elif path not in self.files:
            raise Missing()
        return self.own(path, self.files[path])

    def node(self, raw=b"", *, directory=False, attributes=0, links=1):
        return dict(raw=raw, attributes=attributes | (0x10 if directory else 0),
                    device=1, inode=len(self.handles) + len(self.files) + len(self.directories) + 1,
                    size=len(raw), mtime_ns=1_000_000_000, links=links)

    def missing(self, error):
        return isinstance(error, Missing)

    def collision(self, error):
        return isinstance(error, FileExistsError)

    def info(self, handle):
        assert not handle.closed
        if self.on_info:
            self.on_info(handle)
        result = dict(handle.node)
        if handle.path in self.reparse:
            result["attributes"] |= 0x400
        return result

    def final(self, handle):
        assert not handle.closed
        return handle.path

    def read(self, handle, maximum):
        assert not handle.closed
        return handle.node["raw"][:maximum]

    def write(self, handle, raw):
        assert not handle.closed
        self.writes.append(handle)
        handle.node.update(raw=raw, size=len(raw), mtime_ns=2_000_000_000)

    def hide(self, handle):
        assert not handle.closed
        self.hides.append(handle)
        handle.node["attributes"] |= 6

    def close(self, handle):
        handle.close_calls += 1
        if self.close_failure == handle.path and handle.node is not None and not handle.node["attributes"] & 0x10:
            raise OSError("fixture close unconfirmed")
        handle.closed = True


@pytest.fixture
def canaries(tmp_path, monkeypatch):
    api = MemoryApi(tmp_path / "documents")
    monkeypatch.setattr(io, "_CLOSE_HOLDS", [])
    # Path/custody observation is the modeled Windows boundary on every CI OS;
    # the fake never invokes Windows API, host paths, or actual file creation.
    monkeypatch.setattr(io, "PureWindowsPath", lambda _value: SimpleNamespace(drive="C:"))
    monkeypatch.setattr(io, "_WindowsApi", lambda: pytest.fail("test must not construct native facade"))
    monkeypatch.setattr(io, "_session", lambda base, **kwargs: io._WindowsSession(base, api=api, **kwargs))
    monkeypatch.setattr(deception, "_repo_root", lambda: tmp_path / "data")
    monkeypatch.delenv("ANGERONA_USER_FOLDER_DECEPTION", raising=False)
    return api, tmp_path


def test_new_windows_canary_is_held_before_any_creation_write_or_enrollment(canaries):
    api, root = canaries
    admitted = []
    with pytest.raises(io.CanaryHeld, match="object-relative provider"):
        io.create_canary(root / "private", "passwords.txt", deception._STATIC_CANARY_BYTES,
                         adopt_static=True, on_admitted=admitted.append)
    assert admitted == [] and not api.files
    assert not api.creates and not api.mkdirs and not api.writes and not api.hides
    assert all(handle.closed for handle in api.handles)


def test_real_user_wallet_collision_is_preserved_unhidden_and_other_slots_continue(canaries, monkeypatch):
    api, _root = canaries
    monkeypatch.setenv("ANGERONA_USER_FOLDER_DECEPTION", "1")
    monkeypatch.setenv("USERPROFILE", "Z:/attacker-controlled-profile")
    wallet = api.documents_path / "wallet.dat"
    original = api.node(b"actual user wallet bytes", attributes=0x20)
    api.files[wallet] = original
    for name in ("passwords.txt", "backup_keys.txt"):
        api.files[api.documents_path / name] = api.node(deception._STATIC_CANARY_BYTES)
    before = dict(original)
    module = deception.DeceptionModule()
    assert module._base is None and api.documents_calls == 0
    module._plant()
    assert api.files[wallet] == before
    assert str(wallet) not in module._canaries
    assert len(module._canaries) == 2 and len(module._canary_hold_reasons) == 1
    assert all(handle.path != wallet for handle in api.writes + api.hides)
    assert module._base == api.documents_path


def test_exact_static_bytes_reenroll_after_restart_without_writes_or_attributes(canaries):
    api, _root = canaries
    path = api.documents_path / "passwords.txt"
    api.files[path] = api.node(deception._STATIC_CANARY_BYTES, attributes=0x20)
    # Even a high-token reader may observe an exact known static canary; it
    # must never create/hide a missing file or upgrade the write authority.
    api.facts.update(elevated=True, integrity=0x3000)
    before = dict(api.files[path])
    first = io.create_canary(None, path.name, deception._STATIC_CANARY_BYTES, personal=True, adopt_static=True)
    second = io.create_canary(None, path.name, deception._STATIC_CANARY_BYTES, personal=True, adopt_static=True)
    assert not first.created and first.evidence == second.evidence
    assert api.files[path] == before and not api.writes and not api.hides and not api.creates


@pytest.mark.parametrize("state", ["elevated", "high", "unknown", "impersonating"])
def test_nonordinary_or_unknown_tokens_prevent_new_personal_writes(canaries, state):
    api, _root = canaries
    if state == "elevated":
        api.facts["elevated"] = True
    elif state == "high":
        api.facts["integrity"] = 0x4000
    elif state == "unknown":
        api.token_failure = True
    else:
        api.facts["impersonated"] = True
    with pytest.raises(io.CanaryHeld):
        io.create_canary(None, "passwords.txt", deception._STATIC_CANARY_BYTES, personal=True, adopt_static=True)
    assert not api.files and not api.creates and not api.writes and not api.hides and not api.mkdirs


def test_token_replacement_cannot_bypass_unconditional_windows_mutation_hold(canaries):
    api, root = canaries
    original = dict(api.facts)
    changed = dict(api.facts, identity=("replacement", "auth", "modified"))
    api.fact_steps = [original, changed]
    with pytest.raises(io.CanaryHeld, match="object-relative provider"):
        io.create_canary(root / "private", "passwords.txt", deception._STATIC_CANARY_BYTES)
    assert not api.creates and not api.mkdirs and not api.writes and not api.hides


def test_windows_hold_prevents_even_a_partial_exclusive_file(canaries):
    api, root = canaries
    original = dict(api.facts)
    api.fact_steps = [original, original, dict(original, identity=("different", "auth", "modified"))]
    with pytest.raises(io.CanaryHeld, match="object-relative provider"):
        io.create_canary(root / "private", "passwords.txt", deception._STATIC_CANARY_BYTES)
    assert not api.files and not api.creates and not api.mkdirs and not api.writes and not api.hides


@pytest.mark.parametrize("damage", ["hardlink", "reparse", "oversized"])
def test_unsafe_existing_leaf_is_never_hidden_or_adopted(canaries, damage):
    api, root = canaries
    path = root / "private" / "wallet.dat"
    node = api.node(deception._STATIC_CANARY_BYTES)
    if damage == "hardlink":
        node["links"] = 2
    elif damage == "reparse":
        node["attributes"] = 0x400
    else:
        node["size"] = io.MAX_BYTES + 1
    api.files[path] = node
    with pytest.raises(io.CanaryHeld):
        io.create_canary(path.parent, path.name, deception._STATIC_CANARY_BYTES, adopt_static=True)
    assert not api.writes and not api.hides and not api.creates


def test_dynamic_name_collision_is_exclusive_and_preserves_existing_bytes(canaries):
    api, root = canaries
    path = root / "private" / "id_rsa_12345678.txt"
    node = api.node(b"user credentials", attributes=0x20)
    api.files[path] = node
    before = dict(node)
    with pytest.raises(io.CanaryHeld, match="object-relative provider"):
        io.create_canary(path.parent, path.name, deception._DYNAMIC_CANARY_BYTES)
    assert node == before and not api.writes and not api.hides


@pytest.mark.parametrize("failure", ["existing-data-writer", "reparse-admission", "reparse-before-write"])
def test_directory_write_sharing_or_reparse_uncertainty_holds_before_first_byte(canaries, failure):
    api, root = canaries
    base = root / "private"
    if failure == "existing-data-writer":
        api.denied_directory = base
    elif failure == "reparse-admission":
        api.reparse.add(base)
    else:
        calls = [0]

        def mutate(handle):
            if handle.path == base:
                calls[0] += 1
                if calls[0] >= 2:
                    api.reparse.add(base)

        api.on_info = mutate
    with pytest.raises(io.CanaryHeld):
        io.create_canary(base, "passwords.txt", deception._STATIC_CANARY_BYTES)
    assert not api.creates and not api.writes and not api.hides


def test_missing_personal_documents_is_held_without_creating_it(canaries):
    api, _root = canaries
    api.missing_directories.add(api.documents_path)
    with pytest.raises(io.CanaryHeld):
        io.create_canary(None, "passwords.txt", deception._STATIC_CANARY_BYTES, personal=True)
    assert not api.mkdirs and not api.creates


def test_close_uncertainty_holds_future_io_without_retrying_handle(canaries):
    api, root = canaries
    path = root / "private" / "passwords.txt"
    api.close_failure = path
    api.files[path] = api.node(deception._STATIC_CANARY_BYTES)
    with pytest.raises(io.CanaryHeld, match="retirement"):
        io.create_canary(path.parent, path.name, deception._STATIC_CANARY_BYTES, adopt_static=True)
    failed = next(handle for handle in api.handles if handle.path == path)
    assert failed.close_calls == 1 and io._CLOSE_HOLDS
    before = (len(api.handles), len(api.creates), len(api.writes))
    with pytest.raises(io.CanaryHeld):
        io.create_canary(path.parent, "backup_keys.txt", deception._STATIC_CANARY_BYTES)
    assert (len(api.handles), len(api.creates), len(api.writes)) == before
    assert failed.close_calls == 1


def test_disposable_selftest_never_resolves_documents_even_with_optin(canaries, monkeypatch):
    api, root = canaries
    monkeypatch.setenv("ANGERONA_USER_FOLDER_DECEPTION", "1")

    @contextmanager
    def temporary(**kwargs):
        assert kwargs == {"prefix": "angerona-deception-selftest-"}
        yield str(root / "private-diagnostic-only")

    monkeypatch.setattr(deception.tempfile, "TemporaryDirectory", temporary)
    module = deception.DeceptionModule()
    ok, reason = module.self_test()
    if deception.os.name == "nt":
        assert (ok, reason) == (False, deception.DECEPTION_WINDOWS_CREATION_HELD)
        assert not api.handles and not api.creates and not api.mkdirs
    else:
        assert ok is False and "enrollment failed" in reason
    assert api.documents_calls == 0 and not module._canaries and module._base is None


def test_registry_and_legacy_export_are_held_while_canary_detection_still_emits(canaries, monkeypatch):
    api, _root = canaries
    module = deception.DeceptionModule()
    events = []
    monkeypatch.setattr(module, "emit", lambda message, severity, **details: events.append((message, severity, details)))
    for name in deception.CANARY_NAMES:
        api.files[module._base / name] = api.node(deception._STATIC_CANARY_BYTES)
    module._plant()
    path = Path(next(iter(module._canaries)))
    api.files[path]["raw"] += b"changed"
    api.files[path]["size"] += 7
    module._check_canaries()
    assert any("Canary file TOUCHED" in event[0] for event in events)
    module._plant_fake_registry_cred("existing-user-value")
    assert "exclusive key ownership" in module._registry_lure_held
    assert "authenticated EventBus alerts remain active" in module._legacy_export_held
    assert not any("shared_logs" in str(path) for path in api.creates)


def test_failed_restage_attempts_are_bounded_without_unlimited_partial_files(canaries, monkeypatch):
    _api, _root = canaries
    module = deception.DeceptionModule()
    attempts = []

    def held(*args, **kwargs):
        attempts.append((args, kwargs))
        raise io.CanaryHeld("Unproved creation custody")

    monkeypatch.setattr(io, "create_canary", held)
    for _ in range(1000):
        module._restage("credential discovery")
    assert len(attempts) == 12 and module._restage_count == 0
    assert len(module._canary_hold_reasons) <= 8


def test_native_open_contract_is_read_only_and_create_new_never_reaches_api():
    api = object.__new__(io._WindowsApi)
    calls = []
    api.file = SimpleNamespace(CreateFile=lambda *args: calls.append(args) or "inert handle")
    api.attributes = lambda *_args, **_kwargs: pytest.fail("new security descriptor requested")
    api.directory(Path("plain"))
    with pytest.raises(io.CanaryHeld, match="object-relative provider"):
        api.leaf(Path("canary"), "S-1-5-21-1", create=True)
    api.leaf(Path("canary"), "S-1-5-21-1", create=False)
    directory, existing = calls
    assert directory[1] == 0x81 and directory[2] == 1 and directory[5] == 0x02200000
    assert existing[1] == 0x80000000 and existing[2] == 1 and existing[4] == 3
    assert existing[3] is None and existing[5] & 0x00200000
    # share1 is not claimed to exclude attribute-only reparse modification.
    assert all(call[4] != 1 for call in calls)


def test_all_windows_native_mutation_methods_hold_without_calling_os():
    api = object.__new__(io._WindowsApi)
    api.file = SimpleNamespace(CreateDirectory=lambda *_args: pytest.fail("native mkdir"),
        WriteFile=lambda *_args: pytest.fail("native write"),
        FlushFileBuffers=lambda *_args: pytest.fail("native flush"))
    api.kernel = SimpleNamespace(SetFileInformationByHandle=lambda *_args: pytest.fail("native attributes"))
    for action in (lambda: api.mkdir(Path("new"), "S-1-5-21-1"),
                   lambda: api.write(0x100000123, b"canary"),
                   lambda: api.hide(0x100000123)):
        with pytest.raises(io.CanaryHeld, match="object-relative provider"):
            action()


@pytest.mark.parametrize("facts", [None, {}, {"elevated": None},
    {"elevated": False, "integrity": True, "impersonated": False},
    {"elevated": False, "integrity": 8192, "impersonated": None}])
def test_ordinary_token_policy_never_turns_unknown_into_permission(facts):
    with pytest.raises(io.CanaryHeld):
        io._ordinary(facts)


@pytest.mark.parametrize("thread_state", ["none", "denied", "impersonating"])
def test_native_token_probe_accepts_only_explicit_no_thread_token(thread_state, monkeypatch):
    monkeypatch.setattr(io, "_CLOSE_HOLDS", [])

    class NativeError(Exception):
        def __init__(self, code):
            self.winerror = code

    calls = []
    thread_handle, process_handle = Handle(), Handle()
    api = object.__new__(io._WindowsApi)
    api.pywintypes = SimpleNamespace(error=NativeError)
    api.api = SimpleNamespace(GetCurrentThread=lambda: "current-thread", GetCurrentProcess=lambda: "current-process")

    def open_thread(*args):
        calls.append(("thread", args))
        if thread_state != "impersonating":
            raise NativeError(1008 if thread_state == "none" else 5)
        return thread_handle

    def open_process(*args):
        calls.append(("process", args))
        return process_handle

    def close(handle):
        handle.close_calls += 1
        handle.closed = True

    api.security = SimpleNamespace(OpenThreadToken=open_thread, OpenProcessToken=open_process)
    api.close = close
    api._query = lambda _handle: dict(elevated=False, integrity=8192, impersonated=False)
    resources = []
    if thread_state == "none":
        owned, facts = api.token(resources)
        assert owned.value is process_handle and facts["elevated"] is False
        assert calls[-1] == ("process", ("current-process", 0x0E))
        io._close_all(resources)
        assert process_handle.close_calls == 1
    else:
        with pytest.raises(io.CanaryHeld):
            api.token(resources)
        io._close_all(resources)
        assert all(kind != "process" for kind, _args in calls)
        assert thread_handle.close_calls == (1 if thread_state == "impersonating" else 0)


def test_attribute_only_writer_can_reparse_after_checks_but_hold_prevents_outside_create(canaries):
    api, root = canaries
    base, outside = root / "private", root / "outside"
    interleavings = []
    with io._WindowsSession(base, api=api) as session:
        writer = api.attribute_writer(base)  # Not sharing-denied by read leases.
        assert writer.write_attributes and api.attribute_writers == [base]

        def reparse_after_last_check(path):
            interleavings.append(path)
            api.reparse.add(base)
            return outside / path.name

        # The old absolute CreateFile facade would run this after check_write,
        # record an outside CREATE_NEW effect, then fail its final-path check.
        api.before_create = reparse_after_last_check
        with pytest.raises(io.CanaryHeld, match="object-relative provider"):
            with session.leaf("passwords.txt", create=True):
                pytest.fail("held Windows creation yielded a writable leaf")
    assert interleavings == [] and not api.creates and not api.mkdirs
    assert not api.writes and not api.hides and not api.files


def test_missing_windows_parent_is_held_before_absolute_mkdir(canaries):
    api, root = canaries
    base = root / "missing"
    api.missing_directories.add(base)
    with pytest.raises(io.CanaryHeld, match="object-relative provider"):
        io.create_canary(base, "passwords.txt", deception._STATIC_CANARY_BYTES)
    assert not api.mkdirs and not api.creates and not api.writes and not api.hides


def test_all_existing_static_canaries_report_windows_new_deployment_hold(canaries, monkeypatch):
    api, _root = canaries
    monkeypatch.setattr(deception, "os", SimpleNamespace(name="nt", environ=deception.os.environ))
    module = deception.DeceptionModule()
    for name in deception.CANARY_NAMES:
        api.files[module._base / name] = api.node(deception._STATIC_CANARY_BYTES)
    events = []
    monkeypatch.setattr(module, "emit", lambda message, severity, **details:
                        events.append((message, severity, details)))
    monkeypatch.setattr(module, "sleep", lambda _seconds: module.stop())
    monkeypatch.setattr(module, "_check_canaries", lambda: None)
    monkeypatch.setattr(module, "_watch_attack_feed", lambda: None)
    module.run()
    assert len(module._canaries) == 3 and module._canary_hold_reasons == []
    deployed = [details for _message, _severity, details in events if "deployment_mode" in details]
    assert len(deployed) == 1
    assert deployed[0]["deployment_mode"] == "windows-new-mutations-held"
    assert deployed[0]["new_deployment_available"] is False and deployed[0]["read_visibility"] is False
    assert "held" in module.description.lower()
    assert not api.mkdirs and not api.creates and not api.writes and not api.hides


@pytest.mark.parametrize("hresult", [0, 1], ids=["S_OK", "S_FALSE"])
def test_documents_com_is_initialized_and_balanced_on_each_calling_thread(tmp_path, monkeypatch, hresult):
    monkeypatch.setattr(io, "_CLOSE_HOLDS", [])
    calls, token = [], object()
    folder = tmp_path / "Documents"
    current = threading.get_ident
    api = object.__new__(io._WindowsApi)

    def initialize(reserved, flags):
        assert reserved is None
        calls.append(("initialize", current(), flags))
        return hresult

    api.ole = SimpleNamespace(CoInitializeEx=initialize,
        CoUninitialize=lambda: calls.append(("uninitialize", current())))
    api.pywintypes = SimpleNamespace(IID=lambda value: value)

    def resolve(identifier, flags, supplied_token):
        calls.append(("resolve", current(), identifier, flags, supplied_token))
        return str(folder)

    api.shell = SimpleNamespace(SHGetKnownFolderPath=resolve)
    assert api.documents(token) == folder and api.documents(token) == folder
    assert [row[0] for row in calls] == ["initialize", "resolve", "uninitialize"] * 2
    assert all(row[1] == current() for row in calls)
    assert all(row[2:] == (2,) for row in calls if row[0] == "initialize")
    assert all(row[-1] is token and row[-2] == 0 for row in calls if row[0] == "resolve")
    assert not io._CLOSE_HOLDS


@pytest.mark.parametrize("failure", ["unavailable", "initialize", "changed-mode", "resolve", "retire"])
def test_documents_com_unavailability_or_uncertain_retirement_is_explicitly_held(tmp_path, monkeypatch, failure):
    monkeypatch.setattr(io, "_CLOSE_HOLDS", [])
    calls = []

    def initialize(reserved, flags):
        assert reserved is None and flags == 2
        calls.append("initialize")
        if failure == "initialize":
            raise RuntimeError("inert apartment admission failure")
        return -2147417850 if failure == "changed-mode" else 0

    def uninitialize():
        calls.append("uninitialize")
        if failure == "retire":
            raise RuntimeError("inert apartment retirement unknown")

    def resolve(*_args):
        calls.append("resolve")
        if failure == "resolve":
            raise RuntimeError("inert known-folder failure")
        return str(tmp_path / "Documents")

    api = object.__new__(io._WindowsApi)
    api.ole = None if failure == "unavailable" else SimpleNamespace(
        CoInitializeEx=initialize, CoUninitialize=uninitialize)
    api.pywintypes = SimpleNamespace(IID=lambda value: value)
    api.shell = SimpleNamespace(SHGetKnownFolderPath=resolve)
    with pytest.raises(io.CanaryHeld):
        api.documents(object())
    if failure in {"unavailable", "initialize", "changed-mode"}:
        assert "resolve" not in calls and "uninitialize" not in calls
    else:
        assert calls == ["initialize", "resolve", "uninitialize"]
    assert bool(io._CLOSE_HOLDS) is (failure == "retire")
    if failure == "retire":
        before = list(calls)
        with pytest.raises(io.CanaryHeld, match="prior"):
            api.documents(object())
        assert calls == before  # No second apartment close from a later call.


@pytest.mark.parametrize("elevated", [False, 0])
def test_native_token_query_accepts_documented_pywin32_sid_and_statistics_shapes(elevated):
    api = object.__new__(io._WindowsApi)
    api.security = SimpleNamespace(TokenUser=1, TokenElevation=20, TokenIntegrityLevel=25,
        TokenStatistics=10, ConvertSidToStringSid=lambda value: value)
    values = {1: ("S-1-5-21-1", 0), 20: elevated, 25: ("S-1-16-8192", 0x20),
              10: {"TokenId": 123, "AuthenticationId": 456, "ModifiedId": 789}}
    queried = []

    def query(token, kind):
        queried.append((token, kind))
        return values[kind]

    api.security.GetTokenInformation = query
    token = object()
    facts = api._query(token)
    assert facts == dict(sid="S-1-5-21-1", elevated=False, integrity=8192,
                         impersonated=False, identity=("123", "456", "789"))
    assert queried == [(token, kind) for kind in (1, 20, 25, 10)]


def test_native_com_prototypes_and_system_dll_loading_are_explicit_without_native_calls(monkeypatch):
    import ctypes
    from ctypes import wintypes

    class Function:
        def __call__(self, *_args):
            pytest.fail("ABI fixture executed a native operation")

    kernel = SimpleNamespace(GetFileInformationByHandle=Function(), SetFileInformationByHandle=Function())
    ole = SimpleNamespace(CoInitializeEx=Function(), CoUninitialize=Function())
    loaded = []

    def load(name, **kwargs):
        loaded.append((name, kwargs))
        return ole if name == "ole32.dll" else kernel

    monkeypatch.setattr(ctypes, "WinDLL", load, raising=False)
    for name in ("win32api", "win32con", "win32file", "win32security", "pywintypes"):
        monkeypatch.setitem(sys.modules, name, SimpleNamespace())
    monkeypatch.setitem(sys.modules, "win32com", SimpleNamespace(__path__=[]))
    monkeypatch.setitem(sys.modules, "win32com.shell", SimpleNamespace(shell=SimpleNamespace()))
    api = io._WindowsApi()
    assert loaded == [("kernel32", {"use_last_error": True}),
                      ("ole32.dll", {"use_last_error": True, "winmode": 0x800})]
    assert api.ole.CoInitializeEx.argtypes == [wintypes.LPVOID, wintypes.DWORD]
    assert api.ole.CoInitializeEx.restype is ctypes.c_long
    assert api.ole.CoUninitialize.argtypes == [] and api.ole.CoUninitialize.restype is None
