"""Actual activation transactions under inert process-query/Git transports.

Files, private ACL checks, staging, hash-bound plans, complete App supplier,
request and parent-guard validators, publication, fsync and rollback are real.
Read-only Git/process queries and explicit numeric disk-volume/free controls
are modeled. Unit parent-observation records do not prove a host Core retired.
"""
from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import threading
import uuid
from types import SimpleNamespace
import zipfile

import pytest

from test_app_owned_process_composition import (
    composition as composition, context as context,
    inert_child_factory as inert_child_factory, inert_owner as inert_owner,
)
from angerona.core import source_activation as api
from angerona.core import source_activation_broker as broker
from angerona.core import source_activation_file as file_api
from angerona.core import source_activation_storage as storage
from angerona.core import source_activation_workspace as workspace_api
from angerona.core import _source_tomli
from angerona.core._source_tomli import _parser as toml_parser
from angerona.resilience import manager as manager_module
from angerona.resilience.manager import ResilienceManager
from angerona.core.startup_recovery import (
    private_directory, RECOVERY_COHERENCE_FILES, RECOVERY_MANIFEST_PATH,
    RECOVERY_VERIFIER_PATH, RECOVERY_BATCH_PATH, derive_recovery_coherent_tree,
)
from angerona.updater import source_git, source_stage


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows source activation protocol")
_BASE, _FIRST, _SECOND, _LOCAL = (value * 40 for value in "abcd")
_SYSTEM_PS = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
_REAL_OS = os


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _create_private_parents(path):
    if not path.exists():
        _create_private_parents(path.parent)
        assert private_directory(path, create=True)


def _write(path, raw):
    _create_private_parents(path.parent)
    path.write_bytes(raw)


def _json(path):
    return json.loads(path.read_bytes())


def _archive(tree, revision):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as stream:
        for name, raw in sorted(tree.items()):
            stream.writestr("AngeronaSuite-" + revision + "/" + name, raw)
    return output.getvalue()


def _recovery_fixture_tree(extra=None):
    # Read only the real closed profile. No candidate generator is imported.
    repo = Path(__file__).resolve().parents[1]
    names = (*RECOVERY_COHERENCE_FILES, RECOVERY_MANIFEST_PATH,
             RECOVERY_VERIFIER_PATH, RECOVERY_BATCH_PATH)
    files = {name: (repo / name).read_bytes() for name in names}
    files.update(extra or {})
    effective, _proof = derive_recovery_coherent_tree(files)
    return effective


class _View:
    def __init__(self, original, **overrides):
        self.original, self.overrides = original, overrides

    def __getattr__(self, name):
        return self.overrides[name] if name in self.overrides else getattr(self.original, name)


class _Function:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


class _ProcessQueries:
    """Model only process handles; all file/token/ACL calls delegate natively."""
    def __init__(self, native):
        self.native = native
        self.generations, self.handles, self.calls = {}, {}, []
        self.open_errors = {}
        self.issued_handles = set()
        self.next_handle = 0x710000000000
        self.OpenProcess = _Function(self.open)
        self.GetProcessTimes = _Function(self.times)
        self.QueryFullProcessImageNameW = _Function(self.image)
        self.WaitForSingleObject = _Function(self.wait)
        self.CloseHandle = _Function(self.close)

    def __getattr__(self, name):
        return getattr(self.native, name)

    @staticmethod
    def number(value):
        return getattr(value, "value", value)

    def add(self, pid, birth, image):
        row = {"pid": pid, "birth": str(birth), "image": str(image), "live": True}
        self.generations[pid] = row
        return row

    def open(self, access, inherit, pid):
        assert access == 0x00101000 and not inherit
        row = self.generations.get(pid)
        self.calls.append(("open", pid))
        if pid in self.open_errors:
            ctypes.set_last_error(self.open_errors[pid])
            return 0
        if row is None:
            ctypes.set_last_error(87)
            return 0
        self.next_handle += 1
        self.handles[self.next_handle] = row
        self.issued_handles.add(self.next_handle)
        return self.next_handle

    def times(self, handle, created, exited, kernel, user):
        key = self.number(handle)
        if key not in self.handles:
            assert key not in self.issued_handles, "Retired inert process token was queried"
            from ctypes import wintypes as w
            function = self.native.GetProcessTimes
            function.argtypes = (w.HANDLE, ctypes.POINTER(w.FILETIME),
                ctypes.POINTER(w.FILETIME), ctypes.POINTER(w.FILETIME), ctypes.POINTER(w.FILETIME))
            function.restype = w.BOOL
            return function(handle, created, exited, kernel, user)
        row = self.handles[key]
        raw = int(row["birth"])
        created._obj.dwHighDateTime, created._obj.dwLowDateTime = raw >> 32, raw & 0xffffffff
        for field in (exited, kernel, user):
            field._obj.dwHighDateTime = field._obj.dwLowDateTime = 0
        self.calls.append(("birth", row["pid"]))
        return True

    def image(self, handle, flags, buffer, length):
        key = self.number(handle)
        if key not in self.handles:
            assert key not in self.issued_handles, "Retired inert process token was queried"
            from ctypes import wintypes as w
            function = self.native.QueryFullProcessImageNameW
            function.argtypes = (w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD))
            function.restype = w.BOOL
            return function(handle, flags, buffer, length)
        row = self.handles[key]
        assert flags == 0 and length._obj.value >= len(row["image"])
        buffer.value, length._obj.value = row["image"], len(row["image"])
        self.calls.append(("image", row["pid"]))
        return True

    def wait(self, handle, timeout):
        key = self.number(handle)
        if key not in self.handles:
            assert key not in self.issued_handles, "Retired inert process token was queried"
            return self.native.WaitForSingleObject(handle, timeout)
        assert timeout == 0
        row = self.handles[key]
        self.calls.append(("wait", row["pid"]))
        return 258 if row["live"] else 0

    def close(self, handle):
        key = self.number(handle)
        if key not in self.handles:
            assert key not in self.issued_handles, "Inert numeric process close was retried"
            return self.native.CloseHandle(ctypes.c_void_p(key))
        row = self.handles.pop(key)
        self.calls.append(("close", row["pid"]))
        return True


class _GitReads:
    def __init__(self, root):
        self.root, self.head, self.calls = root, _LOCAL, []
        self.index_name = ".git/index"
        self.ignored = {"ignored-note.txt", "new_upstream.py"}

    def inventory(self):
        return sorted(path.relative_to(self.root).as_posix()
                      for path in self.root.rglob("*") if path.is_file()
                      and path.relative_to(self.root).parts[0] not in {".git", "venv", ".tmp"}
                      and path.relative_to(self.root).as_posix() not in self.ignored)

    def run(self, root, argv, *, text, timeout):
        assert Path(root) == self.root and text is False and timeout == 15
        prefix = ("--no-optional-locks", "--no-replace-objects", "--literal-pathspecs",
                  "-c", "diff.external=", "-c", "core.attributesFile=" + os.devnull,
                  "-c", "credential.helper=")
        assert tuple(argv[:len(prefix)]) == prefix
        command = tuple(argv[len(prefix):])
        self.calls.append(command)
        if command == ("remote", "get-url", "origin"):
            raw = api.ORIGIN.encode() + b"\n"
        elif command == ("rev-parse", "--verify", "HEAD"):
            raw = self.head.encode() + b"\n"
        elif command == ("rev-parse", "--verify", "refs/remotes/origin/main"):
            raw = _BASE.encode() + b"\n"
        elif command == ("rev-parse", "--git-path", "index"):
            raw = self.index_name.encode() + b"\n"
        elif command == ("ls-files", "-z", "--cached", "--others", "--exclude-standard"):
            raw = ("\0".join(self.inventory()) + "\0").encode()
        elif len(command) == 4 and command[:2] == ("merge-base", "--is-ancestor"):
            assert all(len(value) == 40 for value in command[2:])
            raw = b""
        else:
            raise AssertionError("Unexpected Git read " + repr(command))
        return SimpleNamespace(returncode=0, stdout=raw)


class _Crash(BaseException):
    pass


@pytest.fixture
def activation(tmp_path, monkeypatch, composition, request):
    root, data = tmp_path / "source", tmp_path / "data"
    profile_parent = profile_identity = None
    if getattr(request, "param", None) == "actual-d-source-c-profile":
        supplied = os.environ.get("ANGERONA_TEST_SOURCE_ACTIVATION_PROFILE_SCRATCH")
        if not supplied:
            pytest.skip("Root-owned C scratch unavailable; actual D/C transaction gate not executed")
        profile_parent = Path(supplied)
        assert profile_parent.is_absolute() and profile_parent.drive.casefold() == "c:"
        assert not str(profile_parent).startswith(("\\\\", "//")) and ".." not in profile_parent.parts
        profile_parent = file_api.plain_path(profile_parent, directory=True)
        assert private_directory(profile_parent, create=False)
        profile_identity = file_api.directory_identity(profile_parent)
        assert root.drive.casefold() == "d:"
        data = profile_parent / ("activation-protocol-test-" + uuid.uuid4().hex)
    assert private_directory(root, create=True)
    assert private_directory(data, create=True)
    state = data / "github-updates"
    assert private_directory(state, create=True)
    repo = Path(__file__).resolve().parents[1]
    common = _recovery_fixture_tree({
        "src/angerona/__init__.py": (repo / "src/angerona/__init__.py").read_bytes(),
        ".gitignore": b"ignored-note.txt\nnew_upstream.py\nvenv/\n.tmp/\n",
        "feature.py": b"value=1\n",
    })
    assert set(api.BROKER_FILES).issubset(common)
    base = dict(common)
    first, _ = derive_recovery_coherent_tree(dict(base, **{
        "feature.py": b"value=2\n", "new_upstream.py": b"new=2\n",
        "new_directory/nested/added.py": b"added=True\n"}))
    second, _ = derive_recovery_coherent_tree(dict(first, **{
        "feature.py": b"value=3\n", "new_upstream.py": b"new=3\n"}))
    user = dict(base, **{"custom.py": b"my_local_preference=True\n"})
    for name, raw in user.items():
        _write(root / name, raw)
    _write(root / ".git/HEAD", b"ref: refs/heads/private-source-user\n")
    _write(root / ".git/index", b"private index bytes")
    _write(root / "venv/private.bin", b"private runtime")
    _write(root / "ignored-note.txt", b"private ignored note")
    for name in ("settings.json", "bus.key", "shutdown.key"):
        content = (b"s" * 32).hex().encode() if name == "shutdown.key" else ("private-" + name).encode()
        _write(data / name, content)
    git = _GitReads(root)
    token = source_git._ACTIVE.set(git)
    monkeypatch.setattr(api, "_RUNTIME", None)
    monkeypatch.setattr(api._NativeProcess, "_close_holds", [])
    monkeypatch.setattr(broker._NativeProcess, "_close_holds", [])
    monkeypatch.setattr(file_api, "_CLOSE_HOLDS", [])
    actual_win_dll = ctypes.WinDLL
    native = _ProcessQueries(actual_win_dll("kernel32", use_last_error=True))

    def dll(name, *args, **kwargs):
        return native if str(name).casefold() in {"kernel32", "kernel32.dll"} else actual_win_dll(name, *args, **kwargs)

    monkeypatch.setattr(ctypes, "WinDLL", dll)
    monkeypatch.setattr(broker, "os", _View(_REAL_OS, getppid=lambda: 9001))
    monkeypatch.setattr(api, "time", SimpleNamespace(monotonic=lambda: composition.clock[0]))
    core = composition.core_context.identities["core"]
    native.add(core.pid, core.birth_ticks, core.image)
    native.add(9001, "133000000000000001", _SYSTEM_PS)
    native.add(9002, "133000000000000002", _SYSTEM_PS)
    owner = {"schema": 1, "launch_id": "1" * 32, "source_root": str(root),
             "state_root": str(state), "supervisor_pid": 9002,
             "supervisor_birth": "133000000000000002", "supervisor_image": _SYSTEM_PS,
             "token": "2" * 64, "broker_pid": 9001, "broker_birth": "133000000000000001",
             "broker_image": _SYSTEM_PS, "core_pid": core.pid,
             "core_birth": str(core.birth_ticks), "core_image": core.image, "owner_state": "bound"}
    _write(state / "activation-owner.json", _encoded(owner))
    composition.app.config = SimpleNamespace(data_dir=data)
    composition.app._source_update_controller = api.SourceActivationController(root, state, owner["launch_id"])
    api.register_source_activation_runtime(composition.app)
    sample = SimpleNamespace(root=root, data=data, state=state, base=base, first=first,
        second=second, user=user, git=git, native=native, owner=owner, app=composition.app,
        composition=composition, archives={_BASE: _archive(base, _BASE),
        _FIRST: _archive(first, _FIRST), _SECOND: _archive(second, _SECOND)})
    sample.protected = {str(path): (path.read_bytes(), path.stat().st_ino)
        for path in [root / ".git/HEAD", root / ".git/index", root / "ignored-note.txt",
                     root / "venv/private.bin", data / "settings.json", data / "bus.key",
                     data / "shutdown.key"]}
    sample.fixture_root = tmp_path
    sample.profile_fixture = data if profile_parent is not None else None
    sample.profile_parent, sample.profile_identity = profile_parent, profile_identity
    try:
        yield sample
    finally:
        source_git._ACTIVE.reset(token)
        assert native.handles == {}, "A modeled process-query handle was not closed"
        if profile_parent is not None:
            # Bounded artificial C test evidence is retained for Root review;
            # this fixture never recursively removes a profile directory.
            assert file_api.directory_identity(profile_parent) == profile_identity


def _protected_unchanged(sample):
    for name, expected in sample.protected.items():
        path = Path(name)
        if not path.is_absolute():
            path = sample.fixture_root / path
        assert (path.read_bytes(), path.stat().st_ino) == expected


def _stage(sample, target=_FIRST):
    def fetch(path):
        left, right = path.removeprefix("compare/").split("...")
        assert right == target and left in sample.archives
        return {"status": "ahead", "base_commit": {"sha": left},
                "merge_base_commit": {"sha": left}}
    return source_stage.prepare_source_update(sample.root, sample.state / "stages", target,
        fetch=fetch, download=sample.archives.__getitem__)


def _plan(sample, target=_FIRST):
    stage = _stage(sample, target)
    assert stage.status == "prepared"
    return api.prepare_source_activation(sample.root, sample.state,
                                         stage.stage_id, stage.manifest_sha256)


def _approve(sample, plan, **kwargs):
    return api.approve_source_activation(sample.state, plan["activation_id"],
        plan["plan_sha256"], sample.owner, accepted=True, **kwargs)


def _operation(sample, plan):
    return sample.state / "activations" / ("apply-" + plan["activation_id"])


def _guard(sample, plan, request, *, reconcile=False, change=None, stop_change=None):
    operation = _operation(sample, plan)
    binding = {"launch_id": sample.owner["launch_id"], "activation_id": plan["activation_id"],
               "request_sha256": request["request_sha256"], "core_pid": sample.owner["core_pid"],
               "core_birth": sample.owner["core_birth"]}
    stop = {"schema": 1, "state": "retired", "operator_stop_recorded": True,
            "pending_workers": [], "pending_custody": [], "before_cleanup_pending": 0,
            "tracked_workers": 0, "cleanup_error": "", "discovery_error": "",
            "scope": "unit parent observation", "forced": False, "epoch": 1,
            "source_activation": binding}
    if stop_change:
        stop_change(stop)
    _write(sample.data / "diagnostics/operator-stop.json", _encoded(stop))
    owner_sha = _sha((sample.state / "activation-owner.json").read_bytes())
    retired = {"schema": "angerona.source-activation-core-retired/v1",
               "launch_id": sample.owner["launch_id"], "core_pid": sample.owner["core_pid"],
               "core_birth": sample.owner["core_birth"], "core_exit_code": 0,
               "native_wait0": True, "owner_sha256": owner_sha}
    retired_raw = _encoded(retired)
    _write(sample.state / "launches" / sample.owner["launch_id"] / "core-retired.json", retired_raw)
    script = "tools/Resume-AngeronaSourceActivation.ps1" if reconcile else "tools/Invoke-AngeronaSourceStartup.ps1"
    script_path = operation / "broker" / script if reconcile else sample.root / script
    value = {"schema": 1, "operation": "reconcile" if reconcile else "activate",
             "guard_nonce": os.urandom(16).hex(), "launch_id": sample.owner["launch_id"],
             "activation_id": plan["activation_id"], "plan_sha256": plan["plan_sha256"],
             "request_sha256": request["request_sha256"], "owner_sha256": owner_sha,
             "source_root": str(sample.root), "state_root": str(sample.state),
             "parent_pid": 9001, "parent_birth": sample.owner["broker_birth"],
             "parent_image": _SYSTEM_PS, "parent_script_sha256": _sha(script_path.read_bytes()),
             "root_identity": file_api.directory_identity(sample.root),
             "leases": {"runtime": True, "source_helper": True, "core": True,
                        "no_pending_repair": True, "no_active_venv": True},
             "retirement": {"core_pid": sample.owner["core_pid"], "core_birth": sample.owner["core_birth"],
                 "core_exit_code": 0, "complete": True, "gaps": [],
                 "stop_receipt_sha256": _sha(_encoded(stop)), "core_retired_sha256": _sha(retired_raw)},
             "snapshot_sha256": _sha((operation / "broker/snapshot.json").read_bytes())}
    if change:
        change(value)
    path = operation / ("guard-" + value["guard_nonce"] + ".json")
    raw = _encoded(value)
    file_api.write_new(path, raw)
    return path, _sha(raw)


def _run(sample, plan, request, guard=None, *, reconcile=False, checkpoint=lambda _p, _n: None):
    path, digest = guard or _guard(sample, plan, request, reconcile=reconcile)
    return broker.run_source_activation(sample.root, sample.state, plan["activation_id"],
        plan["plan_sha256"], request["request_sha256"], path, digest,
        reconcile=reconcile, checkpoint=checkpoint)


def test_actual_supplier_consent_guard_and_two_successive_updates_preserve_local_state(activation):
    sample = activation
    for target, expected in ((_FIRST, b"value=2\n"), (_SECOND, b"value=3\n")):
        plan = _plan(sample, target)
        request = _approve(sample, plan)
        recorded = _json(sample.state / "activation-request.json")
        expected_scope = {os.getpid(), 1001, 1002, 1003, 2001, 2002, 2101, 2201}
        assert {row["pid"] for row in recorded["retirement_scope"]} == expected_scope
        assert all(row["role"] not in {"source-update-controller", "source-update-supervisor"}
                   for row in recorded["retirement_scope"])
        result = _run(sample, plan, request)
        assert result["status"] == "committed"
        assert (sample.root / "feature.py").read_bytes() == expected
        assert (sample.root / "new_upstream.py").read_bytes() == (b"new=2\n" if target == _FIRST else b"new=3\n")
        assert (sample.root / "custom.py").read_bytes() == b"my_local_preference=True\n"
        assert not (sample.state / "activation-pending.json").exists()
        assert not (sample.state / "activation-request.json").exists()
        assert api.applied_source_base(sample.root, sample.state)["target_revision"] == target
        _protected_unchanged(sample)
    assert ("rev-parse", "--git-path", "index") in sample.git.calls
    assert any(kind == "birth" for kind, _pid in sample.native.calls)
    assert sample.composition.native.opened and sample.composition.inventory_context.native.opened


def test_declining_exact_plan_creates_no_request_or_source_mutation(activation):
    sample = activation
    plan = _plan(sample)
    before = source_stage.snapshot_local(sample.root, source_stage.source_inventory(sample.root))
    with pytest.raises(api.SourceActivationError, match="explicit current approval"):
        api.approve_source_activation(sample.state, plan["activation_id"], plan["plan_sha256"],
                                      sample.owner, accepted=False)
    assert not (sample.state / "activation-request.json").exists()
    assert source_stage.snapshot_local(sample.root, source_stage.source_inventory(sample.root)) == before
    _protected_unchanged(sample)


def test_genuine_unresolved_conflict_cannot_produce_activation_plan(activation):
    sample = activation
    _write(sample.root / "feature.py", b"local_change=4\n")
    staged = _stage(sample)
    assert staged.status == "conflicts" and "feature.py" in staged.conflicts
    with pytest.raises(api.SourceActivationError, match="Resolve every source conflict"):
        api.prepare_source_activation(sample.root, sample.state, staged.stage_id, staged.manifest_sha256)
    assert (sample.root / "feature.py").read_bytes() == b"local_change=4\n"
    assert not (sample.state / "activation-request.json").exists()


@pytest.mark.parametrize("change", ["candidate", "source", "head-bytes", "head-revision", "index", "settings"])
def test_current_plan_rejects_actual_post_review_change_before_consent(activation, change):
    sample = activation
    plan = _plan(sample)
    if change == "candidate":
        path = sample.state / "stages" / plan["stage_id"] / "candidate/feature.py"
        _write(path, b"candidate_tamper=1\n")
    elif change == "source":
        _write(sample.root / "feature.py", b"concurrent_edit=1\n")
    elif change == "head-bytes":
        _write(sample.root / ".git/HEAD", b"ref: refs/heads/foreign\n")
    elif change == "head-revision":
        sample.git.head = "e" * 40
    elif change == "index":
        _write(sample.root / ".git/index", b"changed index")
    else:
        _write(sample.data / "settings.json", b"concurrent preference edit")
    with pytest.raises((api.SourceActivationError, source_stage.SourceStageError)):
        _approve(sample, plan)
    assert not (sample.state / "activation-request.json").exists()
    assert not (sample.state / "activation-pending.json").exists()


def test_approval_cancellation_nonce_cannot_cancel_foreign_consent(activation):
    sample = activation
    plan = _plan(sample)
    approval_id = "7" * 32
    request = _approve(sample, plan, approval_id=approval_id)
    path = sample.state / "activation-request.json"
    before = path.read_bytes()
    held = api.cancel_source_activation_approval(sample.state, plan["activation_id"],
        plan["plan_sha256"], "8" * 32)
    assert held["status"] == "held" and path.read_bytes() == before
    cancelled = api.cancel_source_activation_approval(sample.state, plan["activation_id"],
        plan["plan_sha256"], approval_id)
    assert cancelled["status"] == "cancelled" and not path.exists()
    assert _json(_operation(sample, plan) / ("cancelled-" + approval_id + ".json"))["approval_id"] == approval_id
    assert len(request["request_sha256"]) == 64
    assert (sample.root / "feature.py").read_bytes() == b"value=1\n"


def test_cancel_after_request_creation_retires_only_its_own_exact_request(activation):
    sample = activation
    plan = _plan(sample)
    calls = []

    def cancelled():
        calls.append((sample.state / "activation-request.json").exists())
        return len(calls) == 2

    with pytest.raises(api.SourceActivationError, match="cancelled before dashboard handoff"):
        _approve(sample, plan, approval_id="9" * 32, cancelled=cancelled)
    assert calls == [False, True]
    assert not (sample.state / "activation-request.json").exists()
    assert (_operation(sample, plan) / ("cancelled-" + "9" * 32 + ".json")).exists()
    assert (sample.root / "feature.py").read_bytes() == b"value=1\n"


@pytest.mark.parametrize("case", ["lease-int", "wrong-root", "foreign-request", "wrong-parent", "extra-field"])
def test_exact_hash_does_not_authorize_malformed_parent_guard(activation, case):
    sample = activation
    plan, request = _plan(sample), None
    request = _approve(sample, plan)

    def change(value):
        if case == "lease-int":
            value["leases"]["core"] = 1
        elif case == "wrong-root":
            value["root_identity"]["inode"] = "0"
        elif case == "foreign-request":
            value["request_sha256"] = "0" * 64
        elif case == "wrong-parent":
            value["parent_birth"] = "1"
        else:
            value["extra"] = True

    guard = _guard(sample, plan, request, change=change)
    with pytest.raises(broker.SourceActivationError):
        _run(sample, plan, request, guard)
    assert (sample.root / "feature.py").read_bytes() == b"value=1\n"
    assert not (sample.state / "activation-pending.json").exists()
    _protected_unchanged(sample)


@pytest.mark.parametrize("case", ["forced", "pending-worker", "cleanup-error", "unbound"])
def test_managed_stop_receipt_must_be_clean_and_exactly_bound(activation, case):
    sample = activation
    plan = _plan(sample)
    request = _approve(sample, plan)

    def change(stop):
        if case == "forced":
            stop["forced"] = True
        elif case == "pending-worker":
            stop["pending_workers"] = ["native-view-worker-_eco_worker"]
        elif case == "cleanup-error":
            stop["cleanup_error"] = "inert cleanup error"
        else:
            stop["source_activation"] = None

    guard = _guard(sample, plan, request, stop_change=change)
    with pytest.raises(broker.SourceActivationError, match="clean and bound"):
        _run(sample, plan, request, guard)
    assert not (sample.state / "activation-pending.json").exists()
    assert (sample.root / "feature.py").read_bytes() == b"value=1\n"


def test_native_parent_exit_after_guard_admission_blocks_first_publication(activation):
    sample = activation
    plan = _plan(sample)
    request = _approve(sample, plan)
    guard_path, digest = _guard(sample, plan, request)
    with broker.SourceActivationGuard(sample.root, sample.state, plan["activation_id"],
        plan["plan_sha256"], request["request_sha256"], guard_path, digest, operation="activate") as guard:
        guard.check()
        sample.native.generations[9001]["live"] = False
        with pytest.raises(broker.SourceActivationError, match="not live"):
            guard.check()
    assert (sample.root / "feature.py").read_bytes() == b"value=1\n"
    assert not (sample.state / "activation-pending.json").exists()


def test_guard_nonce_is_single_use_even_before_source_publication(activation):
    sample = activation
    plan = _plan(sample)
    request = _approve(sample, plan)
    path, digest = _guard(sample, plan, request)
    with broker.SourceActivationGuard(sample.root, sample.state, plan["activation_id"],
        plan["plan_sha256"], request["request_sha256"], path, digest, operation="activate") as guard:
        guard.claim()
        with pytest.raises(FileExistsError):
            guard.claim()
    assert not (sample.state / "activation-pending.json").exists()


@pytest.mark.parametrize("phase", ["prepared", "before-directory", "directory-created",
    "before-file", "old-preserved", "new-published", "base-prepared", "base-published"])
def test_crash_preserves_startup_barrier_then_original_broker_rolls_back(activation, phase):
    sample = activation
    plan = _plan(sample)
    request = _approve(sample, plan)
    seen = []

    def crash(current, name):
        seen.append((current, name))
        if current == phase:
            raise _Crash("inert crash at exact durable checkpoint")

    with pytest.raises(_Crash):
        _run(sample, plan, request, checkpoint=crash)
    assert any(current == phase for current, _name in seen)
    assert (sample.state / "activation-pending.json").exists()
    with pytest.raises(api.SourceActivationError, match="Interrupted source activation"):
        api.applied_source_base(sample.root, sample.state)
    restored = _run(sample, plan, request, reconcile=True)
    assert restored["status"] == "rolled_back"
    assert (sample.root / "feature.py").read_bytes() == b"value=1\n"
    assert not (sample.root / "new_upstream.py").exists()
    assert not (sample.state / "activation-pending.json").exists()
    assert api.applied_source_base(sample.root, sample.state) is None
    if phase == "directory-created":
        made = next(name for current, name in seen if current == phase)
        assert (sample.root / made).is_dir()
        assert not list((sample.root / made).iterdir())
    _protected_unchanged(sample)


def test_ordinary_publication_exception_has_real_conditional_rollback(activation):
    sample = activation
    plan = _plan(sample)
    request = _approve(sample, plan)
    faulted = []

    def fault(phase, name):
        if phase == "new-published" and not faulted:
            faulted.append(name)
            raise OSError("inert post-rename publication failure")

    result = _run(sample, plan, request, checkpoint=fault)
    assert faulted and result["status"] == "rolled_back"
    assert result["publication_failure"] == "OSError"
    assert (sample.root / "feature.py").read_bytes() == b"value=1\n"
    assert not (sample.state / "activation-pending.json").exists()
    _protected_unchanged(sample)


def test_changed_native_object_or_content_never_gets_overwritten_by_rollback(activation):
    sample = activation
    plan = _plan(sample)
    request = _approve(sample, plan)
    published = []

    def crash(phase, name):
        if phase == "new-published":
            published.append(name)
            raise _Crash()

    with pytest.raises(_Crash):
        _run(sample, plan, request, checkpoint=crash)
    target = sample.root / published[0]
    before_id = target.stat().st_ino
    with target.open("r+b") as stream:
        stream.write(b"concurrent unknown edit")
        stream.truncate()
    with pytest.raises(broker.SourceActivationError, match="unknown replacement"):
        _run(sample, plan, request, reconcile=True)
    assert target.read_bytes() == b"concurrent unknown edit"
    assert target.stat().st_ino == before_id
    assert (sample.state / "activation-pending.json").exists()
    assert (_operation(sample, plan) / "archive").is_dir()


def _tool(sample, plan, monkeypatch):
    path = _operation(sample, plan) / "broker/tools/activate_source_update.py"
    spec = importlib.util.spec_from_file_location("_original_activation_test_broker", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "os", _View(_REAL_OS, getppid=lambda: 9001))
    previous = {name: value for name, value in sys.modules.items()
                if name == "angerona" or name.startswith("angerona.")
                or name == "tools" or name.startswith("tools.")}
    actual_load = module._load_module

    def load(name, filename, raw):
        loaded = actual_load(name, filename, raw)
        if name == "angerona.updater.source_git":
            loaded._ACTIVE.set(sample.git)
        elif name == "angerona.core.source_activation_broker":
            loaded.os = _View(_REAL_OS, getppid=lambda: 9001)
        return loaded

    monkeypatch.setattr(module, "_load_module", load)
    return module, previous


def _restore_imports(previous):
    for name in list(sys.modules):
        if (name == "angerona" or name.startswith("angerona.")
                or name == "tools" or name.startswith("tools.")) and name not in previous:
            del sys.modules[name]
    sys.modules.update(previous)


@pytest.mark.parametrize("case", ["complete", "missing", "tampered", "malicious-root-import"])
def test_original_capsule_refuses_missing_or_tampered_input_and_never_imports_root_app(
    activation, monkeypatch, case
):
    sample = activation
    plan = _plan(sample)
    request = _approve(sample, plan)
    path, digest = _guard(sample, plan, request)
    capsule = _operation(sample, plan) / "broker"
    marker = sample.fixture_root / "MUST-NOT-EXECUTE"
    payload = ("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('executed')\n").encode()
    if case == "malicious-root-import":
        _write(sample.root / "src/angerona/__init__.py", payload)
        _write(sample.root / "tools/__init__.py", payload)
    tool, previous = _tool(sample, plan, monkeypatch)
    options = SimpleNamespace(root=sample.root, state_root=sample.state,
        activation_id=plan["activation_id"], plan_sha256=plan["plan_sha256"],
        request_sha256=request["request_sha256"], guard_file=path, guard_sha256=digest,
        reconcile=False)
    if case == "missing":
        (capsule / "src/angerona/core/source_activation_broker.py").unlink()
    elif case == "tampered":
        _write(capsule / "src/angerona/core/source_activation_broker.py", b"raise RuntimeError('wrong broker')\n")
    try:
        if case == "missing":
            with pytest.raises(FileNotFoundError):
                tool.run(options)
        elif case == "tampered":
            with pytest.raises(tool.BrokerBootstrapError, match="dependency pin"):
                tool.run(options)
        elif case == "malicious-root-import":
            # The exact original broker must reach the current-source fence.
            # Accept neither an arbitrary exception nor an earlier parent hold.
            try:
                tool.run(options)
            except Exception as error:
                loaded = sys.modules["angerona.core.source_activation_broker"]
                assert type(error) is loaded.SourceActivationError
                assert "Source/candidate/Git/preferences/runtime changed" in str(error)
            else:
                pytest.fail("Mixed-root source change was admitted")
        else:
            result = tool.run(options)
            assert set(result) == {"schema", "status", "activation_id", "receipt_sha256"}
            assert result["schema"] == "angerona.source-activation-output/v1"
            assert result["status"] == "committed" and result["activation_id"] == plan["activation_id"]
            guard_nonce = _json(path)["guard_nonce"]
            outcome_path = _operation(sample, plan) / ("result-" + guard_nonce + ".json")
            outcome_raw = outcome_path.read_bytes()
            outcome = json.loads(outcome_raw)
            assert _sha(outcome_raw) == result["receipt_sha256"]
            assert outcome["schema"] == "angerona.source-activation-outcome/v1"
            assert outcome["pending_present"] is False
            assert (outcome["plan_sha256"], outcome["request_sha256"], outcome["guard_sha256"]) == (
                plan["plan_sha256"], request["request_sha256"], digest)
            assert outcome["source_root"] == str(sample.root)
            assert outcome["state_root"] == str(sample.state)
            assert (sample.root / "feature.py").read_bytes() == b"value=2\n"
            _protected_unchanged(sample)
        assert not marker.exists()
        assert not (sample.state / "activation-pending.json").exists()
    finally:
        _restore_imports(previous)


@pytest.mark.parametrize("case", ["missing", "wrong-core", "nonzero-exit", "wait-unproven", "foreign-owner"])
def test_core_retirement_receipt_is_required_independently_of_clean_stop(activation, case):
    sample = activation
    plan = _plan(sample)
    request = _approve(sample, plan)
    path, digest = _guard(sample, plan, request)
    retired_path = sample.state / "launches" / sample.owner["launch_id"] / "core-retired.json"
    if case == "missing":
        retired_path.unlink()
        expected = FileNotFoundError
    else:
        retired = _json(retired_path)
        if case == "wrong-core":
            retired["core_birth"] = "1"
        elif case == "nonzero-exit":
            retired["core_exit_code"] = 1
        elif case == "wait-unproven":
            retired["native_wait0"] = False
        else:
            retired["owner_sha256"] = "0" * 64
        retired_raw = _encoded(retired)
        retired_path.write_bytes(retired_raw)
        # Supply the exact new pin so the test reaches the semantic contract,
        # not just the byte-hash check already exercised by capsule controls.
        value = _json(path)
        value["retirement"]["core_retired_sha256"] = _sha(retired_raw)
        guard_raw = _encoded(value)
        path.write_bytes(guard_raw)
        digest = _sha(guard_raw)
        expected = broker.SourceActivationError
    with pytest.raises(expected) as result:
        _run(sample, plan, request, (path, digest))
    if case != "missing":
        assert "Original retained Core exit observation" in str(result.value)
    assert not (sample.state / "activation-pending.json").exists()
    assert (sample.root / "feature.py").read_bytes() == b"value=1\n"


@pytest.mark.parametrize("state", ["live", "retired", "absent", "query-refused"])
def test_actual_controller_supervisor_lifetime_does_not_change_core_scope(activation, state):
    sample = activation
    if state == "retired":
        sample.native.generations[9002]["live"] = False
    elif state == "absent":
        del sample.native.generations[9002]
    elif state == "query-refused":
        sample.native.open_errors[9002] = 5
    supplier = sample.app._owned_process_identities_for_response
    if state == "query-refused":
        with pytest.raises(api.SourceActivationError, match="query handle"):
            supplier()
        return
    rows = supplier()
    assert any(row.pid == 9001 and row.role == "source-update-controller" for row in rows)
    assert any(row.pid == 9002 and row.role == "source-update-supervisor" for row in rows) is (state == "live")
    scope = api.capture_source_activation_retirement_scope(sample.root, sample.state, sample.owner)
    assert {row["pid"] for row in scope} == {os.getpid(), 1001, 1002, 1003, 2001, 2002, 2101, 2201}
    assert all(row["pid"] not in {9001, 9002} for row in scope)


def test_reused_supervisor_pid_is_not_a_generic_exemption_for_actual_owned_child(activation):
    sample = activation
    replacement = sample.composition.make_child((9002,))
    sample.composition.supervisor.components["scanner"].proc = replacement.owner
    identity = replacement.native.identities[9002]
    sample.native.add(9002, identity.birth_ticks, identity.image)
    rows = sample.app._owned_process_identities_for_response()
    assert any(row.pid == 9002 and row.role == "scanner" for row in rows)
    assert not any(row.pid == 9002 and row.role == "source-update-supervisor" for row in rows)
    scope = api.capture_source_activation_retirement_scope(sample.root, sample.state, sample.owner)
    assert any(row["pid"] == 9002 and row["role"] == "scanner" and
               row["birth"] == str(identity.birth_ticks) for row in scope)


@pytest.mark.parametrize("command", [
    ("rev-parse", "--git-path", "objects"), ("checkout", "main"),
    ("reset", "--hard", "HEAD"), ("config", "core.hooksPath"), ("read-tree", "HEAD"),
])
def test_unsafe_git_queries_never_reach_read_only_transport(activation, command):
    sample = activation
    before = list(sample.git.calls)
    with pytest.raises(source_git.SourceGitUnavailable, match="unsupported source Git command"):
        source_git.read_source_git(sample.root, command)
    assert sample.git.calls == before


def test_linked_worktree_actual_external_index_and_head_are_preserved(activation):
    sample = activation
    git_dir = sample.fixture_root / "worktree-admin"
    index, head = git_dir / "index", git_dir / "HEAD"
    _write(index, b"actual external index")
    _write(head, b"ref: refs/heads/worktree-source\n")
    sample.git.index_name = str(index)
    for path in (index, head):
        sample.protected[str(path.relative_to(sample.fixture_root))] = (path.read_bytes(), path.stat().st_ino)
    plan = _plan(sample)
    document = _json(_operation(sample, plan) / "plan.json")
    assert document["git"]["index_path"] == str(index)
    assert document["git"]["head_path"] == str(head)
    request = _approve(sample, plan)
    assert _run(sample, plan, request)["status"] == "committed"
    _protected_unchanged(sample)


def test_unknown_directory_created_at_precreation_checkpoint_holds_rollback(activation):
    sample = activation
    plan = _plan(sample)
    request = _approve(sample, plan)
    unknown = []

    def race(phase, name):
        if phase == "before-directory":
            directory = sample.root / name
            directory.mkdir()
            marker = directory / "unrelated.bin"
            marker.write_bytes(b"unowned directory contents")
            unknown.append((directory, marker.stat().st_ino))
            raise _Crash()

    with pytest.raises(_Crash):
        _run(sample, plan, request, checkpoint=race)
    with pytest.raises(broker.SourceActivationError, match="without an owned creation receipt"):
        _run(sample, plan, request, reconcile=True)
    directory, original_id = unknown[0]
    assert (directory / "unrelated.bin").read_bytes() == b"unowned directory contents"
    assert (directory / "unrelated.bin").stat().st_ino == original_id
    assert (sample.state / "activation-pending.json").exists()


@pytest.mark.parametrize("when", ["prepare", "approve"])
@pytest.mark.parametrize("reason", ["logical-bytes", "free-reserve"])
def test_storage_hold_precedes_any_request_stop_or_source_effect(
    activation, monkeypatch, when, reason
):
    sample = activation
    staged = _stage(sample)
    plan = None
    if when == "approve":
        plan = api.prepare_source_activation(sample.root, sample.state,
                                            staged.stage_id, staged.manifest_sha256)
    review = storage.review_source_update_storage(sample.root, sample.state)
    before = (sample.root / "feature.py").read_bytes()
    existing_paths = {row["activation_id"] for row in review["operations"]}
    if reason == "logical-bytes":
        # The low constant models an explicitly exhausted shared logical cap;
        # no giant physical files or unrelated disk pressure is created.
        monkeypatch.setattr(storage, "DEFAULT_MAX_BYTES", review["retained_bytes"])
    else:
        observed = storage.shutil
        monkeypatch.setattr(storage, "shutil", _View(observed, disk_usage=lambda _path:
            SimpleNamespace(free=storage.MIN_FREE_BYTES - 1)))
    with pytest.raises(storage.SourceActivationStorageHeld) as result:
        if when == "prepare":
            api.prepare_source_activation(sample.root, sample.state,
                                          staged.stage_id, staged.manifest_sha256)
        else:
            _approve(sample, plan)
    assert ("byte limit" if reason == "logical-bytes" else "free-space reserve") in str(result.value)
    assert result.value.review["retained_bytes"] >= review["retained_bytes"]
    assert (sample.root / "feature.py").read_bytes() == before
    assert not (sample.state / "activation-request.json").exists()
    assert not (sample.state / "activation-pending.json").exists()
    assert not (sample.data / "diagnostics/operator-stop.json").exists()
    assert not sample.app._shutdown_requested.is_set()
    after = storage.review_source_update_storage(sample.root, sample.state)
    assert {row["activation_id"] for row in after["operations"]} == existing_paths
    assert after["automatic_deletion"] is False and after["startup_inhibited"] is False
    _protected_unchanged(sample)


def test_default_two_real_completed_backups_hold_third_before_stop(activation):
    from angerona.core.werfault_guard import OwnedProcessReadError

    sample = activation
    for attempt, target in enumerate((_FIRST, _SECOND), 1):
        plan = _plan(sample, target)
        try:
            request = _approve(sample, plan)
        except OwnedProcessReadError as error:
            if error.reason_code == "supplier_failed":
                # The production exception hides the supplier context. Report
                # only a fixed test gate, never the original message or paths.
                try:
                    args = getattr(error.__context__, "args", ())
                    message = args[0] if len(args) == 1 and type(args[0]) is str else None
                    gate = {
                        "Owned AI observation deadline": "ai-observation-deadline",
                        "Owned AI stop custody is busy": "ai-stop-custody-busy",
                        "Owned AI registry is busy": "ai-registry-busy",
                        "Owned AI launch/STOP admission is unsettled": "ai-admission-unsettled",
                        "Configured ownership lifetime or inventory routing changed": "inventory-routing-changed",
                        "Configured inventory native custody is unavailable": "inventory-custody-unavailable",
                        "Complete companion ownership observation deadline": "companion-observation-deadline",
                        "Source controller native query handle is unavailable": "source-controller-query-unavailable",
                        "Expected external source controller is not bound": "source-controller-unbound",
                    }.get(message, "unclassified")
                    print(f"SOURCE_ACTIVATION_FIXTURE_OWNERSHIP attempt={attempt} gate={gate}", flush=True)
                except Exception:
                    pass  # Preserve the same production failure and traceback.
            raise
        assert _run(sample, plan, request)["status"] == "committed"
    review = storage.review_source_update_storage(sample.root, sample.state)
    assert review["budget"]["completed_backups"] == 2
    assert review["completed_backups"] == 2
    assert review["automatic_deletion"] is False and review["startup_inhibited"] is False
    original_ops = {row["activation_id"] for row in review["operations"]}
    assert len(original_ops) == 2
    third = "f" * 40
    incoming = dict(sample.second, **{"feature.py": b"value=4\n"})
    sample.archives[third] = _archive(incoming, third)
    # The managed staging entry performs the same admission before creating a
    # third stage; the count hold must precede both prepare and operator STOP.
    stages = sample.state / "stages"
    stage_ids = {path.name: (path.stat().st_dev, path.stat().st_ino) for path in stages.iterdir()}
    with pytest.raises(storage.SourceActivationStorageHeld, match="completed backup count") as held:
        _stage(sample, third)
    assert held.value.review["completed_backups"] == 2
    assert {path.name: (path.stat().st_dev, path.stat().st_ino) for path in stages.iterdir()} == stage_ids
    assert (sample.root / "feature.py").read_bytes() == b"value=3\n"
    assert not (sample.state / "activation-request.json").exists()
    assert not (sample.state / "activation-pending.json").exists()
    assert not sample.app._shutdown_requested.is_set()
    after = storage.review_source_update_storage(sample.root, sample.state)
    assert {row["activation_id"] for row in after["operations"]} == original_ops
    assert after["protected_ids"]
    current = api.applied_source_base(sample.root, sample.state)
    assert current["activation_id"] in after["protected_ids"]
    assert current["target_revision"] == _SECOND
    _protected_unchanged(sample)


@pytest.mark.parametrize("policy", [
    {"schema": "angerona.source-activation-storage-policy/v1", "accepted": False,
     "completed_backups": 8, "max_bytes": 2 * 1024**3},
    {"schema": "angerona.source-activation-storage-policy/v1", "accepted": True,
     "completed_backups": 9, "max_bytes": 2 * 1024**3},
    {"schema": "angerona.source-activation-storage-policy/v1", "accepted": True,
     "completed_backups": True, "max_bytes": 2 * 1024**3},
])
def test_unapproved_or_unbounded_storage_policy_cannot_raise_limits(activation, policy):
    sample = activation
    _write(sample.state / "activation-storage-policy.json", _encoded(policy))
    before = (sample.root / "feature.py").read_bytes()
    with pytest.raises(storage.SourceActivationStorageHeld, match="explicit bounded policy"):
        storage.require_source_update_storage(sample.root, sample.state,
                                             additional_bytes=1, new_completed_backup=True)
    assert (sample.root / "feature.py").read_bytes() == before
    assert not (sample.state / "activation-request.json").exists()
    assert not (sample.state / "activation-pending.json").exists()


def test_queued_reconfirmation_reuses_exact_reviewed_plan_without_reminting(activation):
    sample = activation
    plan = _plan(sample)
    queued = api.queue_source_activation_proposal(sample.state, plan["activation_id"],
                                                 plan["plan_sha256"])
    assert queued["status"] == "queued-reconfirm"
    proposal = sample.state / "activation-proposal.json"
    planned = _operation(sample, plan) / "plan.json"
    originals = {path: (path.read_bytes(), path.stat().st_ino) for path in (proposal, planned)}
    operations = {path.name for path in (sample.state / "activations").iterdir()}
    for _ in range(2):
        inspected = api.inspect_source_activation(sample.root, sample.state)
        assert inspected["status"] == "queued-reconfirm"
        assert inspected["activation_id"] == plan["activation_id"]
        assert inspected["plan_sha256"] == plan["plan_sha256"]
        assert {path.name for path in (sample.state / "activations").iterdir()} == operations
        for path, expected in originals.items():
            assert (path.read_bytes(), path.stat().st_ino) == expected
    assert not (sample.state / "activation-request.json").exists()
    assert not sample.app._shutdown_requested.is_set()
    _protected_unchanged(sample)


@pytest.mark.parametrize("selection", ["foreign-id", "foreign-plan", "exact"])
def test_declining_queued_proposal_retires_only_exact_unapproved_selection(activation, selection):
    sample = activation
    plan = _plan(sample)
    api.queue_source_activation_proposal(sample.state, plan["activation_id"], plan["plan_sha256"])
    proposal = sample.state / "activation-proposal.json"
    before, identity = proposal.read_bytes(), proposal.stat().st_ino
    result = api.cancel_source_activation_proposal(sample.state,
        "0" * 32 if selection == "foreign-id" else plan["activation_id"],
        "0" * 64 if selection == "foreign-plan" else plan["plan_sha256"])
    if selection == "exact":
        assert result["status"] == "cancelled" and not proposal.exists()
        archives = list(_operation(sample, plan).glob("proposal-cancelled-*.json"))
        assert len(archives) == 1
        assert (archives[0].read_bytes(), archives[0].stat().st_ino) == (before, identity)
        assert api.inspect_source_activation(sample.root, sample.state) == {"status": "absent"}
    else:
        assert result["status"] == "held"
        assert (proposal.read_bytes(), proposal.stat().st_ino) == (before, identity)
        assert not list(_operation(sample, plan).glob("proposal-cancelled-*.json"))
    assert not (sample.state / "activation-request.json").exists()
    assert not sample.app._shutdown_requested.is_set()
    _protected_unchanged(sample)


@pytest.mark.parametrize("fail_request", [False, True])
def test_exact_queued_proposal_is_archived_only_after_durable_request(
    activation, monkeypatch, fail_request
):
    sample = activation
    plan = _plan(sample)
    api.queue_source_activation_proposal(sample.state, plan["activation_id"], plan["plan_sha256"])
    proposal = sample.state / "activation-proposal.json"
    original = proposal.read_bytes(), proposal.stat().st_ino
    request_path = sample.state / "activation-request.json"
    actual_write, actual_rename = api._new_json, file_api.RetainedFile.rename
    durable, archived = [], []
    failure = OSError("inert refusal before request publication")

    def write(path, value):
        if Path(path) == request_path and fail_request:
            raise failure
        result = actual_write(path, value)
        if Path(path) == request_path:
            durable.append(request_path.read_bytes())
        return result

    def rename(owner, path):
        if owner.path == proposal:
            assert durable and request_path.read_bytes() == durable[0]
            assert owner.read(api.MAX_METADATA) == original[0]
            assert os.fstat(owner.fd).st_ino == original[1]
            archived.append(Path(path))
        return actual_rename(owner, path)

    monkeypatch.setattr(api, "_new_json", write)
    monkeypatch.setattr(file_api.RetainedFile, "rename", rename)
    if fail_request:
        with pytest.raises(OSError) as result:
            _approve(sample, plan, approval_id="6" * 32)
        assert result.value is failure
        assert not durable and not archived and not request_path.exists()
        assert (proposal.read_bytes(), proposal.stat().st_ino) == original
    else:
        request = _approve(sample, plan, approval_id="6" * 32)
        assert request["request_sha256"] == _sha(durable[0])
        expected = _operation(sample, plan) / ("accepted-proposal-" + "6" * 32 + ".json")
        assert archived == [expected] and not proposal.exists()
        assert (expected.read_bytes(), expected.stat().st_ino) == original
        assert api.inspect_source_activation(sample.root, sample.state)["status"] == "requested"
    assert not sample.app._shutdown_requested.is_set()
    _protected_unchanged(sample)


@pytest.mark.parametrize("implementation", ["core", "original-broker"])
def test_process_query_close_lost_ack_retains_custody_without_numeric_retry(
    activation, monkeypatch, implementation
):
    sample = activation
    module = api if implementation == "core" else broker
    process = module._NativeProcess(sample.owner["broker_pid"], sample.owner["broker_birth"],
                                    sample.owner["broker_image"])
    token = process.handle
    close_calls = []
    actual = sample.native.close
    failure = _Crash("inert close completed but acknowledgement was lost")

    def close(handle):
        if sample.native.number(handle) != token:
            return actual(handle)
        close_calls.append(sample.native.number(handle))
        assert actual(handle) is True
        raise failure

    monkeypatch.setattr(sample.native, "CloseHandle", _Function(close))
    with pytest.raises(_Crash) as result:
        process.close()
    assert result.value is failure and close_calls == [token]
    assert token not in sample.native.handles
    assert process.handle is None and process.close_held is True
    assert module._NativeProcess._close_holds == [(process, token)]
    if module is api:
        assert api.source_activation_resource_retirement_proven() is False
    with pytest.raises(module.SourceActivationError, match="retirement is held"):
        process.close()
    before = list(sample.native.calls)
    with pytest.raises(module.SourceActivationError, match="Prior source-controller native retirement"):
        module._NativeProcess(sample.owner["broker_pid"], sample.owner["broker_birth"],
                              sample.owner["broker_image"])
    assert sample.native.calls == before and close_calls == [token]


def _assert_source_workspace_transaction(sample, monkeypatch, rollback):
    plan = _plan(sample)
    request = _approve(sample, plan)
    actual = file_api.RetainedFile.rename
    moves = []

    def rename(owner, target):
        origin, target = owner.path, Path(target)
        before = os.fstat(owner.fd)
        result = actual(owner, target)
        after = os.fstat(owner.fd)
        moves.append((origin, target, (before.st_dev, before.st_ino),
                      (after.st_dev, after.st_ino)))
        return result

    def checkpoint(phase, name):
        if rollback and phase == "new-published":
            raise RuntimeError("inert failure after genuine source-local publication")

    monkeypatch.setattr(file_api.RetainedFile, "rename", rename)
    result = _run(sample, plan, request, checkpoint=checkpoint)
    assert result["status"] == ("rolled_back" if rollback else "committed")
    operation = _operation(sample, plan)
    transaction = _json(operation / "transaction.json")
    local = sample.root / transaction["workspace"]["relative"]
    assert local.parent == sample.root / ".tmp"
    assert transaction["workspace"]["identity"] == file_api.directory_identity(local)
    payload_moves = [row for row in moves if sample.root in row[0].parents]
    assert payload_moves
    assert all(sample.root in target.parents and before == after
               for _origin, target, before, after in payload_moves)
    assert any(target.parent == local / "old" for _origin, target, _before, _after in payload_moves)
    assert any(origin.parent == local / "new" and sample.root in target.parents
               for origin, target, _before, _after in payload_moves)
    if rollback:
        assert any(target.parent == local / "rolled-back"
                   for _origin, target, _before, _after in payload_moves)
        assert (sample.root / "feature.py").read_bytes() == b"value=1\n"
    else:
        assert (sample.root / "feature.py").read_bytes() == b"value=2\n"
    assert not any((operation / leaf).exists() for leaf in ("old", "new", "rolled-back"))
    assert (operation / "archive").is_dir() and (operation / "journal.jsonl").is_file()
    for raw in sample.user.values():
        assert (operation / "archive" / _sha(raw)).read_bytes() == raw
    _protected_unchanged(sample)


@pytest.mark.parametrize("rollback", [False, True])
def test_source_payload_native_moves_use_source_workspace_and_control_archive_stays_separate(
    activation, monkeypatch, rollback
):
    _assert_source_workspace_transaction(activation, monkeypatch, rollback)


@pytest.mark.parametrize("activation", ["actual-d-source-c-profile"], indirect=True)
@pytest.mark.parametrize("rollback", [False, True])
def test_actual_d_source_c_profile_transaction_keeps_archive_and_native_moves_on_correct_volumes(
    activation, monkeypatch, rollback
):
    sample = activation
    assert sample.root.drive.casefold() == "d:" and sample.state.drive.casefold() == "c:"
    assert sample.profile_fixture is not None
    assert sample.root.stat().st_dev != sample.state.stat().st_dev
    _assert_source_workspace_transaction(sample, monkeypatch, rollback)
    review = storage.review_source_update_storage(sample.root, sample.state)
    assert review["same_volume"] is False
    control_bytes = sum(path.stat().st_size for path in sample.state.rglob("*") if path.is_file())
    source_bytes = sum(path.stat().st_size for path in (sample.root / ".tmp").rglob("*") if path.is_file())
    assert source_bytes > 0 and control_bytes > 0
    assert review["retained_bytes"] == control_bytes + source_bytes
    assert file_api.directory_identity(sample.profile_parent) == sample.profile_identity
    _protected_unchanged(sample)


@pytest.mark.parametrize("limited", ["control", "source"])
def test_separate_volume_reserve_hold_uses_actual_plan_before_stop(activation, monkeypatch, limited):
    sample = activation
    plan = _plan(sample)
    value = _json(_operation(sample, plan) / "plan.json")
    assert 0 < value["source_reserve_bytes"] <= value["storage_reserve_bytes"]
    # ONLY the disk-volume selection/free observations are modeled; all file
    # identities remain actual. This does not claim real C:/D: I/O coverage.
    monkeypatch.setattr(storage, "_same_volume", lambda _root, _state: False)
    control = value["storage_reserve_bytes"] - value["source_reserve_bytes"]
    free = {sample.state: storage.MIN_FREE_BYTES + control,
            sample.root: storage.MIN_FREE_BYTES + value["source_reserve_bytes"]}
    free[sample.state if limited == "control" else sample.root] -= 1
    monkeypatch.setattr(storage, "shutil", _View(storage.shutil,
        disk_usage=lambda path: SimpleNamespace(free=free[Path(path)])))
    before = (sample.root / "feature.py").read_bytes()
    with pytest.raises(storage.SourceActivationStorageHeld, match="required volume") as result:
        _approve(sample, plan)
    assert result.value.review["same_volume"] is False
    assert result.value.review["source_free_bytes"] == free[sample.root]
    assert result.value.review["free_bytes"] == free[sample.state]
    assert not (sample.state / "activation-request.json").exists()
    assert not (sample.state / "activation-pending.json").exists()
    assert not sample.app._shutdown_requested.is_set()
    assert (sample.root / "feature.py").read_bytes() == before
    _protected_unchanged(sample)


@pytest.mark.parametrize("implementation", ["core", "original-broker"])
@pytest.mark.parametrize("shape", ["dotted-key", "nested-array"])
def test_actual_vendored_parser_bounds_reject_without_runtime_contract_grant(implementation, shape):
    module = api if implementation == "core" else broker
    if shape == "dotted-key":
        raw = (".".join(["a"] * (toml_parser.MAX_KEY_PARTS + 1)) + "=1\n").encode()
    else:
        levels = toml_parser.MAX_INLINE_NESTING + 1
        raw = ("a=" + "[" * levels + "0" + "]" * levels + "\n").encode()
    # The unchanged vendored parser documents RecursionError for these bounds.
    # Both actual caller boundaries must translate it into a typed held result.
    with pytest.raises(RecursionError):
        _source_tomli.loads(raw.decode())
    with pytest.raises(module.SourceActivationError, match="runtime dependency contract") as held:
        module._dependency_contract({"pyproject.toml": raw})
    assert isinstance(held.value.__cause__, RecursionError)


@pytest.mark.parametrize("edit", ["version-only", "metadata-only", "dependencies", "requires-python", "scripts"])
def test_real_plan_allows_metadata_version_but_holds_runtime_contract_changes(activation, edit):
    sample = activation
    incoming = dict(sample.first)
    project = sample.base["pyproject.toml"]
    if edit == "version-only":
        version = _source_tomli.loads(project.decode("utf-8-sig"))["project"]["version"]
        old = ('version = "' + version + '"').encode()
        assert project.count(old) == 1
        changed = project.replace(old, b'version = "99.0.1"', 1)
    elif edit == "metadata-only":
        changed = project + b'\n[tool.angerona_fixture]\nreviewed = true\n'
    elif edit == "dependencies":
        marker = b"dependencies = ["
        assert project.count(marker) == 1
        newline = b"\r\n" if b"\r\n" in project else b"\n"
        changed = project.replace(marker, marker + newline + b'    "unapproved-runtime",', 1)
    elif edit == "requires-python":
        assert project.count(b'requires-python = ">=3.10"') == 1
        changed = project.replace(b'requires-python = ">=3.10"', b'requires-python = ">=3.12"', 1)
    else:
        assert project.count(b'angerona = "angerona.__main__:main"') == 1
        changed = project.replace(b'angerona = "angerona.__main__:main"', b'angerona = "unsafe:main"', 1)
    incoming["pyproject.toml"] = changed
    incoming, _ = derive_recovery_coherent_tree(incoming)
    sample.archives[_FIRST] = _archive(incoming, _FIRST)
    if edit in {"version-only", "metadata-only"}:
        plan = _plan(sample)
        request = _approve(sample, plan)
        assert _run(sample, plan, request)["status"] == "committed"
        assert (sample.root / "pyproject.toml").read_bytes() == changed
    else:
        staged = _stage(sample)
        assert staged.status == "prepared"
        with pytest.raises(api.SourceActivationError, match="Dependency or Python ABI"):
            api.prepare_source_activation(sample.root, sample.state, staged.stage_id, staged.manifest_sha256)
        assert (sample.root / "pyproject.toml").read_bytes() == sample.base["pyproject.toml"]
        assert not (sample.state / "activation-request.json").exists()
        assert not sample.app._shutdown_requested.is_set()
    _protected_unchanged(sample)


@pytest.mark.parametrize("phase", ["started", "sample", "stop"])
def test_optional_observer_exception_does_not_end_default_cache_loop_or_supervisor_stop(
    activation, monkeypatch, phase
):
    sample = activation
    owner = sample.app._source_update_controller
    # Composition intentionally supplies only native ownership os fields. The
    # real observer loop additionally reads environ before its default sample.
    monkeypatch.setattr(manager_module, "os", _View(manager_module.os, environ=os.environ))
    manager = ResilienceManager.__new__(ResilienceManager)
    manager._stop = threading.Event()
    manager._source_update_observer_error = ""
    published, stopped, calls = [], [], []
    sampled_twice = threading.Event()

    class SchedulingCache:
        # Explicit scheduling-only cache; it grants no HMAC/native identity or
        # response authority. Actual optional controller methods still execute.
        def __init__(self):
            self.samples, self.closed, self.stopped, self.refreshed = 0, False, False, 0

        def sample(self, *, held):
            self.samples += 1
            if self.samples >= 2:
                sampled_twice.set()

        def refresh_owned_processes(self):
            self.refreshed += 1

        def mark_stopped(self):
            self.stopped = True

        def close(self):
            self.closed = True

    cache = manager._component_heartbeat_cache = SchedulingCache()
    manager._sup = SimpleNamespace(components={}, request_stop=lambda: stopped.append(True))
    manager._publish = lambda *args: published.append(args)
    manager.set_source_update_controller(owner)
    name = "heartbeat_" + phase
    actual = getattr(owner, name)

    def fail_after_actual(*args):
        actual(*args)
        calls.append((name, threading.current_thread()))
        raise OSError("inert optional observer failure after actual method")

    monkeypatch.setattr(owner, name, fail_after_actual)
    worker = threading.Thread(target=manager._component_heartbeat_loop,
                              name="actual-source-observer-isolation")
    worker.start()
    try:
        assert sampled_twice.wait(8.0)
        manager.request_stop()
        worker.join(8.0)
        assert not worker.is_alive()
        assert calls and manager._source_update_observer_error == "OSError"
        assert cache.samples >= 2 and cache.refreshed >= 2
        assert cache.closed and cache.stopped and stopped == [True]
        assert published == []
        if phase == "started":
            assert owner.heartbeat_retired(worker) is False
        else:
            assert owner.heartbeat_retired(worker) is True
    finally:
        if worker.is_alive():
            manager.request_stop()
            worker.join(8.0)
        assert not worker.is_alive()
        if not getattr(owner, "_observer_closed", False):
            api.SourceActivationController.heartbeat_close(owner)


@pytest.mark.parametrize("change", ["unknown-entry", "replaced-generation"])
def test_reconcile_holds_unknown_or_replaced_source_workspace_without_source_effect(
    activation, change
):
    sample = activation
    plan = _plan(sample)
    request = _approve(sample, plan)

    def crash(phase, name):
        if phase == "new-published":
            raise _Crash("inert interruption with real workspace/source effects retained")

    with pytest.raises(_Crash):
        _run(sample, plan, request, checkpoint=crash)
    transaction = _json(_operation(sample, plan) / "transaction.json")
    local = sample.root / transaction["workspace"]["relative"]
    if change == "unknown-entry":
        evidence = local / "unknown-user-data.txt"
        evidence.write_bytes(b"must never be removed or adopted")
    else:
        marker = (local / "workspace.json").read_bytes()
        retained = sample.fixture_root / "unknown-preserved-original-workspace"
        local.rename(retained)
        assert private_directory(local, create=True)
        for leaf in ("new", "old", "rolled-back"):
            assert private_directory(local / leaf, create=True)
        file_api.write_new(local / "workspace.json", marker)
        evidence = retained / "workspace.json"
    original = evidence.read_bytes(), evidence.stat().st_dev, evidence.stat().st_ino
    before = source_stage.snapshot_local(sample.root, source_stage.source_inventory(sample.root))
    with pytest.raises(workspace_api.SourceActivationWorkspaceError):
        _run(sample, plan, request, reconcile=True)
    assert source_stage.snapshot_local(sample.root, source_stage.source_inventory(sample.root)) == before
    assert (evidence.read_bytes(), evidence.stat().st_dev, evidence.stat().st_ino) == original
    assert (sample.state / "activation-pending.json").exists()
    assert not (_operation(sample, plan) / "rolled-back.json").exists()
    _protected_unchanged(sample)
