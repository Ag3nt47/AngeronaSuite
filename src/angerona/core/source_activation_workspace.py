"""Exact source-local rename workspace for one approved activation plan.

Control records and complete archives remain under the separate state root.
This helper grants no approval, retirement, reuse, cleanup or source authority.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

from angerona.core.source_activation_file import (
    directory_identity, plain_path, read_exact, write_new,
)
from angerona.core.startup_recovery import private_directory, private_repair_file


_SCHEMA = "angerona.source-activation-workspace/v1"
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_DECIMAL = re.compile(r"[0-9]{1,40}\Z")
_MARKER_KEYS = frozenset(("schema", "source_root", "state_root", "activation_id",
    "plan_nonce", "plan_sha256", "root_identity", "workspace_identity"))
_LEAVES = ("new", "old", "rolled-back")
_MAX_MARKER = 16 * 1024
_MAX_PLAN = 16 * 1024**2


class SourceActivationWorkspaceError(RuntimeError):
    """Preserve an absent, foreign, incomplete or changed activation workspace."""


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _identity(value):
    return (type(value) is dict and set(value) == {"device", "inode"}
            and all(type(value[key]) is str and _DECIMAL.fullmatch(value[key])
                    for key in ("device", "inode")))


def _absolute_directory(value):
    if not isinstance(value, (str, Path)):
        raise SourceActivationWorkspaceError("Workspace scope must be an explicit directory")
    path = Path(value)
    if (not path.is_absolute() or ".." in path.parts
            or str(path).startswith(("\\\\", "//"))):
        raise SourceActivationWorkspaceError("Workspace scope is not a plain local absolute path")
    path = plain_path(path, directory=True)
    directory_identity(path)  # Missing final directories must never verify.
    return path


def _scope(root, plan, state=None, plan_sha256=None):
    root = _absolute_directory(root)
    if (type(plan) is not dict or plan.get("schema") != "angerona.source-activation-plan/v1"
            or type(plan.get("source_root")) is not str
            or plan["source_root"] != str(root)
            or type(plan.get("state_root")) is not str
            or type(plan.get("activation_id")) is not str
            or not _HEX32.fullmatch(plan["activation_id"])
            or type(plan.get("plan_nonce")) is not str
            or not _HEX32.fullmatch(plan["plan_nonce"])
            or not _identity(plan.get("root_identity"))
            or plan["root_identity"] != directory_identity(root)):
        raise SourceActivationWorkspaceError("Workspace plan scope or native root identity changed")
    expected_state = _absolute_directory(plan["state_root"])
    if str(expected_state) != plan["state_root"]:
        raise SourceActivationWorkspaceError("Workspace state scope is not canonical")
    if state is not None and _absolute_directory(state) != expected_state:
        raise SourceActivationWorkspaceError("Workspace belongs to another state scope")
    if plan_sha256 is not None:
        if type(plan_sha256) is not str or not _HEX64.fullmatch(plan_sha256):
            raise SourceActivationWorkspaceError("Workspace plan pin is invalid")
        raw = _encoded(plan)
        body = dict(plan)
        body.pop("activation_id")
        if (len(raw) > _MAX_PLAN or _sha(raw) != plan_sha256
                or _sha(_encoded(body))[:32] != plan["activation_id"]):
            raise SourceActivationWorkspaceError("Workspace plan content identity changed")
    return root, expected_state


def workspace_path(root, plan):
    """Derive one fixed nonce path; no descriptor or caller path selects it."""
    root, _state = _scope(root, plan)
    return root / ".tmp" / ("source-activation-" + plan["plan_nonce"])


def _private_new(path):
    if os.path.lexists(path):
        raise SourceActivationWorkspaceError("An activation workspace destination already exists")
    # Original helper uses exclusive native CreateDirectoryW with a protected
    # current-user/SYSTEM/Administrators ACL; it does not rewrite an existing ACL.
    if not private_directory(path, create=True):
        raise SourceActivationWorkspaceError("New activation workspace lacks private custody")
    plain_path(path, directory=True)
    if not private_directory(path, create=False):
        raise SourceActivationWorkspaceError("New activation workspace privacy changed")


def _parents(root, temporary, root_identity, temporary_identity):
    if (directory_identity(root) != root_identity
            or directory_identity(temporary) != temporary_identity
            or temporary_identity["device"] != root_identity["device"]):
        raise SourceActivationWorkspaceError("Activation workspace parent generation changed")


def _marker(root, state, plan, plan_sha256, workspace_identity):
    return {"schema": _SCHEMA, "source_root": str(root), "state_root": str(state),
            "activation_id": plan["activation_id"], "plan_nonce": plan["plan_nonce"],
            "plan_sha256": plan_sha256, "root_identity": dict(plan["root_identity"]),
            "workspace_identity": dict(workspace_identity)}


def _descriptor(plan, workspace_identity, raw):
    return {"relative": ".tmp/source-activation-" + plan["plan_nonce"],
            "identity": dict(workspace_identity), "marker_sha256": _sha(raw)}


def create_workspace(root, state, plan, plan_sha256):
    """Create absent-only private custody; preserve every incomplete creation."""
    root, state = _scope(root, plan, state, plan_sha256)
    root_identity = directory_identity(root)
    path = workspace_path(root, plan)
    temporary = path.parent
    if not os.path.lexists(temporary):
        _private_new(temporary)
    else:
        plain_path(temporary, directory=True)  # Existing .tmp ACL is never changed.
    temporary_identity = directory_identity(temporary)
    _parents(root, temporary, root_identity, temporary_identity)
    _private_new(path)  # Any collision or raced creation refuses; never adopt it.
    workspace_identity = directory_identity(path)
    if workspace_identity["device"] != root_identity["device"]:
        raise SourceActivationWorkspaceError("Activation workspace is not on the source volume")
    _parents(root, temporary, root_identity, temporary_identity)
    raw = _encoded(_marker(root, state, plan, plan_sha256, workspace_identity))
    if len(raw) > _MAX_MARKER:
        raise SourceActivationWorkspaceError("Workspace marker exceeds its fixed bound")
    write_new(path / "workspace.json", raw)  # First payload, before all staging dirs.
    for leaf in _LEAVES:
        _parents(root, temporary, root_identity, temporary_identity)
        if directory_identity(path) != workspace_identity:
            raise SourceActivationWorkspaceError("Activation workspace generation changed")
        _private_new(path / leaf)
    expected = _descriptor(plan, workspace_identity, raw)
    _actual_path, actual = validate_workspace(root, state, plan, plan_sha256, expected)
    _parents(root, temporary, root_identity, temporary_identity)
    return actual


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SourceActivationWorkspaceError("Workspace marker has duplicate fields")
        result[key] = value
    return result


def validate_workspace(root, state, plan, plan_sha256, descriptor=None):
    """Verify only the derived exact workspace; no creation, repair or reuse."""
    root, state = _scope(root, plan, state, plan_sha256)
    root_identity = directory_identity(root)
    path = workspace_path(root, plan)
    temporary_identity = directory_identity(path.parent)
    _parents(root, path.parent, root_identity, temporary_identity)
    plain_path(path, directory=True)
    if not private_directory(path, create=False):
        raise SourceActivationWorkspaceError("Activation workspace is not private")
    workspace_identity = directory_identity(path)
    if workspace_identity["device"] != root_identity["device"]:
        raise SourceActivationWorkspaceError("Activation workspace volume differs from source")
    marker_path = path / "workspace.json"
    if not private_repair_file(marker_path):
        raise SourceActivationWorkspaceError("Activation workspace marker is not private")
    raw = read_exact(marker_path, _MAX_MARKER)
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise SourceActivationWorkspaceError("Activation workspace marker is malformed") from error
    expected = _marker(root, state, plan, plan_sha256, workspace_identity)
    if (type(value) is not dict or set(value) != _MARKER_KEYS or value != expected
            or _encoded(value) != raw):
        raise SourceActivationWorkspaceError("Activation workspace marker binding changed")
    names = set()
    with os.scandir(path) as entries:
        for entry in entries:
            if len(names) >= 4:
                raise SourceActivationWorkspaceError("Unknown activation workspace entries remain held")
            names.add(entry.name)
    if names != {"workspace.json", *_LEAVES}:
        raise SourceActivationWorkspaceError("Activation workspace is incomplete or has unknown entries")
    for leaf in _LEAVES:
        child = plain_path(path / leaf, directory=True)
        if (not private_directory(child, create=False)
                or directory_identity(child)["device"] != root_identity["device"]):
            raise SourceActivationWorkspaceError("Activation staging directory lacks private source-volume custody")
    actual = _descriptor(plan, workspace_identity, raw)
    if descriptor is not None and (type(descriptor) is not dict
            or set(descriptor) != {"relative", "identity", "marker_sha256"}
            or type(descriptor["relative"]) is not str
            or not _identity(descriptor["identity"])
            or type(descriptor["marker_sha256"]) is not str
            or not _HEX64.fullmatch(descriptor["marker_sha256"])
            or descriptor != actual):
        raise SourceActivationWorkspaceError("Activation workspace descriptor changed")
    _parents(root, path.parent, root_identity, temporary_identity)
    if directory_identity(path) != workspace_identity:
        raise SourceActivationWorkspaceError("Activation workspace changed during verification")
    return path, actual
