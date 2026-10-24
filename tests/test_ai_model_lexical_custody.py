"""Original-name custody controls for the actual model admission helpers.

Metadata stand-ins execute only the source helpers. They do not replace a hash,
key, baseline, verifier or transport. Real-file cases use tiny new temp fixtures;
no host model/key or listener is consulted. Native symlink coverage may be
unavailable, and those exact skips remain coverage gaps for future gate review.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
from types import SimpleNamespace

import pytest


_SOURCE = Path(__file__).resolve().parents[1] / "src/angerona/modules/ai_model_integrity.py"
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


@pytest.fixture(scope="module")
def helpers():
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"), filename=str(_SOURCE))
    names = ("ModelIntegrityError", "_require_model_root", "_require_confined_regular_file")
    selected = []
    for name in names:
        nodes = [node for node in tree.body
                 if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name == name]
        assert len(nodes) == 1
        selected.append(nodes[0])
    namespace = {"Path": object, "os": SimpleNamespace(stat_result=object), "stat": stat}
    exec(compile(ast.Module(body=selected, type_ignores=[]), "<inert-model-lexical-custody>",
                 "exec", dont_inherit=True, optimize=0), namespace)
    return namespace


def _info(mode, inode, *, size=0, reparse=False):
    return SimpleNamespace(st_mode=mode, st_dev=7, st_ino=inode, st_size=size,
                           st_file_attributes=_REPARSE if reparse else 0)


class _Path:
    """Pure lexical names plus explicitly supplied metadata/resolution facts."""

    def __init__(self, fixture, name):
        self.fixture = fixture
        self.name = PurePosixPath(name)

    def absolute(self):
        name = self.name if self.name.is_absolute() else self.fixture.cwd / self.name
        return self.fixture.path(name)

    @property
    def parts(self):
        return self.name.parts

    @property
    def parent(self):
        return self.fixture.path(self.name.parent)

    def relative_to(self, root):
        return self.name.relative_to(root.name)

    def __truediv__(self, part):
        return self.fixture.path(self.name / part)

    def __eq__(self, other):
        return isinstance(other, _Path) and self.fixture is other.fixture and self.name == other.name

    def __hash__(self):
        return hash((id(self.fixture), self.name))

    def stat(self, *, follow_symlinks=True):
        name = self.absolute().name
        count = self.fixture.stat_count.get(name, 0) + 1
        self.fixture.stat_count[name] = count
        self.fixture.trace.append(("stat", str(name), follow_symlinks, count))
        failure = self.fixture.failures.get(("stat", name, count))
        if failure:
            raise failure("inert metadata refusal")
        if follow_symlinks or name not in self.fixture.nodes:
            name = self.fixture.resolved_name(name)
        info = copy.copy(self.fixture.nodes[name])
        for field, value in self.fixture.drift.get((name, count), {}).items():
            setattr(info, field, value)
        return info

    def resolve(self, *, strict=False):
        assert strict is True
        name = self.absolute().name
        count = self.fixture.resolve_count.get(name, 0) + 1
        self.fixture.resolve_count[name] = count
        self.fixture.trace.append(("resolve", str(name), count))
        failure = self.fixture.failures.get(("resolve", name, count))
        if failure:
            raise failure("inert resolution refusal")
        return self.fixture.path(self.fixture.resolved_name(name))

    def open(self, *_args, **_kwargs):
        raise AssertionError("admission helper must not open a model")


class _Fixture:
    def __init__(self):
        self.cwd = PurePosixPath("/inert")
        self.root_name = self.cwd / "models"
        self.file_name = self.root_name / "manifests" / "latest"
        self.nodes = {
            self.root_name: _info(stat.S_IFDIR | 0o700, 11),
            self.root_name / "manifests": _info(stat.S_IFDIR | 0o700, 12),
            self.file_name: _info(stat.S_IFREG | 0o600, 13, size=17),
            self.root_name / "plain": _info(stat.S_IFDIR | 0o700, 14),
            self.root_name / "plain" / "latest": _info(stat.S_IFREG | 0o600, 13, size=17),
        }
        self.aliases = {}
        self.drift = {}
        self.failures = {}
        self.trace = []
        self.stat_count = {}
        self.resolve_count = {}

    def path(self, name):
        return _Path(self, name)

    @property
    def root(self):
        return self.path(self.root_name)

    @property
    def file(self):
        return self.path(self.file_name)

    def resolved_name(self, name):
        for original, target in sorted(self.aliases.items(), key=lambda row: len(row[0].parts), reverse=True):
            try:
                relative = name.relative_to(original)
            except ValueError:
                continue
            return target / relative
        return name


def _leaf_was_resolved(fixture):
    return any(row[:2] == ("resolve", str(fixture.file_name)) for row in fixture.trace)


@pytest.mark.parametrize("kind", ["symlink", "junction"])
def test_root_alias_is_refused_before_original_name_resolution(helpers, kind):
    fixture = _Fixture()
    fixture.nodes[fixture.root_name] = _info(
        stat.S_IFLNK if kind == "symlink" else stat.S_IFDIR, 11, reparse=kind == "junction")
    fixture.aliases[fixture.root_name] = PurePosixPath("/inert/physical-models")
    with pytest.raises(helpers["ModelIntegrityError"], match="directory is not trusted"):
        helpers["_require_model_root"](fixture.root)
    assert fixture.resolve_count == {}
    assert fixture.trace == [("stat", str(fixture.root_name), False, 1)]


@pytest.mark.parametrize("field,value", [
    ("st_dev", 8), ("st_ino", 21), ("st_mode", stat.S_IFREG), ("st_file_attributes", _REPARSE),
], ids=["device", "inode", "type", "reparse"])
def test_root_identity_or_type_drift_during_resolution_is_refused(helpers, field, value):
    fixture = _Fixture()
    fixture.drift[(fixture.root_name, 2)] = {field: value}
    with pytest.raises(helpers["ModelIntegrityError"], match="directory changed during resolution"):
        helpers["_require_model_root"](fixture.root)
    assert fixture.stat_count[fixture.root_name] == 2


@pytest.mark.parametrize("where", ["intermediate", "leaf"])
@pytest.mark.parametrize("kind", ["symlink", "junction"])
def test_original_components_are_refused_even_when_resolution_stays_inside_root(helpers, where, kind):
    fixture = _Fixture()
    alias = fixture.root_name / "manifests" if where == "intermediate" else fixture.file_name
    target = fixture.root_name / "plain" if where == "intermediate" else fixture.root_name / "plain" / "latest"
    fixture.aliases[alias] = target
    fixture.nodes[alias] = _info(stat.S_IFLNK if kind == "symlink" else
                               stat.S_IFDIR if where == "intermediate" else stat.S_IFREG,
                               91, reparse=kind == "junction")
    with pytest.raises(helpers["ModelIntegrityError"], match="link or junction"):
        helpers["_require_confined_regular_file"](fixture.file, fixture.root)
    assert not _leaf_was_resolved(fixture)


@pytest.mark.parametrize("name", [
    "/outside/latest", "/inert/models/manifests/../latest", "/inert/models",
], ids=["outside-lexical-root", "parent-traversal", "root-is-not-file"])
def test_ambiguous_or_unconfined_original_names_fail_before_leaf_resolution(helpers, name):
    fixture = _Fixture()
    path = fixture.path(name)
    with pytest.raises(helpers["ModelIntegrityError"], match="not confined|escaped or is unavailable"):
        helpers["_require_confined_regular_file"](path, fixture.root)
    assert fixture.resolve_count == {fixture.root_name: 1}


def test_non_directory_original_component_fails_before_leaf_resolution(helpers):
    fixture = _Fixture()
    fixture.nodes[fixture.root_name / "manifests"] = _info(stat.S_IFREG | 0o600, 12)
    with pytest.raises(helpers["ModelIntegrityError"], match="non-directory"):
        helpers["_require_confined_regular_file"](fixture.file, fixture.root)
    assert not _leaf_was_resolved(fixture)


@pytest.mark.parametrize("relative", [False, True], ids=["absolute", "relative"])
def test_plain_names_keep_regular_file_and_root_identity_snapshots(helpers, relative):
    fixture = _Fixture()
    root = fixture.path("models") if relative else fixture.root
    file = fixture.path("models/manifests/latest") if relative else fixture.file
    resolved, info = helpers["_require_confined_regular_file"](file, root)
    assert resolved == fixture.file
    assert (info.st_dev, info.st_ino, info.st_size) == (7, 13, 17)
    assert fixture.resolve_count == {fixture.root_name: 1, fixture.file_name: 1}
    assert fixture.stat_count[fixture.root_name] == 3
    assert fixture.stat_count[fixture.file_name] == 2
    assert all(row[2] is False for row in fixture.trace if row[0] == "stat")


@pytest.mark.parametrize("field,value", [
    ("st_dev", 8), ("st_ino", 23), ("st_size", 18),
    ("st_mode", stat.S_IFLNK), ("st_file_attributes", _REPARSE),
], ids=["device", "inode", "size", "type", "reparse"])
def test_leaf_identity_type_or_reparse_drift_cannot_return_admission(helpers, field, value):
    fixture = _Fixture()
    fixture.drift[(fixture.file_name, 2)] = {field: value}
    with pytest.raises(helpers["ModelIntegrityError"], match="not a regular file|changed during resolution"):
        helpers["_require_confined_regular_file"](fixture.file, fixture.root)


@pytest.mark.parametrize("stage", [
    "root-before", "root-resolve", "root-after", "component", "file-resolve", "file-after", "root-final",
])
@pytest.mark.parametrize("error", [OSError, RuntimeError, ValueError], ids=["os-error", "runtime-error", "value-error"])
def test_metadata_and_resolution_failures_remain_typed_without_opening(helpers, stage, error):
    fixture = _Fixture()
    routes = {
        "root-before": ("stat", fixture.root_name, 1),
        "root-resolve": ("resolve", fixture.root_name, 1),
        "root-after": ("stat", fixture.root_name, 2),
        "component": ("stat", fixture.root_name / "manifests", 1),
        "file-resolve": ("resolve", fixture.file_name, 1),
        "file-after": ("stat", fixture.file_name, 2),
        "root-final": ("stat", fixture.root_name, 3),
    }
    fixture.failures[routes[stage]] = error
    with pytest.raises(helpers["ModelIntegrityError"]) as captured:
        helpers["_require_confined_regular_file"](fixture.file, fixture.root)
    assert type(captured.value.__cause__) is error


def _real_fixture(tmp_path):
    root = tmp_path / "models"
    blob_bytes = b"synthetic lexical custody fixture"
    blob_digest = hashlib.sha256(blob_bytes).hexdigest()
    blob = root / "blobs" / ("sha256-" + blob_digest)
    manifest = root / "manifests" / "registry.ollama.ai" / "library" / "lexical-fixture" / "latest"
    blob.parent.mkdir(parents=True)
    manifest.parent.mkdir(parents=True)
    blob.write_bytes(blob_bytes)
    raw = json.dumps({"config": {"digest": "sha256:" + blob_digest, "size": len(blob_bytes)},
                      "layers": []}, sort_keys=True, separators=(",", ":")).encode()
    manifest.write_bytes(raw)
    return root, blob, manifest, "sha256:" + hashlib.sha256(raw).hexdigest()


def test_real_fixture_still_requires_the_pinned_manifest_and_blob_digest(tmp_path):
    from angerona.modules.ai_model_integrity import ModelIntegrityError, verify_ollama_model_files

    root, blob, manifest, digest = _real_fixture(tmp_path)
    result = verify_ollama_model_files("lexical-fixture:latest", digest, models_root=root)
    assert result.manifest_digest == digest and result.blob_count == 1
    assert result.bytes_verified == blob.stat().st_size
    original_manifest = manifest.read_bytes()
    with pytest.raises(ModelIntegrityError, match="catalog"):
        verify_ollama_model_files("lexical-fixture:latest", "sha256:" + "0" * 64, models_root=root)
    assert manifest.read_bytes() == original_manifest
    blob.write_bytes(b"x" * blob.stat().st_size)
    with pytest.raises(ModelIntegrityError, match="content digest"):
        verify_ollama_model_files("lexical-fixture:latest", digest, models_root=root)


@pytest.mark.parametrize("where", ["root", "manifest-directory", "blob-leaf"])
def test_native_links_refuse_even_identical_pinned_fixture_bytes(tmp_path, where):
    from angerona.modules.ai_model_integrity import ModelIntegrityError, verify_ollama_model_files

    root, blob, manifest, digest = _real_fixture(tmp_path)
    assert verify_ollama_model_files("lexical-fixture:latest", digest, models_root=root).manifest_digest == digest
    if where == "root":
        alias, destination = tmp_path / "root-alias", root
        observed_root = alias
        directory = True
    elif where == "manifest-directory":
        destination = root / "plain-manifests"
        manifest.parent.rename(destination)
        alias = manifest.parent
        observed_root = root
        directory = True
    else:
        destination = root / "plain-blob"
        blob.rename(destination)
        alias = blob
        observed_root = root
        directory = False
    try:
        alias.symlink_to(destination, target_is_directory=directory)
    except NotImplementedError:
        pytest.skip("native symlink API unavailable (NotImplementedError)")
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("native symlink privilege unavailable (winerror=1314)")
        raise
    with pytest.raises(ModelIntegrityError, match="not trusted|link or junction"):
        verify_ollama_model_files("lexical-fixture:latest", digest, models_root=observed_root)


@pytest.mark.parametrize("kind", ["symlink", "junction"])
def test_trusted_ambient_ancestor_alias_keeps_consistently_spelled_root_and_file_admission(helpers, kind):
    fixture = _Fixture()
    ambient = PurePosixPath("/trusted-ambient")
    fixture.nodes[ambient] = _info(
        stat.S_IFLNK if kind == "symlink" else stat.S_IFDIR, 90, reparse=kind == "junction")
    fixture.aliases[ambient] = fixture.cwd
    supplied_root = fixture.path(ambient / "models")
    supplied_file = supplied_root / "manifests" / "latest"

    resolved, info = helpers["_require_confined_regular_file"](supplied_file, supplied_root)

    assert resolved == fixture.file
    assert (info.st_dev, info.st_ino, info.st_size) == (7, 13, 17)
    assert fixture.resolve_count == {supplied_root.name: 1, supplied_file.name: 1}
    assert fixture.stat_count == {
        supplied_root.name: 1, fixture.root_name: 2,
        supplied_root.name / "manifests": 1, supplied_file.name: 1, fixture.file_name: 1,
    }
    assert all(row[1] != str(ambient) for row in fixture.trace)
    assert all(row[2] is False for row in fixture.trace if row[0] == "stat")
    assert fixture.trace[-2:] == [
        ("stat", str(fixture.file_name), False, 1),
        ("stat", str(fixture.root_name), False, 2),
    ]


@pytest.mark.parametrize("field,value", [
    ("st_dev", 8), ("st_ino", 23), ("st_mode", stat.S_IFREG),
    ("st_file_attributes", _REPARSE),
], ids=["device", "inode", "type", "reparse"])
def test_final_root_identity_or_type_drift_after_leaf_resolution_refuses_admission(helpers, field, value):
    fixture = _Fixture()
    fixture.drift[(fixture.root_name, 3)] = {field: value}

    with pytest.raises(helpers["ModelIntegrityError"], match="path changed during resolution"):
        helpers["_require_confined_regular_file"](fixture.file, fixture.root)

    assert fixture.resolve_count == {fixture.root_name: 1, fixture.file_name: 1}
    assert fixture.stat_count[fixture.root_name] == 3
    assert fixture.stat_count[fixture.file_name] == 2
    assert fixture.trace[-3:] == [
        ("resolve", str(fixture.file_name), 1),
        ("stat", str(fixture.file_name), False, 2),
        ("stat", str(fixture.root_name), False, 3),
    ]
    assert (fixture.nodes[fixture.file_name].st_dev, fixture.nodes[fixture.file_name].st_ino,
            fixture.nodes[fixture.file_name].st_size) == (7, 13, 17)
