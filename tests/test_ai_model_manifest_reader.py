"""Inert custody regressions for the actual Ollama manifest reader.

Only _read_verified_file's AST executes. The module is never imported; its
admission seam, path, stream, and fstat are explicit in-memory doubles. These
controls prove reader semantics, not OS confinement or hostile-Python isolation.
"""
from __future__ import annotations

import ast
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest


_MAXIMUM = 16 * 1024 * 1024
_SOURCE = Path(__file__).resolve().parents[1] / "src/angerona/modules/ai_model_integrity.py"


class ModelIntegrityError(RuntimeError):
    """The extracted reader's typed failure, without product import side effects."""


def _reader_node():
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"), filename=str(_SOURCE))
    nodes = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_read_verified_file"
    ]
    assert len(nodes) == 1
    return nodes[0]


def _read_call(node):
    calls = [
        call for call in ast.walk(node)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "stream"
        and call.func.attr == "read"
    ]
    assert len(calls) == 1 and len(calls[0].args) == 1 and not calls[0].keywords
    return calls[0]


def _compile_reader(node, fixture):
    namespace = {
        "Path": object,
        "ModelIntegrityError": ModelIntegrityError,
        "_require_confined_regular_file": fixture.admit,
        "os": SimpleNamespace(fstat=fixture.fstat),
    }
    unit = ast.Module(body=[copy.deepcopy(node)], type_ignores=[])
    exec(compile(ast.fix_missing_locations(unit), "<inert-model-reader>", "exec"), namespace)
    return namespace["_read_verified_file"]


def _identical_trace_except_requested_count(trace):
    return [(entry[0],) if entry[0] == "read" else entry for entry in trace]


class _Fixture:
    def __init__(self, *, size=8, body=b"manifest", drift=None, admission=None, fault=None):
        self.before = SimpleNamespace(st_dev=11, st_ino=22, st_size=size)
        self.opened = copy.copy(self.before)
        self.after = copy.copy(self.before)
        if drift is not None:
            stage, field = drift
            info = self.opened if stage == "opened" else self.after
            setattr(info, field, getattr(info, field) + 1)
        self.body = body
        self.admission = admission
        self.fault = fault
        self.trace = []
        self.requested = []
        self.closed = False
        self.fileno_calls = 0
        self.fstat_calls = 0
        self.path_token = object()
        self.root_token = object()

    def _fail(self, stage):
        if self.fault == stage:
            raise OSError("inert " + stage)
        if self.fault == "runtime_" + stage:
            raise RuntimeError("inert " + stage)

    def admit(self, path, root):
        assert path is self.path_token and root is self.root_token
        self.trace.append(("admit",))
        if self.admission is not None:
            raise ModelIntegrityError(self.admission)
        return self, self.before

    def open(self, mode):
        assert mode == "rb"
        self.trace.append(("open", mode))
        self._fail("open")
        return self

    def __enter__(self):
        self.trace.append(("enter",))
        self._fail("enter")
        return self

    def __exit__(self, kind, _exception, _traceback):
        self.trace.append(("close", None if kind is None else kind.__name__))
        self.closed = True
        self._fail("close")
        return False

    def fileno(self):
        self.fileno_calls += 1
        self.trace.append(("fileno", self.fileno_calls))
        self._fail("fileno_before" if self.fileno_calls == 1 else "fileno_after")
        return 701  # Opaque fake descriptor: no real os.fstat ever sees it.

    def fstat(self, descriptor):
        assert descriptor == 701
        self.fstat_calls += 1
        self.trace.append(("fstat", self.fstat_calls))
        self._fail("fstat_before" if self.fstat_calls == 1 else "fstat_after")
        assert self.fstat_calls <= 2
        return self.opened if self.fstat_calls == 1 else self.after

    def read(self, count):
        assert isinstance(count, int) and count > 0
        self.requested.append(count)
        self.trace.append(("read", count))
        self._fail("read")
        return self.body[:count]  # No allocation proportional to the large count.


def _outcome(reader, fixture, maximum):
    try:
        payload = reader(fixture.path_token, fixture.root_token, maximum=maximum)
    except (ModelIntegrityError, RuntimeError) as exc:
        cause = None if exc.__cause__ is None else (type(exc.__cause__).__name__, str(exc.__cause__))
        return ("error", type(exc).__name__, str(exc), cause)
    return ("ok", payload, hashlib.sha256(payload).hexdigest())


def _pair(*, maximum=_MAXIMUM, **settings):
    actual_node = _reader_node()
    actual_call = _read_call(actual_node)
    assert ast.dump(actual_call.args[0]) == ast.dump(ast.parse("before.st_size + 1", mode="eval").body)
    baseline_node = copy.deepcopy(actual_node)
    _read_call(baseline_node).args[0] = ast.parse("maximum + 1", mode="eval").body
    baseline, actual = _Fixture(**settings), _Fixture(**settings)
    old_outcome = _outcome(_compile_reader(baseline_node, baseline), baseline, maximum)
    new_outcome = _outcome(_compile_reader(actual_node, actual), actual, maximum)
    assert new_outcome == old_outcome
    assert _identical_trace_except_requested_count(actual.trace) == _identical_trace_except_requested_count(baseline.trace)
    assert actual.closed == baseline.closed
    return actual, baseline, new_outcome



@pytest.mark.parametrize(
    "size,maximum",
    [(1, _MAXIMUM), (8, _MAXIMUM), (8192, _MAXIMUM), (32, 32)],
    ids=["single-byte", "small-manifest", "eight-kib", "exact-cap"],
)
def test_stable_manifest_retains_exact_bytes_digest_and_complete_guard_order(size, maximum):
    body = bytes((index % 251 for index in range(size)))
    actual, baseline, outcome = _pair(size=size, body=body, maximum=maximum)
    assert outcome == ("ok", body, hashlib.sha256(body).hexdigest())
    assert actual.requested == [size + 1]
    assert baseline.requested == [maximum + 1]
    assert actual.requested[0] <= maximum + 1
    assert actual.trace == [
        ("admit",), ("open", "rb"), ("enter",), ("fileno", 1), ("fstat", 1),
        ("read", size + 1), ("fileno", 2), ("fstat", 2), ("close", None),
    ]
    assert actual.closed


@pytest.mark.parametrize("size", [-1, 0, 9], ids=["negative", "empty", "over-cap"])
def test_invalid_size_still_fails_before_opening_or_allocating(size):
    actual, baseline, outcome = _pair(size=size, maximum=8)
    assert outcome == ("error", "ModelIntegrityError", "Ollama manifest has an invalid size", None)
    assert actual.trace == [("admit",)]
    assert actual.requested == baseline.requested == []


@pytest.mark.parametrize(
    "body_size,maximum", [(9, _MAXIMUM), (136, _MAXIMUM), (9, 8)],
    ids=["one-extra-byte", "large-growth", "growth-at-global-cap"],
)
def test_growth_sentinel_refuses_bytes_before_any_digest_is_returned(body_size, maximum):
    actual, baseline, outcome = _pair(size=8, body=b"x" * body_size, maximum=maximum)
    assert outcome == ("error", "ModelIntegrityError", "Ollama manifest changed during verification", None)
    assert actual.requested == [9] and baseline.requested == [maximum + 1]
    assert actual.fstat_calls == 2 and actual.closed


@pytest.mark.parametrize("body_size", [0, 7], ids=["eof-before-data", "one-byte-shrink"])
def test_shrink_cannot_return_a_partial_manifest(body_size):
    actual, _baseline, outcome = _pair(size=8, body=b"x" * body_size)
    assert outcome == ("error", "ModelIntegrityError", "Ollama manifest changed during verification", None)
    assert actual.fstat_calls == 2 and actual.closed


@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size"], ids=["device", "inode", "size"])
def test_opened_descriptor_must_match_the_admitted_object_before_read(field):
    actual, baseline, outcome = _pair(drift=("opened", field))
    assert outcome == ("error", "ModelIntegrityError", "Ollama manifest changed before verification", None)
    assert actual.requested == baseline.requested == []
    assert actual.fstat_calls == 1 and actual.closed
    assert actual.trace[-1] == ("close", "ModelIntegrityError")


@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size"], ids=["device", "inode", "size"])
def test_post_read_descriptor_drift_cannot_return_bytes(field):
    actual, _baseline, outcome = _pair(drift=("after", field))
    assert outcome == ("error", "ModelIntegrityError", "Ollama manifest changed during verification", None)
    assert actual.fstat_calls == 2 and actual.closed
    assert actual.trace[-1] == ("close", None)


@pytest.mark.parametrize(
    "message",
    [
        "Ollama model path escaped or is unavailable",
        "Ollama model path contains a link or junction",
        "Ollama model path is not confined",
        "Ollama model file is a link or reparse point",
        "Ollama model file is unavailable",
        "Ollama model object is not a regular file",
    ],
    ids=["escape", "ancestor-link", "not-confined", "leaf-link", "unavailable", "not-regular"],
)
def test_admission_failure_remains_authoritative_and_never_opens_a_stream(message):
    actual, baseline, outcome = _pair(admission=message)
    assert outcome == ("error", "ModelIntegrityError", message, None)
    assert actual.trace == [("admit",)]
    assert actual.requested == baseline.requested == []


@pytest.mark.parametrize(
    "stage",
    ["open", "enter", "fileno_before", "fstat_before", "read", "fileno_after", "fstat_after", "close"],
    ids=["open", "enter", "first-fileno", "first-fstat", "read", "second-fileno", "second-fstat", "close"],
)
def test_os_errors_keep_typed_chaining_and_existing_context_cleanup_semantics(stage):
    actual, _baseline, outcome = _pair(fault=stage)
    assert outcome == (
        "error", "ModelIntegrityError", "Ollama manifest could not be read",
        ("OSError", "inert " + stage),
    )
    assert actual.closed is (stage not in {"open", "enter"})
    assert sum(entry[0] == "open" for entry in actual.trace) == 1
    assert len(actual.requested) <= 1


@pytest.mark.parametrize("stage", ["read", "fstat_after"], ids=["read", "post-read-metadata"])
def test_non_os_stream_failures_propagate_without_returning_bytes_or_retry(stage):
    actual, _baseline, outcome = _pair(fault="runtime_" + stage)
    assert outcome == ("error", "RuntimeError", "inert " + stage, None)
    assert actual.closed
    assert sum(entry[0] == "open" for entry in actual.trace) == 1
    assert len(actual.requested) == 1
