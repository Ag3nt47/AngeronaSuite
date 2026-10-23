from __future__ import annotations

import sys
import threading
from types import SimpleNamespace

import pytest

import angerona.modules.self_integrity as integrity
from angerona.modules.self_integrity import (
    SelfIntegrityEngine, SelfIntegrityMonitor, _fingerprint, _native_acl_weaknesses,
)


def test_fingerprint_detects_constants_only_code_patch() -> None:
    def decision() -> str:
        return "allow"

    before = _fingerprint(decision)
    constants = tuple("deny" if value == "allow" else value for value in decision.__code__.co_consts)
    decision.__code__ = decision.__code__.replace(co_consts=constants)

    assert decision() == "deny"
    assert _fingerprint(decision) != before


def test_fingerprint_detects_referenced_global_name_patch() -> None:
    namespace = {"allow": lambda: True, "deny": lambda: False}
    exec("def decision():\n    return allow()\n", namespace)
    decision = namespace["decision"]
    before = _fingerprint(decision)
    names = tuple("deny" if value == "allow" else value for value in decision.__code__.co_names)
    decision.__code__ = decision.__code__.replace(co_names=names)

    assert decision() is False
    assert _fingerprint(decision) != before


def test_fingerprint_detects_defaults_and_closure_changes() -> None:
    def with_default(verdict: str = "allow") -> str:
        return verdict

    default_before = _fingerprint(with_default)
    with_default.__defaults__ = ("deny",)
    assert _fingerprint(with_default) != default_before

    def make_decision():
        verdict = "allow"

        def decision() -> str:
            return verdict

        return decision

    closed = make_decision()
    closure_before = _fingerprint(closed)
    replacement = (lambda value: lambda: value)("deny").__closure__[0]
    closed.__closure__[0].cell_contents = replacement.cell_contents
    assert closed() == "deny"
    assert _fingerprint(closed) != closure_before


def test_fingerprint_defaults_are_unambiguous_and_cover_complete_strings() -> None:
    def decision(value=("a|str:b", "c")):
        return value

    before = _fingerprint(decision)
    decision.__defaults__ = (("a", "b|str:c"),)
    assert _fingerprint(decision) != before
    decision.__defaults__ = ("prefix" * 12000 + "allow",)
    before = _fingerprint(decision)
    decision.__defaults__ = ("prefix" * 12000 + "deny",)
    assert _fingerprint(decision) != before


def test_fingerprint_stays_stable_while_a_constant_is_used_by_another_thread() -> None:
    entered, release = threading.Event(), threading.Event()

    def hold(value):
        entered.set()
        release.wait(5)
        return value

    def decision():
        return hold(987654321)

    # A freshly allocated constant has no incidental references from this test
    # module's own constant pool. The in-flight call temporarily adds one; a
    # marshal dump changes reference flags despite unchanged executable code.
    decision.__code__ = decision.__code__.replace(
        co_consts=(None, int("987654321"))
    )
    before = _fingerprint(decision)
    thread = threading.Thread(target=decision)
    thread.start()
    try:
        assert entered.wait(2), "inert worker did not enter its bounded call"
        assert _fingerprint(decision) == before
    finally:
        release.set()
        thread.join(2)
    assert not thread.is_alive()
    assert _fingerprint(decision) == before


def test_executable_sha256_fingerprint_stays_stable_during_live_file_read(monkeypatch, tmp_path) -> None:
    from angerona.core import process_allowlist

    target = tmp_path / "inert-executable.bin"
    target.write_bytes(b"inert test binary")
    entered, release = threading.Event(), threading.Event()
    original_open = process_allowlist._open_hash_stream
    results = []

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size):
            # Keep the exact callable in an in-flight bounded file read,
            # without replacing its executable code.
            entered.set()
            release.wait(5)
            return self.stream.read(size)

        def fileno(self):
            return self.stream.fileno()

    def blocked_open(path):
        stream = original_open(path)
        return Reader(stream) if path == target else stream

    def hash_file():
        results.append(process_allowlist.executable_sha256(str(target)))

    callable_before = process_allowlist.executable_sha256
    code_before = callable_before.__code__
    fingerprint_before = _fingerprint(callable_before)
    monkeypatch.setattr(process_allowlist, "_open_hash_stream", blocked_open)
    worker = threading.Thread(target=hash_file)
    worker.start()
    try:
        assert entered.wait(2), "inert executable hash did not enter its bounded read"
        assert _fingerprint(process_allowlist.executable_sha256) == fingerprint_before
        assert process_allowlist.executable_sha256 is callable_before
        assert callable_before.__code__ is code_before
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive()
    assert len(results) == 1 and len(results[0]) == 64
    assert _fingerprint(callable_before) == fingerprint_before


def test_fingerprint_detects_nested_code_and_exception_table_changes() -> None:
    def outer():
        return lambda: "allow"

    before = _fingerprint(outer)
    nested = next(value for value in outer.__code__.co_consts if hasattr(value, "co_code"))
    changed = nested.replace(co_consts=(None, "deny"))
    outer.__code__ = outer.__code__.replace(
        co_consts=tuple(changed if value is nested else value for value in outer.__code__.co_consts)
    )
    assert outer()() == "deny"
    assert _fingerprint(outer) != before

    def protected():
        try:
            return int("1")
        except ValueError:
            return 0

    if hasattr(protected.__code__, "co_exceptiontable"):
        before = _fingerprint(protected)
        protected.__code__ = protected.__code__.replace(co_exceptiontable=b"")
        assert _fingerprint(protected) != before


def test_previous_fingerprint_format_requires_explicit_baseline_review(monkeypatch) -> None:
    def decision():
        return "allow"

    spec = "fixture:decision"
    monkeypatch.setattr(integrity, "_resolve", lambda _spec: decision)
    observed = SelfIntegrityEngine((spec,))
    assert observed.arm() == 1
    evidence = observed.evidence(spec)
    assert ":v2-" in evidence["fingerprint"]
    manifest = {spec: {key: evidence[key] for key in ("fingerprint", "file_sha256")}}
    manifest[spec]["fingerprint"] = manifest[spec]["fingerprint"].replace(":v2-", ":")
    stale = SelfIntegrityEngine((spec,), approved_manifest=manifest)
    assert stale.arm() == 1
    assert stale.manifest_status == "mismatch"
    monitor = SelfIntegrityMonitor()
    monitor._engine = stale
    score, reason = monitor._assurance_health({"status": "ok"})
    assert score == 25 and "explicitly re-approve" in reason


def _fake_native_acl(monkeypatch, entries):
    class Dacl:
        def GetAceCount(self):
            return len(entries)

        def GetAce(self, index):
            return entries[index]

    descriptor = SimpleNamespace(
        GetSecurityDescriptorDacl=lambda: None if entries is None else Dacl()
    )
    api = SimpleNamespace(
        GetNamedSecurityInfo=lambda *_args: descriptor,
        SE_FILE_OBJECT=1,
        DACL_SECURITY_INFORMATION=4,
        ACCESS_ALLOWED_ACE_TYPE=0,
        ACCESS_DENIED_ACE_TYPE=1,
        ConvertSidToStringSid=lambda sid: sid,
    )
    monkeypatch.setitem(sys.modules, "win32security", api)
    return api


def test_native_acl_uses_sid_and_mutation_rights_without_launching_helpers(monkeypatch) -> None:
    _fake_native_acl(monkeypatch, [
        ((0, 0), 0x00120089, "S-1-1-0"),     # broad read-only
        ((0, 3), 0x001301BF, "S-1-5-32-545"),  # inherited/localized Users write
        ((0, 0), 0x001F01FF, "S-1-5-18"),    # SYSTEM full access
        ((1, 0), 0x001F01FF, "S-1-5-11"),    # deny is not a grant
    ])
    findings = _native_acl_weaknesses("inert-state")
    assert len(findings) == 1 and "S-1-5-32-545" in findings[0]


def test_native_acl_null_and_unsupported_entries_cannot_report_clean(monkeypatch) -> None:
    _fake_native_acl(monkeypatch, None)
    assert "NULL DACL" in _native_acl_weaknesses("inert-state")[0]
    _fake_native_acl(monkeypatch, [((9, 0), 0x001F01FF, "S-1-1-0")])
    with pytest.raises(ValueError, match="unsupported ACE"):
        _native_acl_weaknesses("inert-state")


@pytest.mark.parametrize("denied", [False, True])
def test_acl_audit_native_success_and_denial_start_no_subprocess(monkeypatch, tmp_path, denied) -> None:
    import angerona.core.config as config

    monkeypatch.setattr(integrity.sys, "platform", "win32")
    monkeypatch.setattr(config, "_data_dir", lambda: tmp_path)

    def collect(_path):
        if denied:
            raise PermissionError("inert access denied")
        return []

    monkeypatch.setattr(integrity, "_native_acl_weaknesses", collect)
    monkeypatch.setattr(
        integrity.subprocess, "run",
        lambda *_args, **_kwargs: pytest.fail("native ACL audit must not launch a helper"),
    )
    result = integrity.audit_state_dir_status()
    assert result["status"] == ("collection-failed" if denied else "ok")
    assert result["path"] == str(tmp_path)
    assert result["findings"] == []
    if denied:
        assert "access denied" in result["reason"]


def test_acl_collection_failure_is_explicit_health_without_response_authority(monkeypatch) -> None:
    monitor = SelfIntegrityMonitor()
    events = []
    monkeypatch.setattr(monitor, "emit", lambda *args, **details: events.append((args, details)))
    monitor._report_acl_assurance({
        "status": "collection-failed", "reason": "access denied", "path": "inert-state"
    })
    assert len(events) == 1
    details = events[0][1]
    assert details["schema"] == "angerona.self-integrity-acl-health.v1"
    assert details["response_authorized"] is False
    assert details["response_authority"] == "observe-only"
    assert details["acl_status"] == "collection-failed"
