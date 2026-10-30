"""Inert pending-queue/version fixtures; no OS files, policy or reboot changes."""
from __future__ import annotations

import sys

import pytest

from angerona.core.eventbus import EventBus, Severity
from angerona.core.windows_rollback_audit import (
    CRITICAL_IMAGES, MAX_OPERATIONS, MAX_XML_BYTES, WindowsRollbackAuditProvider,
    audit_versions, local_path, parse_pending, pending_reference, read_disk_version,
)
from angerona.modules.driver_provenance_guard import DriverProvenanceGuard


WINDOWS = r"C:\Windows"
CURRENT = r"C:\Windows\System32\ci.dll"
SOURCE = r"C:\staging\ci.dll"
NEW = (10, 0, 26100, 100)
OLD = (10, 0, 26100, 1)


def queue(action: str) -> bytes:
    return ("<PendingTransaction><POQ>" + action + "</POQ></PendingTransaction>").encode()


def replacement(source=SOURCE, destination=CURRENT, operation="HardlinkFile"):
    return f'<{operation} source="{source}" destination="{destination}"/>'


@pytest.mark.parametrize("operation", ["HardlinkFile", "MoveFile", "CopyFile"])
def test_direct_scheduled_lower_critical_image_is_review_lead_only(operation):
    calls = []
    def version(path):
        calls.append(path)
        return NEW if path == CURRENT else OLD
    result = audit_versions(windows=WINDOWS, pending=queue(replacement(operation=operation)),
                            version_reader=version, old_present=False)
    assert calls == [CURRENT, SOURCE]
    assert result.compared == 1 and len(result.leads) == 1
    assert result.leads[0].origin == "pending-queue"
    details = result.event_details()
    assert details["leads"][0]["candidate_version"] == list(OLD)
    assert SOURCE not in str(details) and CURRENT not in str(details)
    for field in ("active_attack", "response_authorized", "signature_verified",
                  "loaded_image_binding", "full_queue_coverage", "reboot_blocked"):
        assert details[field] is False


def test_equal_or_newer_versions_do_not_create_regression_lead():
    for candidate in (NEW, (10, 0, 26100, 101)):
        result = audit_versions(windows=WINDOWS, pending=queue(replacement()),
                                version_reader=lambda p: NEW if p == CURRENT else candidate,
                                old_present=False)
        assert result.compared == 1 and not result.leads


def test_windows_old_is_explicit_recovery_data_and_does_not_become_scheduled_work():
    result = audit_versions(windows=WINDOWS, pending=None, old_present=True,
                            version_reader=lambda p: OLD if "Windows.old" in p else NEW)
    assert result.pending_state == "absent" and result.compared == len(CRITICAL_IMAGES)
    assert all(lead.origin == "recovery-copy-only" for lead in result.leads)
    assert "not a scheduled downgrade" in result.event_details()["reason"]


def test_rollback_information_nested_operations_are_not_current_poq():
    raw = ("<PendingTransaction><RollbackInformation><POQ>" + replacement()
           + "</POQ></RollbackInformation><POQ/></PendingTransaction>").encode()
    result = parse_pending(raw, WINDOWS)
    assert not result.replacements


def test_out_of_scope_targets_and_unknown_actions_remain_counted():
    result = parse_pending(queue(replacement(destination=r"C:\Windows\not-fixed.dll")
                                 + "<DeleteFile path='C:\\example'/><SetKeyValue/>"), WINDOWS)
    assert result.ignored_targets == 1 and result.unsupported == 2
    assert not result.replacements


@pytest.mark.parametrize("path", [r"\\server\share\x.dll", r"\\?\C:\x.dll",
                                     r"C:\x.dll:stream", r"C:\a\..\x.dll",
                                     r"C:\con.dll", r"C:relative.dll", r"C:\a.\x.dll",
                                     "%SystemRoot%\\System32\\ci.dll"])
def test_hostile_or_ambiguous_paths_never_reach_version_reader(path):
    calls = []
    result = audit_versions(windows=WINDOWS, pending=queue(replacement(source=path)),
                            version_reader=lambda p: calls.append(p) or NEW, old_present=False)
    assert not calls and result.unsupported == 1


def test_native_systemroot_prefix_is_resolved_from_supplied_os_root_only():
    assert local_path(r"\SystemRoot\System32\ci.dll", WINDOWS) == CURRENT
    assert local_path(r"\??\C:\Windows\System32\ci.dll", WINDOWS) == CURRENT


def test_registry_custom_queue_is_followed_as_data_and_marked_for_review():
    path, state = pending_reference(
        [r'C:\Windows\System32\poqexec.exe /display_progress \??\C:\staging\pending.xml'], WINDOWS)
    assert path == r"C:\staging\pending.xml" and state == "custom-local-reference"
    path, state = pending_reference(
        [r'"C:\Windows\System32\poqexec.exe" "C:\Windows\WinSxS\pending.xml"'], WINDOWS)
    assert path == r"C:\Windows\WinSxS\pending.xml" and state == "canonical-reference"


@pytest.mark.parametrize("value", [[], ["x", "y"], [r"poqexec.exe C:\x.xml"],
    [r"C:\attacker\poqexec.exe C:\x.xml"], [r"C:\Windows\System32\poqexec.exe /unknown C:\x.xml"],
    [r"C:\Windows\System32\poqexec.exe \\server\share\pending.xml"],
    [r"C:\Windows\System32\poqexec.exe C:\x.xml & calc.exe"],
    [r"C:\Windows\System32\poqexec.exe C:\x.exe"], ["x" * 8193]],
    ids=["empty", "multiple", "relative-image", "lookalike", "unknown-flag", "remote",
         "shell-text", "not-xml", "oversize"])
def test_ambiguous_servicing_command_is_never_executed_or_used_as_path(value):
    with pytest.raises(ValueError):
        pending_reference(value, WINDOWS)


@pytest.mark.parametrize("raw", [b"", b"<unsupported/>", b"<PendingTransaction>",
    b'<!DOCTYPE x [<!ENTITY x "boom">]><PendingTransaction>&x;</PendingTransaction>',
    b'<PendingTransaction xmlns="urn:unknown"><POQ/></PendingTransaction>',
    b"x" * (MAX_XML_BYTES + 1),
    queue("<DeleteFile/>" * (MAX_OPERATIONS + 1)),
    queue(replacement(source=r"C:relative.dll") * (MAX_OPERATIONS + 1))],
    ids=["empty", "unknown-root", "malformed", "dtd-entity", "namespace", "oversize",
         "action-bound", "invalid-action-bound"])
def test_invalid_oversized_or_expanding_xml_is_unavailable_not_absent(raw):
    calls = []
    result = audit_versions(windows=WINDOWS, pending=raw, old_present=False,
                            version_reader=lambda p: calls.append(p) or NEW)
    assert not calls and result.pending_state == "unavailable-or-unsupported"
    assert result.unsupported > 0


def test_read_failures_bad_version_and_deadline_are_explicit():
    def denied(_path):
        raise PermissionError("fixture denied")
    for reader in (denied, lambda _p: (True, 0, 1, 2), lambda _p: "10.0.1.2"):
        result = audit_versions(windows=WINDOWS, pending=queue(replacement()),
                                version_reader=reader, old_present=False)
        assert result.unavailable == 1 and not result.leads
    ticks = iter([0.0, 0.1, 6.0])
    calls = []
    result = audit_versions(windows=WINDOWS, pending=queue(replacement()), old_present=False,
                            version_reader=lambda p: calls.append(p) or NEW,
                            clock=lambda: next(ticks))
    assert result.budget_exhausted and calls == [CURRENT] and not result.leads


def test_module_surfaces_scheduled_lead_once_and_never_authorizes_response():
    result = audit_versions(windows=WINDOWS, pending=queue(replacement()), old_present=False,
                            version_reader=lambda p: NEW if p == CURRENT else OLD)
    class Provider:
        def collect(self):
            return result
    guard = DriverProvenanceGuard(rollback_provider=Provider())
    bus = EventBus()
    guard.bind(bus)
    guard.observe_rollback_once()
    guard.observe_rollback_once()
    events = bus.recent(10)
    assert len(events) == 1 and events[0].severity == Severity.HIGH
    assert events[0].details["response_authorized"] is False and guard.health <= 20


def test_module_provider_failure_is_explicit_coverage_gap():
    class Provider:
        def collect(self):
            raise OSError("fixture unavailable")
    guard = DriverProvenanceGuard(rollback_provider=Provider())
    bus = EventBus()
    guard.bind(bus)
    result = guard.observe_rollback_once()
    assert result.unavailable == 1 and result.pending_state == "unavailable-or-unsupported"
    assert bus.recent(1)[0].severity == Severity.MEDIUM


def test_default_driver_registration_wires_real_audit_provider():
    assert isinstance(DriverProvenanceGuard()._rollback_provider, WindowsRollbackAuditProvider)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native VERSIONINFO is required")
def test_native_read_samples_inbox_version_without_loading_executable():
    from angerona.core.privilege import trusted_windows_directories
    _windows, system = trusted_windows_directories()
    result = read_disk_version(str(system / "kernel32.dll"))
    assert type(result) is tuple and len(result) == 4 and result[0] >= 6
