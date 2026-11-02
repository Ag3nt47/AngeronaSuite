"""UNEXECUTED inert draft; no UAC, scheduler, task launch, signing or native IO.

Mocks exercise refusal/verification logic only and do not prove an installed
publisher, real COM serialization, task ACL or actual logon execution.
"""
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace
from xml.etree import ElementTree as XML

import pytest

from angerona.core import installed_autostart as ia

SID = "S-1-5-21-100-200-300-1001"
ROOT = r"C:\Program Files\WindowsApps\Angerona_1.0_x64__fixture"


def binding():
    return ia._Binding(SID, ia._TASK_PREFIX + SID, ROOT + r"\AngeronaSafeStart.exe", "--automatic-start",
                       ROOT, "Angerona_1.0_x64__fixture", "Angerona_fixture")


def xml_fixture():
    current = binding()
    task = XML.Element(ia._NS + "Task", {"version": "1.2"})
    def node(parent, name, text=None, **attrs):
        item = XML.SubElement(parent, ia._NS + name, attrs)
        item.text = text
        return item
    info = node(task, "RegistrationInfo")
    for name, value in {"Source": ia._SOURCE, "Author": SID,
                        "URI": "\\" + current.task, "Description": current.description}.items():
        node(info, name, value)
    principals = node(task, "Principals")
    principal = node(principals, "Principal", id="AngeronaInstalled")
    for name, value in {"UserId": SID, "LogonType": "InteractiveToken", "RunLevel": "HighestAvailable"}.items():
        node(principal, name, value)
    trigger = node(node(task, "Triggers"), "LogonTrigger")
    node(trigger, "UserId", SID)
    node(trigger, "Enabled", "true")
    action = node(node(task, "Actions", Context="AngeronaInstalled"), "Exec")
    for name, value in {"Command": current.executable, "Arguments": current.arguments, "WorkingDirectory": current.cwd}.items():
        node(action, name, value)
    settings = node(task, "Settings")
    for name, value in {"MultipleInstancesPolicy": "IgnoreNew", "DisallowStartIfOnBatteries": "false",
        "StopIfGoingOnBatteries": "false", "AllowHardTerminate": "false", "StartWhenAvailable": "false",
        "RunOnlyIfNetworkAvailable": "false", "AllowStartOnDemand": "false", "Enabled": "true",
        "Hidden": "false", "RunOnlyIfIdle": "false", "WakeToRun": "false", "ExecutionTimeLimit": "PT0S", "Priority": "7"}.items():
        node(settings, name, value)
    idle = node(settings, "IdleSettings")
    node(idle, "StopOnIdleEnd", "false")
    node(idle, "RestartOnIdle", "false")
    return task


def snapshot(*, present=True, legacy=False):
    return {"present": present, "legacy": legacy,
            "xml": XML.tostring(xml_fixture(), encoding="unicode") if present else "",
            "security": {"owner": ia._BA, "group": ia._SY, "protected": True,
                "aces": [{"sid": sid, "mask": mask, "flags": 0, "qualifier": 0}
                         for sid, mask in ((ia._SY, ia._FULL), (ia._BA, ia._FULL), (SID, ia._READ_EXECUTE))]}
                if present else None}


def test_complete_inert_snapshot_verifies_and_is_read_only():
    value = snapshot()
    before = deepcopy(value)
    assert ia._verified_snapshot(value, binding()) is value
    assert value == before


@pytest.mark.parametrize("case", [
    "helper", "arguments", "cwd", "principal", "trigger-user", "extra-principal", "extra-trigger",
    "disabled-extra-trigger", "extra-action", "registration-trigger", "restart", "repetition",
    "future-start", "expiration", "demand-start", "hidden", "time-limit", "foreign-namespace", "version-drift",
], ids=["legacy-helper-refused", "argv-closed", "cwd-bound", "principal-sid-bound", "trigger-sid-bound",
        "one-principal", "one-trigger", "disabled-trigger-still-extra", "one-exec", "no-registration-trigger",
        "zero-restarts", "no-repetition", "no-future-start", "no-expiry", "no-demand-start", "visible-task",
        "unlimited-app-lifetime", "closed-schema", "package-version-review"])
def test_task_semantics_reject_unsafe_or_drifted_definition(case):
    root = xml_fixture()
    find = lambda path: root.find("/".join(ia._NS + part for part in path.split("/")))
    if case == "helper":
        find("Actions/Exec/Command").text = ROOT + r"\AngeronaStartup.exe"
    elif case == "arguments":
        find("Actions/Exec/Arguments").text += " --arbitrary"
    elif case == "cwd":
        find("Actions/Exec/WorkingDirectory").text = r"C:\Mutable"
    elif case == "principal":
        find("Principals/Principal/UserId").text = "S-1-5-18"
    elif case == "trigger-user":
        find("Triggers/LogonTrigger/UserId").text = "S-1-5-18"
    elif case == "extra-principal":
        XML.SubElement(find("Principals"), ia._NS + "Principal")
    elif case in {"extra-trigger", "disabled-extra-trigger", "registration-trigger"}:
        extra = XML.SubElement(find("Triggers"), ia._NS + ("RegistrationTrigger" if case == "registration-trigger" else "LogonTrigger"))
        XML.SubElement(extra, ia._NS + "Enabled").text = "false" if case == "disabled-extra-trigger" else "true"
    elif case == "extra-action":
        XML.SubElement(find("Actions"), ia._NS + "Exec")
    elif case == "restart":
        XML.SubElement(find("Settings"), ia._NS + "RestartOnFailure")
    elif case in {"repetition", "future-start", "expiration"}:
        XML.SubElement(find("Triggers/LogonTrigger"), ia._NS + {"repetition": "Repetition", "future-start": "StartBoundary", "expiration": "EndBoundary"}[case]).text = "2099-01-01T00:00:00"
    elif case == "demand-start":
        find("Settings/AllowStartOnDemand").text = "true"
    elif case == "hidden":
        find("Settings/Hidden").text = "true"
    elif case == "time-limit":
        find("Settings/ExecutionTimeLimit").text = "PT72H"
    elif case == "foreign-namespace":
        find("Actions/Exec").tag = "{urn:untrusted}Exec"
    elif case == "version-drift":
        find("RegistrationInfo/Description").text += "-different-version"
    with pytest.raises(ia._Held):
        ia._verify_xml(XML.tostring(root, encoding="unicode"), binding())


@pytest.mark.parametrize("case", ["owner", "unprotected", "principal-write", "inherited", "everyone", "denied", "boolean-mask"],
                         ids=["owner-not-admin-or-system", "dacl-not-protected", "no-principal-write", "no-inherited-ace",
                              "no-extra-user", "closed-ace-qualifier", "strict-numeric-mask"])
def test_task_security_rejects_unreviewed_access(case):
    value = snapshot()["security"]
    if case == "owner":
        value["owner"] = SID
    elif case == "unprotected":
        value["protected"] = False
    elif case == "principal-write":
        value["aces"][2]["mask"] = ia._FULL
    elif case == "inherited":
        value["aces"][2]["flags"] = 16
    elif case == "everyone":
        value["aces"].append({"sid": "S-1-1-0", "mask": ia._FULL, "flags": 0, "qualifier": 0})
    elif case == "denied":
        value["aces"][2]["qualifier"] = 1
    else:
        value["aces"][2]["mask"] = True
    with pytest.raises(ia._Held, match="task-security-held"):
        ia._verify_security(value, binding())


@pytest.mark.parametrize("sid", ["S-1-5-18", "S-1-5-21-01-2-3-1001", "S-1-5-21-1-2-3-4294967296", "caller", SID + "\n"],
                         ids=["no-system-account", "canonical-decimal", "uint32-subauthority", "not-a-sid", "no-control-suffix"])
def test_user_sid_is_closed_and_never_environment_text(sid):
    assert not ia._valid_sid(sid)


def configure(monkeypatch, *, enrolled=False, legacy=False, elevated=True):
    current = binding()
    calls, state = [], {"present": enrolled, "legacy": legacy}
    monkeypatch.setattr(ia, "sys", SimpleNamespace(platform="win32", frozen=True))
    monkeypatch.setattr("angerona.core.windows_package_identity.verify_current_msix_authority",
        lambda: SimpleNamespace(trusted=True, identity=SimpleNamespace(full_name=current.full_name, family_name=current.family_name)))
    monkeypatch.setattr("angerona.core.autostart._target_action", lambda: (current.executable, current.arguments, current.cwd))
    monkeypatch.setattr("angerona.core.privilege.is_admin", lambda: elevated)
    def native(request):
        calls.append(deepcopy(request))
        operation = request["operation"]
        if operation == "identity":
            return {"sid": SID, "elevated": elevated}
        if operation == "inspect":
            return snapshot(**state)
        if operation == "enroll":
            state["present"] = True
            return {"snapshot": snapshot(**state), "changed": True}
        assert operation == "revoke"
        assert request["expected_xml_sha256"] == hashlib.sha256(snapshot(**state)["xml"].encode("utf-8")).hexdigest()
        state["present"] = False
        return {"snapshot": snapshot(**state), "changed": True}
    monkeypatch.setattr(ia, "_native", native)
    return calls, state


def test_source_never_queries_enrolls_revokes_or_requests_uac(monkeypatch):
    monkeypatch.setattr(ia, "sys", SimpleNamespace(platform="win32", frozen=False))
    monkeypatch.setattr(ia, "_native", lambda *_: pytest.fail("source tried native enrollment"))
    for operation in (ia.inspect_enrollment, ia.enroll_current_admin, ia.revoke_current_admin):
        status = operation()
        assert status.code == "source-or-platform-held" and status.enabled is None


def test_unprovisioned_real_publisher_pins_remain_a_hard_hold(monkeypatch):
    monkeypatch.setattr(ia, "sys", SimpleNamespace(platform="win32", frozen=True))
    monkeypatch.setattr("angerona.core.windows_package_identity.verify_current_msix_authority",
                        lambda: SimpleNamespace(trusted=False, identity=None))
    monkeypatch.setattr(ia, "_native", lambda *_: pytest.fail("untrusted package queried native task"))
    assert ia.enroll_current_admin().code == "package-authority-held"


def test_initial_admin_is_required_but_status_remains_read_only(monkeypatch):
    calls, _state = configure(monkeypatch, elevated=False)
    assert ia.inspect_enrollment().code == "not-enrolled"
    assert ia.enroll_current_admin().code == "initial-admin-required"
    assert ia.revoke_current_admin().code == "initial-admin-required"
    assert not {call["operation"] for call in calls}.intersection({"enroll", "revoke"})


def test_enrollment_and_revocation_report_only_verified_native_effect(monkeypatch):
    calls, state = configure(monkeypatch)
    created = ia.enroll_current_admin()
    assert created.code == "enrolled-created" and created.enabled is True and created.changed is True
    assert ia.enroll_current_admin().code == "enrolled"
    assert sum(call["operation"] == "enroll" for call in calls) == 1
    revoked = ia.revoke_current_admin()
    assert revoked.code == "revoked" and revoked.enabled is False and revoked.changed is True
    assert state["present"] is False
    assert set(call["operation"] for call in calls) <= {"identity", "inspect", "enroll", "revoke"}


def test_foreign_legacy_task_is_preserved_and_conflict_is_visible(monkeypatch):
    calls, state = configure(monkeypatch, legacy=True)
    result = ia.enroll_current_admin()
    assert result.code == "legacy-conflict" and result.requires_review and result.enabled is False
    assert not any(call["operation"] == "enroll" for call in calls)
    assert state["legacy"] is True


def test_native_failure_cannot_report_disabled_or_success(monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(ia, "_native", lambda *_: (_ for _ in ()).throw(ia._Held("native-retirement-held")))
    for operation in (ia.inspect_enrollment, ia.enroll_current_admin, ia.revoke_current_admin):
        result = operation()
        assert result.code == "native-retirement-held"
        assert result.enabled is None and not result.changed and result.requires_review


def test_package_path_drift_requires_review_and_never_deletes_task(monkeypatch):
    calls, _state = configure(monkeypatch, enrolled=True)
    native = ia._native
    def drifted(request):
        value = native(request)
        if request["operation"] == "inspect":
            value["xml"] = value["xml"].replace("--automatic-start", "--different-package-entry")
        return value
    monkeypatch.setattr(ia, "_native", drifted)
    result = ia.revoke_current_admin()
    assert result.code == "reenrollment-review" and result.enabled is None
    assert not any(call["operation"] == "revoke" for call in calls)


def test_post_registration_security_failure_retains_unknown_effect(monkeypatch):
    configure(monkeypatch)
    native = ia._native
    def unverified(request):
        value = native(request)
        if request["operation"] == "enroll":
            value["snapshot"]["security"]["aces"][2]["mask"] = ia._FULL
        return value
    monkeypatch.setattr(ia, "_native", unverified)
    result = ia.enroll_current_admin()
    assert result.code == "task-security-held"
    assert result.enabled is None and result.changed is False and result.requires_review


def test_concurrent_creator_is_not_falsely_counted_as_our_registration(monkeypatch):
    configure(monkeypatch)
    native = ia._native
    def concurrent(request):
        value = native(request)
        if request["operation"] == "enroll":
            value["changed"] = False
        return value
    monkeypatch.setattr(ia, "_native", concurrent)
    result = ia.enroll_current_admin()
    assert result.code == "enrolled" and result.enabled is True and result.changed is False


def test_exact_revocation_preserves_legacy_and_never_targets_live_process(monkeypatch):
    calls, state = configure(monkeypatch, enrolled=True, legacy=True)
    result = ia.revoke_current_admin()
    assert result.code == "revoked-legacy-preserved" and result.enabled is False
    assert state == {"present": False, "legacy": True}
    assert all(call["operation"] in {"identity", "inspect", "revoke"} for call in calls)


def test_large_documentation_inspection_and_revocation_keep_exact_digest_with_small_request(monkeypatch):
    configure(monkeypatch, enrolled=True)
    original_native = ia._native
    document = xml_fixture()
    registration = document.find(ia._NS + "RegistrationInfo")
    XML.SubElement(registration, ia._NS + "Documentation").text = "inert documentation " + "x" * (20 * 1024)
    # Keep the exact native string, including BOM/newlines. The digest must not
    # parse/re-serialize, trim, strip the BOM or normalize line endings.
    exact_xml = "\ufeff" + XML.tostring(document, encoding="unicode").replace("><", ">\r\n<") + "\r\n"
    assert ia._MAX_REQUEST < len(exact_xml.encode("utf-8")) < ia._MAX_XML
    observed = []
    def native(request):
        if request["operation"] == "inspect":
            value = snapshot()
            value["xml"] = exact_xml
            return value
        if request["operation"] == "revoke":
            observed.append(deepcopy(request))
            assert "expected_xml" not in request
            assert request["expected_xml_sha256"] == hashlib.sha256(exact_xml.encode("utf-8")).hexdigest()
            assert len(json.dumps(dict(request, version=1), ensure_ascii=False,
                                  separators=(",", ":")).encode("utf-8")) <= ia._MAX_REQUEST
            return {"snapshot": snapshot(present=False), "changed": True}
        return original_native(request)
    monkeypatch.setattr(ia, "_native", native)
    assert ia.inspect_enrollment().code == "enrolled"
    revoked = ia.revoke_current_admin()
    assert revoked.code == "revoked" and revoked.changed and len(observed) == 1


@pytest.mark.parametrize("phase,expected", [
    ("normal", None), ("close-raises", "native-retirement-held"),
    ("timeout-close-raises", "native-retirement-held"), ("wait-false", "native-retirement-held"),
    ("timeout", "native-output-held"), ("oversized", "native-output-held"),
    ("malformed", "native-unavailable"),
], ids=["retired-once", "detach-before-close-failure", "cleanup-close-failure-stays-retirement-held",
        "tree-retirement-required", "finite-deadline", "bounded-output", "invalid-json-held"])
def test_native_adapter_closes_exact_owned_probe_once_and_classifies_failure(monkeypatch, tmp_path, phase, expected):
    # Exercise the real adapter with an inert retained-child fake. No Windows
    # SDK call, subprocess, task, credential or elevated operation occurs.
    instances = []
    class Probe:
        def __init__(self, command, *, cwd, env, stdout):
            self.close_calls = 0
            self.returncode = 0
            instances.append(self)
            assert command[0] == str(tmp_path / "powershell.exe")
            assert "-NonInteractive" in command and "-EncodedCommand" in command
            if phase == "oversized":
                stdout.write(b"x" * (ia._MAX_OUTPUT + 1))
            elif phase == "malformed":
                stdout.write(b"not-json")
            else:
                stdout.write(json.dumps({"sid": SID, "elevated": True}).encode("utf-8"))
            stdout.flush()

        def poll(self):
            return None if phase.startswith("timeout") else 0

        def wait_tree(self, *, timeout):
            assert timeout == 1.0
            return phase != "wait-false"

        def close(self):
            self.close_calls += 1
            if phase in {"close-raises", "timeout-close-raises"}:
                raise RuntimeError("inert native retirement failure")
    ticks = iter((0.0, 21.0))
    monkeypatch.setattr(ia, "time", SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _: None))
    monkeypatch.setattr("angerona.startup._WindowsProbe", Probe)
    monkeypatch.setattr("angerona.core.privilege.trusted_powershell_path", lambda: tmp_path / "powershell.exe")
    monkeypatch.setattr("angerona.core.privilege.sanitized_child_environment", lambda: {})
    if expected is None:
        assert ia._native({"operation": "identity"}) == {"sid": SID, "elevated": True}
    else:
        with pytest.raises(ia._Held) as failure:
            ia._native({"operation": "identity"})
        assert failure.value.code == expected
    assert len(instances) == 1 and instances[0].close_calls == 1
