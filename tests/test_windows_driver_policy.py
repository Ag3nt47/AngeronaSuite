"""Real approvals/journal/capabilities with inert policy adapters.

The only native runner acceptance launches owned inert Python children. No test
invokes ConfigCI, CiTool policy mutation, registry, EFI or host network changes.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from angerona.core.approval_identity import ApprovalIdentityVerifier, PrincipalCredential, SignedPrincipalProof
from angerona.core.engine_transport import EngineError, create_private_file, private_directory
from angerona.core.privileged_pipe import NativePeer
from angerona.core.privileged_service import PrivilegedService, PrivilegedServiceClient, PrivilegedServiceError
from angerona.core.response_broker import ResponseBroker
from angerona.core.response_capability import ResponseCapabilityAuthority
from angerona.core import windows_driver_policy as policy

GUID = "1d84faf4-2d8b-4e44-bc93-cec8b570b632"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def compiled(mode):
    return b"INERT TEST FIXTURE, NOT A CI BINARY: " + mode.encode("ascii")


def xml(mode="audit", version="1.0.0.0", *, deny="a" * 64):
    audit = "<Rule><Option>Enabled:Audit Mode</Option></Rule>" if mode == "audit" else ""
    return f'''<SiPolicy xmlns="{policy.NS}" PolicyType="Base Policy">
    <VersionEx>{version}</VersionEx><PolicyID>{{{GUID.upper()}}}</PolicyID>
    <BasePolicyID>{{{GUID.upper()}}}</BasePolicyID>
    <PlatformID>{policy.WINDOWS_PLATFORM_ID}</PlatformID>
    <Rules><Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
    <Rule><Option>Enabled:Update Policy No Reboot</Option></Rule>
    <Rule><Option>Enabled:Boot Audit on Failure</Option></Rule>{audit}</Rules>
    <EKUs/><FileRules><Allow ID="ID_ALLOW_KERNEL" FriendlyName="Allow kernel" FileName="*"/>
    <Allow ID="ID_ALLOW_USER" FriendlyName="Allow user" FileName="*"/>
    <Deny ID="ID_DENY_FIXTURE" Hash="{deny}"/></FileRules>
    <Signers/><SigningScenarios><SigningScenario Value="131" ID="ID_KERNEL">
    <ProductSigners><FileRulesRef><FileRuleRef RuleID="ID_ALLOW_KERNEL"/>
    <FileRuleRef RuleID="ID_DENY_FIXTURE"/></FileRulesRef></ProductSigners></SigningScenario>
    <SigningScenario Value="12" ID="ID_USER"><ProductSigners><FileRulesRef>
    <FileRuleRef RuleID="ID_ALLOW_USER"/></FileRulesRef></ProductSigners></SigningScenario></SigningScenarios>
    <UpdatePolicySigners/><CiSigners/><HvciOptions>0</HvciOptions>
    <Settings><Setting Provider="PolicyInfo" Key="Information" ValueName="Name"><Value>
    <String>{policy.NAME}</String></Value></Setting></Settings></SiPolicy>'''.encode()


def material(mode="audit", **kwargs):
    source = kwargs.pop("xml", xml(mode, "1.0.0.0" if mode == "audit" else "1.0.0.1"))
    catalog = kwargs.pop("catalog", policy.ReviewedDriverCatalog(
        "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/",
        "inert-reviewed-fixture-v1", "Offline test review; no host deployment",
        b"reviewed inert WDAC-image-hash catalog fixture", digest(b"reviewed inert WDAC-image-hash catalog fixture")))
    return policy.DriverPolicyMaterial(GUID, mode, 1 << 48 if mode == "audit" else (1 << 48) + 1,
        source, digest(source), digest(compiled(mode)), catalog, **kwargs)


def snapshot(current):
    return policy.DriverPolicySnapshot(GUID, current.version, False, False, True, True, True,
                                       0, current.compiled_sha256, True)


class Native:
    def __init__(self):
        self.current = policy.DriverPolicySnapshot(GUID)
        self.calls, self.before_update, self.after_update, self.query_hook = [], None, None, None

    def inspect(self, identity):
        assert identity == GUID
        if self.query_hook:
            self.query_hook()
        return self.current

    def update(self, item, *, before_mutation, cancelled=None):
        assert cancelled is not None and not cancelled()
        if self.before_update:
            self.before_update()
        before_mutation()
        self.calls.append(("update", item.identity))
        self.current = snapshot(item)
        if self.after_update:
            self.after_update()

    def remove(self, identity, *, before_mutation, cancelled=None):
        assert identity == GUID and cancelled is not None and not cancelled()
        before_mutation()
        self.calls.append(("remove", identity))
        self.current = policy.DriverPolicySnapshot(GUID)


def peer(index=1):
    return NativePeer(f"S-1-5-21-100-200-300-{index}", "S-1-5-5-1-2", "1:2", 1234, 100.0)


def key(index):
    return Ed25519PrivateKey.from_private_bytes(digest(f"inert-driver-review-{index}".encode()).encode()[:32])


def credential(index):
    return PrincipalCredential(f"operator-{index}", "windows-token", peer(index).user_sid,
        key(index).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def proof(proposal, index, stamp):
    unsigned = SignedPrincipalProof.unsigned(credential(index), proposal.digest,
                                              stamp - 1, stamp + 300, str(index) * 32)
    return replace(unsigned, signature=base64.urlsafe_b64encode(
        key(index).sign(unsigned.signing_bytes())).decode().rstrip("="))


@pytest.fixture
def system(tmp_path):
    clock, accepted, native = [1000.0], [True], Native()
    audit, enforce = material(), material("enforce")
    broker = ResponseBroker(b"b" * 32, clock=lambda: clock[0],
        identity_verifier=ApprovalIdentityVerifier([credential(index) for index in (1, 2, 3)], clock=lambda: clock[0]),
        state_path=tmp_path / "broker" / "state.json")
    journal = policy.DriverPolicyJournal(tmp_path / "journal" / "state.json", b"j" * 32,
                                         installed_guard=lambda: accepted[0])
    authority = ResponseCapabilityAuthority(b"a" * 32, state_path=tmp_path / "authority" / "state.json")
    endpoint = {}

    def consume(**kwargs):
        if endpoint.get("hook"):
            endpoint["hook"]()
        return endpoint["client"].execute(request_id=kwargs["parameters"]["plan_id"], **kwargs)

    backend = policy.WindowsDriverPolicyBackend(broker, journal, native=native,
        materials={item.identity: item for item in (audit, enforce)}, minimum_audit_seconds=300,
        capabilities=authority, consumer=consume, installed_guard=lambda: accepted[0], clock=lambda: clock[0])
    executor = policy.NativeDriverPolicyExecutor(validator=backend.validator, native=native,
                                                installed_guard=lambda: accepted[0])
    service = PrivilegedService(authority, transport_key=b"t" * 32, executor=executor)
    transport = SimpleNamespace(exchange=service.handle)
    endpoint["client"] = PrivilegedServiceClient(transport_key=b"t" * 32, transport=transport)
    result = SimpleNamespace(backend=backend, broker=broker, journal=journal, authority=authority,
        native=native, audit=audit, enforce=enforce, clock=clock, accepted=accepted, endpoint=endpoint,
        executor=executor, service=service)
    try:
        yield result
    finally:
        broker.close()
        journal.close()
        authority.close()


def approved(state, plan):
    proposal = state.backend.proposal(plan, peer())
    for index in (2, 3):
        state.backend.approve(proposal, proof(proposal, index, state.clock[0]), peer(index))
    return proposal


def install_audit(state):
    plan = state.backend.prepare(state.audit.identity)
    receipt = state.backend.execute(approved(state, plan), peer())
    assert receipt.outcome == "completed"
    return plan, receipt


def review(state, audit):
    state.clock[0] += 300
    report = b"Inert offline compatibility/recovery review fixture, not host evidence"
    value = policy.DriverCompatibilityReview(audit.plan_id, state.audit.identity, report, digest(report),
                                             "Test review: boot recovery and driver compatibility accepted")
    state.backend.register_compatibility_review(value)
    return value


def test_actual_durable_approvals_capability_service_audit_enforce_and_owned_remove(system):
    state = system
    audit, audit_receipt = install_audit(state)
    assert state.broker.verify_receipt(audit_receipt)
    assert audit_receipt.result["kernel_prevention_verified"] is False
    assert audit_receipt.result["running_driver_unloaded"] is False
    assert state.authority.health().consumed_sequence == 1
    evidence = review(state, audit)
    enforce = state.backend.prepare(state.enforce.identity, action="enforce", original_id=audit.plan_id,
                                    review_id=evidence.identity)
    proposal = approved(state, enforce)
    receipt = state.backend.execute(proposal, peer())
    assert receipt.outcome == "completed" and state.native.current.matches(state.enforce)
    assert state.journal.row(audit.plan_id)["phase"] == "superseded"
    assert state.backend.execute(proposal, peer()) == receipt
    assert len(state.native.calls) == 2
    remove = state.backend.prepare(state.enforce.identity, action="remove", original_id=enforce.plan_id)
    assert state.backend.execute(approved(state, remove), peer()).outcome == "completed"
    assert not state.native.current.present and state.authority.health().consumed_sequence == 3
    assert state.journal.row(enforce.plan_id)["phase"] == "removed"
    assert state.native.calls[-1] == ("remove", GUID)


def test_preview_is_nonmutating_and_does_not_burn_audit_plan(system):
    state = system
    plan = state.backend.prepare(state.audit.identity)
    receipt = state.backend.execute(state.backend.proposal(plan, peer(), dry_run=True), peer())
    assert receipt.outcome == "previewed" and not state.native.calls
    assert state.authority.health().issued_sequence == 0
    assert state.backend.execute(approved(state, plan), peer()).outcome == "completed"


def test_review_description_discloses_unsigned_and_boot_fallback_limits(system):
    state = system
    plan = state.backend.prepare(state.audit.identity)
    description = state.backend.describe_plan(plan)
    assert description["unsigned_policy"] and description["boot_audit_on_failure"]
    assert description["administrator_tamper_resistance"] is False
    assert description["compiled_sha256"] == state.audit.compiled_sha256
    assert description["catalog_source_url"] == state.audit.catalog.source_url
    assert not state.native.calls


def test_two_independent_nonrequester_native_peers_must_approve(system):
    state = system
    proposal = state.backend.proposal(state.backend.prepare(state.audit.identity), peer())
    with pytest.raises(PermissionError, match="2 approval"):
        state.backend.execute(proposal, peer())
    with pytest.raises(PermissionError, match="own"):
        state.backend.approve(proposal, proof(proposal, 1, state.clock[0]), peer())
    with pytest.raises(PermissionError, match="native pipe user SID"):
        state.backend.approve(proposal, proof(proposal, 2, state.clock[0]), peer(3))
    state.backend.approve(proposal, proof(proposal, 2, state.clock[0]), peer(2))
    with pytest.raises(PermissionError, match="2 approval"):
        state.backend.execute(proposal, peer())
    assert not state.native.calls


@pytest.mark.parametrize("missing", ["guard", "consumer", "authority"])
def test_unaccepted_source_composition_is_held(system, missing):
    state = system
    if missing == "guard":
        state.accepted[0] = False
    elif missing == "consumer":
        state.backend.consumer = None
    else:
        state.backend.capabilities = None
    assert state.backend.status()["state"] == "held"
    plan = state.backend.prepare(state.audit.identity)
    with pytest.raises(PermissionError, match="held"):
        state.backend.execute(approved(state, plan), peer())
    assert not state.native.calls


def test_absent_guard_cannot_create_journal_or_native_adapter(tmp_path):
    with pytest.raises(PermissionError, match="installed"):
        policy.DriverPolicyJournal(tmp_path / "never" / "journal.json", b"x" * 32)
    assert not (tmp_path / "never").exists()
    with pytest.raises(PermissionError, match="installed"):
        policy.WindowsNativeDriverPolicyApi(tmp_path, None)


def test_enforcement_requires_observed_audit_floor_and_retained_review(system):
    state = system
    audit, _ = install_audit(state)
    report = b"inert review"
    value = policy.DriverCompatibilityReview(audit.plan_id, state.audit.identity, report, digest(report), "fixture review")
    state.clock[0] += 299
    with pytest.raises(PermissionError, match="aged"):
        state.backend.register_compatibility_review(value)
    state.clock[0] += 1
    state.backend.register_compatibility_review(value)
    retained = state.journal.path.parent / "compatibility-reviews" / (value.identity + ".json")
    assert base64.b64decode(json.loads(retained.read_bytes())["report_base64"]) == report
    with pytest.raises(PermissionError, match="matching reviewed"):
        state.backend.prepare(state.enforce.identity, action="enforce", original_id=audit.plan_id, review_id="0" * 64)
    plan = state.backend.prepare(state.enforce.identity, action="enforce", original_id=audit.plan_id, review_id=value.identity)
    assert plan.review_id == value.identity


@pytest.mark.parametrize("change", ["catalog", "rules", "version"])
def test_enforcement_cannot_expand_reviewed_audit_rules_or_reuse_version(system, change):
    state = system
    audit, _ = install_audit(state)
    evidence = review(state, audit)
    if change == "catalog":
        different = replace(state.enforce, catalog=replace(state.enforce.catalog, review_reference="different catalog"))
    elif change == "rules":
        source = xml("enforce", "1.0.0.1", deny="b" * 64)
        different = replace(state.enforce, xml=source, xml_sha256=digest(source))
    else:
        source = xml("enforce", "1.0.0.0")
        different = replace(state.enforce, version=1 << 48, xml=source, xml_sha256=digest(source))
    state.backend.validator.materials = policy._material_map({different.identity: different, state.audit.identity: state.audit})
    with pytest.raises(PermissionError, match="matching reviewed"):
        state.backend.prepare(different.identity, action="enforce", original_id=audit.plan_id, review_id=evidence.identity)
    assert len(state.native.calls) == 1


@pytest.mark.parametrize("change", ["signed", "platform", "version", "disk_sha256", "active"])
def test_current_native_policy_drift_cannot_authorize_removal(system, change):
    state = system
    audit, _ = install_audit(state)
    value = {"signed": True, "platform": True, "version": 5, "disk_sha256": "b" * 64, "active": False}[change]
    state.native.current = replace(state.native.current, **{change: value})
    plan = state.backend.prepare(state.audit.identity, action="remove", original_id=audit.plan_id)
    with pytest.raises(PrivilegedServiceError, match="executor failed"):
        state.backend.execute(approved(state, plan), peer())
    assert len(state.native.calls) == 1 and state.journal.row(plan.plan_id)["phase"] == "uncertain"


def test_drift_after_durable_intent_is_held_before_capability_dispatch(system, monkeypatch):
    state = system
    plan = state.backend.prepare(state.audit.identity)
    original = state.journal.begin

    def begin(arguments, cancel):
        original(arguments, cancel)
        state.native.current = snapshot(state.enforce)

    monkeypatch.setattr(state.journal, "begin", begin)
    with pytest.raises(PermissionError, match="drifted"):
        state.backend.execute(approved(state, plan), peer())
    assert not state.native.calls and state.authority.health().issued_sequence == 0


def test_drift_during_staging_is_rechecked_at_final_native_dispatch(system):
    state = system
    plan = state.backend.prepare(state.audit.identity)
    state.native.before_update = lambda: setattr(state.native, "current", snapshot(state.enforce))
    with pytest.raises(PrivilegedServiceError):
        state.backend.execute(approved(state, plan), peer())
    assert not state.native.calls and state.authority.health().consumed_sequence == 1


@pytest.mark.parametrize("boundary", ["prepare", "intent", "consumer", "readback"])
def test_wrong_policy_guid_is_not_proof_of_absence_or_success(system, monkeypatch, boundary):
    state = system
    wrong = policy.DriverPolicySnapshot("3854bdd0-24bb-4d59-9aa7-3dd8ca3a5858")
    if boundary == "prepare":
        state.native.current = wrong
        with pytest.raises(ValueError, match="snapshot"):
            state.backend.prepare(state.audit.identity)
        return
    plan = state.backend.prepare(state.audit.identity)
    if boundary == "intent":
        original = state.journal.begin

        def begin(arguments, token):
            original(arguments, token)
            state.native.current = wrong

        monkeypatch.setattr(state.journal, "begin", begin)
    elif boundary == "consumer":
        state.endpoint["hook"] = lambda: setattr(state.native, "current", wrong)
    else:
        state.native.after_update = lambda: setattr(state.native, "current", wrong)
    if boundary == "readback":
        assert state.backend.execute(approved(state, plan), peer()).outcome == "verification-failed"
    else:
        with pytest.raises((PermissionError, PrivilegedServiceError)):
            state.backend.execute(approved(state, plan), peer())
        assert not state.native.calls


@pytest.mark.parametrize("boundary", ["queued", "intent", "service"])
def test_cancel_is_observed_at_each_mutation_admission_boundary(system, monkeypatch, boundary):
    state = system
    plan, cancel = state.backend.prepare(state.audit.identity), threading.Event()
    if boundary == "queued":
        cancel.set()
    elif boundary == "intent":
        original = state.journal.begin

        def begin(arguments, token):
            original(arguments, token)
            cancel.set()

        monkeypatch.setattr(state.journal, "begin", begin)
    else:
        state.endpoint["hook"] = cancel.set
    with pytest.raises((PermissionError, PrivilegedServiceError)):
        state.backend.execute(approved(state, plan), peer(), cancel=cancel)
    assert not state.native.calls
    if boundary == "intent":
        assert state.journal.row(plan.plan_id)["phase"] == "cancelled"
    elif boundary == "service":
        assert state.journal.row(plan.plan_id)["phase"] == "uncertain"
        assert state.authority.health().consumed_sequence == 1


def test_failed_readback_never_claims_completed_or_automatically_removes_policy(system):
    state = system
    plan = state.backend.prepare(state.audit.identity)
    state.native.after_update = lambda: setattr(state.native, "current", replace(state.native.current, active=False))
    receipt = state.backend.execute(approved(state, plan), peer())
    assert receipt.outcome == "verification-failed" and len(state.native.calls) == 1
    assert state.journal.row(plan.plan_id)["phase"] == "uncertain"
    state.native.current = snapshot(state.audit)
    remove = state.backend.prepare(state.audit.identity, action="remove", original_id=plan.plan_id)
    assert state.backend.execute(approved(state, remove), peer()).outcome == "completed"


def test_removal_cannot_claim_success_from_absence_of_a_different_guid(system, monkeypatch):
    state = system
    audit, _ = install_audit(state)
    plan = state.backend.prepare(state.audit.identity, action="remove", original_id=audit.plan_id)
    original = state.native.remove

    def remove(identity, **kwargs):
        original(identity, **kwargs)
        state.native.current = policy.DriverPolicySnapshot("3854bdd0-24bb-4d59-9aa7-3dd8ca3a5858")

    monkeypatch.setattr(state.native, "remove", remove)
    receipt = state.backend.execute(approved(state, plan), peer())
    assert receipt.outcome == "verification-failed"
    assert state.journal.row(plan.plan_id)["phase"] == "uncertain"
    assert state.journal.row(audit.plan_id)["phase"] == "configured"


def test_clock_regression_inside_native_admission_cannot_be_recovered_by_clock_advance(system):
    state = system
    plan = state.backend.prepare(state.audit.identity)
    state.native.before_update = lambda: state.clock.__setitem__(0, 999.0)
    with pytest.raises((PermissionError, PrivilegedServiceError)):
        state.backend.execute(approved(state, plan), peer())
    state.clock[0] = 1001.0
    assert not state.native.calls
    with pytest.raises(PermissionError, match="regressed"):
        state.backend.prepare(state.audit.identity)


def test_process_restart_does_not_resume_old_durable_intent(tmp_path):
    path = tmp_path / "driver" / "state.json"
    journal = policy.DriverPolicyJournal(path, b"x" * 32, installed_guard=lambda: True)
    item = material()
    arguments = asdict(policy.DriverPolicyPlan("a" * 32, GUID, "audit", item.identity, "absent", "", "", 100, 200))
    journal.begin(arguments, None)
    journal.close()
    reopened = policy.DriverPolicyJournal(path, b"x" * 32, installed_guard=lambda: True)
    try:
        with pytest.raises(PermissionError, match="current-process"):
            reopened.authorize_intent(arguments)
        assert reopened.row("a" * 32)["phase"] == "intent"
    finally:
        reopened.close()


@pytest.mark.parametrize("damage", ["hmac", "marker", "state"])
def test_journal_authentication_and_enrollment_never_adopt_unowned_policy(tmp_path, damage):
    path = tmp_path / "driver" / "state.json"
    journal = policy.DriverPolicyJournal(path, b"x" * 32, installed_guard=lambda: True)
    journal.close()
    if damage == "hmac":
        value = json.loads(path.read_bytes())
        value["hmac"] = "0" * 64
        path.write_text(json.dumps(value))
    elif damage == "marker":
        path.with_suffix(".enrolled").unlink()
    else:
        path.unlink()
    with pytest.raises((ValueError, OSError)):
        policy.DriverPolicyJournal(path, b"x" * 32, installed_guard=lambda: True)


@pytest.mark.parametrize("mutation", [
    lambda raw: raw.replace(b'FileName="*"', b'FileName="only.exe"', 1),
    lambda raw: raw.replace(b"Enabled:Unsigned System Integrity Policy", b"Enabled:UMCI"),
    lambda raw: raw.replace(b"Enabled:Audit Mode", b"Enabled:Allow Supplemental Policies"),
    lambda raw: raw.replace(b'Value="131"', b'Value="999"'),
    lambda raw: raw.replace(b'PolicyType="Base Policy"', b'PolicyType="Supplemental Policy"'),
    lambda raw: raw.replace(GUID.upper().encode(), b"00000000-0000-0000-0000-000000000000", 1),
    lambda raw: raw.replace(b"<HvciOptions>0</HvciOptions>", b"<HvciOptions>2</HvciOptions>"),
    lambda raw: raw.replace(b'<FileRuleRef RuleID="ID_DENY_FIXTURE"/>', b""),
    lambda raw: raw.replace(b"<CiSigners/>", b'<CiSigners><CiSigner SignerId="extra"/></CiSigners>'),
    lambda raw: raw.replace(b'Provider="PolicyInfo"', b'Provider="Unrelated"'),
    lambda raw: raw.replace(b"<EKUs/>", b"<UnknownExtension/><EKUs/>"),
    lambda raw: raw.replace(policy.WINDOWS_PLATFORM_ID.encode(), b"{00000000-0000-0000-0000-000000000000}"),
    lambda raw: raw.replace(b'<FileRuleRef RuleID="ID_ALLOW_USER"/>',
                           b'<FileRuleRef RuleID="ID_ALLOW_USER"/><FileRuleRef RuleID="ID_DENY_FIXTURE"/>'),
])
def test_policy_profile_rejects_global_deny_signed_or_unsupported_semantics(mutation):
    with pytest.raises((ValueError, PermissionError)):
        material(xml=mutation(xml()))


def native_json(item=None, **updates):
    if item is None:
        return json.dumps({"Policies": []}).encode()
    row = {"PolicyID": "{" + GUID.upper() + "}", "BasePolicyID": GUID, "FriendlyName": policy.NAME,
           "Version": str(item.version), "IsSignedPolicy": False, "IsSystemPolicy": False,
           "IsOnDisk": True, "IsEnforced": True, "IsAuthorized": True, "Status": 0}
    row.update(updates)
    return json.dumps({"Policies": [row]}).encode()


def test_native_json_policy_identity_and_written_material_are_both_required():
    item = material()
    observed = policy.parse_citool_policy(native_json(item), GUID, item.compiled_sha256)
    assert observed.matches(item)
    assert not observed.matches(material("enforce"))
    assert not policy.parse_citool_policy(native_json(item, IsEnforced=False), GUID, item.compiled_sha256).matches(item)
    assert not policy.parse_citool_policy(native_json(item), GUID, "b" * 64).matches(item)
    assert not policy.parse_citool_policy(native_json(), GUID, "").present
    with pytest.raises(PermissionError, match="Unlisted"):
        policy.parse_citool_policy(native_json(), GUID, "a" * 64)


@pytest.mark.parametrize("updates", [
    {"IsEnforced": 1}, {"IsSignedPolicy": None}, {"Version": "01"}, {"VersionString": "2.0.0.0"},
    {"BasePolicyID": "f" * 36}, {"FriendlyName": "Other owner"}, {"Status": "0"},
])
def test_native_json_unknown_or_contradictory_values_are_not_healthy(updates):
    item = material()
    with pytest.raises((ValueError, PermissionError, KeyError)):
        policy.parse_citool_policy(native_json(item, **updates), GUID, item.compiled_sha256)


def test_duplicate_or_partial_native_inventory_is_not_absence():
    item = material()
    document = json.loads(native_json(item))
    document["Policies"].append(document["Policies"][0])
    for raw in (b'{}', b'{"Policies":[],"Policies":[]}', json.dumps(document).encode()):
        with pytest.raises((ValueError, RuntimeError)):
            policy.parse_citool_policy(raw, GUID, "")


class StagingApi(policy.WindowsNativeDriverPolicyApi):
    """Exercise real staging/argument rendering with NO native command runner."""
    def __init__(self, root, *, bad_output=False):
        self.root = private_directory(root)
        self.system = Path("C:/Windows/System32")
        self.citool = self.system / "CiTool.exe"
        self.powershell = self.system / "WindowsPowerShell/v1.0/powershell.exe"
        self.configci = self.powershell.parent / "Modules/ConfigCI/ConfigCI.psd1"
        self.guard, self._lock, self.calls, self.bad_output = lambda: True, threading.RLock(), [], bad_output
        self.pins = policy.NativeDriverPolicyPins("a" * 64, "Microsoft", "b" * 64, "Microsoft", digest(b"inert module"))

    @contextmanager
    def _sealed(self, path, **_kwargs):
        yield b"inert module" if path == self.configci else path.read_bytes()

    def _command(self, image, arguments, *, barrier=None, extra=None, **_kwargs):
        if barrier:
            barrier()
        self.calls.append((image, list(arguments), extra))
        if image == self.powershell:
            with os.fdopen(create_private_file(Path(extra["ANGERONA_DRIVER_BINARY"])), "wb") as stream:
                stream.write(b"incorrect compiler output" if self.bad_output else compiled("audit"))
        return b""


def test_actual_adapter_stages_pinned_source_and_invokes_only_fixed_compile_and_update(tmp_path):
    item, barriers = material(), []
    native = StagingApi(tmp_path / "material")
    native.update(item, before_mutation=lambda: barriers.append(True))
    assert len(barriers) >= 3
    assert native.calls[0][0] == native.powershell
    script = base64.b64decode(native.calls[0][1][-1]).decode("utf-16-le")
    assert script == policy.WindowsNativeDriverPolicyApi._COMPILE
    assert "ConvertFrom-CIPolicy" in script and "Invoke-Expression" not in script
    staged = native.root / item.identity
    assert (staged / "policy.xml").read_bytes() == item.xml
    assert (staged / "catalog.artifact").read_bytes() == item.catalog.artifact
    assert native.calls[1][0:2] == (native.citool, ["--update-policy", str(staged / "policy.cip"), "-json"])
    native.remove(GUID, before_mutation=lambda: barriers.append(True))
    assert native.calls[-1][1] == ["--remove-policy", "{" + GUID.upper() + "}", "-json"]


def test_compiled_material_mismatch_is_preserved_and_never_dispatched(tmp_path):
    item = material()
    native = StagingApi(tmp_path / "material", bad_output=True)
    with pytest.raises(PermissionError, match="compiled policy pin"):
        native.update(item, before_mutation=lambda: None)
    assert len(native.calls) == 1 and native.calls[0][0] == native.powershell
    assert (native.root / item.identity / "policy.cip").read_bytes() == b"incorrect compiler output"


def test_optional_policy_storage_capacity_does_not_allow_unbounded_new_material(tmp_path):
    native = StagingApi(tmp_path / "material")
    for index in range(8):
        private_directory(native.root / digest(str(index).encode()))
    with pytest.raises(PermissionError, match="staging capacity"):
        native.update(material(), before_mutation=lambda: None)
    assert not native.calls


@pytest.fixture
def native_images(tmp_path):
    root = private_directory(tmp_path / "native-inbox-fixture")
    native = object.__new__(policy.WindowsNativeDriverPolicyApi)
    native.root, native.system, native.guard = root, root, lambda: True
    native.citool = root / "CiTool.exe"
    native.powershell = private_directory(root / "WindowsPowerShell") / "powershell.exe"
    native.configci = native.powershell.parent / "ConfigCI.psd1"
    for path, body in ((native.citool, b"owned inert CiTool fixture"),
                       (native.powershell, b"owned inert PowerShell fixture")):
        with os.fdopen(create_private_file(path), "wb") as stream:
            stream.write(body)
    native.pins = policy.NativeDriverPolicyPins(digest(native.citool.read_bytes()), "Accepted fixture publisher",
        digest(native.powershell.read_bytes()), "Accepted fixture publisher", "c" * 64)
    return native


@pytest.mark.skipif(os.name != "nt", reason="native Windows hardlink sharing contract")
def test_fixed_native_inbox_hardlink_custody_denies_data_write_and_held_name_deletion(native_images):
    native = native_images
    alias = native.system / "owned-native-alias.exe"
    os.link(native.citool, alias)
    assert native.citool.stat().st_nlink == 2
    with native._system_image(native.citool, native.pins.citool_sha256) as check:
        check()
        with pytest.raises(OSError):
            alias.write_bytes(b"inert forbidden replacement")
        with pytest.raises(OSError):
            native.citool.unlink()
        with pytest.raises(OSError):
            native.citool.rename(native.system / "replacement.exe")
        check()
    # Staged/private material retains its single-link rule. The native-only
    # exception is never applied to its catalog/XML/CIP/journal artifacts.
    with pytest.raises(EngineError, match="Unsafe engine state path"):
        with native._sealed(native.citool, private=True):
            pytest.fail("Private hardlinked artifact was admitted")
    alias.unlink()
    native.citool.write_bytes(b"owned post-release write")


@pytest.mark.skipif(os.name != "nt", reason="native Windows hardlink sharing contract")
def test_unlinking_another_native_hardlink_is_observed_drift_not_claimed_prevention(native_images):
    native = native_images
    alias = native.system / "owned-native-alias.exe"
    os.link(native.citool, alias)
    original = native.citool.read_bytes()
    with pytest.raises(PermissionError, match="identity changed"):
        with native._system_image(native.citool, native.pins.citool_sha256) as check:
            alias.unlink()  # This can succeed on local NTFS despite another link being open.
            assert native.citool.read_bytes() == original
            check()
    assert native.citool.exists() and not alias.exists()


@pytest.mark.parametrize("denial", ["acl", "publisher", "helper-publisher"])
def test_untrusted_native_writer_or_publisher_is_denied_even_with_pinned_bytes(native_images, monkeypatch, denial):
    from angerona.core import executable_trust

    native, calls = native_images, []
    monkeypatch.setattr(executable_trust, "_protected_path", lambda path: denial != "acl")

    def signer(path):
        mismatch = denial == "publisher" and path == native.citool or denial == "helper-publisher" and path == native.powershell
        return "Valid", "Unaccepted publisher" if mismatch else "Accepted fixture publisher", "inert"

    monkeypatch.setattr(executable_trust, "_authenticode_identity", signer)
    monkeypatch.setattr(policy, "_run_native", lambda *_a, **_k: calls.append(True))
    with pytest.raises(PermissionError):
        native._command(native.citool, ["--list-policies", "-json"])
    assert not calls


@pytest.mark.skipif(os.name != "nt", reason="native Windows sealed helper contract")
def test_native_authenticode_helper_is_itself_pinned_and_held_through_child_barriers(native_images, monkeypatch):
    from angerona.core import executable_trust

    native, observed = native_images, []
    alias = native.system / "owned-helper-alias.exe"
    os.link(native.powershell, alias)
    monkeypatch.setattr(executable_trust, "_protected_path", lambda path: True)

    def signer(path):
        with pytest.raises(OSError):
            alias.write_bytes(b"must remain held while checking signatures")
        observed.append(path)
        return "Valid", "Accepted fixture publisher", "inert"

    def run(image, arguments, *, before_launch, **_kwargs):
        assert image == native.citool and arguments == ["--list-policies", "-json"]
        before_launch()  # Equivalent to the runner's pre-CreateProcess barrier.
        before_launch()  # Equivalent to its pre-resume barrier.
        with pytest.raises(OSError):
            native.powershell.unlink()
        return b"owned inert native output"

    monkeypatch.setattr(executable_trust, "_authenticode_identity", signer)
    monkeypatch.setattr(policy, "_run_native", run)
    assert native._command(native.citool, ["--list-policies", "-json"]) == b"owned inert native output"
    assert observed == [native.powershell, native.citool]
    alias.unlink()


@pytest.mark.skipif(os.name != "nt", reason="retained native Windows Job runner")
@pytest.mark.parametrize("condition", ["normal", "timeout", "overflow"])
def test_native_runner_retires_only_its_owned_inert_tree(tmp_path, condition):
    if condition == "normal":
        code, timeout = "print('owned inert output')", 10
    elif condition == "timeout":
        code, timeout = "import time; time.sleep(10)", .2
    else:
        code, timeout = "import sys,time; sys.stdout.buffer.write(b'x'*(3*1024*1024));sys.stdout.flush();time.sleep(10)", 10
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    run = lambda: policy._run_native(Path(sys.executable), ["-I", "-c", code], cwd=tmp_path,
        environment=environment, before_launch=lambda: None, timeout=timeout)
    if condition == "normal":
        assert run().strip() == b"owned inert output"
    else:
        with pytest.raises(TimeoutError, match="bound"):
            run()


class ModeledCommandJob:
    """No native handle/process; only an explicit cleanup contract fixture."""
    def __init__(self, *, fail_close=False):
        self.calls, self.fail_close = [], fail_close
    def terminate(self):
        self.calls.append("terminate")
    def wait_empty(self, timeout):
        self.calls.append("wait-empty")
    def close(self):
        self.calls.append("close")
        if self.fail_close:
            raise OSError("inert ambiguous Job close")


@pytest.fixture
def command_owner(monkeypatch):
    monkeypatch.setattr(policy, "_NATIVE_COMMAND_RETIREMENT_HOLD", ())
    calls = []
    api = SimpleNamespace(CloseHandle=lambda value: calls.append(("close", value)),
        WaitForSingleObject=lambda *_args: 0,
        TerminateProcess=lambda value, _code: calls.append(("terminate", value)))
    owner = policy._OwnedNativeCommand(_api=api)
    owner.job = ModeledCommandJob()
    owner.process, owner.thread, owner.assigned = 101, 202, True  # Inert values, never WinAPI input.
    try:
        yield owner, calls
    finally:
        # Dispose only fixture-owned resources after proving its exact late
        # reader has returned. Production uncertainty remains sticky/unchanged.
        if owner.write_fd is not None:
            owner._close_fd_once("write_fd")
        if owner.reader_transfer and not owner.reader_retired.is_set():
            release = getattr(owner.reader, "fixture_release", None)
            if release is not None:
                release.set()
            activate = getattr(owner.reader, "activate_late", None)
            if activate is not None:
                activate()
            owner.reader.join(3)
            assert owner.reader_retired.is_set() and not owner.reader.is_alive()
        elif not owner.reader_transfer:
            owner._close_fd_once("read_fd")


@pytest.mark.parametrize("late_bootstrap", [False, True])
def test_reader_start_exception_retains_descriptor_and_cleans_other_known_owners(command_owner, late_bootstrap):
    owner, calls = command_owner
    class Reader:
        def __init__(self, *, target, **_kwargs):
            self.target, self.worker = target, None
        def start(self):
            raise RuntimeError("inert start failed before ident publication")
        def is_alive(self):
            return self.worker is not None and self.worker.is_alive()
        def join(self, timeout):
            if self.worker is None:
                raise RuntimeError("cannot join before start")
            self.worker.join(timeout)
        def activate_late(self):
            if self.worker is None:
                self.worker = threading.Thread(target=self.target, name="owned late reader fixture")
                self.worker.start()
    owner.reader_factory = Reader
    descriptor = owner.read_fd
    with pytest.raises(RuntimeError, match="start failed"):
        owner.start_reader()
    assert owner.retire() is False
    assert owner in policy._NATIVE_COMMAND_RETIREMENT_HOLD and owner.read_fd == descriptor
    os.fstat(descriptor)  # Parent has not closed/reused the pending reader's descriptor.
    assert calls == [("close", 202), ("close", 101)]
    assert owner.job.calls == ["terminate", "wait-empty"]  # Job owner retained, not discarded.
    with pytest.raises(PermissionError, match="retirement remains held"):
        policy._run_native(Path("unused"), [], cwd=Path("unused"), environment={}, before_launch=lambda: None)
    if late_bootstrap:
        owner.reader.activate_late()
        owner.reader.join(3)
        assert owner.reader_retired.is_set() and owner.read_fd is None
    assert owner.retire() is False  # No clean second retirement or native-number retry.
    assert calls == [("close", 202), ("close", 101)]


def test_pending_output_reader_keeps_its_descriptor_until_its_own_finally(command_owner, monkeypatch):
    owner, _calls = command_owner
    release, entered = threading.Event(), threading.Event()
    closed = []
    real_close, descriptor = os.close, owner.read_fd
    def close(fd):
        if fd == descriptor:
            closed.append(threading.get_ident())
        return real_close(fd)
    monkeypatch.setattr(policy.os, "close", close)
    class Reader:
        fixture_release = release
        def __init__(self, *, target, **_kwargs):
            def wait():
                entered.set()
                assert release.wait(5)
                target()
            self.worker = threading.Thread(target=wait, name="owned pending reader fixture")
        def start(self):
            self.worker.start()
        def is_alive(self):
            return self.worker.is_alive()
        def join(self, timeout):
            self.worker.join(min(timeout, .02) if not release.is_set() else timeout)
    owner.reader_factory = Reader
    owner.start_reader()
    assert entered.wait(2)
    assert owner.retire() is False and owner.read_fd == descriptor and not closed
    os.fstat(descriptor)
    release.set()
    owner.reader.join(3)
    assert owner.reader_retired.is_set() and owner.read_fd is None
    assert len(closed) == 1 and closed[0] != threading.get_ident()


@pytest.mark.parametrize("failure", ["thread", "job"])
def test_native_close_failure_is_sticky_and_does_not_skip_other_known_cleanup(command_owner, failure):
    owner, calls = command_owner
    if failure == "thread":
        def close(handle):
            calls.append(("close", handle))
            if handle == 202:
                raise OSError("inert ambiguous native close")
        owner.api.CloseHandle = close
    else:
        owner.job.fail_close = True
    assert owner.retire() is False
    assert owner.read_fd is owner.write_fd is owner.process is owner.thread is None
    assert calls == [("close", 202), ("close", 101)]
    first = list(owner.job.calls)
    assert owner.retire() is False and owner.job.calls == first
    assert calls == [("close", 202), ("close", 101)]


def test_reader_descriptor_close_uncertainty_never_retries_its_numeric_value(command_owner, monkeypatch):
    owner, _calls = command_owner
    real_close, descriptor, closes = os.close, owner.read_fd, []
    def close(fd):
        result = real_close(fd)
        if fd == descriptor:
            closes.append(fd)
            raise OSError("modeled ambiguous close after OS actually released this fixture fd")
        return result
    monkeypatch.setattr(policy.os, "close", close)
    owner._close_fd_once("write_fd")
    owner.start_reader()
    owner.reader.join(3)
    assert owner.reader_retired.is_set() and owner.read_fd is None and owner.read_close_error
    assert owner.retire() is False and owner in policy._NATIVE_COMMAND_RETIREMENT_HOLD
    assert owner.retire() is False and closes == [descriptor]


def test_native_cleanup_hold_blocks_helpers_before_any_new_native_work(native_images, monkeypatch):
    from angerona.core import executable_trust

    native = native_images
    monkeypatch.setattr(policy, "_NATIVE_COMMAND_RETIREMENT_HOLD", (object(),))
    monkeypatch.setattr(executable_trust, "_protected_path", lambda *_args: pytest.fail("Unretired command spawned another helper"))
    with pytest.raises(PermissionError, match="retirement remains held"):
        native._command(native.citool, ["--list-policies", "-json"])
    with pytest.raises(PermissionError, match="retirement remains held"):
        with native._sealed(native.citool, private=False):
            pytest.fail("Unretired command opened another native artifact")


def test_native_cleanup_hold_is_visible_in_backend_status_and_prevents_new_capability(system, monkeypatch):
    state = system
    plan = state.backend.prepare(state.audit.identity)
    proposal = approved(state, plan)
    monkeypatch.setattr(policy, "_NATIVE_COMMAND_RETIREMENT_HOLD", (object(),))
    assert state.backend.status()["state"] == "held"
    with pytest.raises(PermissionError, match="held"):
        state.backend.execute(proposal, peer())
    assert not state.native.calls and state.authority.health().issued_sequence == 0
