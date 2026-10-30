"""Managed, audit-first Windows vulnerable-driver deny-policy deployment.

This is an installed-service backend, not an elevation helper. Nothing registers
it with the diagnostic/source service. Trusted composition supplies the protected
installation/root guard, reviewed catalog/XML/binary pins, OS executable pins,
durable independent approvals and capability-consuming transport. Python objects
inside one process are not an OS security boundary.

The first supported profile is an *unsigned*, removable multiple-policy base deny
policy. It does not edit Microsoft's platform policy, existing allowlists, EFI,
registry, HVCI or boot settings. Signed/firmware-bound policy removal is deliberately
unsupported. CiTool configuration/readback is not proof that a particular driver
was blocked or that an already loaded driver was unloaded. Fresh CodeIntegrity
decision/load events and clean-VM/reboot acceptance are separate evidence.

Microsoft references (reviewed 2026-10-29):
https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands
https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-deny-policy
https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/disable-appcontrol-policies
https://learn.microsoft.com/en-us/powershell/module/configci/convertfrom-cipolicy
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass
import base64
import ctypes
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import threading
import time
from types import MappingProxyType
from urllib.parse import urlsplit
import uuid

from defusedxml import ElementTree as ET

from .approval_identity import SignedPrincipalProof
from .engine_transport import canonical, create_private_file, decode, private_directory, verify_private
from .file_lease import ExclusiveFileLease
from .response_broker import ResponseBroker, ResponseOperation, ResponseProposal
from .response_capability import PrivilegedOpcode
from .windows_prevention import WindowsPreventionBackend

MAX_MATERIAL_BYTES = 4 * 1024 * 1024
MAX_CATALOG_BYTES = 2 * 1024 * 1024
MAX_REVIEW_BYTES = 256 * 1024
PLAN_TTL = 300.0
NS = "urn:schemas-microsoft-com:sipolicy"
WINDOWS_PLATFORM_ID = "{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}"
NAME = "Angerona Managed Driver Deny Policy"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[0-9a-f]{32}\Z")
_DOMAIN = b"Angerona-Managed-Driver-Policy-v1\0"
_PLAN_FIELDS = frozenset({"plan_id", "policy_id", "action", "material_id", "expected_state",
                          "original_id", "review_id", "created_at", "expires_at"})
_OPCODES = {"audit": PrivilegedOpcode.DRIVER_POLICY_AUDIT,
            "enforce": PrivilegedOpcode.DRIVER_POLICY_ENFORCE,
            "remove": PrivilegedOpcode.DRIVER_POLICY_REMOVE}
_NATIVE_COMMAND_LOCK = threading.RLock()
_NATIVE_COMMAND_RETIREMENT_HOLD = ()


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _sha(value):
    if type(value) is not str or not _HEX.fullmatch(value):
        raise ValueError("Canonical SHA-256 required")
    return value


def _guid(value):
    if type(value) is not str or str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
        raise ValueError("Canonical nonzero policy GUID required")
    return value


def _stamp(clock):
    value = clock()
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("Driver-policy clock unavailable")
    return value


def _guard(guard):
    if guard is None or guard() is not True:
        raise PermissionError("Protected installed driver-policy composition unavailable")


def _version(value):
    if type(value) is not str or not re.fullmatch(r"\d{1,5}(?:\.\d{1,5}){3}", value):
        raise ValueError("Four-component policy version required")
    parts = value.split(".")
    if any(str(int(part)) != part or int(part) > 65535 for part in parts):
        raise ValueError("Policy version component invalid")
    return sum(int(part) << shift for part, shift in zip(parts, (48, 32, 16, 0)))


def _xml_profile(raw, policy_id, mode, version):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_MATERIAL_BYTES:
        raise ValueError("Bounded reviewed policy XML required")
    root = ET.fromstring(raw)
    tag = lambda name: "{" + NS + "}" + name
    if root.tag != tag("SiPolicy") or root.attrib != {"PolicyType": "Base Policy"}:
        raise ValueError("Only a multiple-policy base deny policy is supported")
    allowed_children = {tag(name) for name in ("VersionEx", "PolicyID", "BasePolicyID", "PlatformID", "Rules",
        "EKUs", "FileRules", "Signers", "SigningScenarios", "UpdatePolicySigners", "CiSigners", "HvciOptions", "Settings")}
    if any(child.tag not in allowed_children for child in root):
        raise ValueError("Unknown policy extension is outside the managed driver-only purpose")
    platforms = root.findall(tag("PlatformID"))
    if len(platforms) != 1 or platforms[0].text != WINDOWS_PLATFORM_ID:
        raise ValueError("Exact reviewed Windows policy platform required")
    hvci = root.findall(tag("HvciOptions"))
    if len(hvci) != 1 or hvci[0].text != "0":
        raise ValueError("Driver deny plans cannot change HVCI configuration")
    for name in ("PolicyID", "BasePolicyID"):
        nodes = root.findall(tag(name))
        if len(nodes) != 1 or nodes[0].text != "{" + policy_id.upper() + "}":
            raise ValueError("Reviewed policy GUID/base identity mismatch")
    versions = root.findall(tag("VersionEx"))
    if len(versions) != 1 or _version(versions[0].text) != version:
        raise ValueError("Reviewed policy version mismatch")
    rules = root.findall(tag("Rules"))
    if len(rules) != 1:
        raise ValueError("Exactly one policy-options block required")
    options = [node.text for node in rules[0].findall(tag("Rule") + "/" + tag("Option"))]
    expected = {"Enabled:Unsigned System Integrity Policy", "Enabled:Update Policy No Reboot",
                "Enabled:Boot Audit on Failure"}
    if mode == "audit":
        expected.add("Enabled:Audit Mode")
    if set(options) != expected or len(options) != len(expected):
        raise ValueError("Policy options differ from the reviewed removable driver-only profile")
    # Deny-only policies need Allow All in BOTH scenarios. Do not accidentally
    # deploy a global implicit-deny allowlist when adding vulnerable-driver rules.
    files = root.findall(tag("FileRules"))
    if len(files) != 1:
        raise ValueError("Exactly one file-rule block required")
    allows = files[0].findall(tag("Allow"))
    if (len(allows) != 2 or any(set(node.attrib) - {"ID", "FriendlyName", "FileName"}
                               or node.attrib.get("FileName") != "*" for node in allows)):
        raise ValueError("Standalone deny profile requires exactly two Allow All rules")
    allow_ids = {node.attrib.get("ID") for node in allows}
    if None in allow_ids or len(allow_ids) != 2:
        raise ValueError("Distinct Allow All rule IDs required")
    scenarios = root.findall(tag("SigningScenarios") + "/" + tag("SigningScenario"))
    if len(scenarios) != 2 or {node.attrib.get("Value") for node in scenarios} != {"131", "12"}:
        raise ValueError("Kernel and user signing scenarios required")
    for scenario in scenarios:
        products = scenario.findall(tag("ProductSigners"))
        if len(products) != 1 or any(child.tag != tag("ProductSigners") for child in scenario):
            raise ValueError("Unsupported signing-scenario extension")
        references = {node.attrib.get("RuleID") for node in scenario.findall(
            tag("ProductSigners") + "/" + tag("FileRulesRef") + "/" + tag("FileRuleRef"))}
        if len(references & allow_ids) != 1:
            raise ValueError("Each signing scenario must reference one Allow All rule")
        if scenario.attrib["Value"] == "12":
            refs = products[0].findall(tag("FileRulesRef") + "/" + tag("FileRuleRef"))
            if (len(refs) != 1 or refs[0].attrib != {"RuleID": next(iter(references & allow_ids))}
                    or len(products[0]) != 1 or products[0][0].tag != tag("FileRulesRef")):
                raise ValueError("User-mode scenario must remain Allow All only")
        elif any(child.tag not in {tag("FileRulesRef"), tag("DeniedSigners")} for child in products[0]):
            raise ValueError("Kernel scenario admits only explicit deny catalog and Allow All references")
    kernel = next(node for node in scenarios if node.attrib["Value"] == "131")
    kernel_references = {node.attrib.get("RuleID") for node in kernel.findall(
        tag("ProductSigners") + "/" + tag("FileRulesRef") + "/" + tag("FileRuleRef"))}
    deny_ids = {node.attrib.get("ID") for node in files[0].findall(tag("Deny"))}
    if not (kernel_references & deny_ids) and not kernel.findall(
            tag("ProductSigners") + "/" + tag("DeniedSigners") + "/" + tag("DeniedSigner")):
        raise ValueError("At least one catalog deny must participate in the kernel signing scenario")
    names = root.findall(tag("Settings") + "/" + tag("Setting"))
    seen_settings = set()
    for node in names:
        field = node.attrib.get("ValueName")
        if (node.attrib != {"Provider": "PolicyInfo", "Key": "Information", "ValueName": field}
                or field not in {"Name", "Id"} or field in seen_settings):
            raise ValueError("Unrelated or duplicate policy setting is outside driver-deny purpose")
        seen_settings.add(field)
        expected_text = NAME if field == "Name" else "{" + policy_id.upper() + "}"
        if node.findtext(tag("Value") + "/" + tag("String")) != expected_text:
            raise ValueError("Managed policy information differs from its approved identity")
    if "Name" not in seen_settings:
        raise ValueError("Managed policy name missing")
    if any(list(node) for node in root.findall(tag("UpdatePolicySigners"))):
        raise ValueError("Signed-policy update signers are outside this unsigned profile")
    if any(list(node) for node in root.findall(tag("CiSigners"))):
        raise ValueError("Additional Code Integrity signers are outside driver-deny purpose")
    # Canonical semantic identity removes ONLY version and Audit Mode. Enforce
    # must carry precisely the same rules/catalog that the reviewed audit used.
    root.remove(versions[0])
    for rule in list(rules[0]):
        if rule.findtext(tag("Option")) == "Enabled:Audit Mode":
            rules[0].remove(rule)

    def tree(node):
        return [node.tag, sorted(node.attrib.items()), (node.text or "").strip(), [tree(child) for child in node]]

    return _digest(canonical(tree(root)))


@dataclass(frozen=True)
class ReviewedDriverCatalog:
    """Pinned review artifact, not a remote download granting trust.

    `artifact` is the actual reviewed catalog/manifest retained by the service.
    Its schema and every PE-image/signer rule still need the enrollment review;
    an ordinary flat-file LOLDrivers SHA-256 is not automatically a WDAC hash.
    """
    source_url: str
    revision: str
    review_reference: str
    artifact: bytes
    artifact_sha256: str

    def __post_init__(self):
        split = urlsplit(self.source_url)
        if (split.scheme != "https" or not split.hostname or split.username or split.password
                or split.fragment or len(self.source_url) > 2048):
            raise ValueError("Reviewed catalog HTTPS provenance required")
        for value in (self.revision, self.review_reference):
            if type(value) is not str or not 1 <= len(value) <= 512 or any(ord(c) < 32 for c in value):
                raise ValueError("Bounded immutable catalog revision/review required")
        if type(self.artifact) is not bytes or not 1 <= len(self.artifact) <= MAX_CATALOG_BYTES:
            raise ValueError("Actual bounded reviewed catalog artifact required")
        if _digest(self.artifact) != _sha(self.artifact_sha256):
            raise ValueError("Reviewed catalog pin mismatch")

    @property
    def identity(self):
        return _digest(canonical({"url": self.source_url, "revision": self.revision,
                                  "review": self.review_reference, "sha256": self.artifact_sha256}))


@dataclass(frozen=True)
class DriverPolicyMaterial:
    policy_id: str
    mode: str
    version: int
    xml: bytes
    xml_sha256: str
    compiled_sha256: str
    catalog: ReviewedDriverCatalog

    def __post_init__(self):
        _guid(self.policy_id)
        if self.mode not in {"audit", "enforce"} or type(self.version) is not int or not 0 < self.version < 2**64:
            raise ValueError("Typed audit/enforce policy version required")
        if type(self.catalog) is not ReviewedDriverCatalog:
            raise ValueError("Actual reviewed catalog provenance required")
        if type(self.xml) is not bytes or not 1 <= len(self.xml) <= MAX_MATERIAL_BYTES:
            raise ValueError("Bounded reviewed policy XML required")
        if _digest(self.xml) != _sha(self.xml_sha256):
            raise ValueError("Reviewed XML pin mismatch")
        _sha(self.compiled_sha256)
        _xml_profile(self.xml, self.policy_id, self.mode, self.version)

    @property
    def rules_digest(self):
        return _xml_profile(self.xml, self.policy_id, self.mode, self.version)

    @property
    def identity(self):
        return _digest(canonical({"policy_id": self.policy_id, "mode": self.mode, "version": self.version,
                                  "xml": self.xml_sha256, "compiled": self.compiled_sha256,
                                  "catalog": self.catalog.identity, "rules": self.rules_digest}))


@dataclass(frozen=True)
class DriverCompatibilityReview:
    audit_plan_id: str
    audit_material_id: str
    report: bytes
    report_sha256: str
    review_reference: str

    def __post_init__(self):
        if type(self.audit_plan_id) is not str or not _ID.fullmatch(self.audit_plan_id):
            raise ValueError("Exact managed audit plan required")
        _sha(self.audit_material_id)
        if type(self.report) is not bytes or not 1 <= len(self.report) <= MAX_REVIEW_BYTES:
            raise ValueError("Retained compatibility/audit evidence required")
        if _digest(self.report) != _sha(self.report_sha256):
            raise ValueError("Compatibility report pin mismatch")
        if (type(self.review_reference) is not str or not 1 <= len(self.review_reference) <= 512
                or any(ord(c) < 32 for c in self.review_reference)):
            raise ValueError("Explicit compatibility/recovery review reference required")

    @property
    def identity(self):
        return _digest(canonical({"audit": self.audit_plan_id, "material": self.audit_material_id,
                                  "report": self.report_sha256, "review": self.review_reference}))


@dataclass(frozen=True)
class DriverPolicySnapshot:
    policy_id: str
    version: int = 0
    signed: bool = False
    platform: bool = False
    on_disk: bool = False
    active: bool = False
    authorized: bool = False
    status: int = 0
    disk_sha256: str = ""
    present: bool = False

    def __post_init__(self):
        _guid(self.policy_id)
        if type(self.version) is not int or not 0 <= self.version < 2**64 or type(self.status) is not int:
            raise ValueError("Invalid native policy version/status")
        if any(type(getattr(self, field)) is not bool for field in
               ("signed", "platform", "on_disk", "active", "authorized", "present")):
            raise ValueError("Native policy flags must be typed booleans")
        if self.disk_sha256:
            _sha(self.disk_sha256)
        if not self.present and any((self.version, self.signed, self.platform, self.on_disk,
                                     self.active, self.authorized, self.status, self.disk_sha256)):
            raise ValueError("Contradictory absent policy state")

    @property
    def fingerprint(self):
        return _digest(canonical(asdict(self))) if self.present else "absent"

    def matches(self, material):
        return (self.present and self.policy_id == material.policy_id and self.version == material.version
                and not self.signed and not self.platform and self.on_disk and self.active
                and self.authorized and self.status == 0 and self.disk_sha256 == material.compiled_sha256)


@dataclass(frozen=True)
class DriverPolicyPlan:
    plan_id: str
    policy_id: str
    action: str
    material_id: str
    expected_state: str
    original_id: str
    review_id: str
    created_at: float
    expires_at: float

    def __post_init__(self):
        validate_plan(asdict(self))

    @property
    def opcode(self):
        return _OPCODES[self.action]

    @property
    def resource(self):
        return "windows-driver-policy:" + self.policy_id


def validate_plan(arguments, *, now=None):
    if type(arguments) is not dict or set(arguments) != _PLAN_FIELDS:
        raise ValueError("Exact driver-policy plan schema required")
    _guid(arguments["policy_id"])
    for field in ("plan_id", "original_id"):
        value = arguments[field]
        if type(value) is not str or (not value and field != "original_id") or (value and not _ID.fullmatch(value)):
            raise ValueError("Invalid driver-policy plan identity")
    _sha(arguments["material_id"])
    if arguments["expected_state"] != "absent":
        _sha(arguments["expected_state"])
    if arguments["action"] not in _OPCODES:
        raise ValueError("Unsupported driver-policy action")
    if arguments["action"] == "audit":
        if arguments["expected_state"] != "absent" or arguments["original_id"] or arguments["review_id"]:
            raise ValueError("Audit admission must target a previously absent managed policy")
    else:
        if not arguments["original_id"] or arguments["original_id"] == arguments["plan_id"]:
            raise ValueError("Managed prior intent required")
        if arguments["expected_state"] == "absent":
            raise ValueError("Existing managed policy required")
        if arguments["action"] == "enforce":
            _sha(arguments["review_id"])
        elif arguments["review_id"]:
            raise ValueError("Removal has no enforcement review")
    created, expires = arguments["created_at"], arguments["expires_at"]
    if (type(created) not in (int, float) or type(expires) not in (int, float)
            or not math.isfinite(created) or not math.isfinite(expires)
            or not 0 <= created < expires <= created + PLAN_TTL):
        raise ValueError("Invalid bounded driver-policy plan lifetime")
    if now is not None and not created <= now < expires:
        raise PermissionError("Driver-policy plan expired or clock regressed")


class DriverPolicyJournal:
    """Authenticated managed ownership/intent journal under installed custody.

    The enrollment guard must validate the service token, fixed root/package,
    ACLs and key custody. Local HMAC/marker detect modification, not whole-root
    replay. The external high-water/independent-witness boundary remains separate.
    """
    def __init__(self, path, key, *, installed_guard=None):
        _guard(installed_guard)
        if type(key) is not bytes or len(key) < 32:
            raise ValueError("Protected driver-policy journal key required")
        self.path, self._key, self._guard = Path(path), key, installed_guard
        if not self.path.is_absolute() or ".." in self.path.parts or str(self.path).startswith(("\\\\", "//")):
            raise ValueError("Fixed local service-custodied journal path required")
        private_directory(self.path.parent)
        self._lock = threading.RLock()
        self._lease = ExclusiveFileLease(self.path.with_suffix(".lease"))
        self._rows, self._active = {}, {}
        self._failed = False
        try:
            marker = self.path.with_suffix(".enrolled")
            anchor = hmac.new(key, _DOMAIN + b"enrollment", hashlib.sha256).hexdigest().encode("ascii")
            if marker.exists():
                if _read_private(marker, 64) != anchor:
                    raise ValueError("Driver-policy journal enrollment mismatch")
                document = decode(_read_private(self.path, 256 * 1024))
                if set(document) != {"schema", "rows", "hmac"} or document["schema"] != "angerona.driver-policy.v1":
                    raise ValueError("Driver-policy journal schema invalid")
                rows = document["rows"]
                mac = hmac.new(key, _DOMAIN + canonical(rows), hashlib.sha256).hexdigest()
                if type(document["hmac"]) is not str or not hmac.compare_digest(document["hmac"], mac):
                    raise ValueError("Driver-policy journal authentication failed")
                if type(rows) is not dict or len(rows) > 128:
                    raise ValueError("Driver-policy journal row bound exceeded")
                for identity, row in rows.items():
                    if (type(row) is not dict or set(row) != {"arguments", "phase", "finished_at"}
                            or row["phase"] not in {"intent", "configured", "cancelled", "uncertain", "removed", "superseded"}
                            or identity != row["arguments"].get("plan_id")
                            or type(row["finished_at"]) not in (int, float)
                            or not math.isfinite(row["finished_at"]) or row["finished_at"] < 0):
                        raise ValueError("Driver-policy journal row invalid")
                    validate_plan(row["arguments"])
                self._rows = rows
            else:
                if self.path.exists():
                    raise ValueError("Driver-policy enrollment marker missing")
                with os.fdopen(create_private_file(marker), "wb") as stream:
                    stream.write(anchor)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._save()
        except BaseException:
            self.close()
            raise

    def ready(self):
        return not self._failed and self._lease.held

    def close(self):
        with self._lock:
            self._failed = True
            self._active.clear()
            self._lease.close()

    def _save(self):
        _guard(self._guard)
        if not self.ready():
            raise PermissionError("Driver-policy journal closed/degraded")
        from .atomic_io import replace_with_retry
        raw = canonical({"schema": "angerona.driver-policy.v1", "rows": self._rows,
                         "hmac": hmac.new(self._key, _DOMAIN + canonical(self._rows), hashlib.sha256).hexdigest()})
        if len(raw) > 256 * 1024:
            self._failed = True
            raise ValueError("Driver-policy journal byte bound exceeded")
        temporary = self.path.with_name("." + self.path.name + "." + secrets.token_hex(8))
        try:
            with os.fdopen(create_private_file(temporary), "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if self.path.exists():
                verify_private(self.path)
            replace_with_retry(temporary, self.path)
        except BaseException:
            self._failed = True
            raise
        finally:
            temporary.unlink(missing_ok=True)

    def row(self, identity):
        with self._lock:
            if not self.ready() or identity not in self._rows:
                raise PermissionError("Authenticated managed driver-policy intent unavailable")
            return json.loads(canonical(self._rows[identity]))

    def begin(self, arguments, cancel):
        validate_plan(arguments)
        with self._lock:
            if not self.ready() or arguments["plan_id"] in self._rows or len(self._rows) >= 128:
                raise PermissionError("Driver-policy intent replay, unavailable journal or capacity")
            prior = arguments["original_id"]
            if prior:
                self.row(prior)
            for row in self._rows.values():
                if row["arguments"]["policy_id"] == arguments["policy_id"] and row["phase"] in {"intent", "uncertain"}:
                    if arguments["action"] != "remove" or row["arguments"]["plan_id"] != prior:
                        raise PermissionError("Unresolved managed policy intent requires exact removal review")
            self._rows[arguments["plan_id"]] = {"arguments": dict(arguments), "phase": "intent", "finished_at": 0}
            self._save()
            self._active[arguments["plan_id"]] = cancel

    def authorize_intent(self, arguments):
        with self._lock:
            row = self.row(arguments["plan_id"])
            if (row["phase"] != "intent" or row["arguments"] != arguments
                    or arguments["plan_id"] not in self._active):
                raise PermissionError("Exact current-process durable driver-policy intent required")
            cancel = self._active[arguments["plan_id"]]
            if cancel is not None and cancel.is_set():
                raise PermissionError("Driver-policy operation cancelled before native mutation")

    def cancelled(self, identity):
        with self._lock:
            if not self.ready() or identity not in self._active:
                return True
            cancel = self._active[identity]
            return cancel is not None and cancel.is_set()

    def finish(self, arguments, phase, stamp):
        with self._lock:
            row = self.row(arguments["plan_id"])
            if phase not in {"configured", "cancelled", "uncertain"} or row["arguments"] != arguments:
                raise ValueError("Invalid driver-policy terminal transition")
            if row["phase"] != "intent":
                raise PermissionError("Driver-policy intent already terminal")
            self._rows[arguments["plan_id"]].update(phase=phase, finished_at=stamp)
            if phase == "configured" and arguments["action"] == "remove":
                self._rows[arguments["original_id"]]["phase"] = "removed"
            if phase == "configured" and arguments["action"] == "enforce":
                self._rows[arguments["original_id"]]["phase"] = "superseded"
            self._save()
            self._active.pop(arguments["plan_id"], None)


def _read_private(path, bound):
    from .executable_trust import _open_sealed

    verify_private(path)
    with _open_sealed(path) as stream:
        held, named = os.fstat(stream.fileno()), path.stat()
        if ((held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
                or held.st_nlink != 1 or not stat.S_ISREG(held.st_mode)):
            raise PermissionError("Protected driver-policy file identity changed")
        raw = stream.read(bound + 1)
        after = os.fstat(stream.fileno())
        if (held.st_size, held.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise PermissionError("Protected driver-policy file changed during read")
    if len(raw) > bound:
        raise ValueError("Protected driver-policy file exceeds bound")
    return raw


def _material_map(materials):
    if type(materials) is not dict or not 1 <= len(materials) <= 32:
        raise ValueError("Bounded trusted driver-policy material catalog required")
    for identity, material in materials.items():
        if type(material) is not DriverPolicyMaterial or identity != material.identity:
            raise ValueError("Trusted material identity mismatch")
    return MappingProxyType(dict(materials))


class DriverPolicyValidator:
    """Same purpose checks at broker admission and capability consumer."""
    def __init__(self, journal, materials, reviews, clock, minimum_audit_seconds):
        self.journal, self.materials = journal, _material_map(materials)
        if type(reviews) is not dict or len(reviews) > 128 or any(
                type(value) is not DriverCompatibilityReview or key != value.identity for key, value in reviews.items()):
            raise ValueError("Trusted compatibility-review catalog required")
        self.reviews, self.clock = MappingProxyType(dict(reviews)), clock
        if (type(minimum_audit_seconds) not in (int, float) or not math.isfinite(minimum_audit_seconds)
                or not 300 <= minimum_audit_seconds <= 30 * 86400):
            raise ValueError("An audit observation floor of at least five minutes is required")
        self.minimum_audit_seconds = minimum_audit_seconds
        self._clock_lock, self._last_clock, self._clock_failed = threading.Lock(), None, False

    def now(self):
        with self._clock_lock:
            now = _stamp(self.clock)
            if self._clock_failed or (self._last_clock is not None and now < self._last_clock):
                self._clock_failed = True
                raise PermissionError("Driver-policy consumer clock regressed")
            self._last_clock = now
            return now

    def validate(self, arguments):
        now = self.now()
        validate_plan(arguments, now=now)
        material = self.materials.get(arguments["material_id"])
        if material is None or material.policy_id != arguments["policy_id"]:
            raise PermissionError("Plan must reference exact trusted managed material")
        action = arguments["action"]
        if action != "remove" and material.mode != action:
            raise PermissionError("Material mode differs from signed operation")
        if action == "audit":
            return material
        original = self.journal.row(arguments["original_id"])
        prior = original["arguments"]
        old = self.materials.get(prior["material_id"])
        if (old is None or prior["policy_id"] != material.policy_id or prior["action"] == "remove"
                or original["phase"] not in ({"configured"} if action == "enforce" else {"configured", "intent", "uncertain"})):
            raise PermissionError("Authenticated original managed deployment required")
        if action == "remove":
            if arguments["material_id"] != prior["material_id"]:
                raise PermissionError("Removal must reference exactly the owned deployed material")
            return material
        review = self.reviews.get(arguments["review_id"])
        if (prior["action"] != "audit" or review is None or review.audit_plan_id != prior["plan_id"]
                or review.audit_material_id != old.identity or old.catalog != material.catalog
                or old.rules_digest != material.rules_digest or material.version <= old.version
                or now - original["finished_at"] < self.minimum_audit_seconds):
            raise PermissionError("Enforcement requires aged exact audit, matching reviewed rules and compatibility evidence")
        return material


class NativeDriverPolicyExecutor:
    """Injected executor after PrivilegedService consumes the exact capability."""
    def __init__(self, *, validator, native, installed_guard=None):
        self.validator, self.native, self.guard = validator, native, installed_guard

    def execute(self, opcode, resource, parameters):
        arguments = dict(parameters)
        material = self.validator.validate(arguments)
        plan = DriverPolicyPlan(**arguments)
        if type(opcode) is not PrivilegedOpcode or opcode is not plan.opcode or resource != plan.resource:
            raise PermissionError("Driver-policy opcode/resource/purpose mismatch")

        def barrier():
            _guard(self.guard)
            self.validator.validate(arguments)
            self.validator.journal.authorize_intent(arguments)
            before = self.native.inspect(plan.policy_id)
            if (type(before) is not DriverPolicySnapshot or before.policy_id != plan.policy_id
                    or before.fingerprint != plan.expected_state):
                raise PermissionError("Native policy changed since reviewed preview")
            if before.present and (before.signed or before.platform or not before.matches(
                    self.validator.materials[self.validator.journal.row(plan.original_id)["arguments"]["material_id"]])):
                raise PermissionError("Only exact own unsigned nonplatform policy can be changed")
            # Native inspection itself may block. Recheck expiry/STOP and the
            # installed generation after it, directly before dispatch.
            _guard(self.guard)
            self.validator.validate(arguments)
            self.validator.journal.authorize_intent(arguments)

        barrier()
        cancelled = lambda: self.validator.journal.cancelled(plan.plan_id)
        if plan.action == "remove":
            self.native.remove(plan.policy_id, before_mutation=barrier, cancelled=cancelled)
        else:
            self.native.update(material, before_mutation=barrier, cancelled=cancelled)
        return {"plan_id": plan.plan_id, "policy_id": plan.policy_id,
                "requested_mode": plan.action, "compiled_sha256": material.compiled_sha256,
                "loaded_driver_removal": "not-performed", "effective_rule_content": "unverified"}


class WindowsDriverPolicyBackend:
    """Durable broker -> intent -> capability service -> independent readback.

    Consumer and guard are trusted constructor dependencies, never request fields.
    Same-process composition is only a contract; a real signed installed service
    with restricted IPC, protected roots and native-token acceptance is required.
    """
    def __init__(self, broker: ResponseBroker, journal: DriverPolicyJournal, *, native,
                 materials, reviews=None, minimum_audit_seconds=3600, capabilities=None,
                 consumer=None, installed_guard=None, clock=time.time):
        self.broker, self.journal, self.native = broker, journal, native
        self.capabilities, self.consumer, self.guard, self.clock = capabilities, consumer, installed_guard, clock
        self.validator = DriverPolicyValidator(journal, materials, reviews or {}, clock, minimum_audit_seconds)
        self._lock, self._clock_lock = threading.RLock(), threading.Lock()
        self._cancel, self._last_clock, self._clock_failed = None, None, False
        for action, opcode in _OPCODES.items():
            broker.register(ResponseOperation(opcode.value, "high", "Manage only an exact reviewed vulnerable-driver deny policy",
                "Remove only the authenticated own unsigned policy with a new separately approved plan; reboot may be required",
                lambda arguments, selected=action: self._validate_for(selected, arguments), self._apply, self._verify))

    def _now(self):
        with self._clock_lock:
            stamp = _stamp(self.clock)
            if self._clock_failed or (self._last_clock is not None and stamp < self._last_clock):
                self._clock_failed = True
                raise PermissionError("Driver-policy clock regressed; backend review required")
            self._last_clock = stamp
            return stamp

    def status(self):
        try:
            _guard(self.guard)
            ready = (self.consumer is not None and self.capabilities is not None and self.journal.ready()
                     and not _NATIVE_COMMAND_RETIREMENT_HOLD
                     and self.capabilities.health().state == "ready"
                     and self.capabilities.health().reason == "durable-epoch-bound-authority-ready"
                     and self.broker.approval_status()["state"] == "configured" and not self._clock_failed)
        except Exception:
            ready = False
        return {"state": "configured" if ready else "held", "profile": "own-unsigned-multiple-policy",
                "reason": "Installed token/root guard, durable approvals and capability consumer required" if not ready else
                          "Audit-first backend composed; exact native preconditions and independent approvals remain required",
                "signed_policy_tamper_resistance": False, "kernel_prevention_verified": False}

    def _validate_for(self, action, arguments):
        self._now()
        material = self.validator.validate(dict(arguments))
        if arguments["action"] != action:
            raise PermissionError("Signed driver-policy operation differs from purpose")
        return material

    def prepare(self, material_id, *, action="audit", original_id="", review_id=""):
        material = self.validator.materials[material_id]
        before = self.native.inspect(material.policy_id)
        if type(before) is not DriverPolicySnapshot or before.policy_id != material.policy_id:
            raise ValueError("Typed native policy snapshot required")
        now = self._now()
        plan = DriverPolicyPlan(secrets.token_hex(16), material.policy_id, action, material_id,
                                before.fingerprint, original_id, review_id, now, now + PLAN_TTL)
        self._validate_for(action, asdict(plan))
        return plan

    def register_compatibility_review(self, review):
        """Trusted service-side enrollment, never a generic IPC request handler.

        The caller must have reviewed the actual retained report and recovery
        route. Independent operators subsequently sign the exact enforce plan.
        Reopening the service requires reloading these pinned review artifacts.
        """
        with self._lock:
            _guard(self.guard)
            if type(review) is not DriverCompatibilityReview:
                raise ValueError("Typed compatibility review required")
            original = self.journal.row(review.audit_plan_id)
            if (original["phase"] != "configured" or original["arguments"]["action"] != "audit"
                    or original["arguments"]["material_id"] != review.audit_material_id
                    or self._now() - original["finished_at"] < self.validator.minimum_audit_seconds):
                raise PermissionError("Exact completed aged managed audit required")
            current = dict(self.validator.reviews)
            if review.identity not in current and len(current) >= 128:
                raise PermissionError("Driver-policy compatibility-review capacity reached")
            # Preserve the actual reviewed artifact alongside its immutable
            # provenance, rather than retaining only an opaque request hash.
            directory = private_directory(self.journal.path.parent / "compatibility-reviews")
            body = canonical({"audit_plan_id": review.audit_plan_id,
                              "audit_material_id": review.audit_material_id,
                              "report_sha256": review.report_sha256,
                              "review_reference": review.review_reference,
                              "report_base64": base64.b64encode(review.report).decode("ascii")})
            _store_pinned(directory / (review.identity + ".json"), body)
            current[review.identity] = review
            self.validator.reviews = MappingProxyType(current)

    def proposal(self, plan, peer, *, dry_run=False):
        if type(plan) is not DriverPolicyPlan:
            raise ValueError("Typed driver-policy plan required")
        self._validate_for(plan.action, asdict(plan))
        return ResponseProposal("driver-policy-" + plan.plan_id + ("-preview" if dry_run else ""),
            plan.opcode.value, asdict(plan), plan.resource, WindowsPreventionBackend._actor(peer),
            plan.created_at, plan.expires_at, dry_run)

    def describe_plan(self, plan):
        """Bounded review data; configuration claims and recovery effects explicit."""
        if type(plan) is not DriverPolicyPlan:
            raise ValueError("Typed driver-policy plan required")
        material = self._validate_for(plan.action, asdict(plan))
        return {"plan_id": plan.plan_id, "policy_id": plan.policy_id, "action": plan.action,
                "material_id": material.identity, "version": material.version,
                "xml_sha256": material.xml_sha256, "compiled_sha256": material.compiled_sha256,
                "catalog_source_url": material.catalog.source_url, "catalog_revision": material.catalog.revision,
                "catalog_sha256": material.catalog.artifact_sha256,
                "catalog_review": material.catalog.review_reference, "kernel_only": True,
                "boot_audit_on_failure": True, "unsigned_policy": True,
                "administrator_tamper_resistance": False,
                "reboot_and_loaded_driver_acceptance": "required separately; running drivers are not unloaded",
                "audit_observation_floor_seconds": self.validator.minimum_audit_seconds,
                "recovery": "New separately approved removal of this exact own policy; restart may be needed"}

    def approve(self, proposal, proof, peer):
        WindowsPreventionBackend._actor(peer)
        arguments = dict(proposal.arguments)
        plan = DriverPolicyPlan(**arguments)
        self._validate_for(plan.action, arguments)
        if proposal.operation_id != plan.opcode.value or proposal.target_id != plan.resource:
            raise PermissionError("Only the exact managed driver-policy proposal can be approved")
        if type(proof) is not SignedPrincipalProof or proof.issuer != "windows-token" or proof.subject != peer.user_sid:
            raise PermissionError("Approval credential must match the native pipe user SID")
        return self.broker.approve(proposal, proof)

    def execute(self, proposal, peer, *, cancel=None):
        with self._lock:
            if cancel is not None and not isinstance(cancel, threading.Event):
                raise ValueError("A trusted operation cancellation Event is required")
            arguments = dict(proposal.arguments)
            plan = DriverPolicyPlan(**arguments)
            if (proposal.requested_by != WindowsPreventionBackend._actor(peer)
                    or proposal.target_id != plan.resource or proposal.operation_id != plan.opcode.value):
                raise PermissionError("Driver-policy requester, target or operation mismatch")
            if not proposal.dry_run and self.status()["state"] != "configured":
                raise PermissionError("Installed driver-policy backend unavailable; operation held")
            self._cancel = cancel
            try:
                self._check_cancel()
                return self.broker.execute(proposal)
            finally:
                self._cancel = None

    def _check_cancel(self):
        if self._cancel is not None and self._cancel.is_set():
            raise PermissionError("Driver-policy operation cancelled before mutation")

    def _apply(self, arguments):
        if self.status()["state"] != "configured":
            raise PermissionError("Installed driver-policy consumer unavailable")
        self._check_cancel()
        self.journal.begin(dict(arguments), self._cancel)
        dispatched = False
        try:
            self._check_cancel()
            self._validate_for(arguments["action"], arguments)
            observed = self.native.inspect(arguments["policy_id"])
            if (type(observed) is not DriverPolicySnapshot or observed.policy_id != arguments["policy_id"]
                    or observed.fingerprint != arguments["expected_state"]):
                raise PermissionError("Native driver-policy preview drifted before dispatch")
            plan = DriverPolicyPlan(**arguments)
            capability = self.capabilities.issue(opcode=plan.opcode, resource=plan.resource, parameters=arguments)
            self._check_cancel()
            dispatched = True
            self.consumer(capability=capability, opcode=plan.opcode, resource=plan.resource, parameters=dict(arguments))
            return {"plan_id": plan.plan_id, "policy_id": plan.policy_id, "requested_mode": plan.action,
                    "material_id": plan.material_id, "kernel_prevention_verified": False,
                    "running_driver_unloaded": False, "reboot_acceptance": "required-separately",
                    "effective_rule_content": "unverified"}
        except BaseException:
            cancelled = not dispatched and self._cancel is not None and self._cancel.is_set()
            self.journal.finish(arguments, "cancelled" if cancelled else "uncertain", self._now())
            raise

    def _verify(self, arguments, _result):
        try:
            _guard(self.guard)
            observed = self.native.inspect(arguments["policy_id"])
            material = self.validator.materials[arguments["material_id"]]
            matched = (type(observed) is DriverPolicySnapshot and observed.policy_id == arguments["policy_id"]) and (
                not observed.present if arguments["action"] == "remove" else observed.matches(material))
            self.journal.finish(arguments, "configured" if matched else "uncertain", self._now())
            return matched
        except Exception:
            if self.journal.ready() and self.journal.row(arguments["plan_id"])["phase"] == "intent":
                self.journal.finish(arguments, "uncertain", self._now())
            return False


def _store_pinned(path, raw):
    if path.exists():
        if _read_private(path, len(raw)) != raw:
            raise PermissionError("Existing managed policy artifact differs from its pin")
        return
    with os.fdopen(create_private_file(path), "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if _read_private(path, len(raw)) != raw:
        raise PermissionError("Managed artifact failed independent file readback")


@dataclass(frozen=True)
class NativeDriverPolicyPins:
    """Build-specific trusted installer pins; no default/sample signer is enrolled."""
    citool_sha256: str
    citool_publisher: str
    powershell_sha256: str
    powershell_publisher: str
    configci_manifest_sha256: str

    def __post_init__(self):
        for value in (self.citool_sha256, self.powershell_sha256, self.configci_manifest_sha256):
            _sha(value)
        for value in (self.citool_publisher, self.powershell_publisher):
            if type(value) is not str or not 1 <= len(value) <= 512 or any(ord(c) < 32 for c in value):
                raise ValueError("Exact accepted Windows executable publisher pin required")


def _system_directory():
    if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise OSError("Native 64-bit Windows driver-policy backend required")
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    api.GetSystemDirectoryW.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    size = api.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < size < len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    result = Path(buffer.value)
    if not result.is_absolute() or ".." in result.parts or str(result).startswith("\\\\"):
        raise OSError("Canonical native system directory unavailable")
    return result


def _native_bool(value):
    if type(value) is bool:
        return value
    if type(value) is str and value in {"true", "false", "True", "False"}:
        return value.lower() == "true"
    raise ValueError("Unknown native CiTool boolean")


def parse_citool_policy(raw, policy_id, disk_sha256):
    """Parse one exact known policy; malformed/duplicate/partial output is held."""
    _guid(policy_id)
    if type(raw) is not bytes or len(raw) > 2 * 1024 * 1024:
        raise ValueError("CiTool output exceeds its bound")
    document = decode(raw)
    policies = document.get("Policies")
    if type(policies) is not list or len(policies) > 512:
        raise ValueError("Bounded complete CiTool policy inventory required")
    seen, selected = set(), None
    for row in policies:
        if type(row) is not dict or type(row.get("PolicyID")) is not str:
            raise ValueError("CiTool policy identity unavailable")
        identity = str(uuid.UUID(row["PolicyID"]))
        if identity in seen:
            raise ValueError("Duplicate CiTool policy identity")
        seen.add(identity)
        if identity == policy_id:
            selected = row
    if selected is None:
        if disk_sha256:
            raise PermissionError("Unlisted managed policy file exists; state is uncertain")
        return DriverPolicySnapshot(policy_id)
    if str(uuid.UUID(selected["BasePolicyID"])) != policy_id or selected.get("FriendlyName") != NAME:
        raise PermissionError("Native policy is not the exact own managed base policy")
    values = []
    if "Version" in selected:
        value = selected["Version"]
        if type(value) is int:
            values.append(value)
        elif type(value) is str and value.isascii() and value.isdecimal() and str(int(value)) == value:
            values.append(int(value))
        else:
            raise ValueError("Unknown CiTool policy version")
    if "VersionString" in selected:
        values.append(_version(selected["VersionString"]))
    if not values or len(set(values)) != 1:
        raise ValueError("Missing or contradictory native policy version")
    # An absent status field is preserved as unavailable, not manufactured as
    # successful. The supported adapter profile requires the documented zero.
    if type(selected.get("Status")) is not int:
        raise ValueError("Native policy status unavailable")
    return DriverPolicySnapshot(policy_id, values[0], _native_bool(selected["IsSignedPolicy"]),
        _native_bool(selected["IsSystemPolicy"]), _native_bool(selected["IsOnDisk"]),
        _native_bool(selected["IsEnforced"]), _native_bool(selected["IsAuthorized"]),
        selected["Status"], disk_sha256, True)


class _OwnedNativeCommand:
    """One native generation and its output reader, including failed admission.

    Before Thread.start, the read descriptor transfers to that exact reader.
    A late bootstrap owns/retains it until its own finally closes it. The parent
    must never close a descriptor that a pending reader could revisit after
    Windows/CRT reused its numeric value. Ambiguous closes are attempted once.
    """
    def __init__(self, *, _api=None, _reader_factory=None):
        if _api is None:
            import _winapi
            _api = _winapi
        self.api, self.reader_factory = _api, _reader_factory or threading.Thread
        self.process = self.thread = self.job = self.reader = None
        self.pid = None
        self.assigned = self.primary_done = self.tree_done = False
        self.reader_transfer = self.reader_start_failed = False
        self.reader_retired = threading.Event()
        self.read_close_error = ""
        self.output, self.read_errors, self.cleanup_errors = bytearray(), [], []
        self.overflow = threading.Event()
        self._retired = self._held = False
        self.read_fd, self.write_fd = os.pipe()

    def _close_fd_once(self, field):
        descriptor = getattr(self, field)
        setattr(self, field, None)
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as exc:
                self.cleanup_errors.append(field + ":" + type(exc).__name__)
                if field == "read_fd":
                    self.read_close_error = type(exc).__name__

    def _drain(self):
        try:
            while True:
                block = os.read(self.read_fd, 4096)
                if not block:
                    return
                remaining = 2 * 1024 * 1024 - len(self.output)
                if remaining:
                    self.output.extend(block[:remaining])
                if len(block) > remaining:
                    self.overflow.set()
        except OSError as exc:
            self.read_errors.append(exc)
        finally:
            self._close_fd_once("read_fd")
            self.reader_retired.set()

    def start_reader(self):
        self.reader = self.reader_factory(target=self._drain, name="Angerona managed CI output", daemon=True)
        self.reader_transfer = True
        try:
            self.reader.start()
        except BaseException:
            self.reader_start_failed = True
            self._hold()
            raise

    def _hold(self):
        global _NATIVE_COMMAND_RETIREMENT_HOLD
        if not self._held:
            self._held = True
            _NATIVE_COMMAND_RETIREMENT_HOLD = (*_NATIVE_COMMAND_RETIREMENT_HOLD, self)

    def _close_native_once(self, field):
        handle = getattr(self, field)
        setattr(self, field, None)  # Never retry an ambiguous numeric handle.
        if handle is not None:
            try:
                self.api.CloseHandle(handle)
            except BaseException as exc:
                self.cleanup_errors.append(field + ":" + type(exc).__name__)

    def retire(self):
        if self._retired:
            return not self._held
        self._retired = True
        if self.process is not None and (not self.primary_done or not self.tree_done):
            try:
                if self.assigned:
                    self.job.terminate()
                else:
                    self.api.TerminateProcess(self.process, 1)
            except BaseException as exc:
                self.cleanup_errors.append("terminate:" + type(exc).__name__)
            try:
                self.primary_done = self.api.WaitForSingleObject(self.process, 5000) == 0
                if not self.primary_done:
                    self.cleanup_errors.append("primary-wait")
            except BaseException as exc:
                self.cleanup_errors.append("primary-wait:" + type(exc).__name__)
            if self.assigned:
                try:
                    self.job.wait_empty(timeout=2)
                    self.tree_done = True
                except BaseException as exc:
                    self.cleanup_errors.append("job-wait:" + type(exc).__name__)
        self._close_fd_once("write_fd")
        if self.reader_transfer:
            try:
                self.reader.join(2)
            except BaseException as exc:
                self.cleanup_errors.append("reader-join:" + type(exc).__name__)
            try:
                alive = self.reader.is_alive()
            except BaseException:
                alive = True
            if self.reader_start_failed or alive or not self.reader_retired.is_set() or self.read_close_error:
                self.cleanup_errors.append("reader-retirement")
            # Only the exact reader can close read_fd after admission transfer.
        else:
            self._close_fd_once("read_fd")
        # Join failures must not skip cleanup of independently known resources.
        self._close_native_once("thread")
        if self.primary_done or self.process is None:
            self._close_native_once("process")
        if self.cleanup_errors:
            self._hold()  # Retain Job plus reader/FD owner; no replacement.
        elif self.job is not None:
            try:
                self.job.close()
                self.job = None
            except BaseException as exc:
                self.cleanup_errors.append("job-close:" + type(exc).__name__)
                self._hold()
        return not self._held

    def run(self, image, arguments, *, cwd, environment, before_launch, cancelled, timeout):
        import msvcrt
        import win32process
        from .windows_child_job import WindowsChildJob

        self.job = WindowsChildJob()
        startup = subprocess.STARTUPINFO()
        startup.dwFlags = 0x101
        startup.wShowWindow = 0
        with open(os.devnull, "rb") as nul:
            handles = [msvcrt.get_osfhandle(self.write_fd), msvcrt.get_osfhandle(nul.fileno())]
            startup.hStdOutput = startup.hStdError = handles[0]
            startup.hStdInput = handles[1]
            startup.lpAttributeList = {"handle_list": handles}
            for handle in handles:
                os.set_handle_inheritable(handle, True)
            try:
                before_launch()
                self.process, self.thread, self.pid, _tid = self.api.CreateProcess(
                    str(image), subprocess.list2cmdline([str(image), *arguments]), None, None, True,
                    0x08000004, environment, str(cwd), startup)
            finally:
                for handle in handles:
                    os.set_handle_inheritable(handle, False)
        self._close_fd_once("write_fd")
        if self.cleanup_errors:
            raise OSError("Native policy output writer close remains unproven")
        self.job.assign(self.process)
        self.assigned = True
        before_launch()
        self.start_reader()
        if win32process.ResumeThread(self.thread) != 1:
            raise OSError("Native managed-policy child failed to resume")
        self._close_native_once("thread")
        if self.cleanup_errors:
            raise OSError("Native policy primary-thread close remains unproven")
        deadline = time.monotonic() + timeout
        while self.api.WaitForSingleObject(self.process, 50) != 0:
            if self.overflow.is_set() or time.monotonic() >= deadline or (cancelled is not None and cancelled()):
                raise TimeoutError("Owned native-policy command exceeded output/time bound")
        self.primary_done = True
        code = self.api.GetExitCodeProcess(self.process)
        self.job.wait_empty(timeout=2)
        self.tree_done = True
        self.reader.join(2)
        if self.reader.is_alive() or not self.reader_retired.is_set() or self.read_errors or self.overflow.is_set():
            raise OSError("Native managed-policy output/reader retirement unavailable")
        if code != 0:
            raise OSError(f"Native managed-policy command failed (exit {code}); no success inferred")
        return bytes(self.output)


def _require_native_command_retirement():
    if _NATIVE_COMMAND_RETIREMENT_HOLD:
        raise PermissionError("Previous native policy command retirement remains held")


def _run_native(image, arguments, *, cwd, environment, before_launch, cancelled=None, timeout=30.0):
    """Fixed command, retained native generation/reader and sticky uncertainty."""
    with _NATIVE_COMMAND_LOCK:
        _require_native_command_retirement()
        owner = _OwnedNativeCommand()
        try:
            return owner.run(image, arguments, cwd=cwd, environment=environment,
                             before_launch=before_launch, cancelled=cancelled, timeout=timeout)
        finally:
            if not owner.retire():
                raise OSError("Owned native policy command cleanup remains uncertain: " + ",".join(owner.cleanup_errors))


class WindowsNativeDriverPolicyApi:
    """Actual fixed ConfigCI/CiTool adapter for an accepted installed service.

    Constructing or importing this module never invokes a command. Callers must
    not instantiate it with source-tree or request-selected guards/pins. Updates
    stage reviewed material in the protected service root, hold the compiled
    file against write/delete, and invoke only its policy GUID through CiTool.
    """
    _COMPILE = ("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
                "Import-Module -Name $env:ANGERONA_DRIVER_CONFIGCI -ErrorAction Stop; "
                "ConvertFrom-CIPolicy -XmlFilePath $env:ANGERONA_DRIVER_XML "
                "-BinaryFilePath $env:ANGERONA_DRIVER_BINARY -ErrorAction Stop | Out-Null")

    def __init__(self, root, pins, *, installed_guard=None):
        _guard(installed_guard)
        _require_native_command_retirement()
        if type(pins) is not NativeDriverPolicyPins:
            raise PermissionError("Accepted native Windows executable/module pins required")
        self.root, self.pins, self.guard = Path(root), pins, installed_guard
        if not self.root.is_absolute() or ".." in self.root.parts or str(self.root).startswith("\\\\"):
            raise ValueError("Fixed local protected managed-policy root required")
        verify_private(self.root, directory=True)
        self.system = _system_directory()
        self.citool = self.system / "CiTool.exe"
        self.powershell = self.system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        self.configci = self.powershell.parent / "Modules" / "ConfigCI" / "ConfigCI.psd1"
        self._lock = threading.RLock()

    @contextmanager
    def _sealed(self, path, *, private=True, bound=MAX_MATERIAL_BYTES):
        from .executable_trust import _open_sealed, _reject_reparse_components

        _guard(self.guard)
        _require_native_command_retirement()
        _reject_reparse_components(path)
        with ExitStack() as stack:
            if private:
                verify_private(path)
            else:
                stack.enter_context(self._native_path_custody(path))
            stream = stack.enter_context(_open_sealed(path))
            held, named = os.fstat(stream.fileno()), path.stat()
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_nlink)
            if (identity(held) != identity(named) or not stat.S_ISREG(held.st_mode)
                    or (held.st_nlink != 1 if private else not 1 <= held.st_nlink <= 1024)
                    or not 0 < held.st_size <= bound):
                raise PermissionError("Native policy artifact identity/size invalid")
            raw = stream.read(bound + 1)
            if len(raw) > bound or identity(os.fstat(stream.fileno())) != identity(held):
                raise PermissionError("Native policy artifact changed during sealed read")
            yield raw
            if identity(path.stat()) != identity(held) or identity(os.fstat(stream.fileno())) != identity(held):
                raise PermissionError("Native policy artifact changed while held")

    def _environment(self, extra=None):
        environment = {"SystemRoot": str(self.system.parent), "WINDIR": str(self.system.parent),
                       "PATH": str(self.system), "TEMP": str(self.root), "TMP": str(self.root),
                       "PSModulePath": str(self.configci.parent.parent)}
        if extra:
            environment.update(extra)
        return environment

    @contextmanager
    def _system_image(self, image, digest_pin):
        """A narrow exception for hardlinked protected Windows inbox images.

        This does not relax acquire_pinned_executable for arbitrary tools. The
        fixed native-root path and every ancestor must be protected; a retained
        FILE_SHARE_READ-only handle prevents data writes through aliases and
        deletion/replacement of the held pathname. Unlinking a different hardlink
        can still succeed on NTFS; link-count/object drift is rejected. Identity,
        link count and hash are revalidated before
        creation/resume and after child/tree retirement. Local administrator or
        kernel compromise is not defeated by this unsigned policy profile.
        """
        from .executable_trust import _open_sealed, _reject_reparse_components

        if image not in (self.citool, self.powershell):
            raise PermissionError("Only fixed native-root Windows executables are accepted")
        _guard(self.guard)
        _require_native_command_retirement()
        _reject_reparse_components(image)
        if image.absolute() != image.resolve(strict=True):
            raise PermissionError("Native inbox executable path resolves through an alias")
        with _open_sealed(image) as stream:
            original = os.fstat(stream.fileno())
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                                      value.st_nlink, getattr(value, "st_file_attributes", 0))
            if (not stat.S_ISREG(original.st_mode) or not 1 <= original.st_nlink <= 1024
                    or not 0 < original.st_size <= 64 * 1024 * 1024
                    or getattr(original, "st_file_attributes", 0) & 0x400):
                raise PermissionError("Native inbox executable object is unavailable")

            def check():
                _guard(self.guard)
                _require_native_command_retirement()
                _reject_reparse_components(image)
                if identity(os.fstat(stream.fileno())) != identity(original) or identity(image.stat()) != identity(original):
                    raise PermissionError("Retained native inbox executable identity changed")
                stream.seek(0)
                raw = stream.read(original.st_size + 1)
                if len(raw) != original.st_size or _digest(raw) != digest_pin:
                    raise PermissionError("Retained native inbox executable hash differs from enrollment")
                if identity(os.fstat(stream.fileno())) != identity(original):
                    raise PermissionError("Native inbox executable changed during hash validation")

            check()
            yield check
            check()

    @contextmanager
    def _native_path_custody(self, path):
        from .executable_trust import _authenticode_identity, _protected_path

        # The existing bounded Authenticode/ACL helpers run native System32
        # PowerShell. Retain and hash-pin that actual helper FIRST, including
        # while it verifies itself; stdout text alone never admits authority.
        with self._system_image(self.powershell, self.pins.powershell_sha256) as check_ps:
            if not _protected_path(self.powershell):
                raise PermissionError("Native PowerShell/root ACL custody unavailable")
            ps_status, ps_publisher, _ = _authenticode_identity(self.powershell)
            if ps_status != "Valid" or not hmac.compare_digest(
                    ps_publisher.encode("utf-8"), self.pins.powershell_publisher.encode("utf-8")):
                raise PermissionError("Native PowerShell Authenticode pin mismatch")
            if path != self.powershell and not _protected_path(path):
                raise PermissionError("Native artifact/root ACL custody unavailable")
            check_ps()
            yield check_ps
            check_ps()

    def _command(self, image, arguments, *, barrier=None, extra=None, cancelled=None, timeout=30):
        from .executable_trust import _authenticode_identity

        _require_native_command_retirement()
        digest = self.pins.citool_sha256 if image == self.citool else self.pins.powershell_sha256
        publisher = self.pins.citool_publisher if image == self.citool else self.pins.powershell_publisher
        if image not in (self.citool, self.powershell):
            raise PermissionError("Only fixed native CiTool/ConfigCI commands are available")
        with self._native_path_custody(image) as check_ps:
            with self._system_image(image, digest) as check_image:
                status, actual_publisher, _ = _authenticode_identity(image)
                if status != "Valid" or not hmac.compare_digest(actual_publisher.encode("utf-8"), publisher.encode("utf-8")):
                    raise PermissionError("Native executable Authenticode pin mismatch")

                def check():
                    if barrier is not None:
                        barrier()
                    check_ps()
                    check_image()

                return _run_native(image, arguments, cwd=self.system, environment=self._environment(extra),
                                   before_launch=check, cancelled=cancelled, timeout=timeout)

    def inspect(self, policy_id):
        _guid(policy_id)
        with self._lock:
            _guard(self.guard)
            path = self.system / "CodeIntegrity" / "CiPolicies" / "Active" / ("{" + policy_id.upper() + "}.cip")
            disk = ""
            if path.exists():
                with self._sealed(path, private=False) as raw:
                    disk = _digest(raw)
                    document = self._command(self.citool, ["--list-policies", "-json"])
                    return parse_citool_policy(document, policy_id, disk)
            document = self._command(self.citool, ["--list-policies", "-json"])
            if path.exists():
                raise PermissionError("Managed CI policy appeared during absent-state observation")
            return parse_citool_policy(document, policy_id, disk)

    def _stage(self, material, barrier, cancelled):
        if type(material) is not DriverPolicyMaterial:
            raise ValueError("Trusted typed policy material required")
        directory = self.root / material.identity
        if not directory.exists():
            # Bounded direct-child inventory, never a recursive cache walk.
            # Exhausting optional policy staging holds this action, not startup.
            with os.scandir(self.root) as entries:
                for index, entry in enumerate(entries):
                    if index >= 7 or not _HEX.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
                        raise PermissionError("Managed policy staging capacity/unknown contents require review")
            private_directory(directory)
        verify_private(directory, directory=True)
        xml, binary = directory / "policy.xml", directory / "policy.cip"
        _store_pinned(xml, material.xml)
        _store_pinned(directory / "catalog.artifact", material.catalog.artifact)
        _store_pinned(directory / "catalog.json", canonical({"source_url": material.catalog.source_url,
            "revision": material.catalog.revision, "review_reference": material.catalog.review_reference,
            "artifact_sha256": material.catalog.artifact_sha256, "material_id": material.identity,
            "xml_sha256": material.xml_sha256, "compiled_sha256": material.compiled_sha256}))
        if not binary.exists():
            with self._sealed(self.configci, private=False, bound=1024 * 1024) as manifest:
                if _digest(manifest) != self.pins.configci_manifest_sha256:
                    raise PermissionError("Native ConfigCI module manifest pin mismatch")
                with self._sealed(xml) as source:
                    if _digest(source) != material.xml_sha256:
                        raise PermissionError("Native compilation source differs from reviewed XML")
                    encoded = base64.b64encode(self._COMPILE.encode("utf-16-le")).decode("ascii")
                    self._command(self.powershell,
                        ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "AllSigned", "-EncodedCommand", encoded],
                        barrier=barrier, cancelled=cancelled, timeout=45, extra={"ANGERONA_DRIVER_CONFIGCI": str(self.configci),
                        "ANGERONA_DRIVER_XML": str(xml), "ANGERONA_DRIVER_BINARY": str(binary)})
        return binary

    def update(self, material, *, before_mutation, cancelled=None):
        with self._lock:
            _guard(self.guard)
            before_mutation()
            path = self._stage(material, before_mutation, cancelled)
            with self._sealed(path) as compiled:
                if _digest(compiled) != material.compiled_sha256:
                    raise PermissionError("ConfigCI output does not match the accepted compiled policy pin")
                before_mutation()
                self._command(self.citool, ["--update-policy", str(path), "-json"],
                              barrier=before_mutation, cancelled=cancelled)

    def remove(self, policy_id, *, before_mutation, cancelled=None):
        _guid(policy_id)
        with self._lock:
            _guard(self.guard)
            before_mutation()
            # Native executor independently proves exact journal ownership,
            # unsigned/nonplatform status and the current compiled artifact.
            self._command(self.citool, ["--remove-policy", "{" + policy_id.upper() + "}", "-json"],
                          barrier=before_mutation, cancelled=cancelled)
