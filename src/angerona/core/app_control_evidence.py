"""Pure parsing and correlation for Windows App Control evidence.

The Code Integrity event channel is evidence about decisions Windows already
made.  Nothing in this module changes policy or grants response authority.
"""
from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import PureWindowsPath
from uuid import UUID

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

MAX_EVENT_XML_CHARS = 1024 * 1024
MAX_EVENT_FIELDS = 128
MAX_FIELD_CHARS = 4096
MAX_PENDING_GROUPS = 256
MAX_SIGNATURES_PER_GROUP = 64
MAX_DECISIONS_PER_GROUP = 8


@dataclass(frozen=True)
class AppControlRecord:
    event_id: int
    record_id: int
    activity_id: str
    observed_at: str
    kind: str
    disposition: str
    fields: dict[str, str]

    @property
    def is_decision(self) -> bool:
        return self.event_id in {3004, 3033, 3034, 3076, 3077}

    @property
    def is_signature(self) -> bool:
        return self.event_id == 3089

    @property
    def is_policy_event(self) -> bool:
        return 3095 <= self.event_id <= 3105


@dataclass(frozen=True)
class CorrelatedDecision:
    decision: AppControlRecord
    signatures: tuple[AppControlRecord, ...]
    correlation_status: str

    def details(self, path_tokenizer=None) -> dict:
        """Return bounded, typed EventBus details with no response authority."""
        decision_fields = dict(self.decision.fields)
        file_path = decision_fields.get("File Name", "")
        process_path = decision_fields.get("Process Name", "")
        file_name = PureWindowsPath(file_path).name if file_path else ""
        process_name = PureWindowsPath(process_path).name if process_path else ""
        file_token = path_tokenizer(file_path) if path_tokenizer and file_path else ""
        process_token = (
            path_tokenizer(process_path) if path_tokenizer and process_path else ""
        )
        signature_totals: list[int] = []
        signature_indexes: set[int] = set()
        for signature in self.signatures:
            try:
                signature_totals.append(
                    int(signature.fields.get("TotalSignatureCount", ""))
                )
                signature_indexes.add(int(signature.fields.get("Signature", "")))
            except (TypeError, ValueError):
                continue
        total = signature_totals[0] if signature_totals else None
        missing = (
            sorted(set(range(total)) - signature_indexes)
            if isinstance(total, int) and total > 0
            else []
        )
        signature_state = (
            "untrusted"
            if self.correlation_status in {"untrusted", "record-id-conflict"}
            else "unsigned"
            if total == 0 and len(self.signatures) == 1
            else "signed"
            if self.correlation_status == "complete" and bool(self.signatures)
            else "partial"
            if bool(self.signatures)
            else "unavailable"
        )
        signature_keys = {
            "Hash",
            "IssuerName",
            "IssuerTBSHash",
            "PublisherName",
            "PublisherTBSHash",
            "Signature",
            "SignatureType",
            "TotalSignatureCount",
            "Validated Signing Level",
            "VerificationError",
        }
        return {
            "event_id": self.decision.event_id,
            "record_id": self.decision.record_id,
            "activity_id": self.decision.activity_id,
            "decision": self.decision.disposition,
            "correlation_status": self.correlation_status,
            "policy_name": decision_fields.get("PolicyName", ""),
            "policy_id": (
                decision_fields.get("PolicyId", "")
                or decision_fields.get("PolicyGUID", "")
            ),
            "policy_hash": decision_fields.get("PolicyHash", ""),
            "file_name": file_name,
            "process_name": process_name,
            "file_path_token": file_token,
            "process_path_token": process_token,
            "sha256": (
                decision_fields.get("SHA256 Hash", "")
                or decision_fields.get("SHA256 Flat Hash", "")
            ),
            "status": decision_fields.get("Status", ""),
            "requested_signing_level": decision_fields.get(
                "Requested Signing Level", ""
            ),
            "validated_signing_level": decision_fields.get(
                "Validated Signing Level", ""
            ),
            "signature_evidence": [
                {
                    key: value
                    for key, value in item.fields.items()
                    if key in signature_keys
                }
                for item in self.signatures
            ],
            "signature_state": signature_state,
            "missing_signature_indices": missing,
            "raw_sensor_evidence": True,
            "response_authorized": False,
            "response_authority": "observe-only",
            "local_sensitive_paths_omitted": True,
        }

    def message(self) -> str:
        raw_path = self.decision.fields.get("File Name", "")
        name = PureWindowsPath(raw_path).name if raw_path else "code"
        policy = self.decision.fields.get("PolicyName", "")
        # Microsoft documents that 3004/3033 can occur without an App Control
        # policy (for example Code Integrity Guard). Do not invent policy
        # attribution when the event itself contains none.
        if self.decision.event_id in {3004, 3033, 3034} and not policy:
            if self.decision.disposition.startswith("audit"):
                return f"Code Integrity would reject {name}"
            return f"Code Integrity rejected {name}"
        policy = policy or "an App Control policy"
        if self.decision.disposition.startswith("audit"):
            return f"App Control would block {name} under {policy}"
        return f"App Control blocked {name} under {policy}"


_EVENT_TYPES: dict[int, tuple[str, str]] = {
    3004: ("decision", "invalid-signature-block"),
    3033: ("decision", "signature-rejection-block"),
    3034: ("decision", "audit-signature-rejection"),
    3076: ("decision", "audit-would-block"),
    3077: ("decision", "enforced-block"),
    3089: ("signature", "signature-evidence"),
    3095: ("policy", "refresh-requires-reboot"),
    3096: ("policy", "already-current"),
    3097: ("policy", "refresh-failed"),
    3099: ("policy", "policy-loaded"),
    3100: ("policy", "activation-failed"),
    3101: ("policy", "refresh-started"),
    3102: ("policy", "refresh-finished"),
    3103: ("policy", "refresh-ignored"),
    3105: ("policy", "refresh-attempted"),
}


def _local_name(tag: object) -> str:
    return str(tag).rsplit("}", 1)[-1]


def _bounded(value: object) -> str:
    return str(value or "").replace("\x00", "")[:MAX_FIELD_CHARS]


_CANONICAL_FIELDS = {
    "filename": "File Name",
    "filenamebuffer": "File Name",
    "processname": "Process Name",
    "processnamebuffer": "Process Name",
    "requestedsigninglevel": "Requested Signing Level",
    "requestedpolicy": "Requested Signing Level",
    "validatedsigninglevel": "Validated Signing Level",
    "validatedpolicy": "Validated Signing Level",
    "status": "Status",
    "sha1hash": "SHA1 Hash",
    "sha256hash": "SHA256 Hash",
    "sha1flathash": "SHA1 Flat Hash",
    "sha256flathash": "SHA256 Flat Hash",
    "policyname": "PolicyName",
    "policyid": "PolicyId",
    "policyguid": "PolicyGUID",
    "policyhash": "PolicyHash",
    "originalfilename": "OriginalFileName",
    "internalname": "InternalName",
    "filedescription": "FileDescription",
    "productname": "ProductName",
    "fileversion": "FileVersion",
    "userwriteable": "UserWriteable",
    "packagefamilyname": "PackageFamilyName",
    "totalsignaturecount": "TotalSignatureCount",
    "signature": "Signature",
    "hash": "Hash",
    "signaturetype": "SignatureType",
    "verificationerror": "VerificationError",
    "publishername": "PublisherName",
    "issuername": "IssuerName",
    "publishertbshash": "PublisherTBSHash",
    "issuertbshash": "IssuerTBSHash",
}


def _canonical_field(name: str) -> str:
    token = "".join(character for character in name.casefold() if character.isalnum())
    return _CANONICAL_FIELDS.get(token, name)


def _first(root: ET.Element, name: str) -> ET.Element | None:
    for node in root.iter():
        if _local_name(node.tag) == name:
            return node
    return None


def parse_app_control_xml(xml_text: str) -> AppControlRecord:
    """Parse one bounded Code Integrity XML event without resolving entities."""
    if not isinstance(xml_text, str) or not xml_text.strip():
        raise ValueError("App Control event XML is empty")
    if len(xml_text) > MAX_EVENT_XML_CHARS:
        raise ValueError("App Control event XML exceeds the 1 MiB bound")
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise ValueError(f"App Control event XML is invalid: {exc}") from exc

    event_node = _first(root, "EventID")
    record_node = _first(root, "EventRecordID")
    if event_node is None or record_node is None:
        raise ValueError("App Control event is missing EventID or EventRecordID")
    try:
        event_id = int((event_node.text or "").strip())
        record_id = int((record_node.text or "").strip())
    except ValueError as exc:
        raise ValueError("App Control event identifiers are not integers") from exc
    if event_id not in _EVENT_TYPES or record_id < 0:
        raise ValueError(f"unsupported App Control event ID: {event_id}")

    correlation = _first(root, "Correlation")
    activity_id = ""
    if correlation is not None:
        for key, value in correlation.attrib.items():
            if _local_name(key).casefold() == "activityid":
                raw_activity = _bounded(value).strip()
                if raw_activity:
                    try:
                        activity_id = "{" + str(UUID(raw_activity.strip("{}"))) + "}"
                    except ValueError as exc:
                        raise ValueError("App Control ActivityID is not a GUID") from exc
                break
    created = _first(root, "TimeCreated")
    observed_at = ""
    if created is not None:
        observed_at = _bounded(created.attrib.get("SystemTime", ""))

    fields: dict[str, str] = {}
    for node in root.iter():
        if _local_name(node.tag) != "Data" or len(fields) >= MAX_EVENT_FIELDS:
            continue
        name = _canonical_field(_bounded(node.attrib.get("Name", "")).strip())
        if not name:
            continue
        # Duplicate names are preserved deterministically instead of silently
        # replacing earlier security evidence.
        candidate = name
        suffix = 2
        while candidate in fields:
            candidate = f"{name}#{suffix}"
            suffix += 1
        fields[candidate] = _bounded(node.text)

    kind, disposition = _EVENT_TYPES[event_id]
    return AppControlRecord(
        event_id=event_id,
        record_id=record_id,
        activity_id=activity_id,
        observed_at=observed_at,
        kind=kind,
        disposition=disposition,
        fields=fields,
    )


@dataclass
class _CorrelationGroup:
    updated_at: float
    decisions: list[AppControlRecord] = field(default_factory=list)
    signatures: dict[int, AppControlRecord] = field(default_factory=dict)
    untrusted: bool = False


class DecisionCorrelator:
    """Bounded, reorder-tolerant ActivityID join for 30xx decision evidence."""

    def __init__(
        self,
        *,
        max_groups: int = 512,
        ttl_seconds: float = 15.0,
        max_records_per_group: int = 64,
    ) -> None:
        self.max_groups = max(8, min(MAX_PENDING_GROUPS, int(max_groups)))
        self.ttl_seconds = max(0.1, float(ttl_seconds))
        requested_bound = max(2, int(max_records_per_group))
        self.max_signatures = min(MAX_SIGNATURES_PER_GROUP, requested_bound)
        self.max_decisions = min(MAX_DECISIONS_PER_GROUP, requested_bound)
        self._groups: OrderedDict[str, _CorrelationGroup] = OrderedDict()
        self._seen_records: OrderedDict[int, str] = OrderedDict()

    @staticmethod
    def _fingerprint(record: AppControlRecord) -> str:
        import hashlib
        import json
        body = json.dumps(
            {
                "activity_id": record.activity_id,
                "disposition": record.disposition,
                "event_id": record.event_id,
                "fields": record.fields,
                "record_id": record.record_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(body).hexdigest()

    @staticmethod
    def _semantic_fingerprint(record: AppControlRecord) -> str:
        import hashlib
        import json
        body = json.dumps(
            {
                "activity_id": record.activity_id,
                "disposition": record.disposition,
                "event_id": record.event_id,
                "fields": record.fields,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(body).hexdigest()

    def _seen(self, record: AppControlRecord) -> str:
        record_id = record.record_id
        if record_id <= 0:
            return "new"
        fingerprint = self._fingerprint(record)
        if record_id in self._seen_records:
            return (
                "duplicate"
                if self._seen_records[record_id] == fingerprint
                else "conflict"
            )
        self._seen_records[record_id] = fingerprint
        while len(self._seen_records) > self.max_groups * 8:
            self._seen_records.popitem(last=False)
        return "new"

    @staticmethod
    def _signature_metadata(record: AppControlRecord) -> tuple[bool, int, int]:
        if any(
            key.startswith("TotalSignatureCount#") or key.startswith("Signature#")
            for key in record.fields
        ):
            return False, -1, -1
        try:
            total = int(record.fields["TotalSignatureCount"])
            index = int(record.fields["Signature"])
        except (KeyError, TypeError, ValueError):
            return False, -1, -1
        if not 0 <= total <= MAX_SIGNATURES_PER_GROUP:
            return False, index, total
        if total == 0:
            return index == 0, index, total
        return 0 <= index < total, index, total

    @classmethod
    def _ready(cls, group: _CorrelationGroup) -> bool:
        if not group.decisions or not group.signatures:
            return False
        if group.untrusted:
            return True
        totals: list[int] = []
        indexes: set[int] = set()
        for signature in group.signatures.values():
            valid, index, total = cls._signature_metadata(signature)
            if not valid:
                return True
            totals.append(total)
            indexes.add(index)
        # Windows emits one 3089 row with TotalSignatureCount=0 for unsigned
        # content. Missing, malformed, negative, or out-of-range cardinality is
        # untrusted and can never be called complete.
        if len(set(totals)) > 1:
            return True
        expected = max(totals, default=0)
        expected_rows = max(1, expected)
        if expected == 0:
            return indexes == {0}
        return indexes == set(range(expected_rows))

    @staticmethod
    def _finish(group: _CorrelationGroup, status: str) -> list[CorrelatedDecision]:
        signatures = tuple(
            group.signatures[key] for key in sorted(group.signatures)
        )
        return [
            CorrelatedDecision(decision, signatures, status)
            for decision in group.decisions
        ]

    def ingest(
        self, record: AppControlRecord, *, now: float | None = None
    ) -> list[CorrelatedDecision]:
        moment = time.monotonic() if now is None else float(now)
        ready = self.flush_expired(now=moment)
        if not (record.is_decision or record.is_signature):
            return ready
        seen = self._seen(record)
        if seen == "duplicate":
            return ready
        if seen == "conflict":
            if record.is_decision:
                ready.append(CorrelatedDecision(record, (), "record-id-conflict"))
            return ready
        if not record.activity_id:
            if record.is_decision:
                ready.append(CorrelatedDecision(record, (), "missing-activity-id"))
            return ready

        group = self._groups.get(record.activity_id)
        if group is None:
            group = _CorrelationGroup(updated_at=moment)
            self._groups[record.activity_id] = group
        else:
            group.updated_at = moment
            self._groups.move_to_end(record.activity_id)
        if record.is_decision:
            if len(group.decisions) >= self.max_decisions:
                oldest = group.decisions.pop(0)
                ready.append(
                    CorrelatedDecision(oldest, (), "bounded-eviction")
                )
                group.untrusted = True
            identity = (
                record.fields.get("File Name", ""),
                record.fields.get("SHA256 Hash", "")
                or record.fields.get("SHA256 Flat Hash", ""),
            )
            for existing in group.decisions:
                previous = (
                    existing.fields.get("File Name", ""),
                    existing.fields.get("SHA256 Hash", "")
                    or existing.fields.get("SHA256 Flat Hash", ""),
                )
                if all(identity) and all(previous) and identity != previous:
                    group.untrusted = True
            group.decisions.append(record)
        else:
            valid_signature, signature_index, _total = self._signature_metadata(record)
            if not valid_signature:
                signature_index = record.record_id
                group.untrusted = True
            existing = group.signatures.get(signature_index)
            if (
                existing is not None
                and self._semantic_fingerprint(existing)
                != self._semantic_fingerprint(record)
            ):
                group.untrusted = True
            else:
                if (
                    existing is None
                    and len(group.signatures) >= self.max_signatures
                ):
                    oldest_index = next(iter(group.signatures))
                    group.signatures.pop(oldest_index)
                    group.untrusted = True
                group.signatures[signature_index] = record
            totals = {
                item.fields.get("TotalSignatureCount", "")
                for item in group.signatures.values()
            }
            if len(totals) > 1:
                group.untrusted = True

        if self._ready(group):
            ready.extend(self._finish(group, "untrusted" if group.untrusted else "complete"))
            self._groups.pop(record.activity_id, None)
        while len(self._groups) > self.max_groups:
            _, evicted = self._groups.popitem(last=False)
            if evicted.decisions:
                ready.extend(self._finish(evicted, "bounded-eviction"))
        return ready

    def flush_expired(self, *, now: float | None = None) -> list[CorrelatedDecision]:
        moment = time.monotonic() if now is None else float(now)
        result: list[CorrelatedDecision] = []
        expired = [
            key for key, group in self._groups.items()
            if moment - group.updated_at >= self.ttl_seconds
        ]
        for key in expired:
            group = self._groups.pop(key)
            if group.decisions:
                status = (
                    "untrusted"
                    if group.untrusted
                    else "partial" if group.signatures else "no-signature-evidence"
                )
                result.extend(self._finish(group, status))
        return result

    def flush_all(self, status: str) -> list[CorrelatedDecision]:
        result: list[CorrelatedDecision] = []
        for group in self._groups.values():
            if group.decisions:
                result.extend(self._finish(group, status))
        self.reset()
        return result

    def reset(self) -> None:
        self._groups.clear()
        self._seen_records.clear()

    @staticmethod
    def _record_document(record: AppControlRecord) -> dict:
        return {
            "activity_id": record.activity_id,
            "disposition": record.disposition,
            "event_id": record.event_id,
            "fields": dict(record.fields),
            "kind": record.kind,
            "observed_at": record.observed_at,
            "record_id": record.record_id,
        }

    @staticmethod
    def _record_from_document(value: object) -> AppControlRecord:
        expected = {
            "activity_id", "disposition", "event_id", "fields", "kind",
            "observed_at", "record_id",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("pending App Control record schema is invalid")
        fields = value.get("fields")
        if (
            not isinstance(fields, dict)
            or len(fields) > MAX_EVENT_FIELDS
            or any(
                not isinstance(key, str)
                or not isinstance(item, str)
                or len(key) > 128
                or len(item) > MAX_FIELD_CHARS
                for key, item in fields.items()
            )
        ):
            raise ValueError("pending App Control fields exceed their bounds")
        event_id = value.get("event_id")
        record_id = value.get("record_id")
        if type(event_id) is not int or event_id not in _EVENT_TYPES:
            raise ValueError("pending App Control event ID is invalid")
        if type(record_id) is not int or record_id < 0:
            raise ValueError("pending App Control record ID is invalid")
        activity = value.get("activity_id")
        if not isinstance(activity, str) or len(activity) > 40:
            raise ValueError("pending App Control ActivityID is invalid")
        if activity:
            try:
                normalized = "{" + str(UUID(activity.strip("{}"))) + "}"
            except ValueError as exc:
                raise ValueError("pending App Control ActivityID is invalid") from exc
            if normalized != activity:
                raise ValueError("pending App Control ActivityID is not canonical")
        kind, disposition = _EVENT_TYPES[event_id]
        if value.get("kind") != kind or value.get("disposition") != disposition:
            raise ValueError("pending App Control event semantics are invalid")
        observed_at = value.get("observed_at")
        if not isinstance(observed_at, str) or len(observed_at) > MAX_FIELD_CHARS:
            raise ValueError("pending App Control timestamp is invalid")
        return AppControlRecord(
            event_id=event_id,
            record_id=record_id,
            activity_id=activity,
            observed_at=observed_at,
            kind=kind,
            disposition=disposition,
            fields=dict(fields),
        )

    def export_state(self) -> dict:
        now = time.monotonic()
        return {
            "groups": [
                {
                    "activity_id": activity,
                    "age_seconds": min(
                        self.ttl_seconds, max(0.0, now - group.updated_at)
                    ),
                    "decisions": [self._record_document(row) for row in group.decisions],
                    "signatures": [
                        self._record_document(group.signatures[key])
                        for key in sorted(group.signatures)
                    ],
                    "untrusted": bool(group.untrusted),
                }
                for activity, group in self._groups.items()
            ],
            "seen_records": [
                [record_id, fingerprint]
                for record_id, fingerprint in self._seen_records.items()
            ],
        }

    def import_state(self, value: object) -> None:
        if not isinstance(value, dict) or set(value) != {"groups", "seen_records"}:
            raise ValueError("pending App Control state schema is invalid")
        groups = value.get("groups")
        seen = value.get("seen_records")
        if (
            not isinstance(groups, list)
            or len(groups) > self.max_groups
            or not isinstance(seen, list)
            or len(seen) > self.max_groups * 8
        ):
            raise ValueError("pending App Control state exceeds its bounds")
        restored_groups: OrderedDict[str, _CorrelationGroup] = OrderedDict()
        now = time.monotonic()
        for item in groups:
            if not isinstance(item, dict) or set(item) != {
                "activity_id", "age_seconds", "decisions", "signatures", "untrusted"
            }:
                raise ValueError("pending App Control group schema is invalid")
            activity = item.get("activity_id")
            age = item.get("age_seconds")
            decisions = item.get("decisions")
            signatures = item.get("signatures")
            if (
                not isinstance(activity, str)
                or not activity
                or len(activity) > 40
                or not isinstance(age, (int, float))
                or isinstance(age, bool)
                or not 0 <= float(age) <= self.ttl_seconds
                or not isinstance(decisions, list)
                or len(decisions) > self.max_decisions
                or not isinstance(signatures, list)
                or len(signatures) > self.max_signatures
                or type(item.get("untrusted")) is not bool
            ):
                raise ValueError("pending App Control group exceeds its bounds")
            group = _CorrelationGroup(
                updated_at=now - float(age),
                untrusted=bool(item["untrusted"]),
            )
            for row in decisions:
                record = self._record_from_document(row)
                if not record.is_decision or record.activity_id != activity:
                    raise ValueError("pending App Control decision group is invalid")
                group.decisions.append(record)
            for row in signatures:
                record = self._record_from_document(row)
                if not record.is_signature or record.activity_id != activity:
                    raise ValueError("pending App Control signature group is invalid")
                valid, index, _total = self._signature_metadata(record)
                if not valid and not group.untrusted:
                    raise ValueError("pending App Control signature is malformed")
                key = index if valid else record.record_id
                if key in group.signatures:
                    raise ValueError("pending App Control signature index is duplicated")
                group.signatures[key] = record
            if activity in restored_groups:
                raise ValueError("pending App Control ActivityID is duplicated")
            restored_groups[activity] = group
        restored_seen: OrderedDict[int, str] = OrderedDict()
        for item in seen:
            if (
                not isinstance(item, list)
                or len(item) != 2
                or type(item[0]) is not int
                or item[0] <= 0
                or not isinstance(item[1], str)
                or len(item[1]) != 64
                or any(character not in "0123456789abcdef" for character in item[1])
            ):
                raise ValueError("pending App Control dedupe state is invalid")
            if item[0] in restored_seen:
                raise ValueError("pending App Control dedupe record is duplicated")
            restored_seen[item[0]] = item[1]
        self._groups = restored_groups
        self._seen_records = restored_seen
