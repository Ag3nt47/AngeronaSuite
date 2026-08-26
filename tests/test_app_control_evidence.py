from __future__ import annotations

import pytest

from angerona.core.app_control_evidence import DecisionCorrelator, parse_app_control_xml


ACTIVITY = "{11111111-1111-1111-1111-111111111111}"


def _xml(event_id: int, record_id: int, fields: dict[str, object], activity=ACTIVITY) -> str:
    data = "".join(
        f"<Data Name='{name}'>{value}</Data>" for name, value in fields.items()
    )
    correlation = f"<Correlation ActivityID='{activity}'/>" if activity is not None else ""
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System><Provider Name='Microsoft-Windows-CodeIntegrity'/>
      <EventID>{event_id}</EventID><EventRecordID>{record_id}</EventRecordID>
      <TimeCreated SystemTime='2026-08-25T00:00:00Z'/>{correlation}</System>
      <EventData>{data}</EventData></Event>"""


def test_parser_preserves_audit_semantics_and_canonical_fields() -> None:
    record = parse_app_control_xml(_xml(3076, 40, {
        "FileName": r"C:\Users\Example\payload.exe",
        "ProcessName": r"C:\Windows\explorer.exe",
        "RequestedSigningLevel": "2",
        "ValidatedSigningLevel": "1",
        "PolicyName": "Audit policy",
        "PolicyID": "audit-1",
        "SHA256Hash": "a" * 64,
    }))
    assert record.disposition == "audit-would-block"
    assert record.activity_id == ACTIVITY
    assert record.fields["File Name"].endswith("payload.exe")
    assert record.fields["Process Name"].endswith("explorer.exe")
    assert record.fields["Requested Signing Level"] == "2"
    assert record.fields["Validated Signing Level"] == "1"
    assert record.fields["SHA256 Hash"] == "a" * 64


def test_parser_normalizes_live_3033_buffer_schema_without_false_policy_claim() -> None:
    record = parse_app_control_xml(_xml(3033, 41, {
        "FileNameBuffer": r"\Device\HarddiskVolume3\Windows\System32\blocked.dll",
        "ProcessNameBuffer": r"\Device\HarddiskVolume3\Windows\browser.exe",
        "RequestedPolicy": "8",
        "ValidatedPolicy": "1",
        "Status": "3221226536",
    }))
    assert record.fields["File Name"].endswith("blocked.dll")
    assert record.fields["Process Name"].endswith("browser.exe")
    assert record.fields["Requested Signing Level"] == "8"
    assert record.fields["Validated Signing Level"] == "1"

    correlator = DecisionCorrelator(ttl_seconds=1)
    correlator.ingest(record, now=0)
    result = correlator.flush_expired(now=2)
    assert result[0].message() == "Code Integrity rejected blocked.dll"


def test_correlator_joins_reversed_multi_signature_evidence_exactly_once() -> None:
    correlator = DecisionCorrelator(ttl_seconds=10)
    signature_1 = parse_app_control_xml(_xml(3089, 42, {
        "TotalSignatureCount": "2", "Signature": "1", "PublisherName": "B",
        "ValidatedSigningLevel": "12", "VerificationError": "21",
    }))
    signature_0 = parse_app_control_xml(_xml(3089, 41, {
        "TotalSignatureCount": "2", "Signature": "0", "PublisherName": "A",
        "ValidatedSigningLevel": "8", "VerificationError": "0",
    }))
    decision = parse_app_control_xml(_xml(3077, 43, {
        "FileName": r"C:\Temp\blocked.exe", "PolicyName": "Enforced",
        "SHA256Hash": "b" * 64,
    }))

    assert correlator.ingest(signature_1, now=0) == []
    assert correlator.ingest(signature_0, now=1) == []
    result = correlator.ingest(decision, now=2)
    assert len(result) == 1
    assert result[0].correlation_status == "complete"
    assert [item.fields["Signature"] for item in result[0].signatures] == ["0", "1"]
    assert correlator.ingest(decision, now=3) == []


def test_unsigned_and_partial_evidence_are_distinguished() -> None:
    unsigned = DecisionCorrelator(ttl_seconds=5)
    decision = parse_app_control_xml(_xml(3077, 50, {"FileName": "unsigned.exe"}))
    signature = parse_app_control_xml(_xml(3089, 51, {
        "TotalSignatureCount": "0", "Signature": "0", "Hash": "c" * 64,
    }))
    assert unsigned.ingest(decision, now=0) == []
    complete = unsigned.ingest(signature, now=1)
    assert complete[0].correlation_status == "complete"
    assert complete[0].signatures[0].fields["TotalSignatureCount"] == "0"

    partial = DecisionCorrelator(ttl_seconds=5)
    assert partial.ingest(decision, now=0) == []
    expired = partial.flush_expired(now=6)
    assert expired[0].correlation_status == "no-signature-evidence"


def test_incomplete_signature_cardinality_never_becomes_complete() -> None:
    correlator = DecisionCorrelator(ttl_seconds=5)
    decision = parse_app_control_xml(_xml(3077, 52, {"FileName": "partial.exe"}))
    first_of_two = parse_app_control_xml(_xml(3089, 53, {
        "TotalSignatureCount": "2", "Signature": "0", "PublisherName": "A",
    }))
    assert correlator.ingest(decision, now=0) == []
    assert correlator.ingest(first_of_two, now=1) == []
    expired = correlator.flush_expired(now=6)
    assert len(expired) == 1
    assert expired[0].correlation_status == "partial"
    assert expired[0].details()["missing_signature_indices"] == [1]


@pytest.mark.parametrize(
    "fields",
    [
        {"Signature": "0"},
        {"TotalSignatureCount": "two", "Signature": "0"},
        {"TotalSignatureCount": "-1", "Signature": "0"},
        {"TotalSignatureCount": "65", "Signature": "0"},
        {"TotalSignatureCount": "1", "Signature": "1"},
    ],
    ids=("missing-total", "non-integer", "negative", "over-bound", "out-of-range"),
)
def test_malformed_signature_cardinality_is_untrusted(fields: dict[str, str]) -> None:
    correlator = DecisionCorrelator(ttl_seconds=5)
    decision = parse_app_control_xml(_xml(3077, 54, {"FileName": "bad.exe"}))
    signature = parse_app_control_xml(_xml(3089, 55, fields))
    assert correlator.ingest(decision, now=0) == []
    result = correlator.ingest(signature, now=1)
    assert len(result) == 1
    assert result[0].correlation_status == "untrusted"


def test_duplicate_signature_cardinality_field_is_untrusted() -> None:
    correlator = DecisionCorrelator(ttl_seconds=5)
    decision = parse_app_control_xml(_xml(3077, 56, {"FileName": "bad.exe"}))
    xml = _xml(3089, 57, {"TotalSignatureCount": "1", "Signature": "0"})
    xml = xml.replace(
        "</EventData>",
        "<Data Name='TotalSignatureCount'>1</Data></EventData>",
    )
    signature = parse_app_control_xml(xml)
    correlator.ingest(decision, now=0)
    result = correlator.ingest(signature, now=1)
    assert result[0].correlation_status == "untrusted"


def test_event_details_omit_exact_local_paths_and_bound_signature_fields() -> None:
    correlator = DecisionCorrelator(ttl_seconds=5)
    decision = parse_app_control_xml(_xml(3077, 58, {
        "FileName": r"C:\Users\Private\payload.exe",
        "ProcessName": r"C:\Secret\runner.exe",
    }))
    signature = parse_app_control_xml(_xml(3089, 59, {
        "TotalSignatureCount": "0",
        "Signature": "0",
        "PublisherName": "Example",
        "FileName": r"C:\Must\Not\Leak\payload.exe",
    }))
    correlator.ingest(decision, now=0)
    result = correlator.ingest(signature, now=1)[0]
    details = result.details(lambda value: "token-" + str(len(value)))
    assert details["file_name"] == "payload.exe"
    assert details["process_name"] == "runner.exe"
    assert details["file_path_token"].startswith("token-")
    assert "File Name" not in details["signature_evidence"][0]
    assert "mitre_tags" not in details
    assert r"C:\Users\Private" not in repr(details)
    assert r"C:\Secret" not in repr(details)


def test_authenticated_pending_state_round_trip_is_strict_and_atomic() -> None:
    original = DecisionCorrelator(ttl_seconds=60)
    decision = parse_app_control_xml(_xml(3077, 70, {"FileName": "pending.exe"}))
    original.ingest(decision)
    state = original.export_state()

    restored = DecisionCorrelator(ttl_seconds=60)
    restored.import_state(state)
    signature = parse_app_control_xml(_xml(3089, 71, {
        "TotalSignatureCount": "0", "Signature": "0",
    }))
    result = restored.ingest(signature)
    assert len(result) == 1
    assert result[0].correlation_status == "complete"

    corrupt = original.export_state()
    corrupt["groups"][0]["decisions"][0]["activity_id"] = (
        "{33333333-3333-3333-3333-333333333333}"
    )
    with pytest.raises(ValueError, match="decision group"):
        restored.import_state(corrupt)


def test_conflicting_signature_index_is_untrusted() -> None:
    correlator = DecisionCorrelator(ttl_seconds=5)
    decision = parse_app_control_xml(_xml(3077, 60, {
        "FileName": "blocked.exe", "SHA256Hash": "d" * 64,
    }))
    first = parse_app_control_xml(_xml(3089, 61, {
        "TotalSignatureCount": "2", "Signature": "0", "PublisherName": "A",
    }))
    conflict = parse_app_control_xml(_xml(3089, 62, {
        "TotalSignatureCount": "2", "Signature": "0", "PublisherName": "B",
    }))
    assert correlator.ingest(decision, now=0) == []
    assert correlator.ingest(first, now=1) == []
    result = correlator.ingest(conflict, now=2)
    assert len(result) == 1
    assert result[0].correlation_status == "untrusted"


def test_correlation_group_state_is_bounded_under_one_activity() -> None:
    correlator = DecisionCorrelator(
        ttl_seconds=60,
        max_records_per_group=2,
    )
    decisions = [
        parse_app_control_xml(_xml(3077, index, {
            "FileName": f"blocked-{index}.exe",
        }))
        for index in range(1, 5)
    ]
    emitted = []
    for index, decision in enumerate(decisions):
        emitted.extend(correlator.ingest(decision, now=float(index)))
    assert [item.correlation_status for item in emitted] == [
        "bounded-eviction", "bounded-eviction",
    ]
    group = correlator._groups[ACTIVITY]
    assert len(group.decisions) == 2

    signatures = [
        parse_app_control_xml(_xml(3089, 10 + index, {
            "TotalSignatureCount": "99",
            "Signature": str(index),
        }))
        for index in range(4)
    ]
    signature_only = DecisionCorrelator(
        ttl_seconds=60,
        max_records_per_group=2,
    )
    for index, signature in enumerate(signatures):
        signature_only.ingest(signature, now=float(index))
    signature_group = signature_only._groups[ACTIVITY]
    assert len(signature_group.signatures) == 2
    assert signature_group.untrusted is True


@pytest.mark.parametrize(
    "value",
    ["", "<Event/>", _xml(3077, 1, {}, activity="not-a-guid"), "x" * (1024 * 1024 + 1)],
    ids=("empty", "missing-identifiers", "invalid-activity", "oversized"),
)
def test_malformed_or_oversized_evidence_fails_closed(value: str) -> None:
    with pytest.raises(ValueError):
        parse_app_control_xml(value)
