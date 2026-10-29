"""Real enrolled provenance survives advisory export without becoming authority."""
from __future__ import annotations

import base64
import copy
from dataclasses import asdict, replace
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest

from angerona.core import enclave_mesh as mesh, live_debug as debug, module_base
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules import soar as soar_module


def view(bus, event):
    # No service constructor, named pipe, database, host sampler or workers.
    service = object.__new__(debug.LiveDebugService)
    service.bus = bus
    return service._event_view(event)


def load_summary():
    path = Path(__file__).resolve().parents[1] / "tools/summarize_live_debug.py"
    spec = importlib.util.spec_from_file_location("test_live_provenance_summary", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def enrolled(tmp_path, monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Inert provenance fixture attempted network, database, process or pipe access")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(debug, "_NamedPipeServer", forbidden)
    monkeypatch.setattr(soar_module, "psutil", SimpleNamespace(Process=forbidden))
    monkeypatch.setenv("ANGERONA_SOAR_AUTOCONTAIN", "0")
    monkeypatch.setenv("ANGERONA_ACTIVE_DEFENSE", "0")
    key = tmp_path / "owned-profile/bus.key"
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: key))
    authority = BusAuthority.generate()
    original_key = key.read_bytes()
    loaded = BusAuthority.load()
    bus, events, packets = EventBus(), [], []
    bus.arm(authority)
    bus.activate_mesh()
    authorities = (bus._mesh_authority, bus._control_mesh)
    bus.subscribe(events.append)
    actual_seal = mesh.MeshPeer.seal

    def capture_packet(self, *args, **kwargs):
        packet = actual_seal(self, *args, **kwargs)
        packets.append(copy.deepcopy(packet))
        assert len(packets) <= 16
        return packet

    monkeypatch.setattr(mesh.MeshPeer, "seal", capture_packet)
    publish = bus.enroll_mesh_publisher("Owned Sensor", hashlib.sha256(b"owned inert producer").hexdigest())
    try:
        yield SimpleNamespace(bus=bus, publish=publish, events=events, packets=packets, authority=loaded)
    finally:
        bus.close_mesh()
        for authority in authorities:
            rotator = getattr(authority, "_rotator", None)
            if rotator is not None:
                rotator.join(2)
                assert not rotator.is_alive()
        assert key.read_bytes() == original_key


def emit_owned(enrolled, *, details=None):
    enrolled.publish(Event("Owned Sensor", "Owned evidence", Severity.HIGH, 1750000000.0,
                           details if details is not None else {"finding_code": "owned.rule"}))
    return enrolled.events[-1]


def test_actual_enrolled_signature_is_exact_and_independently_verified_before_export(enrolled):
    event = emit_owned(enrolled)
    original = asdict(event)
    packet = next(packet for packet in enrolled.packets if packet["signature"] == event.mesh_sig)
    public = base64.b64decode(packet["header"]["certificate"]["body"]["ed25519"], validate=True)
    mesh._verify(public, mesh._PACKET_DOMAIN, {"header": packet["header"], "ciphertext": packet["ciphertext"]}, event.mesh_sig)
    assert enrolled.bus.verify(event) and enrolled.authority.verify(event)
    exported = view(enrolled.bus, event)
    assert len(event.mesh_sig) == 88 and len(base64.b64decode(event.mesh_sig, validate=True)) == 64
    assert exported["original_mesh_signature"] == event.mesh_sig
    assert exported["original_mesh_signature_encoding"] == "base64-ed25519"
    assert exported["original_mesh_peer"] == event.mesh_peer
    assert exported["original_hmac"] == event.hmac_sig
    assert exported["receipt_basis_at_export"] == "mesh-required-observed"
    assert exported["original_integrity_verified"] and exported["live_receipt_verified_at_export"]
    assert debug._decode(debug._encode(dict(exported, protocol=debug.PROTOCOL)))["original_mesh_signature"] == event.mesh_sig
    assert asdict(event) == original


def test_hmac_only_live_flag_and_revoked_mesh_are_distinct_observations(enrolled):
    bus, events = EventBus(), []
    bus.arm(enrolled.authority)
    bus.subscribe(events.append)
    bus.publish(Event("Owned HMAC Only", "No mesh", Severity.INFO, 1.0, {}))
    exported = view(bus, events[0])
    assert exported["live_receipt_verified_at_export"] is True
    assert exported["receipt_basis_at_export"] == "hmac-only-observed"
    assert exported["original_mesh_signature"] == exported["original_mesh_signature_encoding"] == exported["original_mesh_peer"] == ""
    event = emit_owned(enrolled)
    enrolled.bus.freeze_mesh()
    exported = view(enrolled.bus, event)
    assert exported["original_integrity_verified"] is True and exported["live_receipt_verified_at_export"] is False
    assert exported["receipt_basis_at_export"] == "mesh-required-observed"  # Mode is not a receipt proof.
    assert exported["original_mesh_signature"] == event.mesh_sig


@pytest.mark.parametrize("observations", [(False, True), (True, False), (None, None), ("true", "true")])
def test_mode_races_or_unsupported_observations_cannot_be_labeled_as_enrollment(enrolled, observations):
    event = emit_owned(enrolled)

    class ModeObservations:
        integrity_enabled = True

        def __init__(self):
            self.observations = iter(observations)

        @property
        def mesh_required(self):
            return next(self.observations)

        def verify_archived(self, candidate):
            return enrolled.bus.verify_archived(candidate)

        def verify(self, candidate):
            return enrolled.bus.verify(candidate)

    exported = view(ModeObservations(), event)
    assert exported["receipt_basis_at_export"] == "mode-changed-or-unavailable"
    assert exported["live_receipt_verified_at_export"] is True  # Established semantics retained.


def test_format_recognition_is_strict_and_never_verification(enrolled):
    event = emit_owned(enrolled)
    raw = base64.b64decode(event.mesh_sig, validate=True)
    legacy = raw.hex()
    assert debug.mesh_signature_encoding(event.mesh_sig) == "base64-ed25519"
    assert debug.mesh_signature_encoding(legacy) == "hex-ed25519-legacy"
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    pad_bits = event.mesh_sig[:-3] + alphabet[alphabet.index(event.mesh_sig[-3]) + 1] + "=="
    assert base64.b64decode(pad_bits, validate=True) == raw  # Noncanonical, despite a valid alphabet.
    for bad in (None, 1, True, [], "", "x" * 88, "AB" * 64, pad_bits, event.mesh_sig + "\n",
                base64.b64encode(b"x" * 63).decode(), base64.urlsafe_b64encode(b"\xff" * 64).decode()):
        assert debug.mesh_signature_encoding(bad) == ""
    changed = replace(event, mesh_sig=legacy)
    exported = view(enrolled.bus, changed)
    assert exported["original_mesh_signature"] == legacy and exported["original_mesh_signature_encoding"] == "hex-ed25519-legacy"
    assert exported["live_receipt_verified_at_export"] is False  # A shape does not create an enrolled receipt.
    malformed = view(enrolled.bus, replace(event, mesh_sig=pad_bits))
    assert malformed["original_mesh_signature"] == malformed["original_mesh_signature_encoding"] == ""
    assert malformed["live_receipt_verified_at_export"] is False


@pytest.mark.parametrize("name,bad", [
    ("trigger_hmac", "ghp_do_not_export_this_secret_abcdefghijklmnopqrstuvwxyz"),
    ("trigger_hmac", "A" * 64), ("trigger_hmac", True),
    ("trigger_ts", True), ("trigger_ts", float("nan")), ("trigger_ts", float("inf")),
    ("trigger_ts", -1), ("trigger_ts", 10**400),
])
def test_malformed_trigger_provenance_is_omitted_and_explicitly_unavailable(enrolled, name, bad):
    details = dict(trigger="Owned Input", trigger_hmac="a" * 64, trigger_ts=1.0)
    details[name] = bad
    # Nonfinite values cannot enter an actual mesh packet. Use an HMAC-only
    # signed event for this diagnostic-format boundary, without new authority.
    bus, events = EventBus(), []
    bus.arm(enrolled.authority)
    bus.subscribe(events.append)
    bus.publish(Event("Owned Format Input", "Format boundary", Severity.INFO, 1.0, details))
    exported = view(bus, events[0])
    assert name not in exported["details"] and exported["details"]["trigger_provenance_status"] == "unavailable"
    assert "ghp_" not in json.dumps(exported)


def test_derived_status_does_not_hide_omitted_original_fields(enrolled):
    details = dict(trigger="Owned Input", trigger_hmac="not-a-public-signature", trigger_ts=1.0,
                   trigger_provenance_status="forged verified status", private_fixture_detail="not exported")
    event = emit_owned(enrolled, details=details)
    exported = view(enrolled.bus, event)
    assert exported["omitted_detail_count"] == 3  # Invalid HMAC, source status, private field.
    assert exported["details"]["trigger_provenance_status"] == "unavailable"
    assert set(exported["details"]) == {"trigger", "trigger_ts", "trigger_provenance_status"}


@pytest.mark.parametrize("stamp", [True, float("nan"), float("inf"), 10**400])
def test_soar_omits_invalid_source_timestamp_without_new_failure_or_authority(enrolled, stamp):
    bus, events = EventBus(), []
    bus.arm(enrolled.authority)
    bus.subscribe(events.append)
    bus.publish(Event("Owned Input", "Timestamp boundary", Severity.HIGH, stamp, {}))
    source = events[0]
    soar = soar_module.SOARModule()
    soar.bind(bus)
    soar.bind_manager(SimpleNamespace(modules={}))
    soar._run_playbook(source)
    output = events[-1]
    assert output.module == soar.name and output.severity == Severity.INFO and bus.verify(output)
    assert output.details["trigger_hmac"] == source.hmac_sig and "trigger_ts" not in output.details
    assert view(bus, output)["details"]["trigger_provenance_status"] == "unavailable"


@pytest.mark.parametrize("legacy,tag", [(False, "base64-ed25519"), (True, "hex-ed25519-legacy")])
def test_summary_preserves_supported_exact_signatures_old_and_new_without_reverification(enrolled, tmp_path, legacy, tag):
    event = emit_owned(enrolled)
    exported = view(enrolled.bus, event)
    signature = base64.b64decode(event.mesh_sig, validate=True).hex() if legacy else event.mesh_sig
    exported.update(original_mesh_signature=signature, original_mesh_signature_encoding=tag)
    # Old v1 captures had no encoding or basis tags. Absence is supported but
    # never upgraded to a new verification claim by the offline consumer.
    old = dict(exported)
    old.pop("original_mesh_signature_encoding")
    old.pop("receipt_basis_at_export")
    records = [dict(value, protocol=debug.PROTOCOL, run_id="a" * 32, seq=index, ts=float(index))
               for index, value in enumerate((exported, old), 1)]
    path = tmp_path / "owned-capture.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
    original = path.read_bytes()
    report = load_summary().summarize([path])
    case, = report["cases"]
    assert case["occurrences"] == 2 and report["automatic_response"] is False
    assert all(sample["original_mesh_signature"] == signature and sample["original_mesh_signature_encoding"] == tag for sample in case["samples"])
    assert case["samples"][1]["receipt_basis_at_export"] == "unspecified"
    assert case["review_status"] == "needs-review" and "not reverified offline" in case["verification_scope"]
    assert path.read_bytes() == original


@pytest.mark.parametrize("tag", ["unknown", "hex-ed25519-legacy", None, {"forged": "value"}])
def test_summary_rejects_contradictory_explicit_encoding_and_untyped_basis(enrolled, tag):
    event = emit_owned(enrolled)
    record = dict(view(enrolled.bus, event), original_mesh_signature_encoding=tag, receipt_basis_at_export={},
                  protocol=debug.PROTOCOL, run_id="a" * 32, seq=1, ts=1.0)
    consumer = load_summary().CaseSummary()
    consumer.consume(record)
    sample = next(iter(consumer.cases.values()))["samples"][0]
    assert sample["original_mesh_signature"] == sample["original_mesh_signature_encoding"] == ""
    assert sample["receipt_basis_at_export"] == "unspecified"


def test_same_clock_distinct_signed_inputs_keep_exact_links_through_soar_export_and_summary(enrolled, monkeypatch, tmp_path):
    stamp = 1750000000.0
    for value in ("A", "B"):
        enrolled.publish(Event("Owned Sensor", "Distinct input " + value, Severity.HIGH, stamp,
                               dict(finding_code="owned.rule", disposition="active", source_item=value)))
    inputs = list(enrolled.events)
    before = [asdict(event) for event in inputs]
    assert inputs[0].hmac_sig != inputs[1].hmac_sig and all(enrolled.bus.verify(event) for event in inputs)
    soar = soar_module.SOARModule()
    soar.bind(enrolled.bus)
    soar.bind_manager(SimpleNamespace(modules={}))
    soar._mesh_publishers = {soar.name: enrolled.bus.enroll_mesh_publisher(soar.name, hashlib.sha256(b"owned SOAR").hexdigest())}
    with monkeypatch.context() as clock:
        clock.setattr(module_base, "time", SimpleNamespace(time=lambda: stamp))
        for event in inputs:
            soar._run_playbook(event)
    outputs = enrolled.events[2:]
    assert len(outputs) == 2 and all(event.severity == Severity.INFO and enrolled.bus.verify(event) for event in outputs)
    assert outputs[0].message == outputs[1].message and outputs[0].ts == outputs[1].ts == stamp
    assert [event.details["trigger_hmac"] for event in outputs] == [event.hmac_sig for event in inputs]
    assert [event.details["trigger_ts"] for event in outputs] == [stamp, stamp]
    assert outputs[0].hmac_sig != outputs[1].hmac_sig and [asdict(event) for event in inputs] == before
    records = []
    for index, event in enumerate(outputs, 1):
        record = view(enrolled.bus, event)
        assert record["details"]["trigger_hmac"] == inputs[index - 1].hmac_sig
        assert record["details"]["trigger_provenance_status"] == "reported"
        assert debug.sanitize_text(inputs[index - 1].hmac_sig) == "[opaque value redacted]"
        records.append(dict(record, protocol=debug.PROTOCOL, run_id="b" * 32, seq=index, ts=stamp))
    path = tmp_path / "owned-soar-capture.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
    original = path.read_bytes()
    report = load_summary().summarize([path])
    case, = report["cases"]
    assert case["occurrences"] == 2 and report["counts"]["duplicate_records"] == 0
    assert [sample["trigger_hmac"] for sample in case["samples"]] == [event.hmac_sig for event in inputs]
    assert all(sample["trigger_ts"] == stamp and sample["trigger_provenance_status"] == "reported" for sample in case["samples"])
    assert all(sample["original_mesh_signature"] == event.mesh_sig for sample, event in zip(case["samples"], outputs))
    assert report["automatic_response"] is False and case["review_status"] == "needs-review"
    assert path.read_bytes() == original
