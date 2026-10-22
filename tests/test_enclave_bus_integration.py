"""Offline source/producer admission regressions; no sensors, network or TPM."""
from __future__ import annotations

import dataclasses
import copy
import importlib
import importlib.util
from pathlib import Path
import py_compile
import subprocess
import sys
import threading
from types import ModuleType, SimpleNamespace

import pytest

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.module_base import BaseModule
from angerona.core.module_manager import ModuleManager, _AttestedSourceFinder


def config(**changes):
    values = dict(ugcap_enabled=False, module_states={}, save=lambda: None)
    values.update(changes)
    return SimpleNamespace(**values)


@pytest.fixture
def bus():
    instance = EventBus()
    instance.arm(BusAuthority(b"k" * 32))
    instance.require_mesh()
    try:
        yield instance
    finally:
        instance.close_mesh()


def test_raw_critical_spoof_is_archival_advisory_without_response_or_identity(bus):
    original = Event("UGCAP Integrity Guard", "spoofed compromise", Severity.CRITICAL,
        details={"active_attack": True, "response_authorized": True,
                 "response_contract": {"actions": ["isolate_host"]},
                 "evidence": {"nested": [1]}})
    bus.publish(original)
    stored = bus.recent(1)[0]
    assert bus.integrity_enabled
    assert stored.module == "Unattributed local producer"
    assert stored.details["unattributed_module"] == original.module
    assert stored.details["response_authorized"] is False
    assert stored.details["active_attack"] is False
    assert "response_contract" not in stored.details
    assert not bus.verify(stored)
    assert bus.verify_archived(stored)
    original.details["evidence"]["nested"].append(2)
    assert stored.details["evidence"]["nested"] == [1]
    assert original.details["response_authorized"] is True


def test_mesh_requires_integrity_even_without_archival_hmac():
    instance = EventBus()
    try:
        instance.require_mesh()
        assert instance.integrity_enabled
        instance.publish(Event("arbitrary", "advisory"))
        assert not instance.verify(instance.recent(1)[0])
        instance.activate_mesh()
        publisher = instance.enroll_mesh_publisher("scanner", "a" * 64)
        publisher(Event("scanner", "attested source observation"))
        assert instance.verify(instance.recent(1)[0])
    finally:
        instance.close_mesh()


def test_freeze_and_reconfigure_revoke_ordinary_receipts_but_keep_control(bus):
    control = bus.enroll_mesh_publisher("UGCAP Integrity Guard", "c" * 64, control=True)
    control(Event("UGCAP Integrity Guard", "challenge required"))
    control_event = bus.recent(1)[0]
    bus.activate_mesh()
    ordinary = bus.enroll_mesh_publisher("scanner", "a" * 64)
    ordinary(Event("scanner", "first proof"))
    first = bus.recent(1)[0]
    assert bus.verify(first) and bus.verify(control_event)
    bus.freeze_mesh()
    assert not bus.verify(first) and bus.verify_archived(first)
    assert bus.verify(control_event)
    with pytest.raises(RuntimeError):
        ordinary(Event("scanner", "late proof"))
    bus.activate_mesh()
    assert not bus.verify(first) and bus.verify(control_event)
    replacement = bus.enroll_mesh_publisher("scanner", "a" * 64)
    replacement(Event("scanner", "new proof"))
    second = bus.recent(1)[0]
    assert bus.verify(second)
    bus.activate_mesh()
    assert not bus.verify(second)


def test_live_gate_revokes_receipts_and_blocks_pending_deliveries(bus):
    state = {"open": True}
    bus.activate_mesh(admission_gate=lambda: state["open"])
    publisher = bus.enroll_mesh_publisher("scanner", "a" * 64)
    publisher(Event("scanner", "before challenge"))
    proof = bus.recent(1)[0]
    state["open"] = False
    assert not bus.verify(proof)
    before = bus.revision()
    with pytest.raises(RuntimeError, match="revoked"):
        publisher(Event("scanner", "after challenge"))
    assert bus.revision() == before


def test_bound_publisher_rejects_alias_spoof_and_keeps_nested_source_immutable(bus):
    bus.activate_mesh()
    publisher = bus.enroll_mesh_publisher("scanner", "a" * 64)
    with pytest.raises(ValueError, match="another module"):
        publisher(Event("Adversary Combat", "spoof"))
    original = Event("scanner", "detected", Severity.HIGH, details={"nested": {"pid": 42}})
    publisher(original)
    stored = bus.recent(1)[0]
    original.details["nested"]["pid"] = 43
    assert stored.details["nested"]["pid"] == 42 and bus.verify(stored)
    forged = dataclasses.replace(stored, details={"nested": {"pid": 43}})
    forged = dataclasses.replace(forged, hmac_sig=bus._authority.sign(forged))
    assert bus.verify_archived(forged) and not bus.verify(forged)


def test_yara_body_receipt_survives_mesh_metadata_and_mutation_does_not(bus):
    from angerona.modules.yara_scanner import YaraScannerModule
    bus.activate_mesh()
    module = YaraScannerModule()
    module.bind(bus)
    module._mesh_publishers = {module.name: bus.enroll_mesh_publisher(module.name, "a" * 64)}
    event = Event(module.name, "inert analytic receipt", Severity.HIGH,
                  details={"path": "fixture-only", "nested": {"digest": "a" * 64}})
    module._detection_receipts[module._event_digest(event)] = module.lifecycle_generation
    module.publish_event(event)
    received = bus.recent(1)[0]
    assert received.mesh_sig and received.mesh_peer
    assert bus.verify(received) and module.verify_detection_event(received)
    changed = dataclasses.replace(received, details={"path": "another-fixture"})
    assert not module.verify_detection_event(changed) and not bus.verify(changed)


def test_soar_request_alias_gets_distinct_enrolled_identity(bus, monkeypatch):
    from angerona.modules.soar_engine import ActiveResponseSOAR
    manager = ModuleManager(bus, config())
    module = ActiveResponseSOAR()
    module.bind(bus)
    manager._ugcap_verified_files = {"fixture": "a" * 64}
    monkeypatch.setattr(manager, "_verified_source_digest", lambda _path: "a" * 64)
    bus.activate_mesh()
    manager._enroll_mesh_module(module)
    assert set(module._mesh_publishers) == {module.name, "Active Response SOAR Request"}
    module.publish_event(Event("Active Response SOAR Request", "exact request", details={"pid": 42}))
    received = bus.recent(1)[0]
    assert bus.verify(received) and received.module == "Active Response SOAR Request"
    with pytest.raises(ValueError):
        module._mesh_publishers[module.name](Event("Active Response SOAR Request", "wrong handle"))


def test_dns_decoder_does_not_launder_unattributed_source(bus):
    from angerona.modules.network_protocol_decoder import NetworkProtocolDecoderModule
    bus.activate_mesh()
    decoder = NetworkProtocolDecoderModule()
    decoder.bind(bus)
    bus.subscribe(decoder._on_event)
    bus.publish(Event("Network Monitor", "caller-described DNS", details={
        "protocol": "dns", "qname": "xkqjzv92173846091827364509.example.test"}))
    assert decoder.stats()["dns_seen"] == 0
    assert bus.revision() == 1
    source = bus.enroll_mesh_publisher("Network Monitor", "a" * 64)
    source(Event("Network Monitor", "enrolled DNS", details={
        "protocol": "dns", "qname": "example.test"}))
    assert decoder.stats()["dns_seen"] == 1


def source_manager(tmp_path, monkeypatch, sources):
    blake3 = pytest.importorskip("blake3").blake3
    # Production activation imports the pinned-reader bootstrap before it
    # installs the finder. These fixtures use a deliberately tiny manifest.
    importlib.import_module("angerona.core.source_sandbox")
    importlib.import_module("angerona.modules")
    manager = ModuleManager(EventBus(), config())
    manager._ugcap_repository = tmp_path
    for relative, content in sources.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        manager._ugcap_verified_files[relative] = blake3(content).hexdigest()
    finder = _AttestedSourceFinder(manager)
    monkeypatch.setattr(sys, "meta_path", [finder, *sys.meta_path])
    return manager


def test_attested_import_executes_source_even_with_valid_malicious_pyc(tmp_path, monkeypatch):
    import importlib._bootstrap_external as bootstrap
    name = "angerona._attested_pyc_fixture"
    relative = "src/angerona/_attested_pyc_fixture.py"
    manager = source_manager(tmp_path, monkeypatch, {relative: b"VALUE = 'attested'\n"})
    source = tmp_path / relative
    cache = Path(importlib.util.cache_from_source(str(source)))
    py_compile.compile(str(source), cfile=str(cache), doraise=True)
    info = source.stat()
    malicious = compile("VALUE = 'forged-bytecode'\n", str(source), "exec")
    cache.write_bytes(bootstrap._code_to_timestamp_pyc(malicious, int(info.st_mtime), info.st_size))
    monkeypatch.delitem(sys.modules, name, raising=False)
    try:
        module = importlib.import_module(name)
        assert module.VALUE == "attested"
        assert module._angerona_attested_load == (str(tmp_path), manager._ugcap_verified_files[relative])
    finally:
        sys.modules.pop(name, None)


def test_attested_import_executes_exact_checked_bytes_after_path_swap(tmp_path, monkeypatch):
    name, relative = "angerona._attested_swap_fixture", "src/angerona/_attested_swap_fixture.py"
    manager = source_manager(tmp_path, monkeypatch, {relative: b"VALUE = 'verified-snapshot'\n"})
    read = manager._verified_source_bytes
    def swap_after_read(path):
        result = read(path)
        Path(path).write_bytes(b"VALUE = 'unverified-path-swap'\n")
        return result
    monkeypatch.setattr(manager, "_verified_source_bytes", swap_after_read)
    try:
        module = importlib.import_module(name)
        assert module.VALUE == "verified-snapshot"
    finally:
        sys.modules.pop(name, None)


def test_lazy_import_checks_source_again_and_rejects_tampering(tmp_path, monkeypatch):
    first, lazy = "angerona._attested_first_fixture", "angerona._attested_lazy_fixture"
    manager = source_manager(tmp_path, monkeypatch, {
        "src/angerona/_attested_first_fixture.py": b"def load():\n import angerona._attested_lazy_fixture\n",
        "src/angerona/_attested_lazy_fixture.py": b"VALUE = 'baseline'\n"})
    try:
        module = importlib.import_module(first)
        (tmp_path / "src/angerona/_attested_lazy_fixture.py").write_bytes(b"VALUE = 'tampered'\n")
        with pytest.raises(RuntimeError, match="changed after"):
            module.load()
        assert lazy not in sys.modules
        assert manager._ugcap_verified_files
    finally:
        sys.modules.pop(first, None)
        sys.modules.pop(lazy, None)


def test_verified_source_preserves_lexical_path_and_rejects_links(tmp_path, monkeypatch):
    manager = source_manager(tmp_path, monkeypatch, {"src/angerona/plain.py": b"SAFE = True\n"})
    plain, alias = tmp_path / "src/angerona/plain.py", tmp_path / "src/angerona/alias.py"
    try:
        alias.symlink_to(plain)
    except OSError:
        pytest.skip("test host cannot create symlinks")
    with pytest.raises(RuntimeError, match="outside the verified manifest"):
        manager._verified_source_digest(alias)
    manager._ugcap_verified_files["src/angerona/alias.py"] = manager._ugcap_verified_files["src/angerona/plain.py"]
    with pytest.raises(ValueError, match="symlink or reparse"):
        manager._verified_source_digest(alias)


def test_frozen_gate_blocks_new_ordinary_imports(tmp_path, monkeypatch):
    name, relative = "angerona.modules._attested_paused_fixture", "src/angerona/modules/_attested_paused_fixture.py"
    manager = source_manager(tmp_path, monkeypatch, {relative: b"VALUE = True\n"})
    manager._ugcap_paused = True
    with pytest.raises(ImportError, match="held by the UGCAP gate"):
        importlib.import_module(name)
    assert name not in sys.modules
    manager._ugcap_preparing_thread = threading.get_ident()
    try:
        assert importlib.import_module(name).VALUE
    finally:
        sys.modules.pop(name, None)


def test_preloaded_ordinary_code_requires_restart_instead_of_disk_blessing(monkeypatch):
    manager = ModuleManager(EventBus(), config())
    monkeypatch.setitem(sys.modules, "angerona.modules._preloaded_unattested_fixture",
                        ModuleType("angerona.modules._preloaded_unattested_fixture"))
    assert manager.requires_ugcap_restart


class Probe(BaseModule):
    name = "Inert fixture worker"
    supported_platforms = ("windows", "macos", "linux")
    def __init__(self):
        super().__init__()
        self.starts = 0
    def start(self):
        self.starts += 1
        self.status = "running"
    def stop(self):
        self.status = "stopped"


def inert_paused_manager():
    manager = ModuleManager(EventBus(), config(ugcap_enabled=True), target_platform="windows")
    manager._ugcap_deferred_discovery = False
    probe = Probe()
    manager.modules[probe.name] = probe
    manager._ugcap_held.add(probe.name)
    return manager, probe


def test_denied_final_permit_cannot_resume_or_leave_gate_open():
    manager, probe = inert_paused_manager()
    try:
        def denied(open_gate):
            open_gate()  # Even a malformed permit cannot leave a denied gate open.
            return False
        assert manager.resume_after_ugcap(permit=denied)["paused"]
        assert manager.ugcap_paused and probe.starts == 0
        assert not manager.start_if_enabled(probe)
        manager.set_enabled(probe.name, True)
        assert probe.starts == 0
        assert not manager.restart_module_generation(probe.name, probe, probe.lifecycle_generation)
    finally:
        manager.stop_all()


def test_final_permit_commits_gate_then_rechecks_each_start():
    manager, probe = inert_paused_manager()
    try:
        def approved(open_gate):
            assert manager.ugcap_paused
            open_gate()
            return True
        result = manager.resume_after_ugcap(permit=approved)
        assert not result["paused"] and probe.starts == 1
        manager.pause_for_ugcap("new challenge")
        assert not manager.start_if_enabled(probe)
        assert probe.starts == 1
    finally:
        manager.stop_all()


def test_deferred_discovery_failure_keeps_gate_closed_and_never_calls_permit(monkeypatch):
    manager, probe = inert_paused_manager()
    manager._ugcap_deferred_discovery = True
    manager._ugcap_verified_files = {"fixture": "a" * 64}
    manager._ugcap_finder = object()
    called = []
    monkeypatch.setattr(manager, "discover", lambda **_kwargs: manager.discovery_errors.append("fixture failure"))
    try:
        with pytest.raises(RuntimeError, match="could not establish"):
            manager.resume_after_ugcap(permit=lambda _open: called.append(True))
        assert manager.ugcap_paused and probe.starts == 0 and not called
    finally:
        manager.stop_all()


def test_operator_pause_does_not_wait_for_heavy_deferred_imports(monkeypatch):
    manager, probe = inert_paused_manager()
    manager._ugcap_deferred_discovery = True
    manager._ugcap_verified_files = {"fixture": "a" * 64}
    manager._ugcap_finder = object()
    entered, release, paused = threading.Event(), threading.Event(), threading.Event()
    monkeypatch.setattr(manager, "discover", lambda **_kwargs: (entered.set(), release.wait(3)))
    worker = threading.Thread(target=lambda: manager.resume_after_ugcap(permit=lambda _open: False))
    worker.start()
    try:
        assert entered.wait(2)
        pause = threading.Thread(target=lambda: (manager.pause_for_ugcap("user locked"), paused.set()))
        pause.start()
        assert paused.wait(1), "operator pause blocked on heavy source discovery"
        pause.join(1)
        assert probe.starts == 0
    finally:
        release.set()
        worker.join(3)
        manager.stop_all()


def test_source_mismatch_activation_never_initializes_ordinary_mesh(monkeypatch):
    blake3 = pytest.importorskip("blake3").blake3
    manager, probe = inert_paused_manager()
    root = Path(__file__).resolve().parents[1]
    relative = "src/angerona/core/eventbus.py"
    report = activation_report({relative: blake3(b"wrong source snapshot").hexdigest()})
    monkeypatch.setattr(ModuleManager, "requires_ugcap_restart", property(lambda _self: False))
    try:
        with pytest.raises(RuntimeError, match="changed after"):
            manager.activate_enclave_mesh(report)
        assert manager.ugcap_paused and probe.starts == 0
        assert manager.bus._mesh_authority is None
    finally:
        manager.stop_all()


def activation_report(files=None):
    root = Path(__file__).resolve().parents[1]
    common = {"report_id": "a" * 32, "generation": "b" * 32,
        "source_manifest_digest": "c" * 64, "repository": str(root),
        "vault_path": str(root.parent / "offline-fixture" / "golden.ugcap"),
        "verified_files": files or {"src/angerona/core/eventbus.py": "d" * 64}}
    return {"status": "verified", **copy.deepcopy(common), "verification_receipt": copy.deepcopy(common)}


@pytest.mark.parametrize("change", [
    lambda report: [report.pop(key, None) for key in ("report_id", "generation")],
    lambda report: [report["verification_receipt"].pop(key, None) for key in ("report_id", "generation")],
    lambda report: report.update(report_id=""),
    lambda report: report.update(generation=1),
    lambda report: report.update(report_id="A" * 32),
    lambda report: report["verification_receipt"].update(generation="e" * 32),
    lambda report: report.pop("source_manifest_digest"),
    lambda report: report["verification_receipt"].pop("source_manifest_digest"),
    lambda report: report.update(source_manifest_digest="z" * 64),
    lambda report: report["verification_receipt"].update(source_manifest_digest="e" * 64),
    lambda report: report.update(repository=str(Path.cwd().parent)),
    lambda report: report.update(vault_path=str(Path.cwd() / "another-vault.ugcap")),
    lambda report: report["verification_receipt"].update(vault_path=""),
    lambda report: report["verification_receipt"].update(repository="relative-repository"),
    lambda report: report["verification_receipt"].update(verified_files={}),
    lambda report: report["verification_receipt"]["verified_files"].update({"src/angerona/core/eventbus.py": "invalid"}),
])
def test_malformed_receipt_metadata_is_rejected_before_manager_state_changes(change):
    manager, probe = inert_paused_manager()
    report = activation_report()
    change(report)
    try:
        with pytest.raises(RuntimeError, match="verified source receipt"):
            manager.activate_enclave_mesh(report)
        assert manager._ugcap_repository is None and manager._ugcap_verified_files == {}
        assert manager._ugcap_finder is None and manager.bus._mesh_authority is None
        assert manager.ugcap_paused and probe.starts == 0
    finally:
        manager.stop_all()


def inert_integrity_guard():
    from angerona.modules.ugcap_guard import UGCAPGuardModule
    guard = UGCAPGuardModule()
    guard.starts = guard.stops = 0
    def start():
        guard.starts += 1
        guard.status = "running"
    def stop():
        guard.stops += 1
        guard.status = "stopped"
    guard.start, guard.stop = start, stop
    return guard


def test_persisted_generic_guard_off_cannot_disable_enabled_integrity_policy():
    guard = inert_integrity_guard()
    configuration = config(ugcap_enabled=True, module_states={guard.name: False})
    manager = ModuleManager(EventBus(), configuration, target_platform="windows")
    manager.modules[guard.name] = guard
    try:
        assert manager.is_enabled(guard.name)
        assert manager.module_usage(guard.name).selected
        manager.start_enabled(min_settle=0)
        assert guard.starts == 1 and not guard.stops
    finally:
        manager.stop_all()


@pytest.mark.parametrize("policy,paused", [(True, False), (False, True)])
def test_generic_runtime_guard_disable_preserves_integrity_cadence_and_challenge(policy, paused):
    guard = inert_integrity_guard()
    manager = ModuleManager(EventBus(), config(ugcap_enabled=policy), target_platform="windows")
    manager._ugcap_paused = paused
    manager.modules[guard.name] = guard
    guard.status = "running"
    try:
        manager.set_enabled(guard.name, False)
        assert manager.config.module_states[guard.name] is True
        assert manager.is_enabled(guard.name) and guard.stops == 0
        assert guard.status == "running"
    finally:
        manager.stop_all()


def test_fresh_strict_discovery_imports_only_bootstrap_and_defers_external():
    # A subprocess matters: pytest collection has already imported detectors.
    script = """
import sys
from types import SimpleNamespace
from angerona.core.eventbus import EventBus
from angerona.core.module_manager import ModuleManager
manager = ModuleManager(EventBus(), SimpleNamespace(ugcap_enabled=True), target_platform='windows')
try:
    classes = manager._builtin_classes()
    assert {cls.__module__ for cls in classes} == {
        'angerona.modules.ugcap_guard', 'angerona.modules.adversary_combat'}
    assert manager._external_classes() == []
    assert not manager.requires_ugcap_restart, [n for n in sys.modules if n.startswith('angerona.modules.')]
finally:
    manager.bus.close_mesh()
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_fresh_strict_activation_discovers_attested_sources_without_starting_real_workers():
    script = """
import sys
import json
from pathlib import Path
from types import SimpleNamespace
from blake3 import blake3
from angerona.core.eventbus import EventBus
from angerona.core.module_manager import ModuleManager
root = Path.cwd()
starts = []
def inert_factory(cls):
    instance = cls()
    instance.start = lambda: starts.append(instance.name)
    instance.stop = lambda: None
    return instance
configuration = SimpleNamespace(ugcap_enabled=True, module_states={}, save=lambda: None)
manager = ModuleManager(EventBus(), configuration, target_platform='windows', module_factory=inert_factory)
try:
    manager.discover()
    assert not manager.discovery_errors, manager.discovery_errors
    assert len(manager.modules) == 2 and not starts
    files = {path.relative_to(root).as_posix(): blake3(path.read_bytes()).hexdigest()
             for path in (root / 'src' / 'angerona').rglob('*.py')}
    manifest = {path: {'blake3': digest, 'size': (root / path).stat().st_size} for path, digest in files.items()}
    digest = blake3(json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    common = {'report_id': 'a' * 32, 'generation': 'b' * 32, 'source_manifest_digest': digest,
              'repository': str(root), 'vault_path': str(root.parent / 'offline-fixture' / 'golden.ugcap'),
              'verified_files': files}
    report = {'status': 'verified', **common, 'verification_receipt': dict(common)}
    assert manager.activate_enclave_mesh(report)
    def permit(open_gate):
        assert manager.ugcap_paused and not starts
        open_gate()
        return True
    try:
        result = manager.resume_after_ugcap(permit=permit)
    except Exception as error:
        raise AssertionError(manager.discovery_errors) from error
    assert not result['paused'] and not manager.discovery_errors, manager.discovery_errors
    assert len(manager.modules) > 70 and starts
    assert not manager.requires_ugcap_restart
    assert all(getattr(module, '_angerona_attested_load', None)
               for name, module in sys.modules.items() if name.startswith('angerona.modules.')
               and name not in {'angerona.modules.ugcap_guard', 'angerona.modules.adversary_combat'})
finally:
    manager.stop_all()
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr


def test_bootstrap_protected_process_policy_matches_soar():
    from angerona.modules.adversary_combat import _SYSTEM32_NEVER_CONTAIN as combat
    from angerona.modules.soar import _SYSTEM32_NEVER_CONTAIN as soar
    assert combat == soar
    assert {"lsass.exe", "services.exe", "winlogon.exe"}.issubset(combat)
