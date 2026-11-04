"""Self-Test role samples use production checks on inert, isolated evidence."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from angerona.core.eventbus import EventBus, Severity
from angerona.modules import behavioral_tuner, self_healer, shadow_shield, smart_deception
from angerona.modules.chaos_harness import ChaosHarness
from angerona.modules.wfp_controller import WFPController, WFPControllerModule


def test_behavioral_tuner_sample_never_mutates_the_live_baseline(monkeypatch, tmp_path):
    monkeypatch.setattr(behavioral_tuner, "_resolve_db_path", lambda: str(tmp_path / "live.db"))
    monkeypatch.setattr(behavioral_tuner, "_INSTANCE", None)
    tuner = behavioral_tuner.BehavioralTuner()
    tuner.status = "running"
    tuner._connect()
    try:
        ok, detail = tuner.self_test()
        assert ok and "approval and drift samples passed" in detail
        assert behavioral_tuner.get_tuner() is tuner
        assert tuner._db.execute("SELECT COUNT(*) FROM behavioral_baseline").fetchone()[0] == 0
        assert tuner._learned == tuner._downgraded == 0
        monkeypatch.setattr(behavioral_tuner.BehavioralTuner, "check_event", lambda *_args: Severity.INFO)
        assert tuner.self_test()[0] is False
    finally:
        tuner._db.close()


def test_chaos_receipt_samples_never_publish_on_live_bus(monkeypatch):
    chaos = ChaosHarness()
    live_bus = EventBus()
    chaos.bind(live_bus)
    monkeypatch.setattr(chaos, "_probe_apid", lambda: pytest.fail("native probe started"))

    ok, detail = chaos.self_test()
    assert ok and "forged and replayed" in detail
    assert live_bus.recent(8) == [] and chaos._runs == chaos._failures == 0

    monkeypatch.setattr(ChaosHarness, "_wait_for_echo", lambda *_args: False)
    assert chaos.self_test()[0] is False


def test_healer_snapshot_sample_never_creates_or_stages_live_files(monkeypatch, tmp_path):
    from angerona.core import data_paths

    def resolve(*, create):
        assert create is False
        return tmp_path

    monkeypatch.setattr(data_paths, "data_dir", resolve)
    monkeypatch.setattr(self_healer, "_snapshot_dir", lambda: pytest.fail("snapshot directory created"))
    monkeypatch.setattr(self_healer, "_staged_dir", lambda: pytest.fail("staging directory created"))
    healer = self_healer.SelfHealer()

    ok, detail = healer.self_test()
    assert ok and "signed and tampered" in detail
    assert list(tmp_path.iterdir()) == []

    monkeypatch.setattr(self_healer, "verify_crash_snapshot_bundle", lambda *_args, **_kwargs: True)
    assert healer.self_test()[0] is False


def test_shadow_target_samples_do_not_create_cache_or_call_vss(monkeypatch, tmp_path):
    monkeypatch.setattr(shadow_shield, "_data_base", lambda: tmp_path)
    module = shadow_shield.ShadowShield()
    monkeypatch.setattr(module, "_take_vss_snapshot", lambda: pytest.fail("native VSS request"))

    ok, detail = module.self_test()
    assert ok and "escaping rollback targets" in detail
    assert list(tmp_path.iterdir()) == []

    monkeypatch.setattr(module, "_canonical_protected_path", lambda *_args, **_kwargs: None)
    assert module.self_test()[0] is False


def test_smart_deception_samples_do_not_deploy_honeytokens(monkeypatch, tmp_path):
    monkeypatch.setattr(smart_deception, "_runtime_deception_root", lambda: tmp_path)
    monkeypatch.setattr(smart_deception, "_user_folder_deception_enabled", lambda: False)
    monkeypatch.setattr(smart_deception, "_custody_api", lambda: None)
    module = smart_deception.SmartDeception()

    ok, detail = module.self_test()
    assert ok and "offline honeytoken samples passed" in detail
    assert list(tmp_path.iterdir()) == [] and not module._decoys

    monkeypatch.setattr(module, "_matches_decoy_anchor", lambda *_args: True)
    assert module.self_test()[0] is False


def test_wfp_role_sample_only_previews_and_preserves_live_collection_error(monkeypatch):
    monkeypatch.setattr(WFPController, "_try_init_wfp", lambda *_args: pytest.fail("native WFP opened"))
    monkeypatch.setattr(WFPController, "apply_containment", lambda *_args: pytest.fail("firewall mutated"))
    module = WFPControllerModule()
    module.status = "running"
    coverage = SimpleNamespace(collection_ok=True, rows=3)
    module._ctrl = SimpleNamespace(coverage=lambda: coverage)

    ok, detail = module.self_test()
    assert ok and "offline containment preview samples passed" in detail

    coverage.collection_ok, coverage.error = False, "collector unavailable"
    assert module.self_test() == (False, "IP Helper collection failed: collector unavailable")
