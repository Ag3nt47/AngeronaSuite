from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from angerona.core import secure_store
from angerona.core.eventbus import Event, Severity
from angerona.modules.adversary_combat import AdversaryCombat, JournalIntegrityError, _JOURNAL_CONTEXT
from tools import recover_combat_startup as recovery


def _interrupted(tmp_path, monkeypatch, action_name="activate_honeypots"):
    key = b"t" * 32
    (tmp_path / "bus.key").write_text(key.hex(), encoding="ascii")
    protected = tmp_path / "secrets.dpapi"
    protected.write_bytes(b"inert encrypted-store fixture")
    values = {}
    monkeypatch.setattr(secure_store, "read_secret_values", lambda names, *_a, **_k: {
        name: values[name] for name in names if name in values
    })

    def write(updates, root):
        values.update(updates)
        protected.write_text(json.dumps(values), encoding="utf-8")
        return protected

    monkeypatch.setattr(secure_store, "write_secret_map", write)
    monkeypatch.setattr(recovery, "_private_acl", lambda *_a: None)
    monkeypatch.setattr(recovery, "_require_stopped", lambda: None)
    module = AdversaryCombat(tmp_path)
    module._journal_key_cache = hmac.new(key, _JOURNAL_CONTEXT, hashlib.sha256).digest()
    module._read_journal(strict=True)
    action = module._action(
        action_name, "Smart Deception", Event("Adversary Combat", "startup", Severity.INFO),
        "startup", reversible=True, details={"module": "Smart Deception"},
    )

    def interrupted(_record):
        raise OSError("inert interrupted checkpoint")

    monkeypatch.setattr(module, "_advance_recovery_anchor", interrupted)
    with pytest.raises(JournalIntegrityError, match="custody"):
        module._journal_intent(action)
    return module, protected


def test_inspection_is_read_only_and_exact_startup_recovery_keeps_journal(tmp_path, monkeypatch):
    module, protected = _interrupted(tmp_path, monkeypatch)
    paths = (module.receipt_path, protected, module.recovery_witness_path)
    before = [path.read_bytes() for path in paths]
    report = recovery.inspect_startup(tmp_path)[0]
    assert report["checkpoint_sequence"] == 0
    assert report["journal_records"] == 1
    assert [path.read_bytes() for path in paths] == before

    result = recovery.recover_startup(tmp_path, report["review_token"])

    assert result["checkpoint_sequence"] == 1
    assert result["host_actions_executed"] == 0
    assert result["rearmed"] is False
    assert module.receipt_path.read_bytes() == before[0]
    backup = __import__("pathlib").Path(result["backup_directory"])
    assert (backup / "adversary_combat_actions.jsonl").read_bytes() == before[0]
    assert (backup / "secrets.dpapi").read_bytes() == before[1]
    assert (backup / "recovery_witness.json").read_bytes() == before[2]
    # Normal startup can now close its old internal intent without any host
    # action: no Smart Deception worker is running in this isolated fixture.
    restarted = AdversaryCombat(tmp_path)
    restarted._journal_key_cache = module._journal_key_cache
    assert restarted._reconcile_state() is True
    assert restarted._pending_recovery_records() == {}


def test_changed_review_token_cannot_modify_authority(tmp_path, monkeypatch):
    module, protected = _interrupted(tmp_path, monkeypatch)
    token = recovery.inspect_startup(tmp_path)[0]["review_token"]
    protected.write_bytes(protected.read_bytes() + b" ")
    before = protected.read_bytes()
    with pytest.raises(ValueError, match="changed"):
        recovery.recover_startup(tmp_path, token)
    assert protected.read_bytes() == before
    assert not list(tmp_path.glob("combat-startup-recovery-*"))


def test_active_application_blocks_recovery(tmp_path, monkeypatch):
    module, protected = _interrupted(tmp_path, monkeypatch)
    report = recovery.inspect_startup(tmp_path)[0]
    before = protected.read_bytes()

    def running():
        raise ValueError("Stop Angerona before applying checkpoint recovery")

    monkeypatch.setattr(recovery, "_require_stopped", running)
    with pytest.raises(ValueError, match="Stop Angerona"):
        recovery.recover_startup(tmp_path, report["review_token"])
    assert protected.read_bytes() == before


def test_tool_refuses_containment_history(tmp_path, monkeypatch):
    _interrupted(tmp_path, monkeypatch, "isolate_host")
    with pytest.raises(ValueError, match="restricted"):
        recovery.inspect_startup(tmp_path)


def test_tampered_record_cannot_receive_checkpoint_authority(tmp_path, monkeypatch):
    module, protected = _interrupted(tmp_path, monkeypatch)
    record = json.loads(module.receipt_path.read_bytes())
    record["trigger_module"] = "different detector"
    module.receipt_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    before = protected.read_bytes()
    with pytest.raises(ValueError, match="authentication"):
        recovery.inspect_startup(tmp_path)
    assert protected.read_bytes() == before


@pytest.mark.parametrize("change", ["witness", "partial_line", "extra_intent"])
def test_ambiguous_or_incomplete_inputs_are_refused(tmp_path, monkeypatch, change):
    module, protected = _interrupted(tmp_path, monkeypatch)
    before = protected.read_bytes()
    if change == "witness":
        witness = json.loads(module.recovery_witness_path.read_bytes())
        witness["last_journal_sequence"] = 99
        module.recovery_witness_path.write_text(json.dumps(witness), encoding="utf-8")
    elif change == "partial_line":
        module.receipt_path.write_bytes(module.receipt_path.read_bytes().rstrip(b"\n"))
    else:
        record = json.loads(module.receipt_path.read_bytes())
        record["sequence"] = 2
        record["previous_hmac"] = record.pop("record_hmac")
        record["record_hmac"] = module._record_hmac(record)
        with module.receipt_path.open("ab") as stream:
            stream.write(json.dumps(record).encode() + b"\n")
    with pytest.raises((ValueError, JournalIntegrityError)):
        recovery.inspect_startup(tmp_path)
    assert protected.read_bytes() == before
    assert not list(tmp_path.glob("combat-startup-recovery-*"))


def test_process_guard_recognizes_source_runtime(monkeypatch):
    from types import SimpleNamespace
    import psutil

    process = SimpleNamespace(pid=-1, info={"name": "python.exe"},
                              cmdline=lambda: ["python.exe", "-m", "angerona"])
    monkeypatch.setattr(psutil, "process_iter", lambda _fields: [process])
    with pytest.raises(ValueError, match="Stop Angerona"):
        recovery._require_stopped()


def test_journal_change_at_pin_does_not_advance_checkpoint(tmp_path, monkeypatch):
    from contextlib import contextmanager

    module, protected = _interrupted(tmp_path, monkeypatch)
    token = recovery.inspect_startup(tmp_path)[0]["review_token"]
    before = protected.read_bytes()
    original = AdversaryCombat._pinned_journal_session

    @contextmanager
    def changed_at_pin(instance, *, create):
        with original(instance, create=create):
            module.receipt_path.write_bytes(module.receipt_path.read_bytes() + b"\n")
            yield

    monkeypatch.setattr(AdversaryCombat, "_pinned_journal_session", changed_at_pin)
    with pytest.raises((ValueError, JournalIntegrityError)):
        recovery.recover_startup(tmp_path, token)
    assert protected.read_bytes() == before
