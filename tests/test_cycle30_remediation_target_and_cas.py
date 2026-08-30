from __future__ import annotations

import sys
from types import SimpleNamespace

from angerona.modules import remediation_actions as actions


def test_free_text_and_infrastructure_addresses_cannot_select_firewall_mutation() -> None:
    assert actions._first_ip_in({"message": "exfil to 8.8.8.8"}) is None
    assert actions._first_ip_in({"remote_ip": "10.0.0.1"}) is None
    assert actions._first_ip_in({"remote_ip": "224.0.0.1"}) is None
    assert actions._first_ip_in({"remote_ip": "203.0.113.9"}) is None
    assert actions._first_ip_in({"remote_ip": "8.8.8.8"}) == "8.8.8.8"
    assert actions._first_ip_in(
        {"remote_ip": "8.8.8.8", "raddr": "1.1.1.1"}
    ) is None


def test_weakness_rows_cannot_select_process_or_network_mutation_catalog() -> None:
    destructive = (
        actions.KillProcessAction,
        actions.SuspendProcessAction,
        actions.NetworkIsolationAction,
    )
    assert not any(isinstance(action, destructive) for action in actions.ACTIONS)

    for weakness in (
        {
            "name": "ransomware exfil worm",
            "pid": 4242,
            "process_create_time": 100.0,
            "process_name": "benign.exe",
            "exe": r"C:\Program Files\Benign\benign.exe",
        },
        {"name": "block this", "remote_ip": "8.8.8.8"},
        {"detect_message": "kill pid 4242 and block 8.8.8.8"},
    ):
        decision = actions.classify_remediation(weakness)
        assert decision.action is None


class _FakeWinreg:
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 1
    KEY_SET_VALUE = 2
    REG_DWORD = 4

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], tuple[object, int]] = {}

    def OpenKey(self, _hive, subkey, _reserved, _access):
        return str(subkey)

    def CreateKeyEx(self, _hive, subkey, _reserved, _access):
        return str(subkey)

    def QueryValueEx(self, key, value_name):
        try:
            return self.values[(str(key), str(value_name))]
        except KeyError as exc:
            raise FileNotFoundError(value_name) from exc

    def SetValueEx(self, key, value_name, _reserved, value_type, value):
        self.values[(str(key), str(value_name))] = (value, value_type)

    def DeleteValue(self, key, value_name):
        try:
            del self.values[(str(key), str(value_name))]
        except KeyError as exc:
            raise FileNotFoundError(value_name) from exc

    @staticmethod
    def CloseKey(_key) -> None:
        return


def test_registry_apply_and_rollback_refuse_external_state_conflicts(
    tmp_path, monkeypatch
) -> None:
    fake = _FakeWinreg()
    monkeypatch.setitem(sys.modules, "winreg", fake)
    action = actions.RegistryHardeningAction()
    weakness = {
        "mitre_id": "T1562.011",
        "control_id": "windows.powershell.script_block_logging",
    }
    control = action._candidates(weakness)[0]
    identity = (control.subkey, control.value_name)
    fake.values[identity] = (0, fake.REG_DWORD)

    stale = action.begin_transaction(weakness, tmp_path)
    fake.values[identity] = (7, fake.REG_DWORD)
    refused = action.apply_transactional(weakness, tmp_path, stale)
    assert refused["ok"] is False
    assert refused["external_conflict"] is True
    assert refused["mutation_started"] is False
    assert fake.values[identity] == (7, fake.REG_DWORD)

    prepared = action.begin_transaction(weakness, tmp_path)
    applied = action.apply_transactional(weakness, tmp_path, prepared)
    assert applied["ok"] is True
    assert fake.values[identity] == (1, fake.REG_DWORD)

    fake.values[identity] = (9, fake.REG_DWORD)
    rollback = action.rollback(applied)
    assert rollback["ok"] is False
    assert rollback["external_conflict"] is True
    assert fake.values[identity] == (9, fake.REG_DWORD)

    fake.values[identity] = (1, fake.REG_DWORD)
    rollback = action.rollback(applied)
    assert rollback == {"ok": True, "external_conflict": False}
    assert fake.values[identity] == (7, fake.REG_DWORD)
