import json
from types import SimpleNamespace

from angerona.modules.sysmon_listener import SysmonListenerModule


CURSOR_KEY = b"s" * 32


def _record(number: int):
    return SimpleNamespace(RecordNumber=number, EventID=999, StringInserts=None)


def test_sysmon_cursor_is_atomic_bounded_and_restart_safe(tmp_path):
    module = SysmonListenerModule(data_root=tmp_path, cursor_key=CURSOR_KEY)

    module._save_cursor(41)

    assert module._load_cursor() == 41
    payload = json.loads(module._cursor_path.read_text(encoding="utf-8"))
    assert payload["record_number"] == 41
    assert len(payload["_angerona_hmac"]) == 64
    assert not list(module._cursor_path.parent.glob("*.tmp-*"))


def test_sysmon_batch_checkpoints_last_fully_consumed_record(tmp_path, monkeypatch):
    module = SysmonListenerModule(data_root=tmp_path, cursor_key=CURSOR_KEY)
    consumed = []
    monkeypatch.setattr(module, "_process_record", lambda record: consumed.append(
        record.RecordNumber))

    last = module._consume_records([_record(100), _record(101), _record(102)])

    assert last == 102
    assert consumed == [100, 101, 102]
    assert module._load_cursor() == 102


def test_invalid_or_oversized_cursor_fails_closed_to_first_run(tmp_path):
    module = SysmonListenerModule(data_root=tmp_path, cursor_key=CURSOR_KEY)
    module._cursor_path.parent.mkdir(parents=True)
    module._cursor_path.write_text('{"schema":1,"record_number":"bad"}', encoding="utf-8")
    assert module._load_cursor() == 0
    module._cursor_path.write_bytes(b"x" * 5000)
    assert module._load_cursor() == 0


def test_cursor_hmac_rejects_record_or_signature_tampering(tmp_path):
    module = SysmonListenerModule(data_root=tmp_path, cursor_key=CURSOR_KEY)
    module._save_cursor(77)
    payload = json.loads(module._cursor_path.read_text(encoding="utf-8"))

    payload["record_number"] = 9_999_999
    module._cursor_path.write_text(json.dumps(payload), encoding="utf-8")
    assert module._load_cursor() == 0
    assert module._cursor_auth_failed is True

    module._save_cursor(78)
    payload = json.loads(module._cursor_path.read_text(encoding="utf-8"))
    payload["_angerona_hmac"] = "0" * 64
    module._cursor_path.write_text(json.dumps(payload), encoding="utf-8")
    assert module._load_cursor() == 0
    assert module._cursor_auth_failed is True


def test_cursor_without_authority_is_never_persisted_or_trusted(tmp_path):
    module = SysmonListenerModule(data_root=tmp_path)
    module._save_cursor(12)
    assert not module._cursor_path.exists()

    module._cursor_path.parent.mkdir(parents=True)
    module._cursor_path.write_text(
        json.dumps({
            "schema": 2,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "record_number": 12,
            "updated_at": 1.0,
            "_angerona_hmac": "0" * 64,
        }),
        encoding="utf-8",
    )
    assert module._load_cursor() == 0
    assert module._cursor_auth_failed is True


def test_cursor_key_derivation_reuses_the_stable_install_authority(
    tmp_path, monkeypatch
):
    (tmp_path / "bus.key").write_text((b"k" * 32).hex(), encoding="ascii")
    module = SysmonListenerModule(data_root=tmp_path)
    original = type(module._cursor_path).read_text
    reads = []

    def counted(path, *args, **kwargs):
        reads.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(type(module._cursor_path), "read_text", counted)

    first = module._cursor_key()
    second = module._cursor_key()

    assert first == second
    assert isinstance(first, bytes) and len(first) == 32
    assert reads == [tmp_path / "bus.key"]
