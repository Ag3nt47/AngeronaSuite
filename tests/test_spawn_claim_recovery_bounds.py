"""Private spawn-lock fault fixtures; never launch a supervised component."""
import os
import time
from types import SimpleNamespace
import pytest
from angerona.resilience import supervisor


@pytest.mark.parametrize("offset", [-3600, 3600])
def test_future_and_old_stale_claims_cannot_hold_respawn_forever(tmp_path, monkeypatch, offset):
    lock = tmp_path / "core.spawnlock"
    lock.write_text("stale fixture")
    stamp = time.time() + offset
    os.utime(lock, (stamp, stamp))
    monkeypatch.setattr(supervisor, "_spawnlock_path", lambda _name: lock)
    assert supervisor.try_claim_spawn("core", ttl=15)
    assert lock.read_text().startswith(str(os.getpid()) + " ")
    assert not supervisor.try_claim_spawn("core", ttl=15)
    supervisor.release_spawn("core")
    assert not lock.exists()


def test_contended_claim_is_bounded_and_diagnosable(tmp_path, monkeypatch):
    calls = []
    class Vanishing:
        def __str__(self):
            return str(tmp_path / "inert.lock")
        def stat(self):
            raise FileNotFoundError("racing fixture")
    def denied(*_args):
        calls.append(1)
        raise FileExistsError("racing fixture")
    monkeypatch.setattr(supervisor, "_spawnlock_path", lambda _name: Vanishing())
    monkeypatch.setattr(supervisor, "os", SimpleNamespace(open=denied, O_CREAT=1, O_EXCL=2, O_WRONLY=4))
    assert supervisor.try_claim_spawn("core") is False
    assert len(calls) == 3
    assert supervisor.spawn_lock_error("core") == "SpawnClaimContentionLimit"
