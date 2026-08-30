from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from angerona.modules.shadow_shield import ShadowShield
from angerona.modules.soar import SOARModule


def _signal(module: str, *, pid: int, created: float, executable: Path):
    return SimpleNamespace(
        module=module,
        details={
            "pid": pid,
            "process_create_time": created,
            "exe": str(executable),
        },
    )


def test_soar_corroboration_never_crosses_process_generation(tmp_path: Path) -> None:
    soar = SOARModule()
    executable = tmp_path / "worker.exe"

    first_generation = _signal(
        "sensor-a", pid=4242, created=100.0, executable=executable
    )
    reused_pid = _signal(
        "sensor-b", pid=4242, created=101.0, executable=executable
    )

    assert soar._add_signal(4242, first_generation) is False
    assert soar._add_signal(4242, reused_pid) is False
    assert soar._signal_count(4242, first_generation) == 1
    assert soar._signal_count(4242, reused_pid) == 1


def test_soar_corroborates_same_exact_process_across_distinct_sources(
    tmp_path: Path,
) -> None:
    soar = SOARModule()
    executable = tmp_path / "worker.exe"

    assert soar._add_signal(
        4242, _signal("sensor-a", pid=4242, created=100.0, executable=executable)
    ) is False
    assert soar._add_signal(
        4242, _signal("sensor-b", pid=4242, created=100.0, executable=executable)
    ) is True


def test_legacy_bulk_rollback_is_inert_even_with_valid_cache_path(
    tmp_path: Path,
) -> None:
    source = tmp_path / "document.txt"
    source.write_text("current", encoding="utf-8")
    module = ShadowShield()
    module._cache_dir = tmp_path / "shadow-cache"
    keydir = module._keydir(str(source))
    keydir.mkdir(parents=True)
    (keydir / "_source.txt").write_text(str(source), encoding="utf-8")
    (keydir / "1.bak").write_text("attacker-controlled-old-data", encoding="utf-8")
    emitted: list[dict[str, object]] = []
    module.emit = lambda _message, _severity, **details: emitted.append(details)

    result = module.trigger_rollback(paths=[str(source)])

    assert result["refused"] is True
    assert result["restored"] == []
    assert source.read_text(encoding="utf-8") == "current"
    assert emitted[-1]["response_authorized"] is False
    assert emitted[-1]["proposal_only"] is True
