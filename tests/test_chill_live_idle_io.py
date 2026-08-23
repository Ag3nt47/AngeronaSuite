from __future__ import annotations

import builtins
from pathlib import Path

from angerona.core.module_base import BaseModule
from angerona.modules import deception
from angerona.modules.evolution_engine import EvolutionEngine


def test_evolution_engine_parks_instead_of_polling() -> None:
    class StopToken:
        def __init__(self) -> None:
            self.waits: list[float | None] = []

        def is_set(self) -> bool:
            return bool(self.waits)

        def wait(self, timeout: float | None = None) -> bool:
            self.waits.append(timeout)
            return True

    module = EvolutionEngine.__new__(EvolutionEngine)
    BaseModule.__init__(module)
    token = StopToken()
    module.generation_stop_event = lambda: token  # type: ignore[method-assign]

    module.run()

    assert module.first_cycle_complete
    assert token.waits == [None]


def test_deception_does_not_reopen_unchanged_attack_feed(
    tmp_path: Path, monkeypatch,
) -> None:
    feed = tmp_path / "attack_feed.log"
    feed.write_text("quiet status line\n", encoding="utf-8")
    module = deception.DeceptionModule()
    module._feed = feed
    module._feed_pos = 0
    module._feed_identity = None
    restaged: list[str] = []
    module._restage = restaged.append  # type: ignore[method-assign]

    real_open = builtins.open
    opens: list[Path] = []

    def tracked_open(file, *args, **kwargs):
        if Path(file) == feed:
            opens.append(feed)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", tracked_open)
    module._watch_attack_feed()
    module._watch_attack_feed()
    assert opens == [feed]

    with real_open(feed, "a", encoding="utf-8") as handle:
        handle.write("credential discovery marker\n")
    module._watch_attack_feed()
    assert opens == [feed, feed]
    assert restaged == ["credential discovery marker"]
