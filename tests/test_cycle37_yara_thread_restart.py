"""A YARA worker restart must not dispose a thread-bound scanner elsewhere."""
from __future__ import annotations

import threading

from angerona.modules.yara_scanner import YaraScannerModule


def test_yara_activation_on_next_worker_does_not_drop_previous_thread_scanner(tmp_path) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text("rule RestartProbe { condition: true }", encoding="utf-8")
    module = YaraScannerModule()
    first_ready = threading.Event()
    release_first = threading.Event()
    failures: list[BaseException] = []

    def activate_first() -> None:
        try:
            module._activate(rules)
            first_ready.set()
            release_first.wait(10)
        except BaseException as exc:
            failures.append(exc)
            first_ready.set()

    def activate_second() -> None:
        if not first_ready.wait(10):
            failures.append(TimeoutError("first YARA worker did not activate"))
            return
        try:
            module._activate(rules)
        except BaseException as exc:
            failures.append(exc)

    first = threading.Thread(target=activate_first, name="YaraWorkerFirst")
    second = threading.Thread(target=activate_second, name="YaraWorkerSecond")
    first.start()
    second.start()
    second.join(15)
    release_first.set()
    first.join(15)
    assert not first.is_alive() and not second.is_alive()
    assert not failures
    assert module._compiled_rules is not None
