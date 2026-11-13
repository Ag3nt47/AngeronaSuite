"""Bundled observer bytes are corruption-pinned, never privileged activation authority."""
from __future__ import annotations

import ast
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from angerona import _release_integrity
from angerona.resilience import native_watchdog as native


ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64


def test_source_checkout_does_not_pre_enroll_bundled_or_privileged_identity():
    # Parse source data without importing or executing a generated release file.
    tree = ast.parse((ROOT / "src/angerona/_release_integrity.py").read_text(encoding="utf-8"))
    values = {
        target.id: ast.literal_eval(statement.value)
        for statement in tree.body if isinstance(statement, ast.Assign)
        for target in statement.targets if isinstance(target, ast.Name)
        and target.id in {"WATCHDOG3_BUNDLE_SHA256", "WATCHDOG3_SHA256", "WATCHDOG3_PUBLISHER"}
    }
    assert values == {
        "WATCHDOG3_BUNDLE_SHA256": "", "WATCHDOG3_SHA256": "", "WATCHDOG3_PUBLISHER": "",
    }


def test_windows_release_pins_exact_built_observer_before_freezing_dashboard():
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["prepare-windows"]["steps"]
    builders = [step["run"] for step in steps
                if "Build-AngeronaWatchdog3.ps1" in step.get("run", "")]
    assert len(builders) == 1
    script = re.sub(r"\x60\s*\r?\n\s*", " ", builders[0])
    build = re.search(
        r"&\s+\./tools/Build-AngeronaWatchdog3\.ps1\s+-SkipTests\s+"
        r"-OutputPath\s+\(Join-Path\s+\$PWD\s+'([^']+)'\)", script,
    )
    assert build, "Release must build a known native observer artifact"
    digest = re.search(
        r"\$(\w+)\s*=\s*\(Get-FileHash\s+-LiteralPath\s+\"([^\"]+)\"\s+"
        r"-Algorithm\s+SHA256\)\.Hash\.ToLowerInvariant\(\)", script,
    )
    assert digest, "Release must hash the final built helper"
    assert Path(build.group(1)).as_posix() == Path(digest.group(2)).as_posix()
    generated = re.search(
        r"@\((?P<body>.*?)\)\s*\|\s*Set-Content\s+-Encoding\s+utf8\s+"
        r"\"src/angerona/_release_integrity\.py\"", script, re.DOTALL,
    )
    assert generated, "The digest must enter the frozen application, not just a log"
    body = generated.group("body")
    assert 'WATCHDOG3_BUNDLE_SHA256 = ' in body
    assert re.search(r'WATCHDOG3_BUNDLE_SHA256\s*=\s*\x60"\$' + re.escape(digest.group(1)) + r'\x60"', body)
    # The unsigned build has no authority to manufacture privileged release pins.
    assert "'WATCHDOG3_SHA256 = \"\"'" in body
    assert "'WATCHDOG3_PUBLISHER = \"\"'" in body
    freeze = re.search(r"pyinstaller\s+[^\n]*--name\s+Angerona(?:\s|$)", script)
    assert freeze, "Expected the dashboard freeze in the same build step"
    assert build.end() < digest.start() < digest.end() < generated.end() < freeze.start()


@pytest.fixture
def frozen_observer(monkeypatch, tmp_path):
    from angerona.core import source_activation_file

    root = tmp_path / "bundle"
    expected_path = root / native.BINARY_NAME
    monkeypatch.setattr(native, "sys", SimpleNamespace(frozen=True, executable=str(root / "Angerona.exe")))
    monkeypatch.setattr(_release_integrity, "WATCHDOG3_BUNDLE_SHA256", DIGEST)
    # Privileged admission must not be needed or repurposed for ordinary observation.
    monkeypatch.setattr(native, "_release_pins", lambda: pytest.fail("Observer consumed privileged signing pins"))
    state = SimpleNamespace(digest=DIGEST, size=2048, opened=[], checked=[], closed=[], check_error=False)

    class Retained:
        def __init__(self, path):
            self.path = Path(path)
            assert self.path == expected_path
            state.opened.append(self)

        def digest(self, *, limit):
            assert limit == 32 * 1024 * 1024
            return state.digest, state.size

        def check(self):
            state.checked.append(self)
            if state.check_error:
                raise native.NativeWatchdogError("Inert retained identity changed")

        def close(self):
            state.closed.append(self)

    monkeypatch.setattr(source_activation_file, "RetainedFile", Retained)
    state.path = expected_path
    return state


def test_matching_bundle_pin_retains_exact_helper_without_privileged_admission(frozen_observer):
    state = frozen_observer
    with native._admit_observe_bundle() as (path, digest):
        assert path == state.path and digest == DIGEST
        assert len(state.opened) == 1 and not state.closed
        assert state.checked == state.opened
    assert state.closed == state.opened
    assert state.checked == state.opened * 2


@pytest.mark.parametrize("pin", ["", None, True, "A" * 64, "a" * 63, "b" * 65])
def test_missing_or_malformed_bundle_pin_holds_before_file_admission(
    frozen_observer, monkeypatch, pin,
):
    monkeypatch.setattr(_release_integrity, "WATCHDOG3_BUNDLE_SHA256", pin)
    with pytest.raises(native.NativeWatchdogError, match="corruption pin"):
        with native._admit_observe_bundle():
            pytest.fail("Invalid bundle pin yielded a helper")
    assert not frozen_observer.opened


@pytest.mark.parametrize("digest,size", [("b" * 64, 2048), (DIGEST, 1023)])
def test_replaced_or_truncated_bundled_helper_never_yields_and_retires_lease(
    frozen_observer, digest, size,
):
    state = frozen_observer
    state.digest, state.size = digest, size
    with pytest.raises(native.NativeWatchdogError, match="corruption pin"):
        with native._admit_observe_bundle():
            pytest.fail("Substituted helper was admitted")
    assert len(state.opened) == 1
    assert state.closed == state.opened


def test_lost_retained_identity_holds_bundle_even_when_digest_matches(frozen_observer):
    state = frozen_observer
    state.check_error = True
    with pytest.raises(native.NativeWatchdogError, match="identity changed"):
        with native._admit_observe_bundle():
            pytest.fail("Lost file identity was admitted")
    assert len(state.opened) == 1 and state.closed == state.opened
