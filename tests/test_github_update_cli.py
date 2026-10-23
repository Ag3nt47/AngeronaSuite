"""Exercise the installed CLI with inert metadata and source-stage producers."""
from __future__ import annotations

import builtins
import json

import pytest

from angerona.core import data_paths
from angerona.updater import github_updater, source_stage
from tools import check_github_updates as cli

BASE, TARGET = "a" * 40, "b" * 40
STAGE_ID, MANIFEST = "source-" + "c" * 32, "d" * 64
REVIEW = ["--stage-id", STAGE_ID, "--manifest-sha256", MANIFEST]


@pytest.fixture
def paths(tmp_path, monkeypatch):
    source, data = tmp_path / "source", tmp_path / "operator-data"
    monkeypatch.setattr(data_paths, "project_root", lambda: source)
    monkeypatch.setattr(data_paths, "data_dir", lambda: data)
    monkeypatch.setattr(github_updater, "check_installed_updates", lambda *a, **k: pytest.fail("unexpected metadata producer"))
    for name in ("prepare_source_update", "resolve_source_conflict", "validate_source_candidate"):
        monkeypatch.setattr(source_stage, name, lambda *a, **k: pytest.fail("unexpected source-stage producer"))
    return source, data


@pytest.mark.parametrize("force", [False, True])
def test_cli_check_json_uses_shared_cadence_and_reports_unknown_source(paths, monkeypatch, capsys, force):
    source, data = paths
    calls = []
    report = github_updater.UpdateReport("checked", 123.0, "1.14.0", remote_revision=TARGET,
                                        release_status="none", source_status="unknown")

    def check(state, root, *, force):
        calls.append((state, root, force))
        return report

    monkeypatch.setattr(github_updater, "check_installed_updates", check)
    assert cli.main(["--json", *(["--check-now"] if force else [])]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert calls == [(data / "github-updates", source, force)]
    assert payload["source_status"] == "unknown" and payload["available"] is False
    assert "cannot be established" in payload["summary"]
    assert payload["source_url"] == f"https://github.com/Ag3nt47/AngeronaSuite/commit/{TARGET}"
    assert not data.exists()


@pytest.mark.parametrize("status", ["failed", "partial", "clock_rollback"])
def test_cli_failure_states_have_nonzero_exit_without_claiming_currency(paths, monkeypatch, capsys, status):
    report = github_updater.UpdateReport(status, 123.0, "1.14.0", message="Check unavailable.")
    monkeypatch.setattr(github_updater, "check_installed_updates", lambda *a, **k: report)
    assert cli.main(["--check-now", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == status


@pytest.mark.parametrize("conflicts", [(), ("custom.py",)])
def test_cli_source_preparation_preserves_review_boundary_and_explicit_base(paths, monkeypatch, capsys, conflicts):
    source, data = paths
    calls = []
    result = source_stage.StageResult(STAGE_ID, "conflicts" if conflicts else "prepared", BASE, TARGET,
                                     "e" * 40, 4, 2, conflicts, MANIFEST)

    def prepare(root, state, revision, *, base_revision):
        calls.append((root, state, revision, base_revision))
        return result

    monkeypatch.setattr(source_stage, "prepare_source_update", prepare)
    assert cli.main(["--stage", TARGET, "--base", BASE, "--json"]) == (2 if conflicts else 0)
    payload = json.loads(capsys.readouterr().out)
    assert calls == [(source, data / "github-updates/stages", TARGET, BASE)]
    assert payload["activation_status"] == "not_authorized"
    assert payload["stage_directory"] == str(data / "github-updates/stages" / STAGE_ID)
    assert payload["conflicts"] == list(conflicts)
    assert not source.exists() and not data.exists()


@pytest.mark.parametrize("static_checks", ["passed", "failed"])
def test_cli_validates_only_the_explicit_stage_and_digest(paths, monkeypatch, capsys, static_checks):
    source, data = paths
    calls = []

    def validate(stage, digest):
        calls.append((stage, digest))
        return {"static_checks": static_checks, "activation": "held"}

    monkeypatch.setattr(source_stage, "validate_source_candidate", validate)
    assert cli.main(["--validate", *REVIEW, "--json"]) == (1 if static_checks == "failed" else 0)
    assert calls == [(data / "github-updates/stages" / STAGE_ID, MANIFEST)]
    assert json.loads(capsys.readouterr().out)["activation"] == "held"


def test_cli_resolves_only_the_explicit_retained_side(paths, monkeypatch, capsys):
    source, data = paths
    calls = []

    def resolve(stage, digest, path, choice):
        calls.append((stage, digest, path, choice))
        return {"path": path, "choice": choice}

    monkeypatch.setattr(source_stage, "resolve_source_conflict", resolve)
    assert cli.main(["--resolve", "custom.py", "--choose", "user", *REVIEW]) == 0
    assert calls == [(data / "github-updates/stages" / STAGE_ID, MANIFEST, "custom.py", "user")]
    assert json.loads(capsys.readouterr().out) == {"path": "custom.py", "choice": "user"}


@pytest.mark.parametrize("arguments", [
    ["--choose", "user"], ["--base", BASE], ["--base", ""],
    ["--stage-id", STAGE_ID], ["--stage-id", ""], ["--manifest-sha256", MANIFEST],
    ["--validate"], ["--validate", "--resolve", "custom.py", *REVIEW],
    ["--resolve", "custom.py", *REVIEW], ["--resolve", "", "--choose", "user", *REVIEW],
    ["--stage", TARGET, "--validate", *REVIEW], ["--stage", ""],
    ["--stage", "short"], ["--stage", TARGET, "--base", "short"],
    ["--stage", TARGET, "--choose", "user"],
    ["--validate", "--choose", "user", *REVIEW],
    ["--check-now", "--stage", TARGET], ["--check-now", "--validate", *REVIEW],
    ["--check-now", "--resolve", "custom.py", "--choose", "user", *REVIEW],
])
def test_incomplete_or_mixed_actions_fail_before_state_or_product_imports(tmp_path, monkeypatch, capsys, arguments):
    original_import = builtins.__import__
    touched = []

    def import_guard(name, *args, **kwargs):
        if name in {"angerona.core.data_paths", "angerona.updater.github_updater", "angerona.updater.source_stage"}:
            touched.append(name)
            pytest.fail("parser errors must precede state and producer imports")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_guard)
    with pytest.raises(SystemExit) as error:
        cli.main(arguments)
    assert error.value.code == 2
    assert touched == [] and "error:" in capsys.readouterr().err


def test_cli_stage_failure_retains_a_structured_nonmutation_report(paths, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise source_stage.SourceStageError("candidate held")

    monkeypatch.setattr(source_stage, "prepare_source_update", fail)
    assert cli.main(["--stage", TARGET, "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"status": "failed", "error_type": "SourceStageError", "message": "candidate held",
                       "original_installation_changed": False}
