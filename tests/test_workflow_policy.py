from pathlib import Path

from tools.validate_workflow_policy import validate


def test_repository_workflows_follow_security_policy():
    root = Path(__file__).resolve().parents[1]
    assert validate(root) == []


def test_validator_rejects_dangerous_trigger_and_unpinned_action(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "bad.yml").write_text(
        """name: bad
on:
  pull_request_target:
permissions:
  contents: read
concurrency:
  group: bad
jobs:
  bad:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: owner/action@main
""", encoding="utf-8")
    errors = validate(tmp_path)
    assert any("pull_request_target" in item for item in errors)
    assert any("not SHA-pinned" in item for item in errors)
