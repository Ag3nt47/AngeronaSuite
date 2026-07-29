from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs" / "enterprise"


def test_required_enterprise_governance_documents_exist_and_are_linked():
    required = {
        "SUPPORTED_EDITIONS.md": ("Fleet Preview", "Enterprise candidate"),
        "COMPATIBILITY_POLICY.md": ("semantic versioning", "Downgrades"),
        "ARCHITECTURE_DECISIONS.md": ("ADR-001", "ADR-006", "generic remote shell"),
        "DETECTION_CONTENT_GOVERNANCE.md": ("false-positive", "Privacy Reviewer"),
        "SUPPORT_OPERATIONS.md": ("Critical", "Diagnostic bundles"),
    }
    for name, phrases in required.items():
        text = (DOCS / name).read_text(encoding="utf-8")
        assert all(phrase in text for phrase in phrases)
    assert "SUPPORT_OPERATIONS.md" in (ROOT / "SECURITY.md").read_text(
        encoding="utf-8"
    )
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "DETECTION_CONTENT_GOVERNANCE.md" in contributing
    assert "ARCHITECTURE_DECISIONS.md" in contributing
