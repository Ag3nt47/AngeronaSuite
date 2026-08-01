from angerona.core.capability_guide import GUIDES
from angerona.gui import help_content


def test_help_capability_inventory_has_exact_canonical_parity():
    expected = tuple(guide.key for guide in GUIDES)
    assert help_content.CAPABILITY_TOPIC_KEYS == expected
    assert tuple(help_content.capability_topics()) == expected
    assert set(expected).isdisjoint(help_content.SUPPLEMENTARY_TOPIC_KEYS)
    assert tuple(help_content.TOPICS)[-len(expected):] == expected


def test_help_renders_evidence_maturity_limitations_and_destination():
    for guide in GUIDES:
        title, body = help_content.TOPICS[guide.key]
        assert title == guide.name
        assert f"Maturity: {guide.maturity_label}" in body
        assert "EVIDENCE\n" in body
        assert "KNOWN LIMITATIONS\n" in body
        assert "CANONICAL DESTINATION\n" in body
        assert all(reference in body for reference in guide.evidence)
        assert all(limitation in body for limitation in guide.limitations)


def test_supplementary_help_is_preserved_without_plaintext_secret_guidance():
    assert {"getting-started", "troubleshooting"}.issubset(
        help_content.SUPPLEMENTARY_TOPIC_KEYS
    )
    rendered = "\n".join(body for _, body in help_content.TOPICS.values())
    assert ".env" not in rendered
    assert "ANGERONA_TEAMS_APP_PASSWORD" not in rendered
    assert "protected Settings workflow" in rendered


def test_legacy_help_resolves_to_canonical_capability_intent():
    assert help_content.resolve("ARIA") == "local-ai"
    assert help_content.resolve("audit export") == "audit-export"
    assert help_content.resolve("fleet") == "fleet-preview"
    assert "Signed Audit Export" in help_content.get("audit export")
    assert "Local Fleet Control Plane" in help_content.get("fleet")
