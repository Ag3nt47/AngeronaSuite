from angerona.core.capability_guide import GUIDES, search_guides


def test_guides_are_complete_unique_and_searchable():
    assert len({guide.key for guide in GUIDES}) == len(GUIDES)
    for guide in GUIDES:
        assert guide.name and guide.definition and guide.steps
        assert guide.verify and guide.privacy and guide.destination
        assert guide.destination_kind in {"settings", "window"}
    assert search_guides("microphone")[0].key == "local-ai"
    assert search_guides("custody privacy")[0].key == "forensics"
    assert search_guides("no such capability") == ()


def test_empty_search_returns_the_full_stable_catalog():
    assert search_guides("") == GUIDES
