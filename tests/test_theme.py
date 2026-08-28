from angerona.gui.theme import THEMES, build_qss


def test_translucent_theme_colors_use_qt_argb_order() -> None:
    qss = build_qss("cyber")

    assert THEMES["cyber"]["alt_row"] == "#08ffffff"
    assert "alternate-background-color: #08ffffff;" in qss
    assert "background: #151f9cff;" in qss
    assert "background: #331f9cff;" in qss
    assert "border-bottom: 2px solid #551f9cff;" in qss
    assert "#1f9cff15" not in qss


def test_custom_accent_tints_preserve_rgb_bytes() -> None:
    qss = build_qss("slate", accent="#010203")

    assert "background: #15010203;" in qss
    assert "selection-background-color: #44010203;" in qss
