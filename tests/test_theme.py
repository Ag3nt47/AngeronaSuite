from angerona.gui.theme import FUNCTION_ROLES, THEMES, build_qss


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


def test_function_cues_are_opt_in_and_do_not_replace_status_or_action_backgrounds() -> None:
    qss = build_qss("cyber")
    for role, (color, _description) in FUNCTION_ROLES.items():
        edge = f'QPushButton[functionRole="{role}"], QToolButton[functionRole="{role}"]'
        assert edge in qss
        declaration = qss.split(edge, 1)[1].split("}", 1)[0]
        assert "border-left:2px solid " + color in declaration
        assert "background" not in declaration and "color:" not in declaration
    assert 'QLabel[functionRole="analysis"]' in qss
    assert 'QLabel[severity=' not in qss
    assert "background: #dc2626; color: white;" in qss
    assert "background: #ef4444; color: white;" in qss
