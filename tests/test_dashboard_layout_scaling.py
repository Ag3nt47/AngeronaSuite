from types import SimpleNamespace

from angerona.gui.main_window import MainWindow


class _Tabs:
    def __init__(self, current):
        self._current = current

    def currentWidget(self):
        return self._current


class _Splitter:
    def __init__(self, sizes):
        self._sizes = list(sizes)

    def sizes(self):
        return list(self._sizes)

    def height(self):
        return sum(self._sizes)

    def setSizes(self, sizes):
        self._sizes = list(sizes)


def test_scan_center_keeps_bottom_information_row_proportional() -> None:
    scan_center = object()
    splitter = _Splitter([820, 180])
    owner = SimpleNamespace(
        scan_center=scan_center,
        _right_tabs=_Tabs(scan_center),
        _body_splitter=splitter,
    )

    MainWindow._expand_scan_center(owner)

    assert sum(splitter.sizes()) == 1000
    assert splitter.sizes() == [580, 420]
