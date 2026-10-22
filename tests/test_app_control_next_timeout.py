"""Bounded native reads must not turn unavailable collection into an empty log."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from angerona.modules.app_control_monitor import WindowsCodeIntegritySource


class NativeReadError(Exception):
    def __init__(self, code: int, *, winerror: bool = True) -> None:
        super().__init__(code, "fixture native read failure")
        if winerror:
            self.winerror = code


def _source(next_call):
    source = WindowsCodeIntegritySource.__new__(WindowsCodeIntegritySource)
    source._api = SimpleNamespace(EvtNext=next_call)
    return source


def test_native_read_has_finite_wait_and_preserves_returned_handle_identity():
    query, first, second = object(), object(), object()
    calls = []

    def read(*args):
        calls.append(args)
        return (first, second)

    source = _source(read)
    handles = source._next(query, 2)
    assert calls == [(query, 2, 500, 0)]
    assert len(handles) == 2 and handles[0] is first and handles[1] is second


@pytest.mark.parametrize("winerror", [True, False])
def test_only_known_exhaustion_is_a_normal_empty_query(winerror):
    error = NativeReadError(259, winerror=winerror)

    def read(*_args):
        raise error

    assert _source(read)._next(object(), 1) == []


@pytest.mark.parametrize("code", [1460, 5, 6, 15000])
@pytest.mark.parametrize("winerror", [True, False])
def test_timeout_denial_and_invalid_query_are_not_a_healthy_empty_channel(code, winerror):
    error = NativeReadError(code, winerror=winerror)

    def read(*_args):
        raise error

    with pytest.raises(NativeReadError) as caught:
        _source(read)._next(object(), 1)
    assert caught.value is error


@pytest.mark.parametrize("method", ["newest_record_id", "oldest_record_id", "record_anchor"])
def test_timeout_cannot_mint_an_empty_watermark_or_anchor_and_query_is_retired(method):
    query = object()
    closed = []
    error = NativeReadError(1460)

    def read(*_args):
        raise error

    source = _source(read)
    source._query = lambda *_args, **_kwargs: query
    source._api.EvtClose = closed.append
    with pytest.raises(NativeReadError) as caught:
        getattr(source, method)(7) if method == "record_anchor" else getattr(source, method)()
    assert caught.value is error
    assert closed == [query]


def test_bounded_batch_keeps_order_rendering_and_exact_handle_cleanup():
    query, first, second = object(), object(), object()
    closed, calls = [], []

    def read(*args):
        calls.append(args)
        return [first, second]

    source = _source(read)
    source._query = lambda *_args, **_kwargs: query
    source._api.EvtRenderEventXml = 1
    source._api.EvtRender = lambda handle, _flag: "first" if handle is first else "second"
    source._api.EvtClose = closed.append
    assert source.read_after(10, 999) == ["first", "second"]
    assert calls == [(query, 256, 500, 0)]
    assert closed == [first, second, query]
