"""Bounded modern Windows Event Log queries for defensive sensors.

The adapter intentionally exposes only record watermarks, record anchors and a
filtered forward read.  It never clears a channel, changes audit policy, or
accepts a caller-supplied XPath/channel from untrusted input.
"""
from __future__ import annotations

import hashlib
import re
from typing import Iterable, Mapping


_CHANNEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\- ]{0,199}$")
_PROVIDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\- ]{0,199}$")
_MAX_EVENT_IDS = 64
_MAX_BATCH = 256
_MAX_XML_BYTES = 1024 * 1024


def _record_id_from_xml(xml: str) -> int:
    marker = "<EventRecordID>"
    start = xml.find(marker)
    end = xml.find("</EventRecordID>", start + len(marker))
    if start < 0 or end < 0:
        raise ValueError("Windows event has no EventRecordID")
    value = int(xml[start + len(marker):end])
    if value < 0:
        raise ValueError("Windows event record ID is negative")
    return value


class WindowsEventLogSource:
    """Read one constant Windows event channel through the supported WEVT API."""

    def __init__(
        self,
        channel: str,
        event_ids: Iterable[int] = (),
        *,
        providers_by_event: Mapping[int, Iterable[str]] | None = None,
    ) -> None:
        normalized = str(channel or "").strip()
        if not _CHANNEL_RE.fullmatch(normalized):
            raise ValueError("invalid Windows event channel")
        ids = tuple(sorted({int(value) for value in event_ids}))
        if len(ids) > _MAX_EVENT_IDS or any(value < 0 or value > 65535 for value in ids):
            raise ValueError("invalid Windows event ID filter")
        selectors: dict[int, tuple[str, ...]] = {}
        if providers_by_event is not None:
            if set(providers_by_event) != set(ids):
                raise ValueError("provider selectors must cover every event ID")
            for event_id, providers in providers_by_event.items():
                names = tuple(sorted({str(value) for value in providers}))
                if (
                    not names
                    or len(names) > 8
                    or any(not _PROVIDER_RE.fullmatch(value) for value in names)
                ):
                    raise ValueError("invalid Windows event provider filter")
                selectors[int(event_id)] = names
        import win32evtlog  # type: ignore[import]

        self.channel = normalized
        self.event_ids = ids
        self.providers_by_event = selectors
        self._api = win32evtlog

    def _query(self, expression: str, *, reverse: bool = False):
        flags = self._api.EvtQueryChannelPath
        flags |= (
            self._api.EvtQueryReverseDirection
            if reverse
            else self._api.EvtQueryForwardDirection
        )
        return self._api.EvtQuery(self.channel, flags, expression)

    def _next(self, query, count: int):
        try:
            return list(self._api.EvtNext(query, count) or ())
        except Exception as exc:
            args = getattr(exc, "args", ())
            fallback = args[0] if args else 0
            if int(getattr(exc, "winerror", fallback) or 0) == 259:
                return []
            raise

    def _render(self, handle) -> str:
        xml = str(self._api.EvtRender(handle, self._api.EvtRenderEventXml))
        if len(xml.encode("utf-8", "replace")) > _MAX_XML_BYTES:
            raise ValueError("Windows event XML exceeds the admission bound")
        return xml

    def _one(self, expression: str, *, reverse: bool = False) -> str:
        query = self._query(expression, reverse=reverse)
        handles = []
        try:
            handles = self._next(query, 1)
            return self._render(handles[0]) if handles else ""
        finally:
            for handle in handles:
                try:
                    self._api.EvtClose(handle)
                except Exception:
                    pass
            try:
                self._api.EvtClose(query)
            except Exception:
                pass

    def newest_record_id(self) -> int:
        xml = self._one("*[System[EventRecordID >= 0]]", reverse=True)
        return _record_id_from_xml(xml) if xml else 0

    def oldest_record_id(self) -> int:
        xml = self._one("*[System[EventRecordID >= 0]]")
        return _record_id_from_xml(xml) if xml else 0

    def record_anchor(self, record_id: int) -> str:
        value = max(0, int(record_id))
        if value == 0:
            return ""
        xml = self._one(f"*[System[EventRecordID = {value}]]")
        return hashlib.sha256(xml.encode("utf-8", "replace")).hexdigest() if xml else ""

    def read_after(self, record_id: int, limit: int = _MAX_BATCH) -> list[str]:
        cursor = max(0, int(record_id))
        bounded = max(1, min(_MAX_BATCH, int(limit)))
        if self.event_ids:
            if self.providers_by_event:
                identities = []
                for event_id in self.event_ids:
                    providers = " or ".join(
                        f"Provider[@Name='{provider}']"
                        for provider in self.providers_by_event[event_id]
                    )
                    identities.append(f"(EventID={event_id} and ({providers}))")
                selector = " or ".join(identities)
            else:
                selector = " or ".join(f"EventID={value}" for value in self.event_ids)
            expression = f"*[System[({selector}) and EventRecordID > {cursor}]]"
        else:
            expression = f"*[System[EventRecordID > {cursor}]]"
        query = self._query(expression)
        handles = []
        try:
            handles = self._next(query, bounded)
            return [self._render(handle) for handle in handles]
        finally:
            for handle in handles:
                try:
                    self._api.EvtClose(handle)
                except Exception:
                    pass
            try:
                self._api.EvtClose(query)
            except Exception:
                pass

    def close(self) -> None:
        return None


__all__ = ["WindowsEventLogSource", "_record_id_from_xml"]
