"""Small SRT compatibility surface required by Vosk.

Vosk imports :mod:`srt` at module load time but only uses ``Subtitle`` and
``compose`` when its optional ``SrtResult`` helper is called. The upstream
``srt`` release is source-only, which conflicts with Angerona's wheel-only
installer policy. This deliberately small implementation preserves that helper
without executing an unaudited build backend.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable


@dataclass(frozen=True)
class Subtitle:
    index: int
    start: timedelta
    end: timedelta
    content: str
    proprietary: str = ""


def _timestamp(value: timedelta) -> str:
    total_ms = max(0, round(value.total_seconds() * 1000))
    hours, remainder = divmod(total_ms, 3_600_000)
    minutes, remainder = divmod(remainder, 60_000)
    seconds, milliseconds = divmod(remainder, 1_000)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d},{milliseconds:03d}"


def compose(subtitles: Iterable[Subtitle], reindex: bool = True, **_kwargs) -> str:
    blocks: list[str] = []
    for position, subtitle in enumerate(subtitles, 1):
        index = position if reindex else subtitle.index
        content = str(subtitle.content).replace("\r\n", "\n").replace("\r", "\n")
        blocks.append(
            f"{index}\n{_timestamp(subtitle.start)} --> {_timestamp(subtitle.end)}\n"
            f"{content}\n"
        )
    return "\n".join(blocks)


__all__ = ["Subtitle", "compose"]
