"""connectors/research_fetchers.py — fetch bridges for research-on-command.

`connectors/research.py` classifies an indicator and builds vetted, allow-listed
lookup URLs, but deliberately leaves the *page fetch* to an injected callable so
the core stays local and side-effect-free. This module supplies the two realistic
bridges and wires research into the ARIA assistant:

  • Browser-surface mode (default, no egress from the app): open the vetted URLs
    in the operator's default browser. This is the "via Claude-for-Chrome" path —
    with the Claude-for-Chrome extension installed, Claude reads and summarises the
    pages in the browser it just opened. Nothing is fetched by the app itself.

  • Headless-fetch mode (opt-in egress): an ``HttpFetcher`` that GETs an
    allow-listed URL and returns its text for autonomous summaries. It refuses to
    touch the network unless ``allow_egress=True`` is set explicitly, and it only
    fetches hosts on research's allow-list — so it can't be pointed at arbitrary
    URLs.

    HARD SCOPE: read-only reconnaissance of indicators the operator chose to look
    up. Browser mode sends nothing from the app; headless mode is opt-in, GET-only,
    allow-listed, and never submits/uploads anything.
"""
from __future__ import annotations

import webbrowser
from typing import Callable, Optional

try:  # in-package; falls back to flat layout for the standalone runner
    from angerona.connectors.research import (Research, ResearchTask,
                                              _ALLOWED_HOSTS, _host_of)
except ImportError:  # pragma: no cover
    from research import Research, ResearchTask, _ALLOWED_HOSTS, _host_of

try:
    from angerona.core.assistant import Assistant, ToolKind
except ImportError:  # pragma: no cover
    try:
        from assistant import Assistant, ToolKind
    except ImportError:  # pragma: no cover
        Assistant = None  # type: ignore
        ToolKind = None    # type: ignore


# ── Browser-surface mode (the Claude-for-Chrome path; no app egress) ──────────
def open_sources(task: ResearchTask, *,
                 opener: Optional[Callable[[str], bool]] = None) -> int:
    """Open every vetted source URL for ``task`` in the browser. Returns the
    number opened. With the Claude-for-Chrome extension present, Claude reads
    and summarises the pages there — the app fetches nothing itself."""
    op = opener or webbrowser.open
    n = 0
    for _name, url in task.sources:
        if _host_of(url) in _ALLOWED_HOSTS:   # never open a non-allow-listed URL
            try:
                op(url)
                n += 1
            except Exception:
                pass
    return n


# ── Headless-fetch mode (opt-in egress, GET-only, allow-listed) ───────────────
class HttpFetcher:
    """A ``fetch(url) -> text`` callable for research's aggregation path.

    Off by default: constructing it without ``allow_egress=True`` yields a
    fetcher that refuses to touch the network. Even when enabled it only fetches
    hosts on research's allow-list."""

    def __init__(self, *, allow_egress: bool = False, timeout: float = 10.0,
                 user_agent: str = "Angerona-Research/1.0") -> None:
        self.allow_egress = allow_egress
        self.timeout = timeout
        self.user_agent = user_agent

    def __call__(self, url: str) -> str:
        if not self.allow_egress:
            raise RuntimeError("headless egress disabled — set allow_egress=True to fetch")
        if _host_of(url) not in _ALLOWED_HOSTS:
            raise RuntimeError(f"refusing non-allow-listed host: {_host_of(url)}")
        import urllib.request  # local import: no network cost unless actually used
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # pragma: no cover
            return resp.read().decode("utf-8", "replace")


# ── Wire research into the ARIA assistant (recon = read-only) ─────────────────
def register_research_tool(aria, research: Optional[Research] = None, *,
                           open_in_browser: bool = True,
                           opener: Optional[Callable[[str], bool]] = None) -> None:
    """Register a READ tool ``research`` on the assistant. Recon is read-only:
    building the vetted URLs is local, and in browser mode the app fetches
    nothing (Claude-for-Chrome reads the opened pages). Returns the ResearchTask."""
    research = research or Research()

    def _research(indicator: str):
        task = research.run(indicator)
        if open_in_browser and task.sources:
            opened = open_sources(task, opener=opener)
            task.note = (task.note + f"  [opened {opened} source(s) in browser]").strip()
        return task

    aria.register("research", ToolKind.READ, _research,
                  "look up an indicator (hash/IP/domain/URL/CVE) via vetted sources")


# ── Self-test ──────────────────────────────────────────────────────────────────
def self_test() -> tuple[bool, str]:
    """Prove: browser mode opens only allow-listed source URLs via the injected
    opener; the headless fetcher refuses egress by default and rejects
    non-allow-listed hosts even when enabled; and the assistant 'research' tool
    runs as a READ, returning a ResearchTask."""
    try:
        # browser-surface: opener is called once per allow-listed source
        opened: list[str] = []
        task = Research().run("CVE-2026-1234")
        n = open_sources(task, opener=lambda u: (opened.append(u), True)[1])
        assert n == len(task.sources) and opened, "opened each vetted source"
        assert all(_host_of(u) in _ALLOWED_HOSTS for u in opened), "only allow-listed URLs opened"

        # headless fetcher: refuses by default, rejects off-list hosts when enabled
        try:
            HttpFetcher()("https://www.virustotal.com/gui/file/x")
            raise AssertionError("disabled fetcher must refuse egress")
        except RuntimeError as e:
            assert "egress disabled" in str(e)
        try:
            HttpFetcher(allow_egress=True)("https://evil.example.com/x")
            raise AssertionError("must reject non-allow-listed host")
        except RuntimeError as e:
            assert "non-allow-listed" in str(e)

        # assistant wiring (only if the assistant is importable)
        if Assistant is not None:
            aria = Assistant(enabled=True)
            surfaced: list[str] = []
            register_research_tool(aria, Research(), opener=lambda u: (surfaced.append(u), True)[1])
            r = aria.invoke("research", "8.8.8.8")     # READ → runs live
            assert r.ok and not r.needs_confirmation, "research is a live READ tool"
            assert isinstance(r.data, ResearchTask) and r.data.kind == "ip", "returns a ResearchTask"
            assert surfaced, "browser opener invoked through the tool"

        return True, ("OK — browser mode opens only allow-listed source URLs via the "
                      "injected opener; headless fetcher refuses egress by default and "
                      "rejects off-allow-list hosts when enabled; assistant 'research' "
                      "tool runs as a live READ returning a ResearchTask.")
    except AssertionError as exc:
        return False, f"FAIL — {exc}"
    except Exception as exc:  # pragma: no cover
        return False, f"ERROR — {type(exc).__name__}: {exc}"


if __name__ == "__main__":
    ok, detail = self_test()
    print(f"[research_fetchers] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
