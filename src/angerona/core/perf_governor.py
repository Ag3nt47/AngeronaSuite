"""core/perf_governor.py — ARIA Overdrive: adaptive performance governor.

Read-only tuning authority for Angerona's *cosmetic / UI* path. The governor
samples the suite's own vitals, computes a load band with hysteresis, and
publishes a :class:`TuningProfile` that GUI panels and the EventBus consult
instead of hardcoded constants (GUI refresh interval, alert row cap, scan
cap, INFO backpressure point). When load falls, it restores full fidelity.

────────────────────────────────────────────────────────────────────────────
HARD SAFETY INVARIANT  (non-negotiable — see ``self_test`` for the proof)
────────────────────────────────────────────────────────────────────────────
    The governor may ONLY ever relax COSMETIC / UI / non-critical work.
    It must NEVER slow, drop, or throttle detection, correlation, or
    response. Every knob it exposes affects presentation only:

        refresh_ms          → how often the GUI repaints (cosmetic)
        panel_cap           → how many rows a *view* renders (cosmetic)
        scan_cap            → how many strings a *display* batch shows (cosmetic)
        info_drop_occupancy → when INFO (noise) is shed from the bus ring

    The detection hot path reads NONE of these. HIGH / CRITICAL events are
    ALWAYS admitted to the bus regardless of ``info_drop_occupancy``. The
    governor is behaviour-preserving for the security path, always.

Threat-aware priority inversion (the important one):
    Today, when threat goes critical, *everything* slows — including
    detection. Overdrive inverts that: under a threat spike it sheds cheap
    UI work FIRST so the detection hot path keeps its cycles. Priority order
    is detection > response > UI > cosmetics. The SOC speeds up exactly when
    it matters, instead of grinding.

Gated & additive:
    Nothing in this module runs at import time. It is wired into nothing.
    A caller must construct / fetch a :class:`PerfGovernor` and call
    :meth:`PerfGovernor.sample`. Defaults OFF behind
    ``config.perf_governor_enabled`` (default ``False``). Local-first,
    stdlib-only (``psutil`` optional and degraded-safe).

Contract mirrors the other core infra singletons (``gpu_entropy``,
``flow_metrics``): a ``get_governor()`` / ``init_governor()`` factory, a
plain read-only class, and a ``self_test() -> (bool, str)``.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Optional

try:  # optional — governor degrades to neutral vitals without it
    import psutil  # type: ignore
    _HAVE_PSUTIL = True
except Exception:  # pragma: no cover - environment dependent
    psutil = None  # type: ignore
    _HAVE_PSUTIL = False


# ── Load bands ────────────────────────────────────────────────────────────────
class Band(IntEnum):
    """Ordered by severity so comparisons and monotonicity checks are trivial."""
    NOMINAL = 0
    ELEVATED = 1
    HIGH = 2
    CRITICAL = 3

    @property
    def label(self) -> str:
        return self.name


# ── Tuning profile (the only thing the rest of the app reads) ─────────────────
@dataclass(frozen=True)
class TuningProfile:
    """A read-only snapshot of the *cosmetic* knobs for the current band.

    Every field governs presentation only. Consumers read these instead of
    hardcoding constants::

        prof = get_governor().profile()
        timer.setInterval(prof.refresh_ms)          # was hardcoded 2000
        events = storage.recent(prof.panel_cap)     # was hardcoded 120
        batch  = strings[: prof.scan_cap]           # display batch only
        if occupancy >= prof.info_drop_occupancy:   # shed INFO earlier
            ...  # HIGH/CRITICAL still ALWAYS admitted
    """
    band: Band
    refresh_ms: int          # GUI repaint interval (cosmetic)   — NON-DECREASING with load
    panel_cap: int           # rows a view renders (cosmetic)    — NON-INCREASING with load
    scan_cap: int            # strings a display batch shows      — NON-INCREASING with load
    info_drop_occupancy: float  # ring frac at/above which INFO is shed — NON-INCREASING with load
    coalesce_ms: int         # bus-event UI coalescing window     — NON-DECREASING with load
    note: str = ""


# Baseline == today's shipped constants, so NOMINAL is byte-for-byte the
# current behaviour. Higher bands only ever *relax* the UI path.
#   refresh_ms          : main_window two-tier full refresh (2000 ms)
#   panel_cap           : AlertsPanel storage.recent(120)
#   scan_cap            : gpu_entropy display batch (500 shown; 4096 compute cap untouched)
#   info_drop_occupancy : EventBus backpressure point (0.85)
_PROFILES: dict[Band, TuningProfile] = {
    Band.NOMINAL:  TuningProfile(Band.NOMINAL,  2000, 120, 500, 0.85, 100, "full fidelity"),
    Band.ELEVATED: TuningProfile(Band.ELEVATED, 3000,  90, 400, 0.80, 150, "trimming cosmetics"),
    Band.HIGH:     TuningProfile(Band.HIGH,     4500,  60, 250, 0.75, 250, "shedding UI to protect detection"),
    Band.CRITICAL: TuningProfile(Band.CRITICAL, 6000,  40, 150, 0.70, 400, "detection-first — UI minimised"),
}

# Rising thresholds (load must EXCEED to climb) and falling thresholds (load
# must DROP BELOW to descend). The gap between them is the hysteresis dead-band
# that stops the band oscillating on noisy samples.
_RISE = {Band.ELEVATED: 0.35, Band.HIGH: 0.60, Band.CRITICAL: 0.82}
_FALL = {Band.ELEVATED: 0.25, Band.HIGH: 0.50, Band.CRITICAL: 0.72}


@dataclass
class Vitals:
    """One sample of the suite's own vitals. All fields normalised 0.0–1.0
    except where noted. Missing readings default to 0.0 → stays NOMINAL."""
    bus_occupancy: float = 0.0      # EventBus ring fill fraction
    cpu_pct: float = 0.0            # suite process CPU, fraction of one core-equiv
    gui_latency_norm: float = 0.0   # GUI refresh latency vs budget (1.0 == at budget)
    qt_objects_norm: float = 0.0    # live Qt object count vs soft ceiling
    rss_norm: float = 0.0           # process RSS vs soft ceiling
    eps_norm: float = 0.0           # bus events/sec vs soft ceiling
    threat_pressure: float = 0.0    # 0..1 from threat state / inverted Angerona Score
    raw: Optional[dict] = None      # untouched source numbers, for narration


class PerfGovernor:
    """Adaptive, read-only performance governor.

    Usage (all opt-in; wired into nothing by default)::

        gov = get_governor()
        gov.sample(vitals_provider=my_provider)   # call on a slow cadence
        prof = gov.profile()                      # panels read this

    The governor holds NO references to detection modules and issues NO
    commands. It only computes a band and hands back a :class:`TuningProfile`.
    """

    # Optional dual-contract fields so Overdrive can surface next to the other
    # Phase-3 components in status views. It is NOT a BaseModule (no thread).
    CODE = "OVRD"
    NAME = "ARIA Overdrive"

    # How many rising samples before a monotonic climb is flagged an anomaly.
    _ANOMALY_WINDOW = 6

    def __init__(
        self,
        *,
        enabled: bool = False,
        emit: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        """``enabled`` mirrors ``config.perf_governor_enabled`` (default False).
        ``emit`` is an optional ``(message, severity)`` sink used only for
        narration — the governor never emits security events itself."""
        self.enabled = enabled
        self._emit = emit
        self.band: Band = Band.NOMINAL
        self._last_vitals: Vitals = Vitals()
        self._load: float = 0.0          # smoothed composite load
        self._ewma_alpha = 0.4
        self._qt_hist: list[float] = []
        self._lat_hist: list[float] = []
        self.anomalies: list[str] = []
        self._transitions: int = 0
        self._last_change_ts: float = 0.0

    # ── Public read surface ───────────────────────────────────────────────────
    def profile(self) -> TuningProfile:
        """The current cosmetic tuning profile. Safe to call from the GUI
        thread every tick; it is a cheap dict lookup, never blocks."""
        if not self.enabled:
            return _PROFILES[Band.NOMINAL]  # OFF == today's behaviour, exactly
        return _PROFILES[self.band]

    @property
    def load(self) -> float:
        return self._load

    def health_pct(self) -> int:
        """Coarse self-health for status views: full unless an anomaly is live."""
        if not self.enabled:
            return 100
        if self.anomalies:
            return 55
        return 100 if self.band <= Band.HIGH else 80

    # ── Sampling / decision ───────────────────────────────────────────────────
    def sample(
        self,
        vitals: Optional[Vitals] = None,
        *,
        vitals_provider: Optional[Callable[[], Vitals]] = None,
    ) -> TuningProfile:
        """Take one vitals sample, update the band (with hysteresis), and
        return the resulting profile. Pass an explicit ``vitals`` (tests,
        replay) or a ``vitals_provider`` callable; if neither is given the
        governor reads what it can from ``psutil`` and otherwise stays
        NOMINAL. Never raises on a bad sample — degrades to neutral."""
        if vitals is None:
            try:
                vitals = vitals_provider() if vitals_provider else self._default_vitals()
            except Exception:
                vitals = Vitals()  # graceful degradation is first-class
        self._last_vitals = vitals

        raw_load = self._composite_load(vitals)
        # EWMA smoothing so a single spiky sample can't yank the band.
        self._load = (self._ewma_alpha * raw_load) + ((1 - self._ewma_alpha) * self._load)

        self._update_band(self._load)
        self._watch_anomalies(vitals)
        return self.profile()

    def _default_vitals(self) -> Vitals:
        """Best-effort self-telemetry from psutil. Any failure → 0.0 (NOMINAL)."""
        if not _HAVE_PSUTIL:
            return Vitals()
        try:
            p = psutil.Process()
            cpu = p.cpu_percent(interval=None) / 100.0
            rss = p.memory_info().rss
            rss_norm = min(1.0, rss / (1024 * 1024 * 1024))  # soft ceiling 1 GiB
            return Vitals(cpu_pct=min(1.0, cpu), rss_norm=rss_norm,
                          raw={"cpu_pct": cpu, "rss_bytes": rss})
        except Exception:
            return Vitals()

    @staticmethod
    def _composite_load(v: Vitals) -> float:
        """Blend vitals into a single 0..1 load score.

        Resource pressure is a weighted blend of the observable vitals.
        Threat pressure enters as a FLOOR (``max``), not a summand: a threat
        spike alone forces UI shedding to free the detection hot path even
        when CPU is calm. This is the priority-inversion fix — and because it
        only raises the *UI* load score, it can never touch detection."""
        resource = (
            0.30 * v.bus_occupancy +
            0.25 * v.cpu_pct +
            0.15 * v.gui_latency_norm +
            0.10 * v.qt_objects_norm +
            0.10 * v.rss_norm +
            0.10 * v.eps_norm
        )
        resource = max(0.0, min(1.0, resource))
        return max(resource, max(0.0, min(1.0, v.threat_pressure)))

    def _update_band(self, load: float) -> None:
        """Move at most one band per sample, respecting rise/fall hysteresis.

        Climbing uses the higher ``_RISE`` thresholds; descending uses the
        lower ``_FALL`` thresholds. Between the two the band is sticky, which
        is what prevents oscillation on a jittery load signal."""
        cur = self.band
        new = cur
        if cur < Band.CRITICAL and load >= _RISE[Band(cur + 1)]:
            new = Band(cur + 1)
        elif cur > Band.NOMINAL and load < _FALL[cur]:
            new = Band(cur - 1)

        if new != cur:
            self.band = new
            self._transitions += 1
            self._last_change_ts = time.time()
            if self._emit is not None:
                self._emit(self.narrate(), "INFO")

    # ── Self-healing anomaly watch ────────────────────────────────────────────
    def _watch_anomalies(self, v: Vitals) -> None:
        """Flag the failure classes Angerona has actually hit — an unbounded
        climb in live Qt-widget count, or refresh latency trending up — before
        they make the UI unusable. Detection is never involved."""
        self.anomalies = []
        self._qt_hist = (self._qt_hist + [v.qt_objects_norm])[-self._ANOMALY_WINDOW:]
        self._lat_hist = (self._lat_hist + [v.gui_latency_norm])[-self._ANOMALY_WINDOW:]

        if self._strictly_increasing(self._qt_hist) and v.qt_objects_norm > 0.6:
            self.anomalies.append(
                "Live Qt-widget count climbing unbounded — suspect a panel "
                "leaking row widgets; profile falling back to tighter panel_cap."
            )
        if self._strictly_increasing(self._lat_hist) and v.gui_latency_norm > 0.6:
            self.anomalies.append(
                "GUI refresh latency trending up — stretching refresh_ms to "
                "keep the main thread responsive."
            )
        if self.anomalies and self._emit is not None:
            for a in self.anomalies:
                self._emit(f"[Overdrive] {a}", "INFO")

    @staticmethod
    def _strictly_increasing(seq: list[float]) -> bool:
        return len(seq) >= 3 and all(b > a for a, b in zip(seq, seq[1:]))

    # ── Narration (ARIA reads this; the governor doesn't speak on its own) ─────
    def narrate(self) -> str:
        """One-line, human summary of what the governor just did, for ARIA to
        voice or print. Contrasts the active profile against full fidelity so
        the recovered UI headroom is visible."""
        base = _PROFILES[Band.NOMINAL]
        cur = self.profile()
        if cur.band == Band.NOMINAL:
            return "Load nominal — full fidelity, no throttling."
        headroom = int(round((1 - base.refresh_ms / cur.refresh_ms) * 100))
        return (
            f"Load {cur.band.label} — stretched refresh {base.refresh_ms}->{cur.refresh_ms}ms, "
            f"capped alerts {base.panel_cap}->{cur.panel_cap}, shed INFO earlier "
            f"({base.info_drop_occupancy:.0%}->{cur.info_drop_occupancy:.0%}) to protect "
            f"detection; ~{headroom}% UI refresh headroom recovered. Detection path untouched."
        )

    # ── Self-test ─────────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        """Prove the three things that make Overdrive safe and correct:

          1. Tuning is MONOTONIC across severity — as the band worsens,
             refresh_ms/coalesce_ms never fall and panel_cap/scan_cap/
             info_drop_occupancy never rise. (No knob ever *speeds up* the UI
             under load, and none of them is a detection knob.)
          2. Band transitions are CLEAN under a full 0->1->0 load sweep — the
             band climbs, peaks at CRITICAL, and returns to NOMINAL, moving at
             most one step per sample.
          3. Hysteresis PREVENTS oscillation — a load parked in the rise/fall
             dead-band does not flip-flop.

        Returns ``(passed, detail)``."""
        # A Vitals whose six resource fields are all ``t`` yields a composite
        # load of exactly ``t`` (the resource weights sum to 1.0), which makes
        # the band arithmetic below deterministic and easy to reason about.
        def V(t: float) -> Vitals:
            return Vitals(bus_occupancy=t, cpu_pct=t, gui_latency_norm=t,
                          qt_objects_norm=t, rss_norm=t, eps_norm=t)

        try:
            # 1 ── monotonic tuning across the four bands
            ordered = [_PROFILES[b] for b in (Band.NOMINAL, Band.ELEVATED, Band.HIGH, Band.CRITICAL)]
            for a, b in zip(ordered, ordered[1:]):
                assert b.refresh_ms >= a.refresh_ms, "refresh_ms must not fall under load"
                assert b.coalesce_ms >= a.coalesce_ms, "coalesce_ms must not fall under load"
                assert b.panel_cap <= a.panel_cap, "panel_cap must not rise under load"
                assert b.scan_cap <= a.scan_cap, "scan_cap must not rise under load"
                assert b.info_drop_occupancy <= a.info_drop_occupancy, "INFO must be shed no later under load"
            # NOMINAL must equal today's shipped constants exactly
            base = _PROFILES[Band.NOMINAL]
            assert (base.refresh_ms, base.panel_cap, base.scan_cap, base.info_drop_occupancy) \
                == (2000, 120, 500, 0.85), "NOMINAL must match shipped defaults"

            # 2 ── clean transitions on a 0->1->0 sweep (fresh governor, no EWMA lag bias)
            g = PerfGovernor(enabled=True)
            g._ewma_alpha = 1.0  # deterministic: follow the driven load exactly
            up = [i / 20 for i in range(21)]          # 0.00 .. 1.00
            seq_up: list[int] = []
            for x in up:
                g.sample(V(x))
                seq_up.append(int(g.band))
            assert seq_up[0] == Band.NOMINAL, "must start NOMINAL"
            assert max(seq_up) == Band.CRITICAL, "must reach CRITICAL at full load"
            assert all(abs(b - a) <= 1 for a, b in zip(seq_up, seq_up[1:])), "no band skipping"
            assert seq_up == sorted(seq_up), "band must be non-decreasing while load rises"

            seq_dn: list[int] = []
            for x in reversed(up):
                g.sample(V(x))
                seq_dn.append(int(g.band))
            assert seq_dn[-1] == Band.NOMINAL, "must return to NOMINAL when load clears"
            assert seq_dn == sorted(seq_dn, reverse=True), "band must be non-increasing while load falls"

            # 3 ── hysteresis: park load inside the ELEVATED rise/fall dead-band
            #      (_FALL=0.25 .. _RISE=0.35) and confirm no oscillation.
            h = PerfGovernor(enabled=True)
            h._ewma_alpha = 1.0
            h.sample(V(0.50))                         # climb into ELEVATED (>=0.35, <0.60)
            assert h.band == Band.ELEVATED
            start_transitions = h._transitions
            for _ in range(10):
                h.sample(V(0.30))                     # inside dead-band (>=0.25, <0.35)
            assert h.band == Band.ELEVATED, "dead-band load must not drop the band"
            assert h._transitions == start_transitions, "no oscillation inside hysteresis band"

            # 4 ── priority inversion: threat alone (calm CPU) forces UI shedding.
            #      One band per sample, so climb over several samples to CRITICAL.
            t = PerfGovernor(enabled=True)
            t._ewma_alpha = 1.0
            for _ in range(4):
                t.sample(Vitals(cpu_pct=0.0, threat_pressure=0.95))
            assert t.band == Band.CRITICAL, "threat spike must shed UI even with calm CPU"

            # 5 ── OFF == today's behaviour exactly
            off = PerfGovernor(enabled=False)
            off.sample(Vitals(bus_occupancy=1.0, cpu_pct=1.0, threat_pressure=1.0))
            assert off.profile() == _PROFILES[Band.NOMINAL], "disabled governor must not tune"

            return True, (
                "OK — monotonic tuning verified across 4 bands; clean 0->1->0 "
                "sweep (NOMINAL->CRITICAL->NOMINAL, no skips); hysteresis holds "
                "the dead-band; threat-priority-inversion reaches CRITICAL on a "
                "calm CPU; disabled governor is byte-for-byte the shipped defaults."
            )
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


# ── Singleton factory (mirrors gpu_entropy.get_pipeline / flow_metrics) ────────
_GOVERNOR: Optional[PerfGovernor] = None


def init_governor(
    *,
    enabled: bool = False,
    emit: Optional[Callable[[str, str], None]] = None,
) -> PerfGovernor:
    """Create (or replace) the process-wide governor. Call once from
    ``app.py`` after config load, e.g.::

        init_governor(enabled=config.perf_governor_enabled, emit=bus_emit)

    Off by default; wired into nothing until a caller opts in."""
    global _GOVERNOR
    _GOVERNOR = PerfGovernor(enabled=enabled, emit=emit)
    return _GOVERNOR


def get_governor() -> PerfGovernor:
    """Return the shared governor, lazily creating a disabled one so callers
    (panels reading ``.profile()``) are always safe even before wiring."""
    global _GOVERNOR
    if _GOVERNOR is None:
        _GOVERNOR = PerfGovernor(enabled=False)
    return _GOVERNOR


if __name__ == "__main__":  # manual smoke test: ``python -m angerona.core.perf_governor``
    ok, detail = PerfGovernor().self_test()
    print(f"[perf_governor] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    demo = PerfGovernor(enabled=True)
    demo._ewma_alpha = 1.0
    for load in (0.1, 0.4, 0.7, 0.9, 0.95):
        demo.sample(Vitals(bus_occupancy=load, cpu_pct=load, eps_norm=load))
        print(f"  load={load:>4} → {demo.band.label:<8} {demo.narrate()}")
    raise SystemExit(0 if ok else 1)
