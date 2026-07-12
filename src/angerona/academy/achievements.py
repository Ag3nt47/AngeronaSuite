"""achievements.py — Gamified Achievement Tracker.

Hooks into the SAME per-step "verdicts" shape aar_report.py already writes
to shark_aar.json — no separate log format, no re-parsing the flight
recorder. Newly-earned achievements are announced once; re-earning one on a
later run just increments its counter quietly, so the console/GUI never
spams "achievement unlocked" on every single drill.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


@dataclass(frozen=True)
class Achievement:
    key: str
    title: str
    icon: str
    description: str


ACHIEVEMENTS: Dict[str, Achievement] = {
    "first_blood": Achievement(
        "first_blood", "First Blood", "\U0001FA78",
        "Your defense caught its first Shark Attack step, ever.",
    ),
    "ghost_buster": Achievement(
        "ghost_buster", "Ghost Buster", "\U0001F47B",
        "Caught a stealthy (fileless/marker-only) technique in under 3 seconds.",
    ),
    "clean_sweep": Achievement(
        "clean_sweep", "Clean Sweep", "\U0001F9F9",
        "100% catch rate on a single drill — every step detected.",
    ),
    "autopilot": Achievement(
        "autopilot", "Autopilot", "\U0001F916",
        "Active Response SOAR autonomously killed + rolled back an artifact, "
        "with zero human intervention.",
    ),
    "new_kid_on_the_block": Achievement(
        "new_kid_on_the_block", "New Kid On The Block", "\U0001F310",
        "Caught a first-contact external host alert — the novel-destination "
        "signal, not just a suspicious port.",
    ),
    "blind_spot_finder": Achievement(
        "blind_spot_finder", "Blind Spot Finder", "\U0001F50D",
        "Completed a Flight Instructor post-mortem coaching session on a "
        "missed detection.",
    ),
}

# Achievements the AAR verdicts alone can't decide (e.g. "you used a
# feature"), awarded explicitly by name from wherever that thing happened.
_MANUAL_KEYS = {"blind_spot_finder"}


class AchievementTracker:
    def __init__(self, data_dir: Path) -> None:
        self.path = Path(data_dir) / "academy_progress.json"
        self._state = self._load()

    # ── Persistence ──────────────────────────────────────────────────────
    def _load(self) -> dict:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"earned": {}, "runs_evaluated": 0}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._state["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
            self.path.write_text(json.dumps(self._state, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _award(self, key: str) -> Achievement | None:
        entry = self._state["earned"].get(key)
        ach = ACHIEVEMENTS[key]
        is_new = entry is None
        if entry is None:
            entry = {"title": ach.title, "first_earned": time.strftime("%Y-%m-%d %H:%M:%S"), "times": 0}
        entry["times"] += 1
        self._state["earned"][key] = entry
        return ach if is_new else None

    # ── Evaluation ───────────────────────────────────────────────────────
    def evaluate_run(self, verdicts: List[dict]) -> List[Achievement]:
        """Given one AAR's "verdicts" list (same shape as shark_aar.json),
        award any newly-earned achievements and persist. Returns only the
        ones earned for the FIRST time by this call."""
        self._state["runs_evaluated"] = self._state.get("runs_evaluated", 0) + 1
        newly: List[Achievement] = []

        def maybe(key: str) -> None:
            got = self._award(key)
            if got:
                newly.append(got)

        if any(v.get("caught") for v in verdicts):
            maybe("first_blood")

        if any(v.get("caught") and v.get("detect_latency_s") is not None
               and v["detect_latency_s"] < 3.0 for v in verdicts):
            maybe("ghost_buster")

        # Only "detection"-category steps count toward a clean sweep —
        # Noise Injection is supposed to stay uncaught (that's its PASS
        # state) and Discovery has no detector by design, so requiring
        # literally every step caught made this achievement structurally
        # unearnable. Older verdicts (pre-category field) fall back to
        # "detection" so this doesn't crash on a stale shark_aar.json.
        detection_steps = [v for v in verdicts if v.get("category", "detection") == "detection"]
        if detection_steps and all(v.get("caught") for v in detection_steps):
            maybe("clean_sweep")

        if any(v.get("remediated") for v in verdicts):
            maybe("autopilot")

        if any(v.get("caught") and v.get("detected_by") == "Network Monitor"
               and "first contact" in (v.get("detect_message") or "").lower()
               for v in verdicts):
            maybe("new_kid_on_the_block")

        self._save()
        return newly

    def award_manual(self, key: str) -> Achievement | None:
        """For achievements tied to using a feature rather than an AAR
        verdict (currently just 'blind_spot_finder' — see _MANUAL_KEYS)."""
        if key not in _MANUAL_KEYS:
            raise KeyError(f"{key!r} is not a manually-awarded achievement "
                          "(AAR-based ones are awarded via evaluate_run)")
        got = self._award(key)
        self._save()
        return got

    # ── Reporting ────────────────────────────────────────────────────────
    def summary(self) -> str:
        earned = self._state.get("earned", {})
        total = len(ACHIEVEMENTS)
        lines = [
            f"\U0001F393 Academy Progress — {len(earned)}/{total} achievements "
            f"· {self._state.get('runs_evaluated', 0)} drill(s) evaluated",
            "-" * 72,
        ]
        for key, ach in ACHIEVEMENTS.items():
            got = earned.get(key)
            if got:
                lines.append(f"  [x] {ach.icon}  {ach.title:<22} earned {got['first_earned']}"
                             f"  (x{got['times']})")
            else:
                lines.append(f"  [ ] {ach.icon}  {ach.title:<22} {ach.description}")
        return "\n".join(lines)
