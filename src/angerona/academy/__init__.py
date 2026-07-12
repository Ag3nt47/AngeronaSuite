"""Cyber Security Academy — an educational coaching layer on top of the
Shark Attack Engine (``angerona.shark``) and the real defense modules.

Nothing in this package detects, attacks, or remediates anything itself —
it only explains, in real time and after the fact, what's already
happening elsewhere in the app:

    explainer_dictionary.py   Static lookup: technique -> attacker intent,
                              defense architecture, enterprise-tool context,
                              and both a technical and an analogy-level
                              explanation.
    security_academy.py       FlightInstructor: the AI-guided walkthrough
                              engine (live narration + Socratic post-mortem
                              coaching), talking to the same local Ollama
                              instance ai_triage.py already uses.
    achievements.py           AchievementTracker: gamified milestones,
                              persisted to academy_progress.json.
    profiler.py               PerformanceProfiler + TuningSandbox: live
                              CPU/RAM overhead readout and a single place to
                              see/adjust the real tunable knobs already
                              wired into the app (SOAR thresholds, Network
                              Monitor's novelty window, module on/off).

Kept separate from ``angerona.modules`` for the same reason ``angerona.shark``
is: this is not a security capability the ModuleManager should auto-start —
it's an on-demand teaching tool, driven from the console or the Shark
Monitor window.
"""
