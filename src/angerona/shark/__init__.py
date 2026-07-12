"""The Shark Attack Engine — an unannounced, non-destructive adversary
simulation harness used to exercise Angerona's own detection and response
pipeline end to end.

This package is deliberately separate from ``angerona.modules`` (which the
ModuleManager auto-discovers and runs as a real, always-on defensive
capability). Nothing in here is a security module: ``shark_attack.py`` is an
on-demand test orchestrator, and ``aar_report.py`` is a read-only report
generator. The one real, always-on capability this feature adds —
``ActiveResponseSOAR`` — lives in ``angerona.modules.soar_engine`` alongside
the other defensive modules, exactly like every other capability in the app.

See ``shark_attack.py`` for the design philosophy and exactly which classic
red-team techniques were deliberately left out (and why).
"""
